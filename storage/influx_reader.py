"""Lectura de telemetría histórica desde InfluxDB."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from influxdb_client import InfluxDBClient

from analytics.indicators import calculate_indicators


PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")


class InfluxReader:
    """Consulta eventos del gateway y reconstruye sus indicadores."""

    def __init__(self):
        port = os.getenv("INFLUXDB_PORT", "8086")
        url = os.getenv("INFLUXDB_URL", f"http://localhost:{port}")

        token = os.getenv("INFLUXDB_ADMIN_TOKEN")
        org = os.getenv("INFLUXDB_ORG")
        bucket = os.getenv("INFLUXDB_BUCKET")

        missing = [
            name
            for name, value in {
                "INFLUXDB_ADMIN_TOKEN": token,
                "INFLUXDB_ORG": org,
                "INFLUXDB_BUCKET": bucket,
            }.items()
            if not value
        ]

        if missing:
            raise RuntimeError(
                "Faltan variables en .env: " + ", ".join(missing)
            )

        self.org = org
        self.bucket = bucket

        self.client = InfluxDBClient(
            url=url,
            token=token,
            org=org,
            timeout=10000,
        )

        self.query_api = self.client.query_api()

    @staticmethod
    def _flux_string(value):
        """Escapa un texto para utilizarlo como literal Flux."""
        return json.dumps(str(value))

    def build_query(
        self,
        interface,
        source="ubuntu_gateway",
        data_origin="observed",
        lookback_days=30,
        limit=None,
    ):
        """Construye la consulta Flux para reconstruir eventos completos."""

        if not isinstance(lookback_days, int) or lookback_days < 1:
            raise ValueError("lookback_days debe ser un entero positivo")

        if limit is not None:
            if not isinstance(limit, int) or limit < 1:
                raise ValueError("limit debe ser un entero positivo")

        bucket = self._flux_string(self.bucket)
        source_value = self._flux_string(source)
        interface_value = self._flux_string(interface)
        origin_value = self._flux_string(data_origin)

        query = f'''
from(bucket: {bucket})
    |> range(start: -{lookback_days}d)
    |> filter(fn: (r) => r["_measurement"] == "gateway_network")
    |> filter(fn: (r) => r["source"] == {source_value})
    |> filter(fn: (r) => r["interface"] == {interface_value})
    |> filter(fn: (r) => r["data_origin"] == {origin_value})
    |> pivot(
        rowKey: ["_time", "source", "interface", "data_origin"],
        columnKey: ["_field"],
        valueColumn: "_value"
    )
'''

        if limit is not None:
            query += f'''
    |> sort(columns: ["_time"], desc: true)
    |> limit(n: {limit})
'''

        query += '''
    |> sort(columns: ["_time"])
'''

        return query

    @staticmethod
    def _decode_json_field(value):
        """Decodifica un campo JSON sin inventar datos ante errores."""

        if value is None:
            return None

        if not isinstance(value, str):
            return None

        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return None

    @staticmethod
    def _record_to_event(record):
        """Convierte un registro pivotado en un evento del gateway."""

        values = record.values

        timestamp = values.get("_time")

        if isinstance(timestamp, datetime):
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)

            timestamp = timestamp.isoformat()

        elif isinstance(timestamp, str):
            try:
                parsed_timestamp = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )

                if parsed_timestamp.tzinfo is None:
                    parsed_timestamp = parsed_timestamp.replace(
                        tzinfo=timezone.utc
                    )

                timestamp = parsed_timestamp.isoformat()

            except ValueError:
                return None

        else:
            return None

        event = {
            "timestamp": timestamp,
            "source": values.get("source"),
            "interface": values.get("interface"),
            "data_origin": values.get("data_origin"),
        }

        # Métricas numéricas y estados.
        fields = (
            "outbound_bytes_total",
            "outbound_bytes_interval",
            "outbound_bytes_status",
            "established_tcp_connections",
            "unique_external_destinations",
            "process_count",
            "connections_without_process_attribution",
            "authorized_connections",
            "unauthorized_connections",
            "assessed_external_connections",
            "policy_enabled",
        )

        for field in fields:
            if field in values:
                event[field] = values[field]

        # Contexto de procesos observados.
        if "processes_json" in values:
            event["processes"] = InfluxReader._decode_json_field(
                values["processes_json"]
            )

        # Destinos externos observados.
        if "external_destinations_json" in values:
            event["external_destinations"] = (
                InfluxReader._decode_json_field(
                    values["external_destinations_json"]
                )
            )

        # Destinos autorizados.
        if "authorized_destinations_json" in values:
            event["authorized_destinations"] = (
                InfluxReader._decode_json_field(
                    values["authorized_destinations_json"]
                )
            )

        # Destinos no autorizados.
        if "unauthorized_destinations_json" in values:
            event["unauthorized_destinations"] = (
                InfluxReader._decode_json_field(
                    values["unauthorized_destinations_json"]
                )
            )

        return event

    def read_events(
        self,
        interface,
        source="ubuntu_gateway",
        data_origin="observed",
        lookback_days=30,
        limit=None,
    ):
        """Lee eventos completos, ordenados cronológicamente."""

        if not isinstance(interface, str) or not interface.strip():
            raise ValueError("interface debe ser un texto no vacío")

        query = self.build_query(
            interface=interface,
            source=source,
            data_origin=data_origin,
            lookback_days=lookback_days,
            limit=limit,
        )

        tables = self.query_api.query(query, org=self.org)

        events = []

        for table in tables:
            for record in table.records:
                event = self._record_to_event(record)

                if event is not None:
                    events.append(event)

        events.sort(key=lambda event: event["timestamp"])

        return events

    def read_indicators(
        self,
        interface,
        source="ubuntu_gateway",
        data_origin="observed",
        lookback_days=30,
        limit=None,
    ):
        """
        Lee eventos y calcula indicadores en orden cronológico.

        Cada indicador utiliza el evento inmediatamente anterior
        para calcular el intervalo temporal y la tasa de tráfico.
        """

        events = self.read_events(
            interface=interface,
            source=source,
            data_origin=data_origin,
            lookback_days=lookback_days,
            limit=limit,
        )

        indicators = []

        previous = None

        for event in events:
            indicators.append(
                calculate_indicators(
                    current=event,
                    previous=previous,
                )
            )

            previous = event

        return indicators

    def close(self):
        """Cierra la conexión con InfluxDB."""
        self.client.close()


if __name__ == "__main__":

    reader = InfluxReader()

    try:
        events = reader.read_events(interface="wlo1")
        indicators = reader.read_indicators(interface="wlo1")

        print(f"Eventos recuperados: {len(events)}")
        print(f"Indicadores calculados: {len(indicators)}")

        if indicators:
            print("\nÚltimo indicador:")
            print(
                json.dumps(
                    indicators[-1],
                    indent=2,
                    ensure_ascii=False,
                )
            )
        else:
            print("No se encontraron eventos para los filtros indicados.")

    finally:
        reader.close()