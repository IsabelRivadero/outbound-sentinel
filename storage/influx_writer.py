"""Persistencia de telemetría del gateway en InfluxDB."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS


PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")


class InfluxWriter:
    """Escribe eventos de telemetría del gateway en InfluxDB."""

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

        self.write_api = self.client.write_api(
            write_options=SYNCHRONOUS
        )

    @staticmethod
    def _timestamp(value):
        """Convierte el timestamp a datetime con zona horaria."""

        if value:
            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)

            return parsed

        return datetime.now(timezone.utc)

    def event_to_point(self, event: dict[str, Any]) -> Point:
        """Transforma un evento del gateway en un punto de InfluxDB."""

        point = (
            Point("gateway_network")
            .tag("source", str(event.get("source", "unknown")))
            .tag("interface", str(event.get("interface", "unknown")))
            .tag("data_origin", str(event.get("data_origin", "unknown")))
            .time(
                self._timestamp(event.get("timestamp")),
                WritePrecision.NS,
            )
        )

        # Métricas numéricas.
        numeric_fields = [
            "outbound_bytes_total",
            "outbound_bytes_interval",
            "established_tcp_connections",
            "unique_external_destinations",
            "process_count",
            "connections_without_process_attribution",
            "authorized_connections",
            "unauthorized_connections",
            "assessed_external_connections",
        ]

        for field in numeric_fields:
            value = event.get(field)

            if isinstance(value, (int, float)) and not isinstance(value, bool):
                point.field(field, value)

        # Estado del intervalo de bytes.
        status = event.get(
            "outbound_bytes_status",
            event.get("outbound_bytes_interval_status"),
        )

        if status is not None:
            point.field("outbound_bytes_status", str(status))

        # Estado de la política de destinos.
        if isinstance(event.get("policy_enabled"), bool):
            point.field("policy_enabled", event["policy_enabled"])

        # Procesos observados.
        processes = event.get(
            "processes_with_observed_connections",
            event.get("processes"),
        )

        if processes is not None:
            point.field(
                "processes_json",
                json.dumps(processes, ensure_ascii=False),
            )

        # Destinos externos observados.
        destinations = event.get("external_destinations")

        if destinations is not None:
            point.field(
                "external_destinations_json",
                json.dumps(destinations, ensure_ascii=False),
            )

        # Destinos autorizados según la política configurada.
        authorized_destinations = event.get("authorized_destinations")

        if authorized_destinations is not None:
            point.field(
                "authorized_destinations_json",
                json.dumps(authorized_destinations, ensure_ascii=False),
            )

        # Destinos no autorizados según la política configurada.
        unauthorized_destinations = event.get("unauthorized_destinations")

        if unauthorized_destinations is not None:
            point.field(
                "unauthorized_destinations_json",
                json.dumps(unauthorized_destinations, ensure_ascii=False),
            )

        return point

    def write_event(self, event: dict[str, Any]) -> None:
        """Persiste un evento en InfluxDB."""

        if not isinstance(event, dict):
            raise TypeError("El evento debe ser un diccionario.")

        point = self.event_to_point(event)

        self.write_api.write(
            bucket=self.bucket,
            org=self.org,
            record=point,
        )

    def close(self):
        """Cierra la conexión con InfluxDB."""
        self.client.close()


if __name__ == "__main__":

    writer = InfluxWriter()

    try:
        health = writer.client.health()

        print("InfluxDB:", health.status)
        print("Organización:", writer.org)
        print("Bucket:", writer.bucket)
        print("Conexión verificada. No se escribió ninguna medición.")

    finally:
        writer.close()