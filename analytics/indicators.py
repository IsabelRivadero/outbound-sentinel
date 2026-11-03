"""Cálculo y agregación de indicadores de telemetría."""

from collections import defaultdict
from datetime import datetime, timezone, timedelta
from numbers import Real
from typing import Any


def _numeric_value(event: dict, key: str):
    """Devuelve un valor numérico válido o None."""
    value = event.get(key)

    if isinstance(value, bool) or not isinstance(value, Real):
        return None

    return value


def _parse_timestamp(value: Any):
    """Convierte un timestamp ISO-8601 en datetime con zona horaria."""
    if not isinstance(value, str):
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            return None

        return parsed

    except ValueError:
        return None


def calculate_indicators(
    current: dict,
    previous: dict | None = None,
) -> dict:
    """
    Calcula indicadores de una medición individual.

    Los valores no disponibles permanecen como None.
    No realiza inferencias sobre la legitimidad de las conexiones.
    """
    if not isinstance(current, dict):
        raise TypeError("current debe ser un diccionario")

    timestamp = _parse_timestamp(current.get("timestamp"))

    previous_timestamp = (
        _parse_timestamp(previous.get("timestamp"))
        if isinstance(previous, dict)
        else None
    )

    elapsed_seconds = None

    if timestamp is not None and previous_timestamp is not None:
        elapsed = (timestamp - previous_timestamp).total_seconds()

        if elapsed > 0:
            elapsed_seconds = elapsed

    outbound_bytes = _numeric_value(
        current,
        "outbound_bytes_interval",
    )

    outbound_bytes_per_second = None

    if outbound_bytes is not None and elapsed_seconds is not None:
        if outbound_bytes >= 0:
            outbound_bytes_per_second = (
                outbound_bytes / elapsed_seconds
            )

    return {
        "timestamp": current.get("timestamp"),
        "source": current.get("source"),
        "interface": current.get("interface"),
        "data_origin": current.get("data_origin"),

        # Tráfico saliente
        "outbound_bytes_interval": outbound_bytes,
        "outbound_bytes_total": _numeric_value(
            current,
            "outbound_bytes_total",
        ),
        "measurement_interval_seconds": elapsed_seconds,
        "outbound_bytes_per_second": outbound_bytes_per_second,
        "outbound_bytes_status": current.get(
            "outbound_bytes_status",
            current.get("outbound_bytes_interval_status"),
        ),

        # Actividad de red
        "established_tcp_connections": _numeric_value(
            current,
            "established_tcp_connections",
        ),
        "unique_external_destinations": _numeric_value(
            current,
            "unique_external_destinations",
        ),
        "connections_without_process_attribution": _numeric_value(
            current,
            "connections_without_process_attribution",
        ),

        # Procesos
        "process_count": _numeric_value(
            current,
            "process_count",
        ),

        # Política
        "policy_enabled": current.get("policy_enabled"),
        "unauthorized_connections": _numeric_value(
            current,
            "unauthorized_connections",
        ),
        "assessed_external_connections": _numeric_value(
            current,
            "assessed_external_connections",
        ),
    }


def _period_start(timestamp: datetime, period: str) -> datetime:
    """Calcula el inicio UTC del período de agregación."""

    timestamp = timestamp.astimezone(timezone.utc)

    if period == "hour":
        return timestamp.replace(
            minute=0,
            second=0,
            microsecond=0,
        )

    if period == "day":
        return timestamp.replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        )

    if period == "week":
        day_start = timestamp.replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        )

        return day_start - timedelta(days=day_start.weekday())

    raise ValueError(
        "period debe ser 'hour', 'day' o 'week'"
    )


def _aggregate_metric(values: list, operation: str):
    """Calcula una agregación sin inventar valores faltantes."""

    valid_values = [
        value
        for value in values
        if isinstance(value, Real) and not isinstance(value, bool)
    ]

    if not valid_values:
        return None

    if operation == "sum":
        return sum(valid_values)

    if operation == "avg":
        return sum(valid_values) / len(valid_values)

    if operation == "min":
        return min(valid_values)

    if operation == "max":
        return max(valid_values)

    raise ValueError(f"Operación desconocida: {operation}")


def aggregate_indicators(
    events: list[dict],
    period: str = "hour",
) -> list[dict]:
    """
    Agrupa eventos históricos por hora, día o semana.

    La agrupación se realiza en UTC y separa los datos por:
    - source
    - interface
    - data_origin

    Cada métrica informa cuántas muestras válidas participaron
    en su cálculo. Los valores ausentes no se reemplazan por cero.

    Operaciones:
    - outbound_bytes_interval: suma.
    - outbound_bytes_total: máximo y promedio.
    - conexiones TCP: promedio, máximo y mínimo.
    - destinos externos: promedio, máximo y mínimo.
    - procesos: promedio, máximo y mínimo.
    - conexiones sin atribución: promedio, máximo y mínimo.
    - tasa de tráfico: promedio, máximo y mínimo.
    """

    if period not in ("hour", "day", "week"):
        raise ValueError(
            "period debe ser 'hour', 'day' o 'week'"
        )

    if not isinstance(events, list):
        raise TypeError("events debe ser una lista")

    grouped = defaultdict(list)

    for event in events:
        if not isinstance(event, dict):
            continue

        timestamp = _parse_timestamp(event.get("timestamp"))

        if timestamp is None:
            continue

        start = _period_start(timestamp, period)

        # Separamos observaciones de diferentes fuentes,
        # interfaces y orígenes de datos.
        identity = (
            event.get("source"),
            event.get("interface"),
            event.get("data_origin"),
        )

        key = (start, identity)

        grouped[key].append(event)

    metric_operations = {
        "outbound_bytes_interval": ("sum",),
        "outbound_bytes_total": ("avg", "max"),
        "outbound_bytes_per_second": ("avg", "max", "min"),
        "established_tcp_connections": ("avg", "max", "min"),
        "unique_external_destinations": ("avg", "max", "min"),
        "process_count": ("avg", "max", "min"),
        "connections_without_process_attribution": (
            "avg",
            "max",
            "min",
        ),
        "unauthorized_connections": ("sum", "max"),
        "assessed_external_connections": ("sum", "max"),
    }

    results = []

    for (start, identity), period_events in sorted(
        grouped.items(),
        key=lambda item: (item[0][0], str(item[0][1])),
    ):
        source, interface, data_origin = identity

        period_events.sort(
            key=lambda event: event["timestamp"]
        )

        indicators = []

        previous = None

        for event in period_events:
            indicators.append(
                calculate_indicators(
                    current=event,
                    previous=previous,
                )
            )

            previous = event

        result = {
            "period": period,
            "period_start": start.isoformat(),
            "source": source,
            "interface": interface,
            "data_origin": data_origin,
            "sample_count": len(period_events),
            "metrics": {},
        }

        for metric, operations in metric_operations.items():
            values = [
                indicator.get(metric)
                for indicator in indicators
            ]

            valid_count = sum(
                1
                for value in values
                if isinstance(value, Real)
                and not isinstance(value, bool)
            )

            metric_result = {
                "valid_samples": valid_count,
                "total_samples": len(indicators),
            }

            for operation in operations:
                metric_result[operation] = _aggregate_metric(
                    values,
                    operation,
                )

            result["metrics"][metric] = metric_result

        # Estado de la política: se conserva como información
        # descriptiva, sin inferir autorizaciones.
        policy_values = [
            event.get("policy_enabled")
            for event in period_events
            if isinstance(event.get("policy_enabled"), bool)
        ]

        result["policy_enabled_samples"] = len(policy_values)

        result["policy_enabled"] = (
            policy_values[-1]
            if policy_values
            else None
        )

        results.append(result)

    return results