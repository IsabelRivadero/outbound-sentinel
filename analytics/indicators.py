"""Cálculo de indicadores a partir de telemetría observada del gateway."""

from datetime import datetime
from numbers import Real
from typing import Any


def _numeric_value(event: dict, key: str):
    """Devuelve un valor numérico válido o None."""
    value = event.get(key)

    if isinstance(value, bool) or not isinstance(value, Real):
        return None

    return value


def _parse_timestamp(value: Any):
    """Convierte un timestamp ISO-8601 en datetime."""
    if not isinstance(value, str):
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        # Evita comparar timestamps con y sin zona horaria.
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
    Calcula indicadores de una medición del gateway.

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
        current, "outbound_bytes_interval"
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
            current, "outbound_bytes_total"
        ),
        "measurement_interval_seconds": elapsed_seconds,
        "outbound_bytes_per_second": outbound_bytes_per_second,
        "outbound_bytes_status": current.get(
            "outbound_bytes_status",
            current.get("outbound_bytes_interval_status"),
        ),

        # Actividad de red
        "established_tcp_connections": _numeric_value(
            current, "established_tcp_connections"
        ),
        "unique_external_destinations": _numeric_value(
            current, "unique_external_destinations"
        ),
        "connections_without_process_attribution": _numeric_value(
            current, "connections_without_process_attribution"
        ),

        # Procesos
        "process_count": _numeric_value(current, "process_count"),

        # Política
        "policy_enabled": current.get("policy_enabled"),
        "unauthorized_connections": _numeric_value(
            current, "unauthorized_connections"
        ),
        "assessed_external_connections": _numeric_value(
            current, "assessed_external_connections"
        ),
    }
