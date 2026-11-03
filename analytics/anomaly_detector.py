"""Detección estadística de anomalías mediante MAD.

El módulo analiza indicadores previamente calculados.

Separa tres conceptos:
- Anomalía estadística: desviación respecto del comportamiento histórico.
- Cumplimiento de políticas: evaluación de conexiones según la política configurada.
- Calidad de datos: información insuficiente para evaluar.

No clasifica eventos como ataques ni ejecuta acciones de bloqueo.
"""

from math import isfinite
from numbers import Real
from statistics import median


DEFAULT_METRICS = (
    "outbound_bytes_per_second",
    "established_tcp_connections",
    "unique_external_destinations",
    "process_count",
)

DEFAULT_MIN_SAMPLES = 10
DEFAULT_THRESHOLD = 3.5
MAD_NORMALIZATION = 0.6745


def _valid_number(value):
    """Acepta números reales finitos, pero no booleanos."""
    return (
        isinstance(value, Real)
        and not isinstance(value, bool)
        and isfinite(value)
    )


def _validate_min_samples(min_samples):
    if (
        not isinstance(min_samples, int)
        or isinstance(min_samples, bool)
        or min_samples < 1
    ):
        raise ValueError("min_samples debe ser un entero mayor que cero")


def _validate_threshold(threshold):
    if not _valid_number(threshold) or threshold <= 0:
        raise ValueError("threshold debe ser un número mayor que cero")


def _get_valid_values(history, metric):
    """Obtiene los valores históricos válidos de una métrica."""
    values = []

    for sample in history:
        if not isinstance(sample, dict):
            continue

        value = sample.get(metric)

        if _valid_number(value):
            values.append(float(value))

    return values


def evaluate_metric(
    value,
    historical_values,
    min_samples=DEFAULT_MIN_SAMPLES,
    threshold=DEFAULT_THRESHOLD,
):
    """Evalúa una observación utilizando mediana y MAD."""

    _validate_min_samples(min_samples)
    _validate_threshold(threshold)

    if not isinstance(historical_values, (list, tuple)):
        raise TypeError("historical_values debe ser una lista o tupla")

    if not _valid_number(value):
        return {
            "status": "insufficient_current_data",
            "value": None,
            "baseline_median": None,
            "mad": None,
            "score": None,
            "is_anomaly": None,
            "reason": "current_value_missing_or_invalid",
            "sample_count": 0,
        }

    values = [
        float(item)
        for item in historical_values
        if _valid_number(item)
    ]

    if len(values) < min_samples:
        return {
            "status": "insufficient_history",
            "value": float(value),
            "baseline_median": None,
            "mad": None,
            "score": None,
            "is_anomaly": None,
            "reason": "not_enough_valid_historical_samples",
            "sample_count": len(values),
        }

    baseline = median(values)
    deviations = [abs(item - baseline) for item in values]
    mad = median(deviations)

    if mad == 0:
        is_anomaly = float(value) != baseline

        return {
            "status": "evaluated",
            "value": float(value),
            "baseline_median": baseline,
            "mad": mad,
            "score": None,
            "is_anomaly": is_anomaly,
            "reason": (
                "deviation_with_zero_mad"
                if is_anomaly
                else "within_zero_mad_baseline"
            ),
            "sample_count": len(values),
        }

    score = (
        MAD_NORMALIZATION
        * (float(value) - baseline)
        / mad
    )

    is_anomaly = abs(score) > threshold

    return {
        "status": "evaluated",
        "value": float(value),
        "baseline_median": baseline,
        "mad": mad,
        "score": score,
        "is_anomaly": is_anomaly,
        "reason": (
            "robust_deviation_above_threshold"
            if is_anomaly
            else "within_expected_range"
        ),
        "sample_count": len(values),
    }


def evaluate_policy_compliance(current):
    """Evalúa cumplimiento de política sin inferir datos faltantes.

    La política solo se evalúa cuando está explícitamente habilitada.
    No determina si una conexión es maliciosa.
    """

    if not isinstance(current, dict):
        raise TypeError("current debe ser un diccionario")

    policy_enabled = current.get("policy_enabled")

    if policy_enabled is not True:
        return {
            "status": "not_evaluated",
            "policy_enabled": policy_enabled,
            "unauthorized_connections": None,
            "assessed_external_connections": None,
            "reason": "policy_disabled_or_unknown",
        }

    unauthorized = current.get("unauthorized_connections")
    assessed = current.get("assessed_external_connections")

    if not _valid_number(unauthorized) or not _valid_number(assessed):
        return {
            "status": "insufficient_data",
            "policy_enabled": True,
            "unauthorized_connections": (
                unauthorized if _valid_number(unauthorized) else None
            ),
            "assessed_external_connections": (
                assessed if _valid_number(assessed) else None
            ),
            "reason": "policy_metrics_missing_or_invalid",
        }

    if unauthorized < 0 or assessed < 0:
        return {
            "status": "insufficient_data",
            "policy_enabled": True,
            "unauthorized_connections": None,
            "assessed_external_connections": None,
            "reason": "negative_policy_metrics",
        }

    if unauthorized > assessed:
        return {
            "status": "insufficient_data",
            "policy_enabled": True,
            "unauthorized_connections": float(unauthorized),
            "assessed_external_connections": float(assessed),
            "reason": "inconsistent_policy_metrics",
        }

    if assessed == 0:
        return {
            "status": "insufficient_data",
            "policy_enabled": True,
            "unauthorized_connections": float(unauthorized),
            "assessed_external_connections": 0,
            "reason": "no_assessed_external_connections",
        }

    if unauthorized > 0:
        status = "policy_violation"
        reason = "unauthorized_connections_detected"
    else:
        status = "compliant"
        reason = "no_unauthorized_connections_detected"

    return {
        "status": status,
        "policy_enabled": True,
        "unauthorized_connections": float(unauthorized),
        "assessed_external_connections": float(assessed),
        "reason": reason,
    }


def detect_anomalies(
    current,
    history,
    metrics=DEFAULT_METRICS,
    min_samples=DEFAULT_MIN_SAMPLES,
    threshold=DEFAULT_THRESHOLD,
):
    """Evalúa métricas actuales contra el historial."""

    if not isinstance(current, dict):
        raise TypeError("current debe ser un diccionario")

    if not isinstance(history, list):
        raise TypeError("history debe ser una lista")

    if not isinstance(metrics, (list, tuple)):
        raise TypeError("metrics debe ser una lista o tupla")

    if any(not isinstance(metric, str) or not metric for metric in metrics):
        raise ValueError("Todas las métricas deben tener nombres válidos")

    if len(set(metrics)) != len(metrics):
        raise ValueError("metrics no puede contener métricas duplicadas")

    _validate_min_samples(min_samples)
    _validate_threshold(threshold)

    results = {}

    for metric in metrics:
        current_value = current.get(metric)

        # La tasa de bytes solo se evalúa si la medición actual
        # tiene una tasa válida y fue calculada con un intervalo real.
        if metric == "outbound_bytes_per_second":
            if current.get("outbound_bytes_status") != "measured":
                current_value = None

        historical_values = _get_valid_values(history, metric)

        results[metric] = evaluate_metric(
            value=current_value,
            historical_values=historical_values,
            min_samples=min_samples,
            threshold=threshold,
        )

    evaluated = [
        result
        for result in results.values()
        if result["status"] == "evaluated"
    ]

    anomaly_count = sum(
        result["is_anomaly"] is True
        for result in evaluated
    )

    if not evaluated:
        overall_status = "insufficient_data"
    elif anomaly_count:
        overall_status = "potential_anomaly"
    else:
        overall_status = "no_anomaly_detected"

    policy_result = evaluate_policy_compliance(current)

    return {
        "timestamp": current.get("timestamp"),
        "source": current.get("source"),
        "interface": current.get("interface"),
        "data_origin": current.get("data_origin"),
        "method": "MAD",
        "threshold": float(threshold),
        "minimum_historical_samples": min_samples,
        "overall_status": overall_status,
        "evaluated_metrics": len(evaluated),
        "potential_anomalies": anomaly_count,
        "metrics": results,
        "policy_compliance": policy_result,
    }