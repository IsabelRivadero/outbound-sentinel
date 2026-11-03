"""Orquestación de detección, gemelo digital e investigación."""

import argparse
import json

from analytics.anomaly_detector import detect_anomalies
from analytics.digital_twin import DigitalTwin
from analytics.indicators import calculate_indicators
from storage.influx_reader import InfluxReader


DEVICE_ID_BY_SOURCE = {
    "ubuntu_gateway": "gateway-01",
}


def build_investigation_context(event, detection):
    """Asocia anomalías y cumplimiento de política con el evento original."""

    metrics = detection.get("metrics", {})

    anomalous_metrics = [
        {
            "metric": name,
            "value": result.get("value"),
            "score": result.get("score"),
            "reason": result.get("reason"),
        }
        for name, result in metrics.items()
        if isinstance(result, dict)
        and result.get("is_anomaly") is True
    ]

    processes = event.get("processes")
    destinations = event.get("external_destinations")
    policy_compliance = detection.get("policy_compliance")

    if not isinstance(policy_compliance, dict):
        policy_compliance = None

    return {
        "timestamp": event.get("timestamp"),
        "device_id": event.get("device_id"),
        "source": event.get("source"),
        "interface": event.get("interface"),
        "data_origin": event.get("data_origin"),
        "anomalous_metrics": anomalous_metrics,
        "policy_compliance": policy_compliance,
        "processes": processes,
        "external_destinations": destinations,
        "process_context_available": processes is not None,
        "destination_context_available": destinations is not None,
        "policy_context_available": policy_compliance is not None,
    }


def enrich_event_for_digital_twin(event):
    """Enriquece el evento con el identificador explícito del activo."""
    enriched_event = dict(event)

    source = enriched_event.get("source")
    device_id = DEVICE_ID_BY_SOURCE.get(source)

    if device_id is not None:
        enriched_event["device_id"] = device_id

    return enriched_event


def run_detection(
    interface,
    lookback_days=30,
    min_samples=10,
    threshold=3.5,
):
    """Ejecuta el flujo completo de análisis del gateway."""

    twin = DigitalTwin()
    reader = InfluxReader()

    try:
        events = reader.read_events(
            interface=interface,
            lookback_days=lookback_days,
            data_origin="observed",
        )

        if not events:
            return {
                "status": "insufficient_data",
                "reason": "no_historical_events",
                "interface": interface,
                "data_origin": "observed",
                "events_retrieved": 0,
                "historical_samples": 0,
                "detection": {
                    "overall_status": "insufficient_data",
                    "reason": "no_historical_events",
                    "policy_compliance": {
                        "status": "not_evaluated",
                        "policy_enabled": None,
                        "unauthorized_connections": None,
                        "assessed_external_connections": None,
                        "reason": "no_historical_events",
                    },
                },
                "digital_twin": None,
                "investigation_context": None,
            }

        indicators = []
        previous = None

        for event in events:
            indicator = calculate_indicators(
                current=event,
                previous=previous,
            )

            indicators.append(indicator)
            previous = event

        current = indicators[-1]
        history = indicators[:-1]
        current_event = events[-1]

        detection = detect_anomalies(
            current=current,
            history=history,
            min_samples=min_samples,
            threshold=threshold,
        )

        twin_event = enrich_event_for_digital_twin(current_event)

        digital_twin_result = twin.evaluate(
            event=twin_event,
            anomaly_detection=detection,
        )

        investigation_context = build_investigation_context(
            event=twin_event,
            detection=detection,
        )

        return {
            "interface": interface,
            "device_id": twin_event.get("device_id"),
            "source": current_event.get("source"),
            "data_origin": current_event.get("data_origin"),
            "events_retrieved": len(events),
            "historical_samples": len(history),
            "current_timestamp": current.get("timestamp"),
            "detection": detection,
            "digital_twin": digital_twin_result,
            "investigation_context": investigation_context,
        }

    finally:
        reader.close()


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Detecta anomalías en el tráfico saliente "
            "y evalúa el estado del Digital Twin."
        )
    )

    parser.add_argument(
        "--interface",
        default="wlo1",
        help="Interfaz de red a analizar.",
    )

    parser.add_argument(
        "--lookback-days",
        type=int,
        default=30,
        help="Cantidad de días de historial a consultar.",
    )

    parser.add_argument(
        "--min-samples",
        type=int,
        default=10,
        help="Mínimo de observaciones históricas válidas por métrica.",
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=3.5,
        help="Umbral absoluto del modified z-score.",
    )

    args = parser.parse_args()

    if args.lookback_days < 1:
        parser.error("--lookback-days debe ser positivo.")

    if args.min_samples < 1:
        parser.error("--min-samples debe ser positivo.")

    if args.threshold <= 0:
        parser.error("--threshold debe ser positivo.")

    result = run_detection(
        interface=args.interface,
        lookback_days=args.lookback_days,
        min_samples=args.min_samples,
        threshold=args.threshold,
    )

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    )


if __name__ == "__main__":
    main()