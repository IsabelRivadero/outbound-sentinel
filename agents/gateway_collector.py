import argparse
import json
import time

from agents.network_monitor import NetworkMonitor
from agents.mqtt_publisher import MQTTPublisher


def main():
    parser = argparse.ArgumentParser(
        description="Recolector de telemetría del gateway Ubuntu"
    )

    parser.add_argument(
        "--interface",
        default="wlo1",
        help="Interfaz de red a monitorear",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=120,
        help="Intervalo de captura en segundos",
    )
    parser.add_argument(
        "--mqtt-host",
        default="127.0.0.1",
    )
    parser.add_argument(
        "--mqtt-port",
        type=int,
        default=1883,
    )
    parser.add_argument(
        "--no-mqtt",
        action="store_true",
        help="Desactiva la publicación MQTT",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Realiza una única captura y termina",
    )

    args = parser.parse_args()

    if args.interval < 1:
        parser.error("--interval debe ser mayor que cero")

    monitor = NetworkMonitor(
        interface=args.interface,
        policy_file="config/authorized_destinations.yaml",
    )

    publisher = None

    if not args.no_mqtt:
        publisher = MQTTPublisher(
            host=args.mqtt_host,
            port=args.mqtt_port,
        )

        try:
            publisher.connect()
            print("[MQTT] Conexión establecida.")
        except Exception as exc:
            print(f"[MQTT] No se pudo conectar: {exc}")
            print("[MQTT] El recolector continuará sin publicar.")
            publisher = None

    print(
        f"[COLLECTOR] Interfaz: {args.interface} | "
        f"Intervalo: {args.interval}s"
    )

    try:
        while True:
            try:
                measurement = monitor.collect()

                print(
                    json.dumps(
                        measurement,
                        indent=2,
                        ensure_ascii=False,
                    ),
                    flush=True,
                )

                if publisher:
                    try:
                        publisher.publish(measurement)
                        print("[MQTT] Medición publicada.", flush=True)
                    except Exception as exc:
                        print(f"[MQTT] Error al publicar: {exc}")

            except Exception as exc:
                print(f"[ERROR] Falló la captura: {exc}", flush=True)

            if args.once:
                break

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[COLLECTOR] Detenido por el usuario.")

    finally:
        if publisher:
            publisher.close()


if __name__ == "__main__":
    main()