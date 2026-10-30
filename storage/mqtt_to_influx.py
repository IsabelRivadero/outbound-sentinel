"""Consume telemetría MQTT y la persiste en InfluxDB."""

import json
import os
import signal
import threading

import paho.mqtt.client as mqtt

from storage.influx_writer import InfluxWriter


MQTT_HOST = os.getenv("MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_TOPIC = os.getenv(
    "MQTT_TOPIC",
    "outbound-sentinel/gateway",
)


def main():

    writer = InfluxWriter()
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="outbound-sentinel-influx-consumer",
    )

    username = os.getenv("MQTT_USERNAME")
    password = os.getenv("MQTT_PASSWORD")

    if username:
        client.username_pw_set(username, password)

    def on_connect(client, userdata, flags, reason_code, properties):

        if reason_code.is_failure:
            print("[MQTT] Error:", reason_code)
            return

        print("[MQTT] Conectado.")
        client.subscribe(MQTT_TOPIC, qos=1)
        print(f"[MQTT] Suscripto a {MQTT_TOPIC}")

    def on_message(client, userdata, message):

        try:
            event = json.loads(message.payload.decode("utf-8"))

            writer.write_event(event)

            print(
                "[INFLUX] Persistido | "
                f"timestamp={event.get('timestamp')} | "
                f"interface={event.get('interface')} | "
                f"origin={event.get('data_origin')}",
                flush=True,
            )

        except Exception as exc:
            print(f"[ERROR] Procesando mensaje: {exc}", flush=True)

    client.on_connect = on_connect
    client.on_message = on_message

    stopped = threading.Event()

    def shutdown(signum, frame):
        if not stopped.is_set():
            stopped.set()
            print("\n[SENTINEL] Deteniendo consumidor.")
            client.disconnect()
            writer.close()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)

        print("[SENTINEL] MQTT → InfluxDB iniciado.")
        client.loop_forever()

    finally:
        if not stopped.is_set():
            writer.close()


if __name__ == "__main__":
    main()
