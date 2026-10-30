import json
import os
import time

import paho.mqtt.client as mqtt


class MQTTPublisher:
    def __init__(
        self,
        host="127.0.0.1",
        port=1883,
        topic="outbound-sentinel/gateway",
        client_id="outbound-sentinel-gateway",
    ):
        self.host = host
        self.port = int(port)
        self.topic = topic

        self.client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id,
        )

        username = os.getenv("MQTT_USERNAME")
        password = os.getenv("MQTT_PASSWORD")

        if username:
            self.client.username_pw_set(username, password)

        self.connected = False

        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect

    def _on_connect(self, client, userdata, flags, reason_code, properties):
        self.connected = reason_code == 0

    def _on_disconnect(
        self, client, userdata, disconnect_flags, reason_code, properties
    ):
        self.connected = False

    def connect(self):
        self.client.connect(self.host, self.port, keepalive=60)
        self.client.loop_start()

        for _ in range(30):
            if self.connected:
                return True
            time.sleep(0.1)

        raise ConnectionError(
            f"No se pudo conectar con MQTT en {self.host}:{self.port}"
        )

    def publish(self, data):
        if not self.connected:
            raise ConnectionError("El cliente MQTT no está conectado")

        payload = json.dumps(data, ensure_ascii=False)

        result = self.client.publish(
            self.topic,
            payload=payload,
            qos=1,
        )

        result.wait_for_publish(timeout=10)

        if not result.is_published():
            raise TimeoutError("No se confirmó la publicación MQTT")

        return True

    def close(self):
        self.client.loop_stop()
        self.client.disconnect()


if __name__ == "__main__":
    publisher = MQTTPublisher()
    try:
        publisher.connect()
        publisher.publish({
            "source": "mqtt_diagnostic",
            "data_origin": "test",
            "message": "MQTT connection successful",
        })
        print("Mensaje de prueba publicado correctamente.")
    finally:
        publisher.close()
