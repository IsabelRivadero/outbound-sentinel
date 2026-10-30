#!/usr/bin/env python3
import time
import json
import random
import paho.mqtt.client as mqtt

# Configuración del Broker MQTT en Docker
BROKER = "localhost"
PORT = 1883
INTERVALO_SEGUNDOS = 120  # Enviar datos cada 2 minutos (rango 2 a 5 min)

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect(BROKER, PORT, 60)

print(f"[*] Simulador Industrial Iniciado. Publicando cada {INTERVALO_SEGUNDOS} segundos...")

def generar_telemetria():
    return {
        "equipo_1_compresor": {
            "temperatura_c": round(random.uniform(65.0, 95.0), 2),
            "presion_bar": round(random.uniform(6.0, 8.5), 2),
            "corriente_a": round(random.uniform(15.0, 25.0), 2),
            "vibracion_mms": round(random.uniform(0.5, 3.5), 2),
            "horas_uso_h": 1240
        },
        "equipo_2_motor": {
            "temperatura_c": round(random.uniform(40.0, 75.0), 2),
            "velocidad_rpm": round(random.uniform(1400, 1500), 0),
            "corriente_a": round(random.uniform(10.0, 18.0), 2),
            "factor_potencia": round(random.uniform(0.85, 0.98), 2),
            "potencia_kw": round(random.uniform(12.0, 22.0), 2)
        },
        "equipo_3_horno": {
            "temperatura_c": round(random.uniform(180.0, 220.0), 2),
            "flujo_gas_m3h": round(random.uniform(12.0, 18.0), 2),
            "consumo_kwh": round(random.uniform(45.0, 60.0), 2),
            "co2_ppm": round(random.uniform(350, 450), 0),
            "presion_mbar": round(random.uniform(1.0, 2.5), 2)
        }
    }

try:
    while True:
        datos = generar_telemetria()
        for equipo, variables in datos.items():
            topic = f"industria/telemetria/{equipo}"
            payload = json.dumps(variables)
            client.publish(topic, payload)
            print(f"[MQTT -> {topic}]: {payload}")

        time.sleep(INTERVALO_SEGUNDOS)
except KeyboardInterrupt:
    print("\nSimulador detenido.")
    client.disconnect()
