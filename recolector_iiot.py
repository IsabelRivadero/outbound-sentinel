#!/usr/bin/env python3
import time
import json
import random
import socket
import psutil
import paho.mqtt.client as mqtt

# ==============================================================================
# CONFIGURACIÓN GENERAL
# ==============================================================================
BROKER_MQTT = "localhost"
PUERTO_MQTT = 1883
INTERVALO_SEGUNDOS = 120  # Medición cada 2 minutos (rango de consigna: 2 a 5 min)

TOPICO_COMPRESOR = "industria/telemetria/equipo_1_compresor"
TOPICO_HORNO = "industria/telemetria/equipo_2_horno"
TOPICO_GATEWAY = "industria/telemetria/equipo_3_gateway"

# ==============================================================================
# REGLAS DE TRÁFICO AUTORIZADO (LISTA BLANCA / WHITELIST)
# ==============================================================================
# Procesos y puertos considerados legítimos para el servidor/gateway:
PROCESOS_AUTORIZADOS = [
    "node-red", "docker", "dockerd", "python3", "python",
    "systemd-resolve", "chrome", "firefox", "code", "containerd"
]
PUERTOS_AUTORIZADOS = [80, 443, 1883, 8086, 53, 22]  # HTTP, HTTPS, MQTT, InfluxDB, DNS, SSH

# Variables globales de estado para cálculo de la tasa de red
bytes_sent_prev = psutil.net_io_counters().bytes_sent
time_prev = time.time()


def obtener_ip_local():
    """Obtiene la dirección IP privada de la interfaz de red activa."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


LOCAL_IP = obtener_ip_local()


# ==============================================================================
# CAPTURA DE DATOS REALES Y AUDITORÍA: GATEWAY UBUNTU (EQUIPO 3)
# ==============================================================================
def capturar_telemetria_gateway():
    global bytes_sent_prev, time_prev

    time_now = time.time()
    dt = max(time_now - time_prev, 1.0)

    # 1. Tasa de ancho de banda saliente (kB/s)
    net_io_now = psutil.net_io_counters()
    bytes_sent_now = net_io_now.bytes_sent
    delta_bytes = max(bytes_sent_now - bytes_sent_prev, 0)
    ancho_banda_saliente_kbs = round((delta_bytes / 1024.0) / dt, 2)

    # Actualizar contadores de referencia
    bytes_sent_prev = bytes_sent_now
    time_prev = time_now

    # 2. Métricas de recursos del sistema
    uso_cpu_pct = psutil.cpu_percent(interval=None)
    uso_ram_pct = psutil.virtual_memory().percent

    # 3. Auditoría e inspección de sockets salientes
    conexiones_todas = []
    conexiones_sospechosas = []
    pids_emisores = set()

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED' and conn.raddr:
            ip_dest, puerto_dest = conn.raddr[0], conn.raddr[1]

            # Filtrar loopback y subredes locales privadas
            if not ip_dest.startswith(('127.', '192.168.', '10.', '172.16.', '::1')):
                pid = conn.pid
                nombre_proceso = "Desconocido"
                if pid:
                    pids_emisores.add(pid)
                    try:
                        nombre_proceso = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        nombre_proceso = "Privado/Sistema"

                datos_conexion = {
                    "pid": pid,
                    "proceso": nombre_proceso,
                    "ip_destino": ip_dest,
                    "puerto_destino": puerto_dest
                }
                conexiones_todas.append(datos_conexion)

                # EVALUACIÓN DE AUTORIZACIÓN (LISTA BLANCA)
                # Si el proceso O el puerto NO están autorizados, se marca como sospechoso
                es_autorizado = (nombre_proceso in PROCESOS_AUTORIZADOS) or (puerto_dest in PUERTOS_AUTORIZADOS)
                if not es_autorizado:
                    conexiones_sospechosas.append(datos_conexion)

    return {
        "timestamp": int(time_now),
        "ip_gateway": LOCAL_IP,
        "ancho_banda_saliente_kbs": ancho_banda_saliente_kbs,
        "sockets_tcp_activos": len(conexiones_todas),
        "sockets_no_autorizados": len(conexiones_sospechosas),
        "uso_cpu_pct": uso_cpu_pct,
        "uso_ram_pct": uso_ram_pct,
        "procesos_emisores_cant": len(pids_emisores),
        "detalle_sospechosas": conexiones_sospechosas,
        "detalle_conexiones": conexiones_todas
    }


# ==============================================================================
# SIMULACIÓN DE DATOS OPERATIVOS: COMPRESOR Y HORNO (EQUIPOS 1 Y 2)
# ==============================================================================
def generar_telemetria_compresor():
    return {
        "timestamp": int(time.time()),
        "temperatura_c": round(random.uniform(68.0, 92.0), 2),
        "presion_bar": round(random.uniform(6.2, 8.1), 2),
        "corriente_a": round(random.uniform(16.5, 24.0), 2),
        "vibracion_mms": round(random.uniform(0.8, 3.2), 2),
        "horas_uso_h": 1245
    }


def generar_telemetria_horno():
    return {
        "timestamp": int(time.time()),
        "temperatura_c": round(random.uniform(185.0, 215.0), 2),
        "flujo_gas_m3h": round(random.uniform(13.0, 17.5), 2),
        "consumo_kwh": round(random.uniform(48.0, 58.0), 2),
        "presion_mbar": round(random.uniform(1.2, 2.3), 2),
        "co2_ppm": round(random.uniform(360, 440), 0)
    }


# ==============================================================================
# BUCLE PRINCIPAL DE RECOLECCIÓN Y PUBLICACIÓN MQTT
# ==============================================================================
def main():
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="recolector_edge_python")

    try:
        client.connect(BROKER_MQTT, PUERTO_MQTT, keepalive=60)
        print(f"[*] Recolector IIoT conectado exitosamente al Broker MQTT ({BROKER_MQTT}:{PUERTO_MQTT}).")
        print(f"[*] Publicando métricas cada {INTERVALO_SEGUNDOS} segundos...\n")
    except Exception as e:
        print(f"[!] Error al conectar con el Broker MQTT: {e}")
        return

    # Inicializar contador de uso de CPU
    psutil.cpu_percent(interval=None)
    time.sleep(1)

    try:
        while True:
            # 1. Obtención de datos
            data_compresor = generar_telemetria_compresor()
            data_horno = generar_telemetria_horno()
            data_gateway = capturar_telemetria_gateway()

            # 2. Publicación MQTT
            client.publish(TOPICO_COMPRESOR, json.dumps(data_compresor))
            client.publish(TOPICO_HORNO, json.dumps(data_horno))
            client.publish(TOPICO_GATEWAY, json.dumps(data_gateway))

            # 3. Impresión estructurada en consola
            ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            print(f"[{ts_str}] Telemetría enviada:")
            print(f"  ├─► Compresor : Temp={data_compresor['temperatura_c']}°C | Presión={data_compresor['presion_bar']}bar | Vib={data_compresor['vibracion_mms']}mm/s")
            print(f"  ├─► Horno     : Temp={data_horno['temperatura_c']}°C | Gas={data_horno['flujo_gas_m3h']}m³/h | Consumo={data_horno['consumo_kwh']}kWh")
            print(f"  └─► Gateway   : Out={data_gateway['ancho_banda_saliente_kbs']}kB/s | Sockets={data_gateway['sockets_tcp_activos']} | No Autorizados={data_gateway['sockets_no_autorizados']}")

            # ALERTA DE TRÁFICO NO AUTORIZADO EN CONSOLA
            if data_gateway['sockets_no_autorizados'] > 0:
                print("      [⚠️ ALERTA: TRÁFICO NO AUTORIZADO DETECTADO]")
                for c in data_gateway['detalle_sospechosas']:
                    print(f"      └──► Proceso: {c['proceso']} (PID: {c['pid']}) ──► Destino: {c['ip_destino']}:{c['puerto_destino']}")

            print()  # Separador de bloque
            time.sleep(INTERVALO_SEGUNDOS)

    except KeyboardInterrupt:
        print("\n[*] Deteniendo el Recolector IIoT...")
        client.disconnect()


if __name__ == "__main__":
    main()