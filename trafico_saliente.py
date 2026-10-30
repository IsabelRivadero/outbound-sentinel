#!/usr/bin/env python3
import time
import json
import psutil
import socket

def obtener_ip_local():
    """Obtiene la IP local de la interfaz activa."""
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

def capturar_trafico_saliente():
    """Captura métricas agregadas y conexiones salientes activas."""
    # 1. Métricas de red acumuladas
    net_io = psutil.net_io_counters()
    bytes_enviados = net_io.bytes_sent
    bytes_recibidos = net_io.bytes_recv

    conexiones_salientes = []
    pids_activos = set()

    # 2. Inspeccionar sockets inet (TCP/UDP)
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED' and conn.raddr:
            ip_dest, puerto_dest = conn.raddr[0], conn.raddr[1]

            # Filtrar tráfico hacia el exterior (excluir localhost y red local típica)
            if not ip_dest.startswith(('127.', '192.168.', '10.', '172.16.')):
                pid = conn.pid
                try:
                    nombre_proceso = psutil.Process(pid).name() if pid else "Desconocido"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    nombre_proceso = "Privado/Protegido"

                if pid:
                    pids_activos.add(pid)

                conexiones_salientes.append({
                    "pid": pid,
                    "proceso": nombre_proceso,
                    "ip_destino": ip_dest,
                    "puerto_destino": puerto_dest,
                    "ip_origen": conn.laddr.ip,
                    "puerto_origen": conn.laddr.port
                })

    return {
        "timestamp": int(time.time()),
        "bytes_sent_total": bytes_enviados,
        "bytes_recv_total": bytes_recibidos,
        "total_conexiones_salientes": len(conexiones_salientes),
        "total_procesos_emisores": len(pids_activos),
        "detalle_conexiones": conexiones_salientes
    }

if __name__ == "__main__":
    print(f"[*] Monitoreando tráfico saliente desde IP local: {LOCAL_IP}...\n")

    # Prueba de lectura simple
    medicion = capturar_trafico_saliente()
    print(json.dumps(medicion, indent=2))