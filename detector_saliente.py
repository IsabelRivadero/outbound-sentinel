#!/usr/bin/env python3
import socket
from scapy.all import sniff, IP, TCP, UDP

# Obtener la IP local de la interfaz principal
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

LOCAL_IP = get_local_ip()
print(f"[*] Monitoreando tráfico saliente desde IP local: {LOCAL_IP}")

def procesar_paquete(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Filtro: Solo paquetes cuyo origen sea esta máquina y destino no sea loopback/local
        if src_ip == LOCAL_IP and not dst_ip.startswith("127."):
            proto = "TCP" if TCP in packet else ("UDP" if UDP in packet else "OTRO")
            puerto_origen = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else "-")
            puerto_destino = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else "-")
            longitud = len(packet)

            print(f"[SALIENTE] {src_ip}:{puerto_origen} ──► {dst_ip}:{puerto_destino} | Proto: {proto} | Tam: {longitud} bytes")

# Capturar paquetes IP (requiere privilegios root)
sniff(filter="ip", prn=procesar_paquete, store=0)