# Outbound Sentinel

**Detección y monitoreo de tráfico saliente en entornos industriales IIoT mediante telemetría de red, análisis de comportamiento y observabilidad.**

Outbound Sentinel es un proyecto orientado a desarrollar una plataforma de monitoreo de tráfico saliente para gateways y dispositivos conectados en entornos industriales. Su objetivo es proporcionar visibilidad sobre las comunicaciones de red, establecer una línea base de comportamiento y sentar las bases para identificar patrones anómalos, conexiones inesperadas y posibles indicadores de compromiso.

El proyecto utiliza una arquitectura modular basada en Python, MQTT, InfluxDB y Grafana, con servicios auxiliares desplegados mediante Docker Compose.

> **Estado actual:** infraestructura de monitoreo, captura de telemetría y persistencia funcionando. Los módulos de detección avanzada, correlación y gemelo digital se encuentran en desarrollo.

---

## 1. Objetivos

- Monitorear el tráfico saliente de un gateway Linux.
- Obtener métricas de actividad de red y conexiones TCP establecidas.
- Identificar destinos externos y procesos asociados a las conexiones observadas.
- Transportar eventos de telemetría mediante MQTT.
- Persistir las mediciones históricas en InfluxDB.
- Visualizar indicadores de comportamiento mediante Grafana.
- Preparar una arquitectura extensible para incorporar detección de anomalías, análisis de correlación y políticas de destinos autorizados.

El enfoque es de **observabilidad y detección**, no de bloqueo automático del tráfico.

---

## 2. Arquitectura

La arquitectura se organiza en cuatro capas principales:

### 2.1. Captura de telemetría

Un agente Python ejecutado en el gateway Linux recopila información del estado de la red.

Fuentes de información:

- Estadísticas de bytes transmitidos de las interfaces de red mediante `/sys/class/net/`.
- Conexiones TCP establecidas mediante `ss`.
- Direcciones IP remotas.
- Procesos asociados a las conexiones, cuando el sistema operativo permite obtener esa información.

El agente genera eventos estructurados en JSON.

### 2.2. Transporte de eventos

Los eventos se publican mediante MQTT utilizando Mosquitto como broker.

Tópico principal:

```text
outbound-sentinel/gateway
```

La comunicación utiliza QoS 1.

### 2.3. Persistencia

Un consumidor Python se suscribe al tópico MQTT y procesa los eventos recibidos para almacenarlos en InfluxDB 2.7.

Measurement:

```text
gateway_network
```

Los datos se almacenan con timestamps y dimensiones que permiten consultar su evolución temporal.

### 2.4. Visualización

Grafana consulta InfluxDB mediante Flux y presenta indicadores de actividad de red en un dashboard.

La infraestructura también incluye Node-RED como servicio auxiliar para futuras integraciones y automatizaciones.

---

## 3. Flujo de datos

```text
                  GATEWAY LINUX
                       |
                       v
             Python Network Monitor
                       |
             Captura de telemetría
                       |
                       v
              JSON Network Events
                       |
                       v
                 MQTT Publisher
                       |
                       v
                Mosquitto Broker
                       |
              outbound-sentinel/
                    gateway
                       |
                       v
                MQTT Consumer
                       |
                       v
                   InfluxDB
                       |
                 Consultas Flux
                       |
                       v
                    Grafana
                       |
                       v
                Network Dashboard
```

---

## 4. Tecnologías

| Tecnología | Responsabilidad |
|---|---|
| Python 3.12+ | Agentes de captura y procesamiento |
| Paho MQTT | Comunicación mediante MQTT |
| Eclipse Mosquitto | Broker de mensajería |
| InfluxDB 2.7 | Persistencia de series temporales |
| Grafana 11.5 | Visualización y monitoreo |
| Node-RED 4.1 | Integraciones y automatizaciones futuras |
| Docker Compose | Orquestación de servicios |
| PyYAML | Configuración mediante archivos YAML |
| python-dotenv | Gestión de variables de entorno |

---

## 5. Estructura del repositorio

```text
outbound-sentinel/
│
├── agents/
│   ├── gateway_collector.py
│   ├── mqtt_publisher.py
│   └── network_monitor.py
│
├── analytics/
│   ├── anomaly_detector.py
│   ├── correlation_analysis.py
│   ├── digital_twin.py
│   └── indicators.py
│
├── config/
│   ├── authorized_destinations.yaml
│   ├── devices.yaml
│   └── digital_twin.yaml
│
├── data/
│   ├── raw/
│   ├── processed/
│   └── reports/
│
├── mosquitto/
│   └── config/
│       └── mosquitto.conf
│
├── notifications/
│   └── alert_manager.py
│
├── simulators/
│   ├── compressor_simulator.py
│   └── furnace_simulator.py
│
├── storage/
│   ├── export_csv.py
│   ├── influx_writer.py
│   ├── mqtt_to_influx.py
│   └── verify_influx.py
│
├── tests/
│   ├── test_digital_twin.py
│   ├── test_indicators.py
│   ├── test_network_monitor.py
│   └── test_policies.py
│
├── docker-compose.yml
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 6. Requisitos

- Linux (Ubuntu recomendado).
- Python 3.12 o superior.
- Docker Engine.
- Docker Compose.
- Git.

El agente de monitoreo utiliza herramientas del sistema operativo Linux, como `ss`, y estadísticas disponibles en `/sys/class/net/`.

---

## 7. Instalación

### 7.1. Clonar el repositorio

```bash
git clone https://github.com/IsabelRivadero/outbound-sentinel.git
cd outbound-sentinel
```

### 7.2. Crear el entorno virtual

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 7.3. Instalar dependencias

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 7.4. Configurar variables de entorno

Crear el archivo `.env` en la raíz del proyecto:

```bash
cp .env.example .env
```

Completar las variables requeridas:

```dotenv
# InfluxDB
INFLUXDB_ADMIN_USER=admin
INFLUXDB_ADMIN_PASSWORD=CAMBIAR_POR_UNA_PASSWORD_SEGURA
INFLUXDB_ADMIN_TOKEN=CAMBIAR_POR_UN_TOKEN_SEGURO
INFLUXDB_ORG=outbound-sentinel
INFLUXDB_BUCKET=telemetria_equipos
INFLUXDB_PORT=8086

# Grafana
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=CAMBIAR_POR_UNA_PASSWORD_SEGURA

# Zona horaria
TZ=UTC
```

No subir `.env` al repositorio. El archivo está excluido mediante `.gitignore`.

---

## 8. Levantar la infraestructura

Desde la raíz del proyecto:

```bash
docker compose up -d
```

Verificar los servicios:

```bash
docker compose ps
```

Consultar los logs:

```bash
docker compose logs -f
```

Servicios disponibles localmente:

| Servicio | URL |
|---|---|
| InfluxDB | http://localhost:8086 |
| Node-RED | http://localhost:1881 |
| Grafana | http://localhost:3000 |
| Mosquitto MQTT | localhost:1883 |

Los puertos publicados están vinculados a `127.0.0.1`, por lo que los servicios no quedan expuestos directamente a otras interfaces de red del host.

---

## 9. Ejecución del agente de monitoreo

Identificar primero la interfaz de red:

```bash
ip -br link
```

Por ejemplo, para monitorear `wlo1`:

```bash
python -m agents.gateway_collector \
  --interface wlo1 \
  --interval 120
```

El agente:

1. Captura las estadísticas de tráfico saliente.
2. Consulta las conexiones TCP establecidas.
3. Identifica destinos externos.
4. Obtiene procesos asociados cuando están disponibles.
5. Calcula diferencias entre muestras.
6. Genera un evento JSON.
7. Publica el evento mediante MQTT.

Para realizar una única captura:

```bash
python -m agents.gateway_collector \
  --interface wlo1 \
  --once
```

Para ejecutar el agente sin publicar por MQTT:

```bash
python -m agents.gateway_collector \
  --interface wlo1 \
  --no-mqtt \
  --once
```

El intervalo de captura predeterminado es de 120 segundos.

---

## 10. Persistencia en InfluxDB

En una segunda terminal, ejecutar el consumidor MQTT:

```bash
python -m storage.mqtt_to_influx
```

Este componente:

- Se conecta al broker Mosquitto.
- Se suscribe a `outbound-sentinel/gateway`.
- Procesa los eventos JSON.
- Convierte las métricas en puntos de InfluxDB.
- Persiste las mediciones en el bucket configurado.

La conexión a InfluxDB puede verificarse mediante:

```bash
python -m storage.influx_writer
```

Para consultar las mediciones almacenadas:

```bash
python -m storage.verify_influx
```

---

## 11. Indicadores de monitoreo

El sistema dispone de indicadores que permiten caracterizar la actividad de red observada.

| Indicador | Descripción |
|---|---|
| `outbound_bytes_total` | Bytes transmitidos acumulados por la interfaz |
| `outbound_bytes_interval` | Diferencia de bytes transmitidos entre muestras |
| `established_tcp_connections` | Cantidad de conexiones TCP establecidas observadas |
| `unique_external_destinations` | Cantidad de direcciones IP externas únicas observadas |
| `process_count` | Cantidad de procesos asociados a conexiones observadas |
| `connections_without_process_attribution` | Conexiones externas observadas sin atribución de proceso |
| `unauthorized_connections` | Conexiones clasificadas como no autorizadas cuando la política está habilitada |
| `assessed_external_connections` | Conexiones externas evaluadas por la política |

Los indicadores derivados se calculan conservando los valores desconocidos como `null`, evitando interpretar la ausencia de información como cero.

### Consideraciones sobre las métricas

- Los bytes transmitidos corresponden a la interfaz monitoreada y no exclusivamente a tráfico TCP externo.
- Las conexiones TCP se obtienen mediante snapshots de `ss`.
- Las conexiones breves que ocurren entre muestras pueden no observarse.
- El monitoreo actual no proporciona visibilidad completa sobre UDP.
- La atribución de procesos depende de los permisos disponibles en el sistema.
- Una dirección IP externa no constituye por sí misma evidencia de actividad maliciosa.

---

## 12. Dashboard Grafana

Dashboard:

**Outbound Sentinel - Network Monitoring**

Paneles implementados:

1. Outbound Traffic.
2. Established TCP Connections.
3. Unique External Destinations.
4. Process Count.
5. Unattributed External Connections.

El dashboard utiliza InfluxDB como datasource y consultas Flux sobre el measurement `gateway_network`.

---

## 13. Políticas de destinos autorizados

La configuración inicial se encuentra en:

```text
config/authorized_destinations.yaml
```

Configuración actual:

```yaml
policy:
  enabled: false
  authorized_cidrs: []
```

La evaluación de políticas está deshabilitada por defecto.

La intención es permitir que futuras versiones incorporen listas de destinos autorizados y criterios explícitos para evaluar conexiones externas.

La clasificación de una conexión deberá distinguir entre:

- Conexión observada.
- Conexión evaluada.
- Conexión no autorizada según una política configurada.
- Actividad potencialmente anómala.

Estas categorías no son equivalentes.

---

## 14. Tests y validación

Ejecutar los tests:

```bash
python -m unittest discover -s tests -v
```

Verificar la compilación:

```bash
python -m compileall -q agents analytics storage tests
```

Los tests implementados actualmente cubren:

- Captura y procesamiento de conexiones de red.
- Manejo de contadores y reinicios.
- Interpretación de valores faltantes.
- Cálculo de indicadores derivados.

---

## 15. Limitaciones actuales

Outbound Sentinel se encuentra en una etapa inicial de desarrollo.

La implementación actual permite observar y almacenar métricas de red, pero todavía no constituye un sistema completo de detección de intrusiones.

Limitaciones principales:

- Captura basada en snapshots periódicos.
- Visibilidad limitada a las métricas disponibles en el gateway.
- Sin inspección profunda de paquetes.
- Sin análisis completo de tráfico UDP.
- Sin detección automática de comportamiento malicioso.
- Sin bloqueo automático de conexiones.
- Sin modelo de anomalías productivo.
- Sin correlación avanzada entre dispositivos y eventos.

La ausencia de alertas o conexiones clasificadas como no autorizadas no demuestra por sí sola que la red esté libre de amenazas.

---

## 16. Roadmap

### Fase 1 — Infraestructura y observabilidad
- [x] Captura de tráfico saliente en Linux.
- [x] Publicación de eventos mediante MQTT.
- [x] Persistencia en InfluxDB.
- [x] Visualización en Grafana.
- [x] Cálculo de indicadores básicos.
- [x] Tests iniciales.

### Fase 2 — Analítica de comportamiento
- [ ] Detección de anomalías.
- [ ] Construcción de líneas base por dispositivo.
- [ ] Identificación de cambios en patrones de comunicación.
- [ ] Análisis de destinos y procesos.
- [ ] Correlación temporal de eventos.

### Fase 3 — Contexto industrial
- [ ] Inventario de dispositivos IIoT.
- [ ] Configuración de perfiles de comportamiento.
- [ ] Integración de simuladores industriales.
- [ ] Desarrollo del gemelo digital.

### Fase 4 — Alertas y respuesta
- [ ] Gestión y priorización de alertas.
- [ ] Integración con mecanismos de notificación.
- [ ] Evaluación de políticas de destinos autorizados.
- [ ] Generación de reportes de seguridad.

El objetivo es evolucionar hacia una plataforma de detección de comportamiento anómalo y análisis de riesgo en comunicaciones salientes de entornos industriales.

---

## 17. Seguridad

Esta implementación está pensada inicialmente para un entorno de laboratorio local.

Consideraciones:

- Los puertos de los servicios Docker se publican en loopback.
- Mosquitto permite conexiones anónimas en la configuración actual de laboratorio.
- Las credenciales y tokens se administran mediante variables de entorno.
- No se deben subir secretos al repositorio.
- Antes de desplegar en un entorno productivo se deben implementar autenticación, autorización, cifrado TLS y controles de acceso adecuados.
- La plataforma no bloquea conexiones automáticamente.

---

## 18. Repositorio

GitHub:

https://github.com/IsabelRivadero/outbound-sentinel

**Outbound Sentinel — Network Observability and Anomaly Detection for Industrial IoT.**