"""Consulta las últimas mediciones del gateway en InfluxDB."""

import os
from pathlib import Path

from dotenv import load_dotenv
from influxdb_client import InfluxDBClient

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

url = os.getenv(
    "INFLUXDB_URL",
    f"http://localhost:{os.getenv('INFLUXDB_PORT', '8086')}",
)
token = os.getenv("INFLUXDB_ADMIN_TOKEN")
org = os.getenv("INFLUXDB_ORG")
bucket = os.getenv("INFLUXDB_BUCKET")

if not all([token, org, bucket]):
    raise RuntimeError("Faltan variables de conexión en .env")

query = f'''
from(bucket: "{bucket}")
    |> range(start: -1h)
    |> filter(fn: (r) => r["_measurement"] == "gateway_network")
    |> sort(columns: ["_time"], desc: true)
    |> limit(n: 20)
'''

with InfluxDBClient(url=url, token=token, org=org) as client:
    tables = client.query_api().query(query, org=org)

    rows = [
        {
            "timestamp": record.get_time(),
            "measurement": record.get_measurement(),
            "field": record.get_field(),
            "value": record.get_value(),
            "interface": record.values.get("interface"),
            "origin": record.values.get("data_origin"),
        }
        for table in tables
        for record in table.records
    ]

    if not rows:
        print("No se encontraron mediciones gateway_network en la última hora.")
    else:
        print(f"Registros consultados: {len(rows)}")
        print("-" * 90)

        for row in rows:
            print(
                f"{row['timestamp']} | "
                f"{row['field']} = {row['value']} | "
                f"interface={row['interface']} | "
                f"origin={row['origin']}"
            )
