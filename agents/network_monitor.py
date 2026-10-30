import ipaddress
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


class NetworkMonitor:
    """Obtiene métricas observadas de una interfaz de red Linux."""

    def __init__(self, interface="wlo1", policy_file=None):
        self.interface = interface
        self.policy_file = Path(policy_file) if policy_file else None
        self.previous_tx_bytes = None
        self.authorized_networks, self.policy_enabled = self._load_policy()

    def _load_policy(self):
        if not self.policy_file or not self.policy_file.exists():
            return [], False

        try:
            import yaml

            with self.policy_file.open("r", encoding="utf-8") as file:
                config = yaml.safe_load(file) or {}

            policy = config.get("policy", {})
            enabled = bool(policy.get("enabled", False))
            networks = [
                ipaddress.ip_network(value)
                for value in policy.get("authorized_cidrs", [])
            ]
            return networks, enabled

        except Exception as exc:
            print(f"[WARN] No se pudo leer la política: {exc}")
            return [], False

    def _read_tx_bytes(self):
        path = Path(
            f"/sys/class/net/{self.interface}/statistics/tx_bytes"
        )

        if not path.exists():
            raise RuntimeError(
                f"No existe la interfaz o su contador: {self.interface}"
            )

        return int(path.read_text().strip())

    @staticmethod
    def _run_ss():
        result = subprocess.run(
            ["ss", "-Htnp", "state", "established"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return result.stdout.splitlines()

    @staticmethod
    def _extract_ip(address):
        """Extrae una IP desde formatos IPv4 o IPv6 de ss."""
        address = address.strip()

        if address.startswith("["):
            match = re.match(r"^\[([^\]]+)\]:(\d+)$", address)
            return match.group(1) if match else None

        if address.count(":") == 1:
            host, port = address.rsplit(":", 1)
            if port.isdigit():
                return host

        # IPv6 sin corchetes, si aparece en ese formato.
        try:
            ipaddress.ip_address(address)
            return address
        except ValueError:
            return None

    def _is_authorized(self, destination):
        if not self.policy_enabled:
            return None

        try:
            ip = ipaddress.ip_address(destination)
            return any(
                ip.version == network.version and ip in network
                for network in self.authorized_networks
            )
        except ValueError:
            return None

    def _collect_connections(self):
        lines = self._run_ss()

        external_destinations = set()
        processes = set()
        unauthorized = 0
        assessed = 0
        unknown_process_connections = 0

        for line in lines:
            parts = line.split()

            if len(parts) < 4:
                continue

            remote_ip = self._extract_ip(parts[3])
            if not remote_ip:
                continue

            try:
                ip = ipaddress.ip_address(remote_ip)
            except ValueError:
                continue

            # Solo contamos direcciones IP públicas como destinos externos.
            if not ip.is_global:
                continue

            external_destinations.add(str(ip))

            process_matches = re.findall(
                r'users:\(\("([^"]+)",pid=(\d+)', line
            )

            if process_matches:
                for process_name, pid in process_matches:
                    processes.add(f"{process_name}:{pid}")
            else:
                unknown_process_connections += 1

            authorization = self._is_authorized(str(ip))

            if authorization is not None:
                assessed += 1
                if not authorization:
                    unauthorized += 1

        return {
            "established_tcp_connections": len(lines),
            "unique_external_destinations": len(external_destinations),
            "external_destinations": sorted(external_destinations),
            "processes_with_observed_connections": sorted(processes),
            "process_count": len(processes) if processes else None,
            "connections_without_process_attribution": (
                unknown_process_connections
            ),
            "unauthorized_connections": (
                unauthorized if self.policy_enabled else None
            ),
            "assessed_external_connections": (
                assessed if self.policy_enabled else None
            ),
            "policy_enabled": self.policy_enabled,
        }

    def collect(self):
        current_tx_bytes = self._read_tx_bytes()

        if self.previous_tx_bytes is None:
            tx_delta = None
            tx_status = "baseline"
        elif current_tx_bytes >= self.previous_tx_bytes:
            tx_delta = current_tx_bytes - self.previous_tx_bytes
            tx_status = "measured"
        else:
            # El contador se reinició o disminuyó.
            tx_delta = None
            tx_status = "counter_reset"

        self.previous_tx_bytes = current_tx_bytes

        connections = self._collect_connections()

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "ubuntu_gateway",
            "data_origin": "observed",
            "interface": self.interface,
            "outbound_bytes_total": current_tx_bytes,
            "outbound_bytes_interval": tx_delta,
            "outbound_bytes_status": tx_status,
            **connections,
        }


if __name__ == "__main__":
    monitor = NetworkMonitor(
        interface="wlo1",
        policy_file="config/authorized_destinations.yaml",
    )
    print(json.dumps(monitor.collect(), indent=2, ensure_ascii=False))
