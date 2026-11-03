import ipaddress
import unittest
from unittest.mock import patch

from agents.network_monitor import NetworkMonitor


class TestNetworkMonitor(unittest.TestCase):

    def setUp(self):
        self.monitor = NetworkMonitor(
            interface="wlo1",
            policy_file="config/authorized_destinations.yaml",
        )

    def test_extract_ipv4(self):
        result = self.monitor._extract_ip("142.250.184.14:443")
        self.assertEqual(result, "142.250.184.14")

    def test_extract_ipv6(self):
        result = self.monitor._extract_ip("[2606:4700:4700::1111]:443")
        self.assertEqual(result, "2606:4700:4700::1111")

    def test_first_measurement_is_baseline(self):
        with patch.object(self.monitor, "_read_tx_bytes", return_value=1000), \
             patch.object(self.monitor, "_collect_connections", return_value={}):

            result = self.monitor.collect()

        self.assertIsNone(result["outbound_bytes_interval"])
        self.assertEqual(result["outbound_bytes_status"], "baseline")

    def test_second_measurement_calculates_delta(self):
        with patch.object(
            self.monitor, "_read_tx_bytes", side_effect=[1000, 1500]
        ), patch.object(self.monitor, "_collect_connections", return_value={}):

            self.monitor.collect()
            result = self.monitor.collect()

        self.assertEqual(result["outbound_bytes_interval"], 500)
        self.assertEqual(result["outbound_bytes_status"], "measured")

    def test_counter_reset_is_not_negative(self):
        with patch.object(
            self.monitor, "_read_tx_bytes", side_effect=[1500, 100]
        ), patch.object(self.monitor, "_collect_connections", return_value={}):

            self.monitor.collect()
            result = self.monitor.collect()

        self.assertIsNone(result["outbound_bytes_interval"])
        self.assertEqual(result["outbound_bytes_status"], "counter_reset")

    def test_disabled_policy_does_not_classify_connections(self):
        self.assertFalse(self.monitor.policy_enabled)
        self.assertIsNone(self.monitor._is_authorized("8.8.8.8"))

    def test_disabled_policy_returns_none_for_classification(self):
        with patch.object(self.monitor, "_run_ss", return_value=[]):
            result = self.monitor._collect_connections()

        self.assertFalse(result["policy_enabled"])
        self.assertIsNone(result["authorized_connections"])
        self.assertIsNone(result["unauthorized_connections"])
        self.assertIsNone(result["assessed_external_connections"])
        self.assertIsNone(result["authorized_destinations"])
        self.assertIsNone(result["unauthorized_destinations"])

    def test_enabled_policy_classifies_connections(self):
        self.monitor.authorized_networks = [
            ipaddress.ip_network("8.8.8.0/24")
        ]
        self.monitor.policy_enabled = True

        # Formato real de: ss -Htnp state established
        # No incluye la columna ESTAB.
        lines = [
            '0 0 192.168.1.10:50000 8.8.8.8:443 users:(("firefox",pid=100,fd=10))',
            '0 0 192.168.1.10:50001 1.1.1.1:443 users:(("firefox",pid=100,fd=11))',
            '0 0 192.168.1.10:50002 8.8.8.8:443 users:(("firefox",pid=100,fd=12))',
        ]

        with patch.object(
            self.monitor,
            "_run_ss",
            return_value=lines
        ):
            result = self.monitor._collect_connections()

        self.assertEqual(result["assessed_external_connections"], 3)
        self.assertEqual(result["authorized_connections"], 2)
        self.assertEqual(result["unauthorized_connections"], 1)

        self.assertEqual(
            result["authorized_destinations"],
            ["8.8.8.8"]
        )
        self.assertEqual(
            result["unauthorized_destinations"],
            ["1.1.1.1"]
        )
        self.assertEqual(result["unique_external_destinations"], 2)

    def test_real_ss_format_extracts_destinations_and_processes(self):
        lines = [
            '0 0 192.168.1.10:50000 8.8.8.8:443 users:(("firefox",pid=100,fd=10))',
            '0 0 192.168.1.10:50001 1.1.1.1:443 users:(("code",pid=200,fd=11))',
        ]

        with patch.object(
            self.monitor,
            "_run_ss",
            return_value=lines
        ):
            result = self.monitor._collect_connections()

        self.assertEqual(result["established_tcp_connections"], 2)
        self.assertEqual(result["unique_external_destinations"], 2)

        self.assertEqual(
            result["external_destinations"],
            ["1.1.1.1", "8.8.8.8"]
        )

        self.assertEqual(result["process_count"], 2)

        self.assertEqual(
            result["processes_with_observed_connections"],
            ["code:200", "firefox:100"]
        )

        self.assertEqual(
            result["connections_without_process_attribution"],
            0
        )


if __name__ == "__main__":
    unittest.main()