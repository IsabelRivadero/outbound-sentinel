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


if __name__ == "__main__":
    unittest.main()