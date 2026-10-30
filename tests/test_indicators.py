import unittest

from analytics.indicators import calculate_indicators


class TestIndicators(unittest.TestCase):

    def setUp(self):
        self.previous = {
            "timestamp": "2026-10-29T22:00:00+00:00",
        }

        self.current = {
            "timestamp": "2026-10-29T22:02:00+00:00",
            "source": "ubuntu_gateway",
            "interface": "wlo1",
            "data_origin": "observed",
            "outbound_bytes_interval": 12000,
            "outbound_bytes_total": 500000,
            "outbound_bytes_status": "measured",
            "established_tcp_connections": 24,
            "unique_external_destinations": 8,
            "connections_without_process_attribution": 0,
            "process_count": 4,
            "policy_enabled": False,
            "unauthorized_connections": None,
            "assessed_external_connections": None,
        }

    def test_calculates_real_measurement_interval(self):
        result = calculate_indicators(
            self.current, self.previous
        )

        self.assertEqual(
            result["measurement_interval_seconds"], 120
        )

    def test_calculates_outbound_bytes_per_second(self):
        result = calculate_indicators(
            self.current, self.previous
        )

        self.assertEqual(
            result["outbound_bytes_per_second"], 100
        )

    def test_first_measurement_has_no_rate(self):
        result = calculate_indicators(self.current)

        self.assertIsNone(
            result["measurement_interval_seconds"]
        )
        self.assertIsNone(
            result["outbound_bytes_per_second"]
        )

    def test_missing_values_remain_none(self):
        event = {"timestamp": self.current["timestamp"]}

        result = calculate_indicators(event, self.previous)

        self.assertIsNone(result["outbound_bytes_interval"])
        self.assertIsNone(result["process_count"])
        self.assertIsNone(result["unique_external_destinations"])

    def test_zero_or_negative_elapsed_time_has_no_rate(self):
        previous = {
            "timestamp": self.current["timestamp"]
        }

        result = calculate_indicators(self.current, previous)

        self.assertIsNone(
            result["measurement_interval_seconds"]
        )
        self.assertIsNone(
            result["outbound_bytes_per_second"]
        )

    def test_policy_disabled_preserves_unknown_values(self):
        result = calculate_indicators(
            self.current, self.previous
        )

        self.assertFalse(result["policy_enabled"])
        self.assertIsNone(result["unauthorized_connections"])
        self.assertIsNone(result["assessed_external_connections"])

    def test_boolean_is_not_a_numeric_measurement(self):
        event = {
            **self.current,
            "outbound_bytes_interval": True,
        }

        result = calculate_indicators(event, self.previous)

        self.assertIsNone(result["outbound_bytes_interval"])
        self.assertIsNone(result["outbound_bytes_per_second"])


if __name__ == "__main__":
    unittest.main()
