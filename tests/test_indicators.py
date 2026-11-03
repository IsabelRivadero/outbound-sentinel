import unittest

from analytics.indicators import (
    calculate_indicators,
    aggregate_indicators,
)


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
        result = calculate_indicators(self.current, self.previous)
        self.assertEqual(result["measurement_interval_seconds"], 120)

    def test_calculates_outbound_bytes_per_second(self):
        result = calculate_indicators(self.current, self.previous)
        self.assertEqual(result["outbound_bytes_per_second"], 100)

    def test_first_measurement_has_no_rate(self):
        result = calculate_indicators(self.current)
        self.assertIsNone(result["measurement_interval_seconds"])
        self.assertIsNone(result["outbound_bytes_per_second"])

    def test_missing_values_remain_none(self):
        event = {"timestamp": self.current["timestamp"]}
        result = calculate_indicators(event, self.previous)

        self.assertIsNone(result["outbound_bytes_interval"])
        self.assertIsNone(result["process_count"])
        self.assertIsNone(result["unique_external_destinations"])

    def test_zero_or_negative_elapsed_time_has_no_rate(self):
        previous = {"timestamp": self.current["timestamp"]}
        result = calculate_indicators(self.current, previous)

        self.assertIsNone(result["measurement_interval_seconds"])
        self.assertIsNone(result["outbound_bytes_per_second"])

    def test_policy_disabled_preserves_unknown_values(self):
        result = calculate_indicators(self.current, self.previous)

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

    # ---------------------------------------------------------
    # Agregaciones
    # ---------------------------------------------------------

    def test_hourly_aggregation(self):
        events = [
            {
                **self.current,
                "timestamp": "2026-10-29T22:02:00+00:00",
                "outbound_bytes_interval": 12000,
            },
            {
                **self.current,
                "timestamp": "2026-10-29T22:04:00+00:00",
                "outbound_bytes_interval": 18000,
            },
        ]

        result = aggregate_indicators(events, period="hour")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["period"], "hour")
        self.assertEqual(
            result[0]["period_start"],
            "2026-10-29T22:00:00+00:00",
        )
        self.assertEqual(result[0]["sample_count"], 2)
        self.assertEqual(
            result[0]["metrics"]["outbound_bytes_interval"]["sum"],
            30000,
        )

    def test_daily_aggregation(self):
        events = [
            {
                **self.current,
                "timestamp": "2026-10-29T10:00:00+00:00",
            },
            {
                **self.current,
                "timestamp": "2026-10-29T18:00:00+00:00",
            },
        ]

        result = aggregate_indicators(events, period="day")

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["period_start"],
            "2026-10-29T00:00:00+00:00",
        )
        self.assertEqual(result[0]["sample_count"], 2)

    def test_weekly_aggregation_starts_on_monday(self):
        events = [
            {
                **self.current,
                "timestamp": "2026-10-29T10:00:00+00:00",
            },
            {
                **self.current,
                "timestamp": "2026-11-01T10:00:00+00:00",
            },
        ]

        result = aggregate_indicators(events, period="week")

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["period_start"],
            "2026-10-26T00:00:00+00:00",
        )

    def test_missing_values_are_not_replaced_by_zero(self):
        events = [
            {
                "timestamp": "2026-10-29T22:02:00+00:00",
                "source": "ubuntu_gateway",
                "interface": "wlo1",
                "data_origin": "observed",
            }
        ]

        result = aggregate_indicators(events, period="hour")

        metric = result[0]["metrics"]["outbound_bytes_interval"]

        self.assertIsNone(metric["sum"])
        self.assertEqual(metric["valid_samples"], 0)
        self.assertEqual(metric["total_samples"], 1)

    def test_separates_data_origins(self):
        events = [
            {
                **self.current,
                "data_origin": "observed",
            },
            {
                **self.current,
                "data_origin": "simulated",
            },
        ]

        result = aggregate_indicators(events, period="hour")

        self.assertEqual(len(result), 2)

        origins = {item["data_origin"] for item in result}

        self.assertEqual(origins, {"observed", "simulated"})

    def test_invalid_period_raises_error(self):
        with self.assertRaises(ValueError):
            aggregate_indicators([], period="month")

    def test_invalid_events_type_raises_error(self):
        with self.assertRaises(TypeError):
            aggregate_indicators({}, period="hour")

    def test_invalid_events_are_ignored(self):
        events = [
            None,
            {"timestamp": "timestamp-invalido"},
            self.current,
        ]

        result = aggregate_indicators(events, period="hour")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["sample_count"], 1)


if __name__ == "__main__":
    unittest.main()