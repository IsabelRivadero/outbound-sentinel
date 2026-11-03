import unittest

from analytics.anomaly_detector import (
    detect_anomalies,
    evaluate_metric,
    evaluate_policy_compliance,
)


class TestAnomalyDetector(unittest.TestCase):

    def test_detects_large_deviation(self):
        result = evaluate_metric(200, [100] * 10)

        self.assertTrue(result["is_anomaly"])
        self.assertEqual(result["baseline_median"], 100)

    def test_normal_value_is_not_anomaly(self):
        history = [100, 101, 99, 100, 102, 98, 101, 99, 100, 102]

        result = evaluate_metric(101, history)

        self.assertFalse(result["is_anomaly"])

    def test_insufficient_history(self):
        result = evaluate_metric(200, [100, 101, 99])

        self.assertEqual(result["status"], "insufficient_history")
        self.assertIsNone(result["is_anomaly"])

    def test_missing_value_is_not_zero(self):
        result = evaluate_metric(None, [100] * 10)

        self.assertEqual(
            result["status"],
            "insufficient_current_data",
        )
        self.assertIsNone(result["value"])
        self.assertIsNone(result["is_anomaly"])

    def test_zero_mad_detects_deviation(self):
        result = evaluate_metric(150, [100] * 10)

        self.assertTrue(result["is_anomaly"])
        self.assertEqual(result["mad"], 0)

    def test_boolean_is_not_numeric(self):
        result = evaluate_metric(True, [100] * 10)

        self.assertEqual(
            result["status"],
            "insufficient_current_data",
        )

    def test_baseline_traffic_is_not_evaluated(self):
        current = {
            "outbound_bytes_per_second": 100,
            "outbound_bytes_status": "baseline",
            "established_tcp_connections": 20,
        }

        history = [
            {
                "outbound_bytes_per_second": 100,
                "established_tcp_connections": 20,
            }
            for _ in range(10)
        ]

        result = detect_anomalies(current, history)

        self.assertEqual(
            result["metrics"]["outbound_bytes_per_second"]["status"],
            "insufficient_current_data",
        )

    def test_detect_anomalies_reports_overall_status(self):
        current = {
            "timestamp": "2026-10-30T19:00:00+00:00",
            "source": "ubuntu_gateway",
            "interface": "wlo1",
            "data_origin": "observed",
            "established_tcp_connections": 200,
        }

        history = [
            {"established_tcp_connections": 20}
            for _ in range(10)
        ]

        result = detect_anomalies(current, history)

        self.assertEqual(
            result["overall_status"],
            "potential_anomaly",
        )
        self.assertEqual(result["potential_anomalies"], 1)

    def test_disabled_policy_is_not_evaluated(self):
        result = evaluate_policy_compliance({
            "policy_enabled": False,
            "unauthorized_connections": None,
            "assessed_external_connections": None,
        })

        self.assertEqual(result["status"], "not_evaluated")

    def test_unknown_policy_is_not_evaluated(self):
        result = evaluate_policy_compliance({
            "policy_enabled": None,
        })

        self.assertEqual(result["status"], "not_evaluated")

    def test_enabled_policy_detects_violation(self):
        result = evaluate_policy_compliance({
            "policy_enabled": True,
            "unauthorized_connections": 3,
            "assessed_external_connections": 20,
        })

        self.assertEqual(result["status"], "policy_violation")

    def test_enabled_policy_detects_compliance(self):
        result = evaluate_policy_compliance({
            "policy_enabled": True,
            "unauthorized_connections": 0,
            "assessed_external_connections": 20,
        })

        self.assertEqual(result["status"], "compliant")

    def test_enabled_policy_without_data_is_insufficient(self):
        result = evaluate_policy_compliance({
            "policy_enabled": True,
            "unauthorized_connections": None,
            "assessed_external_connections": None,
        })

        self.assertEqual(result["status"], "insufficient_data")

    def test_zero_assessed_connections_is_insufficient(self):
        result = evaluate_policy_compliance({
            "policy_enabled": True,
            "unauthorized_connections": 0,
            "assessed_external_connections": 0,
        })

        self.assertEqual(result["status"], "insufficient_data")

    def test_boolean_policy_metrics_are_invalid(self):
        result = evaluate_policy_compliance({
            "policy_enabled": True,
            "unauthorized_connections": True,
            "assessed_external_connections": 20,
        })

        self.assertEqual(result["status"], "insufficient_data")

    def test_policy_metrics_cannot_be_negative(self):
        result = evaluate_policy_compliance({
            "policy_enabled": True,
            "unauthorized_connections": -1,
            "assessed_external_connections": 20,
        })

        self.assertEqual(result["status"], "insufficient_data")

    def test_unauthorized_connections_cannot_exceed_assessed(self):
        result = evaluate_policy_compliance({
            "policy_enabled": True,
            "unauthorized_connections": 10,
            "assessed_external_connections": 5,
        })

        self.assertEqual(result["status"], "insufficient_data")

    def test_invalid_threshold_raises_error(self):
        with self.assertRaises(ValueError):
            evaluate_metric(100, [100] * 10, threshold=0)

    def test_invalid_min_samples_raises_error(self):
        with self.assertRaises(ValueError):
            evaluate_metric(100, [100] * 10, min_samples=0)

    def test_policy_and_anomaly_results_are_independent(self):
        current = {
            "established_tcp_connections": 200,
            "policy_enabled": True,
            "unauthorized_connections": 0,
            "assessed_external_connections": 20,
        }

        history = [
            {"established_tcp_connections": 20}
            for _ in range(10)
        ]

        result = detect_anomalies(current, history)

        self.assertEqual(
            result["overall_status"],
            "potential_anomaly",
        )

        self.assertEqual(
            result["policy_compliance"]["status"],
            "compliant",
        )


if __name__ == "__main__":
    unittest.main()