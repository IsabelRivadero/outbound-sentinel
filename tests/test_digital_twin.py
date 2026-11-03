import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from analytics.digital_twin import DigitalTwin, DigitalTwinError


NOW = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)


class TestDigitalTwin(unittest.TestCase):

    def setUp(self):
        self.twin = DigitalTwin()

    def valid_gateway_event(self):
        return {
            "device_id": "gateway-01",
            "timestamp": NOW.isoformat(),
            "source": "ubuntu_gateway",
            "interface": "wlo1",
            "data_origin": "observed",
            "available": True,
            "outbound_bytes_interval": 278405,
            "established_tcp_connections": 43,
            "unique_external_destinations": 14,
            "process_count": 4,
            "external_destinations": ["8.8.8.8"],
            "processes": ["firefox:1234"],
        }

    def policy_result(
        self,
        status,
        enabled=True,
        unauthorized=0,
        assessed=10,
    ):
        return {
            "status": status,
            "policy_enabled": enabled,
            "unauthorized_connections": unauthorized,
            "assessed_external_connections": assessed,
            "reason": f"test_{status}",
        }

    def test_valid_gateway_event_passes_data_quality(self):
        result = self.twin.evaluate(
            self.valid_gateway_event(),
            now=NOW,
        )

        self.assertTrue(result["data_quality"]["timestamp_valid"])
        self.assertEqual(result["data_quality"]["age_seconds"], 0)
        self.assertEqual(result["status"], "unknown")

    def test_missing_availability_is_unknown(self):
        event = self.valid_gateway_event()
        event.pop("available")

        result = self.twin.evaluate(event, now=NOW)

        self.assertEqual(
            result["dimensions"]["availability"]["status"],
            "unknown",
        )
        self.assertIsNone(
            result["dimensions"]["availability"]["observed"]
        )

    def test_available_gateway_is_normal(self):
        result = self.twin.evaluate(
            self.valid_gateway_event(),
            now=NOW,
        )

        self.assertEqual(
            result["dimensions"]["availability"]["status"],
            "normal",
        )

    def test_unavailable_gateway_is_unavailable(self):
        event = self.valid_gateway_event()
        event["available"] = False

        result = self.twin.evaluate(event, now=NOW)

        self.assertEqual(
            result["dimensions"]["availability"]["status"],
            "unavailable",
        )
        self.assertIn(
            "Gateway availability differs from expected state",
            result["issues"],
        )

    def test_missing_network_metrics_produce_warning(self):
        event = self.valid_gateway_event()
        event.pop("process_count")

        result = self.twin.evaluate(event, now=NOW)

        network = result["dimensions"]["network"]

        self.assertEqual(network["status"], "warning")
        self.assertIn("process_count", network["missing_metrics"])

    def test_all_missing_network_metrics_produce_unknown(self):
        event = self.valid_gateway_event()
        event["outbound_bytes_interval"] = None
        event["established_tcp_connections"] = None
        event["unique_external_destinations"] = None
        event["process_count"] = None

        result = self.twin.evaluate(event, now=NOW)

        self.assertEqual(
            result["dimensions"]["network"]["status"],
            "unknown",
        )

    def test_missing_policy_result_is_unknown(self):
        result = self.twin.evaluate(
            self.valid_gateway_event(),
            now=NOW,
        )

        policy = result["dimensions"]["security_policy"]

        self.assertEqual(policy["status"], "unknown")
        self.assertIsNone(policy["enabled"])
        self.assertFalse(policy["automatic_blocking"])

    def test_disabled_security_policy_is_unknown(self):
        detection = {
            "overall_status": "no_anomaly_detected",
            "policy_compliance": self.policy_result(
                "not_evaluated",
                enabled=False,
                unauthorized=None,
                assessed=None,
            ),
        }

        result = self.twin.evaluate(
            self.valid_gateway_event(),
            anomaly_detection=detection,
            now=NOW,
        )

        policy = result["dimensions"]["security_policy"]

        self.assertFalse(policy["enabled"])
        self.assertEqual(policy["status"], "unknown")
        self.assertEqual(policy["evaluation_status"], "not_evaluated")
        self.assertFalse(policy["automatic_blocking"])

    def test_insufficient_policy_data_is_unknown(self):
        detection = {
            "overall_status": "no_anomaly_detected",
            "policy_compliance": self.policy_result(
                "insufficient_data",
                unauthorized=0,
                assessed=0,
            ),
        }

        result = self.twin.evaluate(
            self.valid_gateway_event(),
            anomaly_detection=detection,
            now=NOW,
        )

        policy = result["dimensions"]["security_policy"]

        self.assertEqual(policy["status"], "unknown")
        self.assertEqual(
            policy["evaluation_status"],
            "insufficient_data",
        )

    def test_compliant_policy_is_normal(self):
        detection = {
            "overall_status": "no_anomaly_detected",
            "policy_compliance": self.policy_result(
                "compliant",
                unauthorized=0,
                assessed=10,
            ),
        }

        result = self.twin.evaluate(
            self.valid_gateway_event(),
            anomaly_detection=detection,
            now=NOW,
        )

        policy = result["dimensions"]["security_policy"]

        self.assertEqual(policy["status"], "normal")
        self.assertEqual(policy["evaluation_status"], "compliant")
        self.assertEqual(policy["unauthorized_connections"], 0)
        self.assertEqual(policy["assessed_external_connections"], 10)

    def test_policy_violation_is_critical(self):
        detection = {
            "overall_status": "no_anomaly_detected",
            "policy_compliance": self.policy_result(
                "policy_violation",
                unauthorized=2,
                assessed=10,
            ),
        }

        result = self.twin.evaluate(
            self.valid_gateway_event(),
            anomaly_detection=detection,
            now=NOW,
        )

        policy = result["dimensions"]["security_policy"]

        self.assertEqual(policy["status"], "critical")
        self.assertEqual(result["status"], "critical")
        self.assertIn(
            "Security policy violation detected",
            result["issues"],
        )
        self.assertFalse(policy["automatic_blocking"])

    def test_policy_violation_is_independent_from_statistical_anomaly(self):
        detection = {
            "overall_status": "no_anomaly_detected",
            "policy_compliance": self.policy_result(
                "policy_violation",
                unauthorized=1,
                assessed=5,
            ),
        }

        result = self.twin.evaluate(
            self.valid_gateway_event(),
            anomaly_detection=detection,
            now=NOW,
        )

        self.assertEqual(
            result["dimensions"]["traffic_behavior"]["status"],
            "normal",
        )
        self.assertEqual(
            result["dimensions"]["security_policy"]["status"],
            "critical",
        )

    def test_statistical_anomaly_does_not_imply_policy_violation(self):
        detection = {
            "overall_status": "potential_anomaly",
            "policy_compliance": self.policy_result(
                "compliant",
                unauthorized=0,
                assessed=5,
            ),
        }

        result = self.twin.evaluate(
            self.valid_gateway_event(),
            anomaly_detection=detection,
            now=NOW,
        )

        self.assertEqual(
            result["dimensions"]["traffic_behavior"]["status"],
            "warning",
        )
        self.assertEqual(
            result["dimensions"]["security_policy"]["status"],
            "normal",
        )

    def test_invalid_policy_result_is_unknown(self):
        detection = {
            "overall_status": "no_anomaly_detected",
            "policy_compliance": "invalid",
        }

        result = self.twin.evaluate(
            self.valid_gateway_event(),
            anomaly_detection=detection,
            now=NOW,
        )

        self.assertEqual(
            result["dimensions"]["security_policy"]["status"],
            "unknown",
        )

    def test_potential_anomaly_produces_warning(self):
        result = self.twin.evaluate(
            self.valid_gateway_event(),
            anomaly_detection={
                "overall_status": "potential_anomaly",
            },
            now=NOW,
        )

        behavior = result["dimensions"]["traffic_behavior"]

        self.assertEqual(behavior["status"], "warning")
        self.assertIn(
            "Potential traffic anomaly detected",
            result["issues"],
        )

    def test_no_anomaly_produces_normal_behavior(self):
        result = self.twin.evaluate(
            self.valid_gateway_event(),
            anomaly_detection={
                "overall_status": "no_anomaly_detected",
            },
            now=NOW,
        )

        self.assertEqual(
            result["dimensions"]["traffic_behavior"]["status"],
            "normal",
        )

    def test_missing_device_id_is_rejected(self):
        event = self.valid_gateway_event()
        event.pop("device_id")

        result = self.twin.evaluate(event, now=NOW)

        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "Missing or invalid device_id")

    def test_unknown_device_is_rejected(self):
        event = self.valid_gateway_event()
        event["device_id"] = "unknown-device"

        result = self.twin.evaluate(event, now=NOW)

        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "Device is not registered")

    def test_stale_telemetry_is_rejected(self):
        event = self.valid_gateway_event()
        event["timestamp"] = (
            NOW - timedelta(seconds=361)
        ).isoformat()

        result = self.twin.evaluate(event, now=NOW)

        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "Telemetry is stale")
        self.assertEqual(result["dimensions"], {})

    def test_future_timestamp_is_rejected(self):
        event = self.valid_gateway_event()
        event["timestamp"] = (
            NOW + timedelta(seconds=30)
        ).isoformat()

        result = self.twin.evaluate(event, now=NOW)

        self.assertEqual(
            result["reason"],
            "Telemetry timestamp is in the future",
        )

    def test_naive_timestamp_is_rejected(self):
        event = self.valid_gateway_event()
        event["timestamp"] = "2026-11-02T12:00:00"

        result = self.twin.evaluate(event, now=NOW)

        self.assertEqual(
            result["reason"],
            "Missing or invalid timezone-aware timestamp",
        )

    def test_wrong_data_origin_is_rejected(self):
        event = self.valid_gateway_event()
        event["data_origin"] = "simulated"

        result = self.twin.evaluate(event, now=NOW)

        self.assertEqual(result["status"], "unknown")
        self.assertIn("Unexpected data_origin", result["reason"])

    def test_invalid_event_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            self.twin.evaluate("not-a-dictionary", now=NOW)

    def test_naive_evaluation_time_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.twin.evaluate(
                self.valid_gateway_event(),
                now=datetime(2026, 11, 2, 12, 0),
            )

    def test_json_serialization_returns_valid_json(self):
        result = self.twin.evaluate(
            self.valid_gateway_event(),
            now=NOW,
        )

        serialized = self.twin.to_json(result)
        decoded = __import__("json").loads(serialized)

        self.assertEqual(decoded["device_id"], "gateway-01")

    def test_duplicate_device_ids_are_rejected(self):
        devices = {
            "devices": [
                {"device_id": "gateway-01"},
                {"device_id": "gateway-01"},
            ]
        }

        config = {"digital_twin": {"enabled": True}}

        with TemporaryDirectory() as directory:
            devices_path = Path(directory) / "devices.yaml"
            config_path = Path(directory) / "digital_twin.yaml"

            devices_path.write_text(
                yaml.safe_dump(devices),
                encoding="utf-8",
            )
            config_path.write_text(
                yaml.safe_dump(config),
                encoding="utf-8",
            )

            with self.assertRaises(DigitalTwinError):
                DigitalTwin(
                    devices_file=devices_path,
                    config_file=config_path,
                )


if __name__ == "__main__":
    unittest.main()