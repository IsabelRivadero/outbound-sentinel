import unittest

from analytics.run_detection import build_investigation_context
from storage.influx_reader import InfluxReader


class TestInvestigationContext(unittest.TestCase):

    def test_decodes_processes_and_destinations(self):
        from types import SimpleNamespace

        record = SimpleNamespace(values={
            "_time": "2026-11-02T15:56:03+00:00",
            "source": "ubuntu_gateway",
            "interface": "wlo1",
            "data_origin": "observed",
            "processes_json": '[{"name": "python", "pid": 123}]',
            "external_destinations_json": '["8.8.8.8"]',
        })

        event = InfluxReader._record_to_event(record)

        self.assertEqual(
            event["processes"],
            [{"name": "python", "pid": 123}],
        )
        self.assertEqual(
            event["external_destinations"],
            ["8.8.8.8"],
        )

    def test_invalid_json_remains_unknown(self):
        self.assertIsNone(
            InfluxReader._decode_json_field("{invalid")
        )

    def test_missing_context_remains_unknown(self):
        event = {
            "timestamp": "2026-11-02T15:56:03+00:00",
            "source": "ubuntu_gateway",
            "interface": "wlo1",
            "data_origin": "observed",
        }

        detection = {
            "metrics": {
                "outbound_bytes_per_second": {
                    "value": 7000,
                    "score": 3.7,
                    "reason": "robust_deviation_above_threshold",
                    "is_anomaly": True,
                }
            }
        }

        context = build_investigation_context(event, detection)

        self.assertIsNone(context["processes"])
        self.assertIsNone(context["external_destinations"])
        self.assertIsNone(context["policy_compliance"])
        self.assertFalse(context["process_context_available"])
        self.assertFalse(context["destination_context_available"])
        self.assertFalse(context["policy_context_available"])

    def test_only_anomalous_metrics_are_included(self):
        event = {
            "timestamp": "2026-11-02T15:56:03+00:00",
            "interface": "wlo1",
            "data_origin": "observed",
            "processes": [],
            "external_destinations": [],
        }

        detection = {
            "metrics": {
                "outbound_bytes_per_second": {
                    "value": 7000,
                    "score": 3.7,
                    "reason": "robust_deviation_above_threshold",
                    "is_anomaly": True,
                },
                "established_tcp_connections": {
                    "value": 32,
                    "score": 0.4,
                    "reason": "within_expected_range",
                    "is_anomaly": False,
                },
            }
        }

        context = build_investigation_context(event, detection)

        self.assertEqual(
            len(context["anomalous_metrics"]),
            1,
        )
        self.assertEqual(
            context["anomalous_metrics"][0]["metric"],
            "outbound_bytes_per_second",
        )

    def test_policy_compliance_is_included_in_context(self):
        event = {
            "timestamp": "2026-11-02T15:56:03+00:00",
            "source": "ubuntu_gateway",
            "interface": "wlo1",
            "data_origin": "observed",
        }

        policy = {
            "status": "policy_violation",
            "policy_enabled": True,
            "unauthorized_connections": 2,
            "assessed_external_connections": 10,
            "reason": "unauthorized_connections_detected",
        }

        detection = {
            "metrics": {},
            "policy_compliance": policy,
        }

        context = build_investigation_context(event, detection)

        self.assertEqual(context["policy_compliance"], policy)
        self.assertTrue(context["policy_context_available"])


if __name__ == "__main__":
    unittest.main()