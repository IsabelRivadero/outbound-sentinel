
import json
import unittest

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from storage.influx_writer import InfluxWriter, WritePrecision


class TestInfluxWriter(unittest.TestCase):

    def setUp(self):
        # Evita crear una conexión real con InfluxDB.
        self.writer = InfluxWriter.__new__(InfluxWriter)

        self.writer.org = "outbound-sentinel"
        self.writer.bucket = "telemetria_equipos"
        self.writer.write_api = MagicMock()
        self.writer.client = MagicMock()

        # Simula el objeto Point de InfluxDB.
        self.point_patcher = patch("storage.influx_writer.Point")
        self.point_class = self.point_patcher.start()
        self.addCleanup(self.point_patcher.stop)

        self.point = self.point_class.return_value

        # Los métodos de Point utilizan method chaining.
        # Cada uno debe devolver la misma instancia.
        self.point.tag.return_value = self.point
        self.point.field.return_value = self.point
        self.point.time.return_value = self.point

        self.timestamp = "2026-11-02T15:40:00+00:00"

        self.event = {
            "timestamp": self.timestamp,
            "source": "ubuntu_gateway",
            "interface": "wlo1",
            "data_origin": "observed",
            "outbound_bytes_total": 4538599907,
            "outbound_bytes_interval": 154240,
            "outbound_bytes_status": "measured",
            "established_tcp_connections": 32,
            "unique_external_destinations": 12,
            "process_count": 3,
            "connections_without_process_attribution": 2,
            "policy_enabled": False,
            "authorized_connections": None,
            "unauthorized_connections": None,
            "assessed_external_connections": None,
            "processes": [
                {
                    "name": "python",
                    "pid": 1234,
                    "connections": 2,
                }
            ],
            "external_destinations": [
                "8.8.8.8",
                "1.1.1.1",
            ],
            "authorized_destinations": [],
            "unauthorized_destinations": [],
        }

    def get_persisted_fields(self):
        """Obtiene los campos enviados al objeto Point simulado."""

        return {
            args[0]: args[1]
            for args, _ in self.point.field.call_args_list
        }

    def test_event_to_point_creates_expected_measurement(self):
        self.writer.event_to_point(self.event)

        self.point_class.assert_called_once_with(
            "gateway_network"
        )

        self.point.tag.assert_any_call(
            "source",
            "ubuntu_gateway",
        )

        self.point.tag.assert_any_call(
            "interface",
            "wlo1",
        )

        self.point.tag.assert_any_call(
            "data_origin",
            "observed",
        )

    def test_event_to_point_sets_timestamp(self):
        self.writer.event_to_point(self.event)

        expected_timestamp = datetime(
            2026, 11, 2, 15, 40, 0,
            tzinfo=timezone.utc,
        )

        self.point.time.assert_called_once_with(
            expected_timestamp,
            WritePrecision.NS,
        )

    def test_event_to_point_persists_numeric_fields(self):
        self.writer.event_to_point(self.event)

        persisted_fields = self.get_persisted_fields()

        expected_fields = {
            "outbound_bytes_total": 4538599907,
            "outbound_bytes_interval": 154240,
            "established_tcp_connections": 32,
            "unique_external_destinations": 12,
            "process_count": 3,
            "connections_without_process_attribution": 2,
        }

        for field, expected_value in expected_fields.items():
            with self.subTest(field=field):
                self.assertEqual(
                    persisted_fields[field],
                    expected_value,
                )

    def test_event_to_point_does_not_persist_none_as_zero(self):
        self.writer.event_to_point(self.event)

        persisted_fields = self.get_persisted_fields()

        self.assertNotIn(
            "authorized_connections",
            persisted_fields,
        )

        self.assertNotIn(
            "unauthorized_connections",
            persisted_fields,
        )

        self.assertNotIn(
            "assessed_external_connections",
            persisted_fields,
        )

    def test_event_to_point_does_not_treat_booleans_as_numbers(self):
        event = {
            **self.event,
            "outbound_bytes_interval": True,
            "established_tcp_connections": False,
        }

        self.writer.event_to_point(event)

        persisted_fields = self.get_persisted_fields()

        self.assertNotIn(
            "outbound_bytes_interval",
            persisted_fields,
        )

        self.assertNotIn(
            "established_tcp_connections",
            persisted_fields,
        )

    def test_event_to_point_persists_policy_status(self):
        self.writer.event_to_point(self.event)

        persisted_fields = self.get_persisted_fields()

        self.assertEqual(
            persisted_fields["outbound_bytes_status"],
            "measured",
        )

        self.assertIs(
            persisted_fields["policy_enabled"],
            False,
        )

    def test_event_to_point_serializes_json_fields(self):
        self.writer.event_to_point(self.event)

        persisted_fields = self.get_persisted_fields()

        expected_json_fields = {
            "processes_json": self.event["processes"],
            "external_destinations_json": (
                self.event["external_destinations"]
            ),
            "authorized_destinations_json": (
                self.event["authorized_destinations"]
            ),
            "unauthorized_destinations_json": (
                self.event["unauthorized_destinations"]
            ),
        }

        for field, expected_value in expected_json_fields.items():
            with self.subTest(field=field):
                self.assertEqual(
                    json.loads(persisted_fields[field]),
                    expected_value,
                )

    def test_event_to_point_preserves_empty_lists(self):
        event = {
            **self.event,
            "authorized_destinations": [],
            "unauthorized_destinations": [],
        }

        self.writer.event_to_point(event)

        persisted_fields = self.get_persisted_fields()

        self.assertEqual(
            json.loads(
                persisted_fields["authorized_destinations_json"]
            ),
            [],
        )

        self.assertEqual(
            json.loads(
                persisted_fields["unauthorized_destinations_json"]
            ),
            [],
        )

    def test_event_to_point_uses_observed_processes_fallback(self):
        processes = [
            {
                "name": "firefox",
                "pid": 5678,
                "connections": 3,
            }
        ]

        event = {
            **self.event,
            "processes": processes,
        }

        event.pop("processes_with_observed_connections", None)

        self.writer.event_to_point(event)

        persisted_fields = self.get_persisted_fields()

        self.assertEqual(
            json.loads(persisted_fields["processes_json"]),
            processes,
        )

    def test_event_to_point_prefers_observed_processes(self):
        observed_processes = [
            {"name": "python", "pid": 1234}
        ]

        fallback_processes = [
            {"name": "firefox", "pid": 5678}
        ]

        event = {
            **self.event,
            "processes": fallback_processes,
            "processes_with_observed_connections": (
                observed_processes
            ),
        }

        self.writer.event_to_point(event)

        persisted_fields = self.get_persisted_fields()

        self.assertEqual(
            json.loads(persisted_fields["processes_json"]),
            observed_processes,
        )

    def test_write_event_calls_influx_write_api(self):
        self.writer.write_event(self.event)

        self.writer.write_api.write.assert_called_once_with(
            bucket="telemetria_equipos",
            org="outbound-sentinel",
            record=self.point,
        )

    def test_write_event_rejects_non_dictionary(self):
        with self.assertRaises(TypeError):
            self.writer.write_event(["invalid-event"])

        self.writer.write_api.write.assert_not_called()

    def test_close_closes_client(self):
        self.writer.close()

        self.writer.client.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
