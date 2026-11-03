import unittest
import json

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from storage.influx_reader import InfluxReader


class TestInfluxReader(unittest.TestCase):

    def setUp(self):
        # Evita crear una conexión real con InfluxDB.
        self.reader = InfluxReader.__new__(InfluxReader)
        self.reader.bucket = "telemetria_equipos"
        self.reader.org = "outbound-sentinel"
        self.reader.query_api = MagicMock()

    def make_record(self, timestamp, **fields):
        values = {
            "_time": timestamp,
            "source": "ubuntu_gateway",
            "interface": "wlo1",
            "data_origin": "observed",
        }
        values.update(fields)

        return SimpleNamespace(values=values)

    def test_build_query_contains_expected_filters(self):
        query = self.reader.build_query(
            interface="wlo1",
            lookback_days=7,
        )

        self.assertIn("gateway_network", query)
        self.assertIn("ubuntu_gateway", query)
        self.assertIn("wlo1", query)
        self.assertIn("observed", query)
        self.assertIn("range(start: -7d)", query)
        self.assertIn("pivot(", query)

    def test_build_query_validates_parameters(self):
        with self.assertRaises(ValueError):
            self.reader.build_query(
                interface="wlo1",
                lookback_days=0,
            )

        with self.assertRaises(ValueError):
            self.reader.build_query(
                interface="wlo1",
                limit=0,
            )

    def test_record_to_event_converts_fields(self):
        timestamp = datetime(
            2026, 11, 2, 15, 40, 0,
            tzinfo=timezone.utc,
        )

        record = self.make_record(
            timestamp,
            outbound_bytes_interval=154240,
            outbound_bytes_total=4538599907,
            outbound_bytes_status="measured",
            established_tcp_connections=32,
            unique_external_destinations=12,
            process_count=3,
            policy_enabled=False,
            unauthorized_connections=None,
        )

        event = self.reader._record_to_event(record)

        self.assertEqual(event["interface"], "wlo1")
        self.assertEqual(event["data_origin"], "observed")
        self.assertEqual(event["outbound_bytes_interval"], 154240)
        self.assertEqual(event["established_tcp_connections"], 32)
        self.assertEqual(event["policy_enabled"], False)
        self.assertIsNone(event["unauthorized_connections"])

    def test_record_to_event_reconstructs_json_lists(self):
        timestamp = datetime(
            2026, 11, 2, 15, 40, 0,
            tzinfo=timezone.utc,
        )

        processes = [
            {
                "name": "python",
                "pid": 1234,
                "connections": 2,
            },
            {
                "name": "firefox",
                "pid": 5678,
                "connections": 1,
            },
        ]

        external_destinations = [
            "8.8.8.8",
            "1.1.1.1",
        ]

        authorized_destinations = [
            "8.8.8.8",
        ]

        unauthorized_destinations = [
            "1.1.1.1",
        ]

        record = self.make_record(
            timestamp,
            processes_json=json.dumps(processes),
            external_destinations_json=json.dumps(
                external_destinations
            ),
            authorized_destinations_json=json.dumps(
                authorized_destinations
            ),
            unauthorized_destinations_json=json.dumps(
                unauthorized_destinations
            ),
        )

        event = self.reader._record_to_event(record)

        self.assertEqual(event["processes"], processes)

        self.assertEqual(
            event["external_destinations"],
            external_destinations,
        )

        self.assertEqual(
            event["authorized_destinations"],
            authorized_destinations,
        )

        self.assertEqual(
            event["unauthorized_destinations"],
            unauthorized_destinations,
        )

    def test_record_to_event_preserves_empty_json_lists(self):
        timestamp = datetime(
            2026, 11, 2, 15, 40, 0,
            tzinfo=timezone.utc,
        )

        record = self.make_record(
            timestamp,
            processes_json="[]",
            external_destinations_json="[]",
            authorized_destinations_json="[]",
            unauthorized_destinations_json="[]",
        )

        event = self.reader._record_to_event(record)

        self.assertEqual(event["processes"], [])
        self.assertEqual(event["external_destinations"], [])
        self.assertEqual(event["authorized_destinations"], [])
        self.assertEqual(event["unauthorized_destinations"], [])

    def test_record_to_event_handles_invalid_json(self):
        timestamp = datetime(
            2026, 11, 2, 15, 40, 0,
            tzinfo=timezone.utc,
        )

        record = self.make_record(
            timestamp,
            processes_json="{invalid-json}",
            external_destinations_json="not-json",
        )

        event = self.reader._record_to_event(record)

        self.assertIsNone(event["processes"])
        self.assertIsNone(event["external_destinations"])

    def test_record_to_event_supports_historical_records(self):
        timestamp = datetime(
            2026, 10, 1, 12, 0, 0,
            tzinfo=timezone.utc,
        )

        # Simula un registro histórico que no contiene
        # los campos incorporados posteriormente.
        record = self.make_record(
            timestamp,
            outbound_bytes_interval=12000,
            established_tcp_connections=15,
        )

        event = self.reader._record_to_event(record)

        self.assertEqual(
            event["outbound_bytes_interval"],
            12000,
        )

        self.assertEqual(
            event["established_tcp_connections"],
            15,
        )

        self.assertIsNone(event.get("connections_without_process_attribution"))
        self.assertIsNone(event.get("authorized_connections"))
        self.assertIsNone(event.get("unauthorized_connections"))
        self.assertIsNone(event.get("assessed_external_connections"))

        self.assertIsNone(event.get("processes"))
        self.assertIsNone(event.get("external_destinations"))
        self.assertIsNone(event.get("authorized_destinations"))
        self.assertIsNone(event.get("unauthorized_destinations"))

    def test_record_to_event_preserves_missing_numeric_values(self):
        timestamp = datetime(
            2026, 11, 2, 15, 40, 0,
            tzinfo=timezone.utc,
        )

        record = self.make_record(
            timestamp,
            outbound_bytes_interval=1000,
            established_tcp_connections=5,
        )

        event = self.reader._record_to_event(record)

        self.assertIsNone(
            event.get("connections_without_process_attribution")
        )

        self.assertIsNone(event.get("authorized_connections"))
        self.assertIsNone(event.get("unauthorized_connections"))
        self.assertIsNone(event.get("assessed_external_connections"))

        # Un dato ausente no debe convertirse en cero.
        self.assertNotEqual(
            event.get("unauthorized_connections"),
            0,
        )

    def test_invalid_timestamp_returns_none(self):
        record = self.make_record("invalid-timestamp")

        event = self.reader._record_to_event(record)

        self.assertIsNone(event)

    def test_read_events_returns_chronological_order(self):
        later = datetime(
            2026, 11, 2, 15, 4,
            tzinfo=timezone.utc,
        )

        earlier = datetime(
            2026, 11, 2, 15, 2,
            tzinfo=timezone.utc,
        )

        self.reader.query_api.query.return_value = [
            SimpleNamespace(
                records=[
                    self.make_record(
                        later,
                        outbound_bytes_interval=200,
                    ),
                    self.make_record(
                        earlier,
                        outbound_bytes_interval=100,
                    ),
                ]
            )
        ]

        events = self.reader.read_events(interface="wlo1")

        self.assertEqual(len(events), 2)

        self.assertLess(
            events[0]["timestamp"],
            events[1]["timestamp"],
        )

        self.assertEqual(
            events[0]["outbound_bytes_interval"],
            100,
        )

    @patch("storage.influx_reader.calculate_indicators")
    def test_read_indicators_uses_previous_event(
        self,
        calculate_mock,
    ):
        first = {
            "timestamp": "2026-11-02T15:00:00+00:00",
            "outbound_bytes_interval": 100,
        }

        second = {
            "timestamp": "2026-11-02T15:02:00+00:00",
            "outbound_bytes_interval": 200,
        }

        self.reader.read_events = MagicMock(
            return_value=[first, second]
        )

        calculate_mock.side_effect = [
            {"sample": 1},
            {"sample": 2},
        ]

        indicators = self.reader.read_indicators(
            interface="wlo1"
        )

        self.assertEqual(len(indicators), 2)

        self.assertEqual(
            calculate_mock.call_args_list[0].kwargs["previous"],
            None,
        )

        self.assertEqual(
            calculate_mock.call_args_list[1].kwargs["previous"],
            first,
        )


if __name__ == "__main__":
    unittest.main()