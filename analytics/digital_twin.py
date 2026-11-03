"""Digital Twin engine for Outbound Sentinel.

Compares expected device configuration with observed telemetry.
It does not block connections or infer malicious intent.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DigitalTwinError(Exception):
    """Raised when the Digital Twin configuration is invalid."""


class DigitalTwin:
    """Evaluate observed telemetry against the configured digital twin."""

    def __init__(
        self,
        devices_file: str | Path | None = None,
        config_file: str | Path | None = None,
    ) -> None:
        self.devices_file = (
            Path(devices_file)
            if devices_file
            else PROJECT_ROOT / "config" / "devices.yaml"
        )
        self.config_file = (
            Path(config_file)
            if config_file
            else PROJECT_ROOT / "config" / "digital_twin.yaml"
        )

        self.devices_config = self._load_yaml(self.devices_file)
        self.config = self._load_yaml(self.config_file)

        self.devices = self.devices_config.get("devices", [])
        self.twin_config = self.config.get("digital_twin", {})

        if not isinstance(self.devices, list):
            raise DigitalTwinError("'devices' must be a list")

        if not isinstance(self.twin_config, dict):
            raise DigitalTwinError("'digital_twin' must be a mapping")

        self._validate_devices()

    @staticmethod
    def _load_yaml(path: Path) -> dict[str, Any]:
        """Load a YAML file and validate its root structure."""
        if not path.exists():
            raise DigitalTwinError(f"Configuration file not found: {path}")

        try:
            with path.open("r", encoding="utf-8") as file:
                data = yaml.safe_load(file)
        except yaml.YAMLError as exc:
            raise DigitalTwinError(
                f"Invalid YAML in {path}: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise DigitalTwinError(
                f"Invalid YAML root in {path}: expected mapping"
            )

        return data

    def _validate_devices(self) -> None:
        """Ensure every configured device has a unique identifier."""
        identifiers = []

        for device in self.devices:
            if not isinstance(device, dict):
                raise DigitalTwinError(
                    "Each device configuration must be a mapping"
                )

            device_id = device.get("device_id")

            if not isinstance(device_id, str) or not device_id.strip():
                raise DigitalTwinError(
                    "Every device must have a valid device_id"
                )

            identifiers.append(device_id)

        if len(identifiers) != len(set(identifiers)):
            raise DigitalTwinError(
                "Duplicate device_id found in devices.yaml"
            )

    def get_device(self, device_id: str) -> dict[str, Any] | None:
        """Return a device configuration by identifier."""
        for device in self.devices:
            if device.get("device_id") == device_id:
                return device
        return None

    def _get_device_twin_config(
        self,
        device: dict[str, Any],
    ) -> dict[str, Any]:
        """Return the device-specific Digital Twin configuration."""
        device_id = device["device_id"]

        for section in self.twin_config.values():
            if (
                isinstance(section, dict)
                and section.get("device_id") == device_id
            ):
                return section

        return {}

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime | None:
        """Parse an ISO-8601 timestamp. Naive timestamps are rejected."""
        if not isinstance(value, str) or not value.strip():
            return None

        try:
            timestamp = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError:
            return None

        if timestamp.tzinfo is None:
            return None

        return timestamp.astimezone(timezone.utc)

    def _status(self, name: str) -> str:
        status_config = self.twin_config.get("status", {})
        return status_config.get(name, name)

    def _validate_telemetry(
        self,
        event: dict[str, Any],
        device: dict[str, Any],
        now: datetime,
    ) -> tuple[str | None, dict[str, Any]]:
        """Validate telemetry origin, timestamp and freshness."""
        quality_config = self.twin_config.get("data_quality", {})
        timestamp = self._parse_timestamp(event.get("timestamp"))

        details: dict[str, Any] = {
            "timestamp_valid": timestamp is not None,
            "data_origin": event.get("data_origin"),
            "age_seconds": None,
        }

        if (
            quality_config.get("require_timestamp", True)
            and timestamp is None
        ):
            return (
                "Missing or invalid timezone-aware timestamp",
                details,
            )

        if timestamp is not None:
            age = (now - timestamp).total_seconds()
            details["age_seconds"] = round(age, 2)

            if age < 0:
                return "Telemetry timestamp is in the future", details

            max_age = quality_config.get(
                "max_telemetry_age_seconds",
                360,
            )

            if age > max_age:
                return "Telemetry is stale", details

        expected_origin = device.get("data_origin")
        actual_origin = event.get("data_origin")

        if quality_config.get("require_data_origin", True):
            if actual_origin is None:
                return "Missing data_origin", details

            if actual_origin != expected_origin:
                return (
                    f"Unexpected data_origin: expected {expected_origin}, "
                    f"received {actual_origin}",
                    details,
                )

        return None, details

    def _evaluate_security_policy(
        self,
        anomaly_detection: dict[str, Any] | None,
    ) -> tuple[dict[str, Any], list[str]]:
        """Map the AnomalyDetector policy result to a Twin dimension.

        This method does not independently classify destinations.
        The AnomalyDetector is the single source of policy evaluation.
        """
        issues: list[str] = []

        unknown_result = {
            "status": self._status("unknown"),
            "enabled": None,
            "evaluation_status": "not_available",
            "reason": "Policy compliance result is missing or invalid",
            "unauthorized_connections": None,
            "assessed_external_connections": None,
            "automatic_blocking": False,
        }

        if not isinstance(anomaly_detection, dict):
            return unknown_result, issues

        compliance = anomaly_detection.get("policy_compliance")

        if not isinstance(compliance, dict):
            return unknown_result, issues

        compliance_status = compliance.get("status")
        policy_enabled = compliance.get("policy_enabled")

        unauthorized = compliance.get("unauthorized_connections")
        assessed = compliance.get("assessed_external_connections")

        status_mapping = {
            "not_evaluated": "unknown",
            "insufficient_data": "unknown",
            "compliant": "normal",
            "policy_violation": "critical",
        }

        mapped_status = status_mapping.get(compliance_status, "unknown")

        if mapped_status == "critical":
            issues.append("Security policy violation detected")

        reason_mapping = {
            "not_evaluated": (
                "Security policy evaluation is disabled or unavailable"
            ),
            "insufficient_data": (
                "Insufficient information to evaluate security policy"
            ),
            "compliant": (
                "No unauthorized connections detected in assessed traffic"
            ),
            "policy_violation": (
                "Unauthorized connections detected by policy evaluation"
            ),
        }

        reason = compliance.get("reason")

        if not isinstance(reason, str) or not reason:
            reason = reason_mapping.get(
                compliance_status,
                "Policy compliance result is unknown",
            )

        result = {
            "status": self._status(mapped_status),
            "enabled": policy_enabled,
            "evaluation_status": compliance_status,
            "reason": reason,
            "unauthorized_connections": unauthorized,
            "assessed_external_connections": assessed,
            "automatic_blocking": False,
        }

        return result, issues

    def _evaluate_gateway(
        self,
        event: dict[str, Any],
        device: dict[str, Any],
        twin_config: dict[str, Any],
        anomaly_detection: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Evaluate gateway availability, network, policy and behavior."""
        results: dict[str, Any] = {}
        issues: list[str] = []

        # Availability
        availability_config = twin_config.get("availability", {})
        expected_available = availability_config.get("expected", True)
        actual_available = event.get("available")

        if actual_available is None:
            availability_status = self._status("unknown")
        elif not isinstance(actual_available, bool):
            availability_status = self._status("unknown")
        elif actual_available == expected_available:
            availability_status = self._status("normal")
        else:
            availability_status = self._status("unavailable")
            issues.append(
                "Gateway availability differs from expected state"
            )

        results["availability"] = {
            "status": availability_status,
            "expected": expected_available,
            "observed": actual_available,
        }

        # Network telemetry
        network_config = twin_config.get("network", {})
        network_metrics = network_config.get("metrics", [])

        observed_metrics: dict[str, Any] = {}
        missing_metrics: list[str] = []

        for metric in network_metrics:
            value = event.get(metric)
            observed_metrics[metric] = value

            if value is None:
                missing_metrics.append(metric)

        if not network_metrics:
            network_status = self._status("unknown")
        elif len(missing_metrics) == len(network_metrics):
            network_status = self._status("unknown")
        elif missing_metrics:
            network_status = self._status("warning")
            issues.append("Some configured network metrics are missing")
        else:
            network_status = self._status("normal")

        results["network"] = {
            "status": network_status,
            "metrics": observed_metrics,
            "missing_metrics": missing_metrics,
        }

        # Security policy: single source of truth is AnomalyDetector.
        policy_result, policy_issues = self._evaluate_security_policy(
            anomaly_detection
        )

        results["security_policy"] = policy_result
        issues.extend(policy_issues)

        # Traffic behavior
        behavior_config = twin_config.get("traffic_behavior", {})
        behavior_enabled = behavior_config.get(
            "anomaly_detection_enabled",
            False,
        )

        if not behavior_enabled:
            behavior_status = self._status("unknown")
            behavior_reason = "Traffic anomaly detection is disabled"
        elif anomaly_detection is None:
            behavior_status = self._status("unknown")
            behavior_reason = (
                "No anomaly detection result was provided"
            )
        elif not isinstance(anomaly_detection, dict):
            behavior_status = self._status("unknown")
            behavior_reason = "Invalid anomaly detection result"
        else:
            detection_status = anomaly_detection.get("overall_status")

            if detection_status == "potential_anomaly":
                behavior_status = self._status("warning")
                behavior_reason = "Potential traffic anomaly detected"
                issues.append("Potential traffic anomaly detected")
            elif detection_status == "no_anomaly_detected":
                behavior_status = self._status("normal")
                behavior_reason = "No traffic anomaly detected"
            else:
                behavior_status = self._status("unknown")
                behavior_reason = (
                    "Insufficient information for behavior evaluation"
                )

        results["traffic_behavior"] = {
            "status": behavior_status,
            "reason": behavior_reason,
            "anomaly_detection_enabled": behavior_enabled,
        }

        return {
            "dimensions": results,
            "issues": issues,
        }

    def evaluate(
        self,
        event: dict[str, Any],
        anomaly_detection: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Evaluate one telemetry event and return its Digital Twin state."""
        if not isinstance(event, dict):
            raise TypeError("event must be a dictionary")

        device_id = event.get("device_id")
        evaluated_at = now or datetime.now(timezone.utc)

        if (
            not isinstance(evaluated_at, datetime)
            or evaluated_at.tzinfo is None
        ):
            raise ValueError("now must be a timezone-aware datetime")

        evaluated_at = evaluated_at.astimezone(timezone.utc)

        base_result = {
            "device_id": device_id,
            "evaluated_at": evaluated_at.isoformat(),
            "data_origin": event.get("data_origin"),
        }

        if not isinstance(device_id, str) or not device_id.strip():
            return {
                **base_result,
                "status": self._status("unknown"),
                "reason": "Missing or invalid device_id",
                "dimensions": {},
                "issues": ["Missing or invalid device_id"],
            }

        device = self.get_device(device_id)

        if device is None:
            return {
                **base_result,
                "status": self._status("unknown"),
                "reason": "Device is not registered",
                "dimensions": {},
                "issues": ["Unknown device"],
            }

        if not device.get("enabled", True):
            return {
                **base_result,
                "status": self._status("unavailable"),
                "reason": "Device is disabled in configuration",
                "dimensions": {},
                "issues": ["Device disabled"],
            }

        if not self.twin_config.get("enabled", True):
            return {
                **base_result,
                "status": self._status("unknown"),
                "reason": "Digital Twin is disabled",
                "dimensions": {},
                "issues": [],
            }

        validation_error, quality_details = self._validate_telemetry(
            event,
            device,
            evaluated_at,
        )

        if validation_error:
            return {
                **base_result,
                "status": self._status("unknown"),
                "reason": validation_error,
                "data_quality": quality_details,
                "dimensions": {},
                "issues": [validation_error],
            }

        twin_config = self._get_device_twin_config(device)

        if device.get("device_type") == "network_gateway":
            evaluation = self._evaluate_gateway(
                event,
                device,
                twin_config,
                anomaly_detection,
            )
        else:
            evaluation = {
                "dimensions": {
                    "availability": {
                        "status": self._status("unknown"),
                        "reason": (
                            "Operational evaluation is not implemented "
                            "for this device type yet"
                        ),
                    }
                },
                "issues": [],
            }

        dimension_statuses = [
            item.get("status")
            for item in evaluation["dimensions"].values()
        ]

        if self._status("critical") in dimension_statuses:
            overall_status = self._status("critical")
        elif self._status("unavailable") in dimension_statuses:
            overall_status = self._status("unavailable")
        elif self._status("warning") in dimension_statuses:
            overall_status = self._status("warning")
        elif dimension_statuses and all(
            status == self._status("normal")
            for status in dimension_statuses
        ):
            overall_status = self._status("normal")
        else:
            overall_status = self._status("unknown")

        return {
            **base_result,
            "status": overall_status,
            "reason": "Digital Twin evaluation completed",
            "data_quality": quality_details,
            "dimensions": evaluation["dimensions"],
            "issues": evaluation["issues"],
        }

    @staticmethod
    def to_json(
        result: dict[str, Any],
        indent: int = 2,
    ) -> str:
        """Serialize an evaluation result as JSON."""
        return json.dumps(
            result,
            indent=indent,
            ensure_ascii=False,
            default=str,
        )