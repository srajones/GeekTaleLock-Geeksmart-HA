#!/usr/bin/env python3
"""Adversarial boundary stress test suite for Home Assistant Milestone 3 Iteration 2.

Exhaustively verifies parameter validation on:
- /api/ha/lock/<dev_id>/auto_lock (ha_auto_lock_device)
- /api/ha/lock/<dev_id>/unlock (ha_unlock_device)
- /api/ha/lock/<dev_id>/keep_unlocked (ha_keep_unlocked_device)
- /api/ha/lock/<dev_id>/lock (ha_lock_device)
- /api/ha/webhook (ha_incoming_webhook)

Tested Boundary Values:
- Negative integers & strings: -99, "-99", -1, "-1"
- Zero values: 0, "0", "0.0"
- Non-integer floats & strings: 5.5, "5.5"
- Null/None values: None
- Python booleans: True, False (must not coerce to int 1 or 0)
- String booleans: "true", "false"
- Empty containers: [], {}
- Missing parameters (strictly defaults to 5 for auto_lock, None for others)
"""

from __future__ import annotations

import unittest
from typing import Any, Dict, List
from unittest.mock import MagicMock

from flask import Flask

from server.home_assistant import ha_bp


class BaseEndpointTest(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        self.app.config["HA_BEARER_TOKEN"] = "adversarial-test-token"
        self.app.config["HA_WEBHOOK_SECRET"] = "adversarial-webhook-secret"
        self.app.config["SAMPLE_MODE"] = True  # Enable sample mode so lock-101 resolves
        self.app.config["STATE_OVERRIDES"] = {}
        self.app.config["AUTO_LOCK_OVERRIDES"] = {}
        self.app.register_blueprint(ha_bp)
        self.client = self.app.test_client()
        self.headers = {
            "Authorization": "Bearer adversarial-test-token",
            "Content-Type": "application/json",
        }
        self.webhook_headers = {
            "X-HA-Webhook-Secret": "adversarial-webhook-secret",
            "Content-Type": "application/json",
        }


class TestAutoLockEndpointAdversarial(BaseEndpointTest):
    """Stress tests for /api/ha/lock/<dev_id>/auto_lock."""

    BOUNDARY_INVALID_VALUES: List[Any] = [
        -99,
        "-99",
        -1,
        "-1",
        0,
        "0",
        "0.0",
        5.5,
        "5.5",
        None,
        True,
        False,
        "true",
        "false",
        [],
        {},
    ]

    def test_auto_lock_time_boundary_values_rejected_400(self):
        """All requested boundary values for auto_lock_time must return HTTP 400 Bad Request."""
        for val in self.BOUNDARY_INVALID_VALUES:
            for key in ("auto_lock_time", "autoLockTime", "auto_lock_seconds"):
                payload = {key: val, "dry_run": True, "confirmed": True}
                resp = self.client.post(
                    "/api/ha/lock/lock-101/auto_lock",
                    headers=self.headers,
                    json=payload,
                )
                self.assertEqual(
                    resp.status_code,
                    400,
                    f"Expected HTTP 400 for auto_lock key='{key}' with value={val!r}, got {resp.status_code}. Data: {resp.data}",
                )
                data = resp.get_json()
                self.assertFalse(data.get("success", True))
                self.assertIn("auto_lock_time", data.get("error", "").lower())

    def test_auto_lock_missing_time_defaults_to_5(self):
        """Missing auto_lock_time key defaults to 5 seconds and succeeds with HTTP 200."""
        recorded_args = {}

        def mock_exec(dev_id, action, **kwargs):
            recorded_args.update(kwargs)
            return {"success": True}, 200

        self.app.config["EXECUTE_DEVICE_ACTION"] = mock_exec

        payload = {"dry_run": True, "confirmed": True, "enabled": True}
        resp = self.client.post(
            "/api/ha/lock/lock-101/auto_lock",
            headers=self.headers,
            json=payload,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(recorded_args.get("auto_lock_time"), 5)

    def test_auto_lock_valid_positive_values_accepted(self):
        """Valid positive values (5, '5', 10, '10', 5.0) are accepted with HTTP 200."""
        valid_cases = [5, "5", 10, "10", 1, 60, 5.0]
        for val in valid_cases:
            recorded_args = {}

            def mock_exec(dev_id, action, **kwargs):
                recorded_args.update(kwargs)
                return {"success": True}, 200

            self.app.config["EXECUTE_DEVICE_ACTION"] = mock_exec

            payload = {"auto_lock_time": val, "dry_run": True, "confirmed": True}
            resp = self.client.post(
                "/api/ha/lock/lock-101/auto_lock",
                headers=self.headers,
                json=payload,
            )
            self.assertEqual(
                resp.status_code,
                200,
                f"Expected HTTP 200 for valid auto_lock_time={val!r}, got {resp.status_code}. Data: {resp.data}",
            )
            self.assertEqual(recorded_args.get("auto_lock_time"), int(val))

    def test_auto_lock_enabled_boolean_boundaries(self):
        """'enabled' rejects malformed types (null, list, dict, invalid string) with HTTP 400."""
        invalid_enabled = [None, [], {}, "invalid", -99, 123]
        for val in invalid_enabled:
            payload = {"enabled": val, "dry_run": True}
            resp = self.client.post(
                "/api/ha/lock/lock-101/auto_lock",
                headers=self.headers,
                json=payload,
            )
            self.assertEqual(
                resp.status_code,
                400,
                f"Expected HTTP 400 for enabled={val!r}, got {resp.status_code}",
            )


class TestUnlockEndpointAdversarial(BaseEndpointTest):
    """Stress tests for /api/ha/lock/<dev_id>/unlock."""

    BOUNDARY_INVALID_VALUES: List[Any] = [
        -99,
        "-99",
        -1,
        "-1",
        0,
        "0",
        "0.0",
        5.5,
        "5.5",
        None,
        True,
        False,
        "true",
        "false",
        [],
        {},
    ]

    def test_unlock_seconds_boundary_values_rejected_400(self):
        """All requested boundary values for seconds must return HTTP 400 Bad Request."""
        for val in self.BOUNDARY_INVALID_VALUES:
            for key in ("seconds", "auto_lock_seconds", "auto_lock_time", "autoLockTime", "duration"):
                payload = {key: val, "dry_run": True, "confirmed": True}
                resp = self.client.post(
                    "/api/ha/lock/lock-101/unlock",
                    headers=self.headers,
                    json=payload,
                )
                self.assertEqual(
                    resp.status_code,
                    400,
                    f"Expected HTTP 400 for unlock key='{key}' with value={val!r}, got {resp.status_code}. Data: {resp.data}",
                )
                data = resp.get_json()
                self.assertFalse(data.get("success", True))
                self.assertIn("seconds", data.get("error", "").lower())

    def test_unlock_missing_seconds_succeeds_without_seconds_in_response(self):
        """Missing seconds key succeeds with HTTP 200 and omits 'seconds' from response."""
        resp = self.client.post(
            "/api/ha/lock/lock-101/unlock",
            headers=self.headers,
            json={"dry_run": True, "confirmed": True},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("success"))
        self.assertNotIn("seconds", data)

    def test_unlock_valid_seconds_forwarded_and_returned(self):
        """Valid positive seconds are forwarded to exec_fn and returned in JSON response."""
        recorded_args = {}

        def mock_exec(dev_id, action, **kwargs):
            recorded_args.update(kwargs)
            return {"success": True}, 200

        self.app.config["EXECUTE_DEVICE_ACTION"] = mock_exec

        resp = self.client.post(
            "/api/ha/lock/lock-101/unlock",
            headers=self.headers,
            json={"seconds": 15, "dry_run": True, "confirmed": True},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("seconds"), 15)
        self.assertEqual(recorded_args.get("auto_lock_time"), 15)


class TestKeepUnlockedEndpointAdversarial(BaseEndpointTest):
    """Stress tests for /api/ha/lock/<dev_id>/keep_unlocked."""

    BOUNDARY_INVALID_VALUES: List[Any] = [
        -99,
        "-99",
        -1,
        "-1",
        0,
        "0",
        "0.0",
        5.5,
        "5.5",
        None,
        True,
        False,
        "true",
        "false",
        [],
        {},
    ]

    def test_keep_unlocked_duration_boundary_values_rejected_400(self):
        """All requested boundary values for duration must return HTTP 400 Bad Request."""
        for val in self.BOUNDARY_INVALID_VALUES:
            for key in ("duration", "duration_seconds", "seconds"):
                payload = {key: val, "dry_run": True, "confirmed": True}
                resp = self.client.post(
                    "/api/ha/lock/lock-101/keep_unlocked",
                    headers=self.headers,
                    json=payload,
                )
                self.assertEqual(
                    resp.status_code,
                    400,
                    f"Expected HTTP 400 for keep_unlocked key='{key}' with value={val!r}, got {resp.status_code}. Data: {resp.data}",
                )
                data = resp.get_json()
                self.assertFalse(data.get("success", True))
                self.assertIn("duration", data.get("error", "").lower())

    def test_keep_unlocked_missing_duration_succeeds(self):
        """Missing duration key succeeds with HTTP 200 and omits 'duration_seconds' from response."""
        resp = self.client.post(
            "/api/ha/lock/lock-101/keep_unlocked",
            headers=self.headers,
            json={"dry_run": True, "confirmed": True},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("success"))
        self.assertNotIn("duration_seconds", data)

    def test_keep_unlocked_valid_duration_forwarded_and_returned(self):
        """Valid positive duration is forwarded to exec_fn and returned in JSON response."""
        recorded_args = {}

        def mock_exec(dev_id, action, **kwargs):
            recorded_args.update(kwargs)
            return {"success": True}, 200

        self.app.config["EXECUTE_DEVICE_ACTION"] = mock_exec

        resp = self.client.post(
            "/api/ha/lock/lock-101/keep_unlocked",
            headers=self.headers,
            json={"duration_seconds": 120, "dry_run": True, "confirmed": True},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("duration_seconds"), 120)
        self.assertEqual(recorded_args.get("auto_lock_time"), 120)


class TestLockEndpointAdversarial(BaseEndpointTest):
    """Stress tests for /api/ha/lock/<dev_id>/lock."""

    def test_lock_dry_run_and_confirmed_boundary_values(self):
        """Rejects malformed dry_run or confirmed types with HTTP 400."""
        invalid_values = [None, [], {}, "invalid", -99, 123]
        for val in invalid_values:
            resp1 = self.client.post(
                "/api/ha/lock/lock-101/lock",
                headers=self.headers,
                json={"dry_run": val},
            )
            self.assertEqual(
                resp1.status_code,
                400,
                f"Expected HTTP 400 for dry_run={val!r}, got {resp1.status_code}",
            )

            resp2 = self.client.post(
                "/api/ha/lock/lock-101/lock",
                headers=self.headers,
                json={"confirmed": val},
            )
            self.assertEqual(
                resp2.status_code,
                400,
                f"Expected HTTP 400 for confirmed={val!r}, got {resp2.status_code}",
            )

    def test_lock_valid_booleans_accepted(self):
        """Accepts valid boolean representations (True, False, 'true', 'false', '1', '0', 'yes', 'no')."""
        valid_pairs = [
            (True, True),
            (False, True),
            ("true", "true"),
            ("false", "false"),
            ("1", "0"),
            ("yes", "no"),
        ]
        for dry, conf in valid_pairs:
            resp = self.client.post(
                "/api/ha/lock/lock-101/lock",
                headers=self.headers,
                json={"dry_run": dry, "confirmed": conf},
            )
            self.assertEqual(
                resp.status_code,
                200,
                f"Expected HTTP 200 for dry_run={dry!r}, confirmed={conf!r}, got {resp.status_code}",
            )


class TestIncomingWebhookEndpointAdversarial(BaseEndpointTest):
    """Stress tests for /api/ha/webhook."""

    BOUNDARY_INVALID_VALUES: List[Any] = [
        -99,
        "-99",
        -1,
        "-1",
        0,
        "0",
        "0.0",
        5.5,
        "5.5",
        None,
        True,
        False,
        "true",
        "false",
        [],
        {},
    ]

    def test_webhook_secret_validation(self):
        """Rejects requests without valid webhook secret with HTTP 403."""
        resp = self.client.post(
            "/api/ha/webhook",
            headers={"Content-Type": "application/json"},
            json={"action": "lock"},
        )
        self.assertEqual(resp.status_code, 403)

        resp_bad = self.client.post(
            "/api/ha/webhook",
            headers={
                "X-HA-Webhook-Secret": "wrong-secret",
                "Content-Type": "application/json",
            },
            json={"action": "lock"},
        )
        self.assertEqual(resp_bad.status_code, 403)

    def test_webhook_auto_lock_time_boundary_values_rejected_400(self):
        """All requested boundary values for auto_lock_time on webhook must return HTTP 400 Bad Request."""
        for val in self.BOUNDARY_INVALID_VALUES:
            for key in ("auto_lock_time", "autoLockTime", "auto_lock_seconds", "seconds", "duration"):
                payload = {
                    "action": "lock",
                    "device_id": "lock-101",
                    key: val,
                    "dry_run": True,
                }
                resp = self.client.post(
                    "/api/ha/webhook",
                    headers=self.webhook_headers,
                    json=payload,
                )
                self.assertEqual(
                    resp.status_code,
                    400,
                    f"Expected HTTP 400 for webhook key='{key}' with value={val!r}, got {resp.status_code}. Data: {resp.data}",
                )
                data = resp.get_json()
                self.assertFalse(data.get("success", True))
                self.assertIn("auto_lock_time", data.get("error", "").lower())

    def test_webhook_missing_auto_lock_time_succeeds(self):
        """Missing auto_lock_time on webhook succeeds with HTTP 200."""
        payload = {
            "action": "lock",
            "device_id": "lock-101",
            "dry_run": True,
        }
        resp = self.client.post(
            "/api/ha/webhook",
            headers=self.webhook_headers,
            json=payload,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("success"))

    def test_webhook_valid_auto_lock_time_forwarded(self):
        """Valid positive auto_lock_time on webhook is forwarded to exec_fn."""
        recorded_args = {}

        def mock_exec(**kwargs):
            recorded_args.update(kwargs)
            return {"success": True}, 200

        self.app.config["EXECUTE_DEVICE_ACTION"] = mock_exec

        payload = {
            "action": "unlock",
            "device_id": "lock-101",
            "auto_lock_time": 25,
            "dry_run": True,
        }
        resp = self.client.post(
            "/api/ha/webhook",
            headers=self.webhook_headers,
            json=payload,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(recorded_args.get("auto_lock_time"), 25)


if __name__ == "__main__":
    unittest.main()
