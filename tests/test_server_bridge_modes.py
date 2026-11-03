"""Unit test suite for Server Bridge Modes & Hardened Error Translations (Milestone 3).

Verifies:
1. Production mode (sample_mode=False) with 0 devices returns HTTP 200 with locks: [] and count: 0.
2. Sample mode (sample_mode=True) returns mock devices (lock-101 and lock-102).
3. Centralized _is_sample_mode() resolution across config, engine, and environment variables.
4. Non-existent device ID actuation returns HTTP 404 with clean JSON.
5. Invalid auto_lock_time returns HTTP 400 Bad Request.
6. Backend engine errors translate to clean JSON status codes:
   - Auth error -> 401
   - Safety error -> 403
   - Timeout -> 504
   - ValueError -> 404
   - Connection/Communication error -> 502
7. Outgoing webhook dispatcher resilience on null response and HTTP errors.
"""

from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock, patch

import requests
from flask import Flask

from server.home_assistant import (
    _handle_exec_exception,
    _is_sample_mode,
    _resolve_device,
    dispatch_ha_webhook,
    ha_bp,
)


class CustomAuthException(Exception):
    pass


class CustomSafetyException(Exception):
    pass


class TestServerBridgeModes(unittest.TestCase):
    """Test suite covering server bridge sample vs production mode and error handling."""

    def setUp(self):
        # Create dedicated Flask application instance to avoid cross-test contamination
        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        self.app.config["HA_BEARER_TOKEN"] = "test-secret-bearer-token-1234"
        self.app.config["SAMPLE_MODE"] = False
        self.app.config["STATE_OVERRIDES"] = {}
        self.app.config["AUTO_LOCK_OVERRIDES"] = {}
        self.app.register_blueprint(ha_bp)

        self.client = self.app.test_client()
        self.headers = {
            "Authorization": "Bearer test-secret-bearer-token-1234",
            "Content-Type": "application/json",
        }

    # =========================================================================
    # 1. Sample Mode Helper Resolution (_is_sample_mode)
    # =========================================================================

    def test_is_sample_mode_resolution_hierarchy(self):
        """Verifies precedence hierarchy of _is_sample_mode()."""
        with self.app.app_context():
            # 1. Config SAMPLE_MODE takes top precedence
            self.app.config["SAMPLE_MODE"] = True
            self.assertTrue(_is_sample_mode())
            self.app.config["SAMPLE_MODE"] = False
            self.assertFalse(_is_sample_mode())

            # 2. Config HA_SAMPLE_MODE when SAMPLE_MODE is None
            self.app.config["SAMPLE_MODE"] = None
            self.app.config["HA_SAMPLE_MODE"] = True
            self.assertTrue(_is_sample_mode())
            self.app.config["HA_SAMPLE_MODE"] = False
            self.assertFalse(_is_sample_mode())

            # 3. LOCK_ENGINE.sample_mode when configs are None
            self.app.config["HA_SAMPLE_MODE"] = None
            mock_engine = MagicMock()
            mock_engine.sample_mode = True
            self.app.config["LOCK_ENGINE"] = mock_engine
            self.assertTrue(_is_sample_mode())
            mock_engine.sample_mode = False
            self.assertFalse(_is_sample_mode())

            # 4. Environment variables when config & engine are absent
            self.app.config["LOCK_ENGINE"] = None
            for env_key in ("SAMPLE_MODE", "HA_SAMPLE_MODE", "GEEK_DOOR_SAMPLE_MODE"):
                with patch.dict(os.environ, {env_key: "1"}):
                    self.assertTrue(_is_sample_mode())
                with patch.dict(os.environ, {env_key: "true"}):
                    self.assertTrue(_is_sample_mode())
                with patch.dict(os.environ, {env_key: "yes"}):
                    self.assertTrue(_is_sample_mode())
                with patch.dict(os.environ, {env_key: "0"}):
                    self.assertFalse(_is_sample_mode())
                with patch.dict(os.environ, {env_key: "false"}):
                    self.assertFalse(_is_sample_mode())

            # 5. Default is False
            with patch.dict(os.environ, {}, clear=True):
                self.assertFalse(_is_sample_mode())

    # =========================================================================
    # 2. Production vs Sample Mode Status Discovery (ha_status)
    # =========================================================================

    def test_production_mode_zero_devices_returns_empty_list(self):
        """In production (sample_mode=False), empty inventory returns locks: [] and count: 0."""
        self.app.config["SAMPLE_MODE"] = False
        self.app.config["COLLECT_DEVICES"] = lambda: []

        resp = self.client.get("/api/ha/status", headers=self.headers)
        self.assertEqual(resp.status_code, 200)

        data = resp.get_json()
        self.assertEqual(data.get("service"), "mydoor")
        self.assertEqual(data.get("status"), "healthy")
        self.assertEqual(data.get("locks"), [])
        self.assertEqual(data.get("count"), 0)

        # Confirm mock locks lock-101 and lock-102 are NOT present
        lock_ids = [l.get("device_id") for l in data.get("locks", [])]
        self.assertNotIn("lock-101", lock_ids)
        self.assertNotIn("lock-102", lock_ids)

    def test_sample_mode_returns_mock_devices(self):
        """In sample mode (sample_mode=True), empty inventory returns lock-101 and lock-102."""
        self.app.config["SAMPLE_MODE"] = True
        self.app.config["COLLECT_DEVICES"] = lambda: []

        resp = self.client.get("/api/ha/status", headers=self.headers)
        self.assertEqual(resp.status_code, 200)

        data = resp.get_json()
        self.assertEqual(data.get("service"), "mydoor")
        self.assertEqual(data.get("count"), 2)

        locks = data.get("locks", [])
        self.assertEqual(len(locks), 2)
        lock_ids = [l.get("device_id") for l in locks]
        self.assertIn("lock-101", lock_ids)
        self.assertIn("lock-102", lock_ids)

    def test_production_mode_with_real_discovered_devices(self):
        """In production, real devices returned by collect_fn are properly formatted."""
        self.app.config["SAMPLE_MODE"] = False
        real_device = {
            "id": 501,
            "devId": "lock-501",
            "name": "Front Porch Door",
            "isLock": True,
            "isOnline": True,
            "state": "LOCKED",
            "battery": 92,
            "autoLockEnabled": True,
            "autoLockSeconds": 10,
            "hardwareModel": "K02",
        }
        self.app.config["COLLECT_DEVICES"] = lambda: [real_device]

        resp = self.client.get("/api/ha/status", headers=self.headers)
        self.assertEqual(resp.status_code, 200)

        data = resp.get_json()
        self.assertEqual(data.get("count"), 1)
        lock = data["locks"][0]
        self.assertEqual(lock["device_id"], "lock-501")
        self.assertEqual(lock["name"], "Front Porch Door")
        self.assertEqual(lock["state"], "locked")
        self.assertEqual(lock["battery"], 92)

    # =========================================================================
    # 3. Device State Resolution & 404 for Non-Existent Devices
    # =========================================================================

    def test_device_state_lookup_production_vs_sample(self):
        """GET /api/ha/lock/<dev_id>/state returns 404 in production vs 200 in sample mode."""
        # 1. In production mode (sample_mode=False) with no hardware discovered -> 404
        self.app.config["SAMPLE_MODE"] = False
        resp_prod = self.client.get("/api/ha/lock/lock-101/state", headers=self.headers)
        self.assertEqual(resp_prod.status_code, 404)
        data_prod = resp_prod.get_json()
        self.assertFalse(data_prod.get("success", True))
        self.assertIn("not found", data_prod.get("error", "").lower())

        # 2. In sample mode (sample_mode=True) -> 200 with mock lock topology
        self.app.config["SAMPLE_MODE"] = True
        resp_sample = self.client.get("/api/ha/lock/lock-101/state", headers=self.headers)
        self.assertEqual(resp_sample.status_code, 200)
        data_sample = resp_sample.get_json()
        self.assertEqual(data_sample["device_id"], "lock-101")
        self.assertEqual(data_sample["name"], "Living Room Door")
        self.assertTrue(data_sample["is_locked"])

    def test_nonexistent_device_id_actuation_returns_404(self):
        """Actuation endpoints on non-existent devices return HTTP 404 clean JSON when exec_fn is None."""
        self.app.config["SAMPLE_MODE"] = False
        bad_id = "nonexistent-lock-9999"

        routes = [
            f"/api/ha/lock/{bad_id}/lock",
            f"/api/ha/lock/{bad_id}/unlock",
            f"/api/ha/lock/{bad_id}/keep_unlocked",
            f"/api/ha/lock/{bad_id}/auto_lock",
        ]

        for route in routes:
            resp = self.client.post(
                route,
                headers=self.headers,
                json={"dry_run": True, "confirmed": True},
            )
            self.assertEqual(
                resp.status_code,
                404,
                f"Expected HTTP 404 for {route}, got {resp.status_code}",
            )
            data = resp.get_json()
            self.assertFalse(data.get("success", True))
            self.assertIn("not found", data.get("error", "").lower())

    # =========================================================================
    # 4. Invalid auto_lock_time Rejection (HTTP 400 Bad Request)
    # =========================================================================

    def test_invalid_auto_lock_time_returns_400(self):
        """Invalid non-integer auto_lock_time values are rejected with clean HTTP 400."""
        self.app.config["SAMPLE_MODE"] = True  # Enable sample mode so lock-101 is resolved

        invalid_payloads = [
            {"auto_lock_time": "invalid_str"},
            {"auto_lock_time": "ten"},
            {"auto_lock_time": [5, 10]},
            {"auto_lock_time": {"seconds": 5}},
        ]

        for payload in invalid_payloads:
            payload["dry_run"] = True
            resp = self.client.post(
                "/api/ha/lock/lock-101/auto_lock",
                headers=self.headers,
                json=payload,
            )
            self.assertEqual(
                resp.status_code,
                400,
                f"Expected HTTP 400 for payload {payload}, got {resp.status_code}",
            )
            data = resp.get_json()
            self.assertFalse(data.get("success", True))
            self.assertIn("auto_lock_time", data.get("error", "").lower())

    # =========================================================================
    # 5. Backend Engine Error Translation
    # =========================================================================

    def test_backend_error_translations(self):
        """Verifies exec_fn exceptions are translated into clean JSON HTTP status codes."""
        self.app.config["SAMPLE_MODE"] = True  # So lock-101 resolves

        test_cases = [
            (requests.exceptions.Timeout("Connection timeout to gateway"), 504),
            (TimeoutError("Async BLE connection timeout"), 504),
            (ConnectionError("Tuya cloud service unreachable"), 502),
            (CustomAuthException("Tuya token expired / invalid"), 401),
            (CustomSafetyException("Action blocked by Safety Barrier"), 403),
            (ValueError("Device identifier unmapped"), 404),
        ]

        for exc, expected_code in test_cases:
            def failing_exec(*args, **kwargs):
                raise exc

            self.app.config["EXECUTE_DEVICE_ACTION"] = failing_exec

            resp = self.client.post(
                "/api/ha/lock/lock-101/lock",
                headers=self.headers,
                json={"dry_run": True, "confirmed": True},
            )
            self.assertEqual(
                resp.status_code,
                expected_code,
                f"Exception {exc!r} expected HTTP {expected_code}, got {resp.status_code}",
            )
            data = resp.get_json()
            self.assertFalse(data.get("success", True))
            self.assertTrue(len(data.get("error", "")) > 0)

    # =========================================================================
    # 6. Outgoing Webhook Safe Dispatch
    # =========================================================================

    def test_outgoing_webhook_safe_dispatch_on_null_and_error(self):
        """dispatch_ha_webhook handles null response and HTTP errors safely without unhandled crashes."""
        with patch("requests.post", return_value=None):
            # Must not raise AttributeError: 'NoneType' object has no attribute 'status_code'
            t = dispatch_ha_webhook({"action": "locked"}, "http://ha.local:8123/api/webhook/test")
            t.join(timeout=1.0)
            self.assertFalse(t.is_alive())

        mock_err_resp = MagicMock()
        mock_err_resp.status_code = 502
        mock_err_resp.text = "Bad Gateway"
        with patch("requests.post", return_value=mock_err_resp):
            t2 = dispatch_ha_webhook({"action": "unlocked"}, "http://ha.local:8123/api/webhook/test")
            t2.join(timeout=1.0)
            self.assertFalse(t2.is_alive())

    # =========================================================================
    # 7. Unauthenticated Requests Rejected
    # =========================================================================

    def test_unauthenticated_requests_strictly_rejected_401(self):
        """Requests without Authorization or with invalid tokens return HTTP 401."""
        resp1 = self.client.get("/api/ha/status")
        self.assertEqual(resp1.status_code, 401)

        resp2 = self.client.get(
            "/api/ha/status",
            headers={"Authorization": "Bearer totally-wrong-token"},
        )
        self.assertEqual(resp2.status_code, 401)


if __name__ == "__main__":
    unittest.main()
