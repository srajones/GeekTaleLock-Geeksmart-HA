#!/usr/bin/env python3
"""Empirical Challenger Test Suite for Milestone 3 (tests/test_challenger_ha_m3_1.py).

Adversarially stress-tests server/home_assistant.py:
1. Production vs. sample mode separation:
   - Prove that when sample_mode=False and device collection is empty, ha_status NEVER returns mock devices lock-101 or lock-102.
   - Verify that when sample_mode=True, mock devices are returned properly.
   - Verify device state lookup in production mode (404) vs sample mode (200).
2. Nonexistent and randomized device IDs across lock, unlock, keep_unlocked, auto_lock:
   - Verify HTTP 404 with clean JSON, zero unhandled 500 crashes.
3. Mock backend engine exceptions (Auth errors, Timeout errors, Connection errors, Safety errors, Value errors):
   - Verify clean HTTP 401, 504, 502, 403, 404 status codes across all actuation endpoints.
4. Auto-lock payload validation:
   - Non-integer auto_lock_time strings ("invalid", "-99", "", null, [], {}) across /api/ha/lock/<id>/auto_lock:
     Verify HTTP 400 Bad Request with clean JSON, zero unhandled 500 crashes.
"""

from __future__ import annotations

import os
import unittest
import uuid
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import requests
from flask import Flask

from server.home_assistant import (
    _handle_exec_exception,
    _is_sample_mode,
    _resolve_device,
    ha_bp,
)


class CustomAuthError(Exception):
    pass


class CustomConfigEntryAuthFailed(Exception):
    pass


class CustomSafetyViolation(Exception):
    pass


class CustomConnectionError(Exception):
    pass


class TestProductionVsSampleModeSeparation(unittest.TestCase):
    """Stress-test production vs. sample mode separation in server/home_assistant.py."""

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        self.app.config["HA_BEARER_TOKEN"] = "test-token-ha-challenger-m3"
        self.app.config["STATE_OVERRIDES"] = {}
        self.app.config["AUTO_LOCK_OVERRIDES"] = {}
        self.app.register_blueprint(ha_bp)
        self.client = self.app.test_client()
        self.headers = {
            "Authorization": "Bearer test-token-ha-challenger-m3",
            "Content-Type": "application/json",
        }

    def test_production_mode_empty_collection_never_returns_mock_devices(self):
        """In production (sample_mode=False), ha_status NEVER returns mock devices lock-101 or lock-102."""
        self.app.config["SAMPLE_MODE"] = False
        self.app.config["COLLECT_DEVICES"] = lambda: []

        resp = self.client.get("/api/ha/status", headers=self.headers)
        self.assertEqual(resp.status_code, 200)

        data = resp.get_json()
        self.assertEqual(data.get("service"), "mydoor")
        self.assertEqual(data.get("status"), "healthy")
        self.assertEqual(data.get("count"), 0)
        self.assertEqual(data.get("locks"), [])

        # Strict assertion: neither mock lock must ever appear in production
        lock_ids = [l.get("device_id") for l in data.get("locks", [])]
        self.assertNotIn("lock-101", lock_ids)
        self.assertNotIn("lock-102", lock_ids)

    def test_production_mode_resolution_across_all_env_and_configs(self):
        """Tests that _is_sample_mode() correctly resolves to False across all permutations."""
        with self.app.app_context():
            # Explicit False configs
            self.app.config["SAMPLE_MODE"] = False
            self.assertFalse(_is_sample_mode())

            self.app.config["SAMPLE_MODE"] = None
            self.app.config["HA_SAMPLE_MODE"] = False
            self.assertFalse(_is_sample_mode())

            self.app.config["HA_SAMPLE_MODE"] = None
            mock_engine = MagicMock()
            mock_engine.sample_mode = False
            self.app.config["LOCK_ENGINE"] = mock_engine
            self.assertFalse(_is_sample_mode())

            self.app.config["LOCK_ENGINE"] = None
            for env_key in ("SAMPLE_MODE", "HA_SAMPLE_MODE", "GEEK_DOOR_SAMPLE_MODE"):
                for false_val in ("0", "false", "no", "False", "NO", "disabled"):
                    with patch.dict(os.environ, {env_key: false_val}):
                        self.assertFalse(_is_sample_mode())

            with patch.dict(os.environ, {}, clear=True):
                self.assertFalse(_is_sample_mode())

    def test_sample_mode_returns_mock_devices_properly(self):
        """In sample mode (sample_mode=True), ha_status returns mock devices lock-101 and lock-102."""
        self.app.config["SAMPLE_MODE"] = True
        self.app.config["COLLECT_DEVICES"] = lambda: []

        resp = self.client.get("/api/ha/status", headers=self.headers)
        self.assertEqual(resp.status_code, 200)

        data = resp.get_json()
        self.assertEqual(data.get("count"), 2)
        locks = data.get("locks", [])
        self.assertEqual(len(locks), 2)
        dev_ids = [l.get("device_id") for l in locks]
        self.assertIn("lock-101", dev_ids)
        self.assertIn("lock-102", dev_ids)

    def test_device_state_lookup_production_vs_sample(self):
        """GET /api/ha/lock/lock-101/state returns 404 in production vs 200 in sample mode."""
        # Production mode -> 404 Not Found
        self.app.config["SAMPLE_MODE"] = False
        resp_prod = self.client.get("/api/ha/lock/lock-101/state", headers=self.headers)
        self.assertEqual(resp_prod.status_code, 404)
        data_prod = resp_prod.get_json()
        self.assertFalse(data_prod.get("success", True))
        self.assertIn("not found", data_prod.get("error", "").lower())

        # Sample mode -> 200 OK
        self.app.config["SAMPLE_MODE"] = True
        resp_sample = self.client.get("/api/ha/lock/lock-101/state", headers=self.headers)
        self.assertEqual(resp_sample.status_code, 200)
        data_sample = resp_sample.get_json()
        self.assertEqual(data_sample.get("device_id"), "lock-101")
        self.assertEqual(data_sample.get("name"), "Living Room Door")
        self.assertTrue(data_sample.get("is_locked"))


class TestDeviceActuationRobustness(unittest.TestCase):
    """Stress-test non-existent and randomized device IDs across all actuation routes."""

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        self.app.config["HA_BEARER_TOKEN"] = "test-token-ha-challenger-m3"
        self.app.config["SAMPLE_MODE"] = False
        self.app.config["STATE_OVERRIDES"] = {}
        self.app.config["AUTO_LOCK_OVERRIDES"] = {}
        self.app.register_blueprint(ha_bp)
        self.client = self.app.test_client()
        self.headers = {
            "Authorization": "Bearer test-token-ha-challenger-m3",
            "Content-Type": "application/json",
        }

    def test_nonexistent_and_randomized_device_ids_return_404(self):
        """Nonexistent and randomized device IDs return HTTP 404 with clean JSON across all routes."""
        test_device_ids = [
            "nonexistent-dev-12345",
            str(uuid.uuid4()),
            "lock-9999",
            "unknown_lock_device",
            "special_@$%_lock",
        ]
        endpoints = ["lock", "unlock", "keep_unlocked", "auto_lock"]

        for dev_id in test_device_ids:
            for ep in endpoints:
                resp = self.client.post(
                    f"/api/ha/lock/{dev_id}/{ep}",
                    headers=self.headers,
                    json={"dry_run": True, "confirmed": True},
                )
                self.assertEqual(
                    resp.status_code,
                    404,
                    f"Expected 404 for dev_id='{dev_id}' on /{ep}, got {resp.status_code}",
                )
                self.assertTrue(resp.is_json, f"Response for dev_id='{dev_id}' on /{ep} was not JSON")
                data = resp.get_json()
                self.assertFalse(data.get("success", True))
                self.assertIn("not found", data.get("error", "").lower())


class TestBackendEngineExceptionTranslations(unittest.TestCase):
    """Stress-test backend exception translation across all actuation routes."""

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        self.app.config["HA_BEARER_TOKEN"] = "test-token-ha-challenger-m3"
        self.app.config["SAMPLE_MODE"] = True  # Enable sample mode so device resolves
        self.app.config["STATE_OVERRIDES"] = {}
        self.app.config["AUTO_LOCK_OVERRIDES"] = {}
        self.app.register_blueprint(ha_bp)
        self.client = self.app.test_client()
        self.headers = {
            "Authorization": "Bearer test-token-ha-challenger-m3",
            "Content-Type": "application/json",
        }

    def test_exception_translations_across_all_endpoints(self):
        """Translates backend errors into HTTP 401, 403, 504, 404, and 502 across all 4 routes."""
        exceptions_to_test = [
            (CustomAuthError("Tuya token expired / invalid"), 401),
            (CustomConfigEntryAuthFailed("Reauth required"), 401),
            (CustomSafetyViolation("Action blocked by Safety Barrier"), 403),
            (requests.exceptions.Timeout("Connection timeout to gateway"), 504),
            (TimeoutError("Async BLE connection timeout"), 504),
            (ValueError("Device index not found in topology"), 404),
            (CustomConnectionError("Tuya cloud service unreachable"), 502),
            (requests.exceptions.ConnectionError("Connection refused by gateway"), 502),
            (Exception("Arbitrary unhandled internal error"), 502),
        ]

        endpoints = [
            ("/api/ha/lock/lock-101/lock", {"dry_run": True, "confirmed": True}),
            ("/api/ha/lock/lock-101/unlock", {"dry_run": True, "confirmed": True}),
            ("/api/ha/lock/lock-101/keep_unlocked", {"dry_run": True, "confirmed": True}),
            ("/api/ha/lock/lock-101/auto_lock", {"dry_run": True, "confirmed": True, "enabled": True, "auto_lock_time": 5}),
        ]

        for ep, body in endpoints:
            for exc, expected_code in exceptions_to_test:
                def failing_exec(*args, **kwargs):
                    raise exc

                self.app.config["EXECUTE_DEVICE_ACTION"] = failing_exec
                resp = self.client.post(ep, headers=self.headers, json=body)
                self.assertEqual(
                    resp.status_code,
                    expected_code,
                    f"Endpoint {ep} with exception {exc!r} expected HTTP {expected_code}, got {resp.status_code}",
                )
                self.assertTrue(resp.is_json)
                data = resp.get_json()
                self.assertFalse(data.get("success", True))
                self.assertTrue(len(data.get("error", "")) > 0)


class TestAutoLockPayloadValidation(unittest.TestCase):
    """Stress-test auto_lock_time input validation and adversarial payloads."""

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        self.app.config["HA_BEARER_TOKEN"] = "test-token-ha-challenger-m3"
        self.app.config["SAMPLE_MODE"] = True  # Enable sample mode so lock-101 is resolved
        self.app.config["STATE_OVERRIDES"] = {}
        self.app.config["AUTO_LOCK_OVERRIDES"] = {}
        self.app.register_blueprint(ha_bp)
        self.client = self.app.test_client()
        self.headers = {
            "Authorization": "Bearer test-token-ha-challenger-m3",
            "Content-Type": "application/json",
        }

    def test_non_integer_auto_lock_time_rejected_with_400(self):
        """Non-integer auto_lock_time strings ('invalid', '', 'null', [], {}) return HTTP 400."""
        malformed_cases = [
            ("word_string", {"auto_lock_time": "invalid"}),
            ("empty_string", {"auto_lock_time": ""}),
            ("string_null", {"auto_lock_time": "null"}),
            ("empty_list", {"auto_lock_time": []}),
            ("empty_dict", {"auto_lock_time": {}}),
            ("float_string", {"auto_lock_time": "5.5"}),
        ]

        for name, payload in malformed_cases:
            payload["dry_run"] = True
            resp = self.client.post(
                "/api/ha/lock/lock-101/auto_lock",
                headers=self.headers,
                json=payload,
            )
            self.assertEqual(
                resp.status_code,
                400,
                f"Payload case '{name}' expected HTTP 400, got {resp.status_code}. Response: {resp.data}",
            )
            data = resp.get_json()
            self.assertFalse(data.get("success", True))
            self.assertIn("auto_lock_time", data.get("error", "").lower())

    def test_negative_auto_lock_time_and_null_adversarial_vulnerability(self):
        """Adversarially probe '-99' and JSON null on /api/ha/lock/<id>/auto_lock.

        A negative auto_lock_time duration ('-99' or -99) or JSON null must be rejected with HTTP 400
        Bad Request with clean JSON, rather than being accepted as HTTP 200.
        """
        vulnerability_cases = [
            ("negative_string", {"auto_lock_time": "-99"}),
            ("negative_int", {"auto_lock_time": -99}),
            ("zero_int", {"auto_lock_time": 0}),
            ("json_null", {"auto_lock_time": None}),
        ]

        for name, payload in vulnerability_cases:
            payload["dry_run"] = True
            resp = self.client.post(
                "/api/ha/lock/lock-101/auto_lock",
                headers=self.headers,
                json=payload,
            )
            self.assertEqual(
                resp.status_code,
                400,
                f"VULNERABILITY CONFIRMED [{name}]: auto_lock_time={payload['auto_lock_time']!r} returned "
                f"HTTP {resp.status_code} instead of HTTP 400 Bad Request! Response: {resp.get_json()}",
            )


if __name__ == "__main__":
    unittest.main()
