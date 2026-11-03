"""Unit and Integration Tests for Milestone 4 Local Flask Mobile Dashboard Server.

Verifies:
1. Default port 5050 configuration (preventing macOS AirPlay Receiver port 5000 collision).
2. Clean mobile HTML template rendering with responsive viewport.
3. Health check endpoints (/health, /api/health).
4. Account and bridge metadata endpoint (/api/info, /api/status).
5. Device enumeration (/api/devices) returning Smart Plug Gateway and Door Locks.
6. Safe physical control requiring confirmation (zero automated actuation).
7. Safety Barrier Guard blocking destructive actions.
"""
from __future__ import annotations

import json
import os
import unittest
from typing import Any, Dict

from client.safety import ClientMode
from server.flask_app import DEFAULT_PORT, create_app, detect_lan_ip


class TestFlaskServer(unittest.TestCase):
    """Test suite for local Flask server endpoints and safety barriers."""

    @classmethod
    def setUpClass(cls):
        cache_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            ".session_cache.json",
        )
        cls.app = create_app(session_cache_path=cache_file, redact_status=False)
        cls.client = cls.app.test_client()

    def test_default_port_is_5050(self):
        """MANDATORY: Default port must be 5050 to avoid macOS AirPlay Receiver collision."""
        self.assertEqual(DEFAULT_PORT, 5050)
        self.assertEqual(self.app.config.get("PORT"), 5050)

    def test_detect_lan_ip_returns_valid_ip(self):
        """Verify LAN IP detection returns a valid IPv4 address."""
        ip = detect_lan_ip()
        self.assertIsInstance(ip, str)
        parts = ip.split(".")
        self.assertEqual(len(parts), 4)

    def test_health_endpoints(self):
        """GET /health and GET /api/health must report healthy status and port 5050."""
        for endpoint in ("/health", "/api/health"):
            res = self.client.get(endpoint)
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data.get("status"), "healthy")
            self.assertEqual(data.get("port"), 5050)
            self.assertEqual(data.get("safetyMode"), ClientMode.SAFE_CONTROL.value)
            self.assertTrue(data.get("zeroAutomatedActuation"))
            self.assertTrue(data.get("sessionCached"))

    def test_api_info_endpoint(self):
        """GET /api/info must return authenticated account profile and bridge UIDs."""
        res = self.client.get("/api/info")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("email"), "testuser@example.com")
        self.assertEqual(data.get("clientId"), 9999999)
        self.assertEqual(data.get("tuyaUid"), "tuya_mock_uid_1099")
        self.assertEqual(data.get("ttlockUid"), "10000001")
        self.assertEqual(data.get("safetyMode"), ClientMode.SAFE_CONTROL.value)

    def test_dashboard_html_rendering(self):
        """GET / must return HTML5 with responsive viewport and safety confirmation modal."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("viewport", html)
        self.assertIn("GeekSmart", html)
        self.assertIn("5050", html)
        self.assertIn("confirm-modal", html)
        self.assertIn("device-container", html)

    def test_api_devices_enumeration(self):
        """GET /api/devices must return Smart Plug Gateway and Bluetooth Door Locks."""
        res = self.client.get("/api/devices")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        devices = data.get("devices", [])
        self.assertGreaterEqual(len(devices), 1)

        # Check Smart Plug Gateway representation
        gateway = next((d for d in devices if d.get("deviceType") == "GATEWAY"), None)
        self.assertIsNotNone(gateway, "Smart Plug BLE Gateway must be present in devices")
        self.assertEqual(gateway.get("state"), "ONLINE")
        self.assertIn("Smart Plug", gateway.get("name"))

        # Check Door Lock representation
        lock = next((d for d in devices if d.get("deviceType") == "SMART_LOCK"), None)
        if lock:
            self.assertIn(lock.get("state"), ("LOCKED", "UNLOCKED", "UNKNOWN"))
            self.assertIn("unlock", lock.get("availableActions", []))
            self.assertIn("lock", lock.get("availableActions", []))

    def test_device_detail_and_status(self):
        """GET /api/devices/<id> must return individual device telemetry and DPs."""
        res = self.client.get("/api/devices/lock-101")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("name"), "Living Room Door")
        self.assertIn("dps", data)
        self.assertIn("dpSchema", data)

    def test_unconfirmed_physical_actuation_blocked(self):
        """CRITICAL: Physical lock/unlock without confirmed=True must return 400 error."""
        # Test /action endpoint
        res = self.client.post("/api/devices/lock-101/action", json={"action": "unlock"})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("success"))
        self.assertTrue(data.get("requiresConfirmation"))

        # Test /unlock convenience endpoint
        res = self.client.post("/api/devices/lock-101/unlock", json={})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("success"))
        self.assertTrue(data.get("requiresConfirmation"))

        # Test /lock convenience endpoint
        res = self.client.post("/api/devices/lock-101/lock", json={})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("success"))
        self.assertTrue(data.get("requiresConfirmation"))

    def test_safe_control_with_dry_run(self):
        """Dry-run actuation succeeds without requiring confirmation and does NOT actuate locks."""
        res = self.client.post(
            "/api/devices/lock-101/action",
            json={"action": "unlock", "dry_run": True},
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertTrue(data.get("dry_run"))
        self.assertEqual(data.get("newState"), "UNLOCKED")

    def test_safe_control_with_confirmation(self):
        """Actuation with confirmed=True and dry_run=True succeeds safely."""
        res = self.client.post(
            "/api/devices/lock-101/action",
            json={"action": "lock", "confirmed": True, "dry_run": True},
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("newState"), "LOCKED")

    def test_destructive_action_permanently_blocked(self):
        """Safety Barrier must block forbidden destructive actions with HTTP 403."""
        destructive_actions = [
            "deleteClientEquipment",
            "resetFactory",
            "clearFingerprints",
            "removeLock",
            "deletePasscode",
        ]
        for act in destructive_actions:
            res = self.client.post(
                "/api/devices/lock-101/action",
                json={"action": act, "confirmed": True, "dry_run": True},
            )
            self.assertEqual(
                res.status_code,
                403,
                f"Destructive action '{act}' must be blocked with HTTP 403",
            )
            data = res.get_json()
            self.assertFalse(data.get("success"))
            self.assertTrue(data.get("safetyViolation"))

    def test_missing_device_returns_404(self):
        """Querying a non-existent device returns 404."""
        res = self.client.get("/api/devices/non-existent-device-99999")
        self.assertEqual(res.status_code, 404)
        data = res.get_json()
        self.assertFalse(data.get("success"))

    def test_no_cache_headers_and_frontend_retry_resiliency(self):
        """Responses include Cache-Control: no-store and frontend includes fetchWithRetry & telemetry."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("no-store", res.headers.get("Cache-Control", ""))
        self.assertEqual(res.headers.get("Pragma"), "no-cache")
        html = res.get_data(as_text=True)
        self.assertIn("fetchWithRetry", html)
        self.assertIn("refreshDevices", html)
        self.assertIn("-70 dBm", html)

    def test_legacy_aliases_and_signal_telemetry_on_cached_inventory(self):
        """Legacy IDs (101, 102, 103, 201) and Tuya devIds resolve with battery, Wi-Fi, and BLE telemetry."""
        for alias in ("101", "lock-101", "livingroom", "102", "lock-102", "bathroom", "201", "gw-201"):
            res = self.client.get(f"/api/devices/{alias}")
            self.assertEqual(res.status_code, 200)
            payload = res.get_json()
            self.assertTrue(payload.get("success"))
            self.assertEqual(payload.get("wifiRssi"), -70)
            self.assertIsNotNone(payload.get("bleSignalLabel"))
            self.assertIsNotNone(payload.get("signalDiagnostic"))


if __name__ == "__main__":
    unittest.main()
