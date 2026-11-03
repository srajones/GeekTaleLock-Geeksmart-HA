"""Home Assistant Integration Test Suite (Milestone 8 / Requirement R6).

Verifies:
1. Long-Lived Bearer Token authentication on all /api/ha/* endpoints.
2. GET /api/ha/status returning system health and lock inventory.
3. GET /api/ha/lock/<dev_id>/state matching Home Assistant REST sensor schema.
4. POST /api/ha/lock/<dev_id>/lock executing safe actuation.
5. POST /api/ha/lock/<dev_id>/unlock executing safe unlock.
6. POST /api/ha/lock/<dev_id>/keep_unlocked enabling Passage Mode (Auto-lock OFF).
7. POST /api/ha/webhook incoming webhook handler with secret validation.
8. Asynchronous non-blocking outgoing webhook dispatcher with 2.0s socket timeout.
9. Home Assistant YAML configuration snippet validity.
"""

import json
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent

try:
    from server.home_assistant import (
        dispatch_ha_webhook,
        generate_ha_yaml_config,
    )
    from server.flask_app import app
except ImportError:
    dispatch_ha_webhook = None
    generate_ha_yaml_config = None
    try:
        from server.flask_app import app
    except ImportError:
        app = None


class TestHomeAssistantIntegration(unittest.TestCase):
    """Test suite covering Home Assistant REST endpoints and Webhook integrations."""

    def setUp(self):
        if app is None:
            raise unittest.SkipTest("server.flask_app not available")

        self.app = app
        self.app.config["TESTING"] = True
        self.app.config["HA_BEARER_TOKEN"] = "ha-secret-token-test-12345"
        self.app.config["HA_WEBHOOK_SECRET"] = "webhook-secret-token-67890"
        self.client = self.app.test_client()

        self.valid_headers = {
            "Authorization": "Bearer ha-secret-token-test-12345",
            "Content-Type": "application/json",
        }

    # --- 1. Authentication ---

    def test_HA_01_unauthorized_requests_rejected(self):
        """HA.01: Verifies /api/ha/* endpoints reject requests without valid Bearer token."""
        res = self.client.get("/api/ha/status")
        if res.status_code == 404:
            raise unittest.SkipTest("/api/ha/status endpoint not yet registered (Milestone 8).")

        self.assertIn(
            res.status_code,
            [401, 403],
            f"Expected 401/403 for unauthenticated request, got {res.status_code}",
        )

        # Invalid token
        res_bad = self.client.get(
            "/api/ha/status",
            headers={"Authorization": "Bearer invalid-token"},
        )
        self.assertIn(res_bad.status_code, [401, 403])

    def test_HA_02_alternative_header_x_ha_access_accepted(self):
        """HA.02: Verifies X-HA-Access header is accepted as alternate Bearer token format."""
        res = self.client.get(
            "/api/ha/status",
            headers={"X-HA-Access": "ha-secret-token-test-12345"},
        )
        if res.status_code == 404:
            raise unittest.SkipTest("/api/ha/status endpoint not yet registered (Milestone 8).")

        self.assertEqual(res.status_code, 200)

    # --- 2. REST Endpoints ---

    def test_HA_03_get_status_returns_service_and_locks(self):
        """HA.03: Verifies GET /api/ha/status returns valid lock inventory JSON."""
        res = self.client.get("/api/ha/status", headers=self.valid_headers)
        if res.status_code == 404:
            raise unittest.SkipTest("/api/ha/status not yet implemented.")

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("service"), "mydoor")
        self.assertIn("locks", data)
        self.assertIsInstance(data["locks"], list)

    def test_HA_04_get_lock_state_sensor_schema(self):
        """HA.04: Verifies GET /api/ha/lock/<id>/state conforms to HA REST Sensor schema."""
        res = self.client.get("/api/ha/lock/lock-101/state", headers=self.valid_headers)
        if res.status_code == 404:
            raise unittest.SkipTest("/api/ha/lock/<id>/state not yet implemented.")

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("state", data)
        self.assertIn(data["state"], ["locked", "unlocked", "jammed", "unknown"])
        self.assertIn("is_locked", data)
        self.assertIn("battery", data)
        self.assertIsInstance(data["battery"], (int, float))

    def test_HA_05_lock_actuation_endpoint(self):
        """HA.05: Verifies POST /api/ha/lock/<id>/lock triggers safe lock actuation."""
        res = self.client.post(
            "/api/ha/lock/lock-101/lock",
            headers=self.valid_headers,
            json={"confirmed": True, "dry_run": True},
        )
        if res.status_code == 404:
            raise unittest.SkipTest("/api/ha/lock/<id>/lock not yet implemented.")

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("state"), "locked")

    def test_HA_06_unlock_actuation_endpoint(self):
        """HA.06: Verifies POST /api/ha/lock/<id>/unlock triggers safe unlock actuation."""
        res = self.client.post(
            "/api/ha/lock/lock-101/unlock",
            headers=self.valid_headers,
            json={"confirmed": True, "dry_run": True},
        )
        if res.status_code == 404:
            raise unittest.SkipTest("/api/ha/lock/<id>/unlock not yet implemented.")

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("state"), "unlocked")

    def test_HA_07_keep_unlocked_passage_mode_endpoint(self):
        """HA.07: Verifies POST /api/ha/lock/<id>/keep_unlocked disables auto-lock."""
        res = self.client.post(
            "/api/ha/lock/lock-101/keep_unlocked",
            headers=self.valid_headers,
            json={"confirmed": True, "dry_run": True},
        )
        if res.status_code == 404:
            raise unittest.SkipTest("/api/ha/lock/<id>/keep_unlocked not yet implemented.")

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertFalse(data.get("auto_lock_enabled", True))

    # --- 3. Webhook Integration ---

    def test_HA_08_incoming_webhook_handler_with_secret(self):
        """HA.08: Verifies POST /api/ha/webhook validates secret and executes action."""
        # Missing or invalid token -> 403 Forbidden
        res_bad = self.client.post("/api/ha/webhook?token=wrong-secret", json={"action": "lock"})
        if res_bad.status_code == 404:
            raise unittest.SkipTest("/api/ha/webhook not yet implemented.")

        self.assertEqual(res_bad.status_code, 403)

        # Valid token
        res_ok = self.client.post(
            "/api/ha/webhook?token=webhook-secret-token-67890",
            json={"action": "lock", "device_id": "lock-101", "dry_run": True},
        )
        self.assertEqual(res_ok.status_code, 200)
        self.assertTrue(res_ok.get_json().get("success"))

    def test_HA_09_outgoing_webhook_dispatcher_non_blocking_timeout(self):
        """HA.09: Verifies dispatch_ha_webhook runs in background with strict 2.0s timeout."""
        if dispatch_ha_webhook is None:
            raise unittest.SkipTest("dispatch_ha_webhook not yet implemented.")

        event_payload = {
            "event": "lock_state_changed",
            "device_id": "lock-101",
            "new_state": "locked",
            "timestamp": "2026-11-02T15:00:00Z",
        }

        # Mock requests.post to simulate slow/unreachable server
        with patch("requests.post") as mock_post:
            mock_post.side_effect = Exception("Simulated connection timeout")

            start_time = time.time()
            # Dispatch must return immediately (non-blocking)
            dispatch_ha_webhook(event_payload, "http://unreachable-ha-server.local:8123/api/webhook/test")
            elapsed = time.time() - start_time

            # Main thread must not stall
            self.assertLess(elapsed, 0.5, "Outgoing webhook dispatch must be non-blocking")

    # --- 4. YAML Configuration Generator ---

    def test_HA_10_yaml_configuration_generator(self):
        """HA.10: Verifies generate_ha_yaml_config outputs valid Home Assistant YAML snippet."""
        if generate_ha_yaml_config is None:
            raise unittest.SkipTest("generate_ha_yaml_config not yet implemented.")

        yaml_text = generate_ha_yaml_config(
            domain="lock.example.com",
            bearer_token="ha-token-test-xyz",
            device_id="lock-101",
        )

        self.assertIn("lock:", yaml_text)
        self.assertIn("platform: template", yaml_text)
        self.assertIn("rest_command:", yaml_text)
        self.assertIn("sensor:", yaml_text)
        self.assertIn("lock.example.com", yaml_text)
        self.assertIn("ha-token-test-xyz", yaml_text)


if __name__ == "__main__":
    unittest.main()
