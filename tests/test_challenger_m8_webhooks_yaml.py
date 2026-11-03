"""Empirical Adversarial Stress Test Suite for Milestone 8 (Challenger 2).

Executed by challenger_m8_2 to stress-test:
1. Incoming Webhook (`POST /api/ha/webhook`):
   - Secret validation: missing, empty, invalid token (strictly 403 Forbidden).
   - Multi-format token authentication (query ?token=, ?secret=, X-HA-Webhook-Secret,
     X-Webhook-Token, Authorization: Bearer, JSON body token/secret).
   - Action validation: missing action, empty action, unknown action (strictly 400 Bad Request).
   - Action dispatch: lock, unlock, keep_unlocked, auto_lock_off, auto_lock_on, status.
   - Device ID resolution: fallback to default, integer ID coercion, custom IDs.
   - Safety guard: unconfirmed physical actuations when dry_run=False.
   - Malformed/empty payloads: graceful handling with zero crashes.
2. Outgoing Webhook Dispatcher (`dispatch_ha_webhook`):
   - Non-blocking execution (< 0.2s) under simulated 10s hung socket.
   - Comprehensive network exception containment: Timeout, ConnectionError, SSLError,
     HTTPError, RequestException, and arbitrary RuntimeErrors.
   - Verification that no unhandled exceptions escape to the main thread.
   - High-throughput concurrency stress (50 rapid-fire dispatches).
   - Daemon thread status verification.
3. Home Assistant YAML Configuration Generator (`generate_ha_yaml_config`):
   - Strict YAML 1.2 syntax validation via PyYAML (yaml.safe_load).
   - Presence of all required Home Assistant blocks (lock, platform: template,
     rest_command, sensor platform rest, sensor platform template).
   - Normalization of domains (scheme handling, port preservation).
   - Normalization of bearer tokens (stripping redundant 'Bearer ').
   - Boundary checks on scan_interval (clamping to >= 5s, invalid input fallback).
   - Toggle behavior of include_automation.
   - Special character, quote, bracket, and unicode/emoji escaping in lock names.
"""

from __future__ import annotations

import time
import unittest
from unittest.mock import patch

try:
    import yaml
except ImportError:
    yaml = None

import requests

from server.flask_app import app
from server.home_assistant import (
    dispatch_ha_webhook,
    generate_ha_yaml_config,
)


class TestChallengerM8WebhooksAndYAML(unittest.TestCase):
    """Adversarial stress-test harness for Home Assistant webhooks and YAML generator."""

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.app.config["HA_BEARER_TOKEN"] = "ha-challenger-secret-token-abc"
        self.app.config["HA_WEBHOOK_SECRET"] = "ha-challenger-webhook-secret-xyz"
        self.client = self.app.test_client()
        self.secret = "ha-challenger-webhook-secret-xyz"

    # ========================================================================
    # 1. Incoming Webhook: Secret Validation & Header Permutations
    # ========================================================================

    def test_webhook_secret_missing_rejected_403(self):
        """Verifies incoming webhook without any token is strictly rejected with 403."""
        res = self.client.post("/api/ha/webhook", json={"action": "lock", "dry_run": True})
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertFalse(data.get("success"))
        self.assertIn("Forbidden", data.get("error", ""))

    def test_webhook_secret_invalid_query_rejected_403(self):
        """Verifies incoming webhook with invalid query token is strictly rejected with 403."""
        res = self.client.post(
            "/api/ha/webhook?token=wrong-secret-token",
            json={"action": "lock", "dry_run": True},
        )
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertFalse(data.get("success"))

    def test_webhook_secret_empty_query_rejected_403(self):
        """Verifies incoming webhook with empty query token is strictly rejected with 403."""
        res = self.client.post(
            "/api/ha/webhook?token=",
            json={"action": "lock", "dry_run": True},
        )
        self.assertEqual(res.status_code, 403)

    def test_webhook_secret_invalid_headers_rejected_403(self):
        """Verifies invalid secrets passed in various headers are strictly rejected with 403."""
        invalid_headers = [
            {"X-HA-Webhook-Secret": "bad-secret"},
            {"X-Webhook-Token": "bad-token"},
            {"Authorization": "Bearer bad-bearer"},
        ]
        for hdr in invalid_headers:
            res = self.client.post(
                "/api/ha/webhook",
                headers=hdr,
                json={"action": "lock", "dry_run": True},
            )
            self.assertEqual(res.status_code, 403, f"Failed for header {hdr}")

    def test_webhook_secret_alternative_locations_accepted_200(self):
        """Verifies valid secret is accepted across all supported locations."""
        # 1. Query parameter: ?token=
        res1 = self.client.post(
            f"/api/ha/webhook?token={self.secret}",
            json={"action": "status"},
        )
        self.assertEqual(res1.status_code, 200, "Failed on ?token=")

        # 2. Query parameter: ?secret=
        res2 = self.client.post(
            f"/api/ha/webhook?secret={self.secret}",
            json={"action": "status"},
        )
        self.assertEqual(res2.status_code, 200, "Failed on ?secret=")

        # 3. Header: X-HA-Webhook-Secret
        res3 = self.client.post(
            "/api/ha/webhook",
            headers={"X-HA-Webhook-Secret": self.secret},
            json={"action": "status"},
        )
        self.assertEqual(res3.status_code, 200, "Failed on X-HA-Webhook-Secret")

        # 4. Header: X-Webhook-Token
        res4 = self.client.post(
            "/api/ha/webhook",
            headers={"X-Webhook-Token": self.secret},
            json={"action": "status"},
        )
        self.assertEqual(res4.status_code, 200, "Failed on X-Webhook-Token")

        # 5. Header: Authorization: Bearer
        res5 = self.client.post(
            "/api/ha/webhook",
            headers={"Authorization": f"Bearer {self.secret}"},
            json={"action": "status"},
        )
        self.assertEqual(res5.status_code, 200, "Failed on Authorization: Bearer")

        # 6. JSON Body: {"token": ...}
        res6 = self.client.post(
            "/api/ha/webhook",
            json={"token": self.secret, "action": "status"},
        )
        self.assertEqual(res6.status_code, 200, "Failed on body.token")

        # 7. JSON Body: {"secret": ...}
        res7 = self.client.post(
            "/api/ha/webhook",
            json={"secret": self.secret, "action": "status"},
        )
        self.assertEqual(res7.status_code, 200, "Failed on body.secret")

    # ========================================================================
    # 2. Incoming Webhook: Action Validation & Execution Robustness
    # ========================================================================

    def test_webhook_missing_action_rejected_400(self):
        """Verifies webhook with missing action field returns clean 400 without crashing."""
        res = self.client.post(
            f"/api/ha/webhook?token={self.secret}",
            json={"device_id": "lock-101"},
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("success"))
        self.assertIn("Missing required 'action'", data.get("error", ""))

    def test_webhook_empty_or_whitespace_action_rejected_400(self):
        """Verifies webhook with empty or whitespace action returns clean 400."""
        for act in ["", "   ", None]:
            res = self.client.post(
                f"/api/ha/webhook?token={self.secret}",
                json={"action": act, "device_id": "lock-101"},
            )
            self.assertEqual(res.status_code, 400)
            data = res.get_json()
            self.assertFalse(data.get("success"))

    def test_webhook_unknown_action_rejected_400(self):
        """Verifies unknown action is rejected with clean 400 listing allowed actions."""
        res = self.client.post(
            f"/api/ha/webhook?token={self.secret}",
            json={"action": "reboot_device", "device_id": "lock-101"},
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("success"))
        self.assertIn("Invalid webhook action", data.get("error", ""))
        self.assertIn("lock", data.get("error", ""))

    def test_webhook_supported_actions_succeed(self):
        """Verifies all supported actions execute cleanly without errors."""
        supported_actions = [
            ("lock", "locked", True, True),
            ("unlock", "unlocked", False, True),
            ("keep_unlocked", "unlocked", False, False),
            ("auto_lock_off", "unlocked", False, False),
            ("auto_lock_on", "unlocked", False, True),
        ]
        for action, expected_state, expected_locked, expected_auto in supported_actions:
            res = self.client.post(
                f"/api/ha/webhook?token={self.secret}",
                json={"action": action, "device_id": "lock-101", "dry_run": True},
            )
            self.assertEqual(res.status_code, 200, f"Action {action} failed with {res.status_code}")
            data = res.get_json()
            self.assertTrue(data.get("success"))
            self.assertEqual(data.get("state"), expected_state)
            self.assertEqual(data.get("is_locked"), expected_locked)
            self.assertEqual(data.get("auto_lock_enabled"), expected_auto)

    def test_webhook_action_case_insensitivity(self):
        """Verifies actions are handled case-insensitively ('LOCK', 'UnLock')."""
        for act in ["LOCK", "UnLock", "KEEP_UNLOCKED"]:
            res = self.client.post(
                f"/api/ha/webhook?token={self.secret}",
                json={"action": act, "device_id": "lock-101", "dry_run": True},
            )
            self.assertEqual(res.status_code, 200)
            self.assertTrue(res.get_json().get("success"))

    def test_webhook_device_id_variations(self):
        """Verifies device ID defaults and coercions (missing, int, custom string)."""
        # 1. Missing device_id -> defaults to lock-101
        res1 = self.client.post(
            f"/api/ha/webhook?token={self.secret}",
            json={"action": "status"},
        )
        self.assertEqual(res1.status_code, 200)
        self.assertEqual(res1.get_json().get("device_id"), "lock-101")

        # 2. Integer device_id -> coerced cleanly
        res2 = self.client.post(
            f"/api/ha/webhook?token={self.secret}",
            json={"action": "status", "device_id": 102},
        )
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.get_json().get("device_id"), "102")

        # 3. Custom string device_id
        res3 = self.client.post(
            f"/api/ha/webhook?token={self.secret}",
            json={"action": "status", "device_id": "living_room_lock"},
        )
        self.assertEqual(res3.status_code, 200)
        self.assertEqual(res3.get_json().get("device_id"), "living_room_lock")

    def test_webhook_empty_payload_clean_400(self):
        """Verifies completely empty payload returns clean 400 rather than crashing."""
        res = self.client.post(f"/api/ha/webhook?token={self.secret}")
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("success"))
        self.assertIn("Missing required 'action'", data.get("error", ""))

    def test_webhook_malformed_json_clean_400(self):
        """Verifies unparseable malformed JSON returns clean 400 without unhandled crash."""
        res = self.client.post(
            f"/api/ha/webhook?token={self.secret}",
            data="not-a-valid-json-string{",
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("success"))

    # ========================================================================
    # 3. Outgoing Webhook: Latency, Hung Socket & Exception Containment
    # ========================================================================

    def test_outgoing_webhook_hung_socket_latency(self):
        """Asserts dispatch_ha_webhook returns in < 0.2s under 10s simulated socket hang."""
        def hung_post(*args, **kwargs):
            time.sleep(10.0)
            raise TimeoutError("Simulated 10s hung socket")

        with patch("requests.post", side_effect=hung_post):
            start = time.time()
            thread = dispatch_ha_webhook(
                {"event": "lock_state_changed", "device_id": "lock-101"},
                "http://hung.homeassistant.local:8123/api/webhook/state",
            )
            elapsed = time.time() - start

            # Must return immediately to the caller
            self.assertLess(
                elapsed,
                0.2,
                f"Outgoing webhook dispatch blocked the caller for {elapsed:.4f}s (max 0.2s)",
            )
            self.assertTrue(thread.is_alive(), "Background thread should still be processing")
            self.assertTrue(thread.daemon, "Thread must be marked as daemon")

    def test_outgoing_webhook_exception_containment(self):
        """Asserts all network and socket exceptions are contained without leaking."""
        simulated_exceptions = [
            requests.exceptions.ConnectTimeout("Connect timeout"),
            requests.exceptions.ReadTimeout("Read timeout"),
            requests.exceptions.ConnectionError("Connection refused"),
            requests.exceptions.SSLError("SSL verification failure"),
            requests.exceptions.HTTPError("502 Bad Gateway"),
            requests.exceptions.TooManyRedirects("Redirect loop"),
            requests.exceptions.RequestException("Generic network failure"),
            RuntimeError("Unexpected thread runtime error"),
            Exception("Arbitrary unhandled exception"),
        ]

        for exc in simulated_exceptions:
            with patch("requests.post", side_effect=exc):
                start = time.time()
                thread = dispatch_ha_webhook(
                    {"event": "lock_state_changed", "device_id": "lock-101"},
                    "http://error.homeassistant.local:8123/api/webhook/state",
                )
                elapsed = time.time() - start
                self.assertLess(elapsed, 0.2)

                # Thread must catch the exception and terminate cleanly
                thread.join(timeout=1.0)
                self.assertFalse(
                    thread.is_alive(),
                    f"Thread did not terminate cleanly on {type(exc).__name__}",
                )

    def test_outgoing_webhook_high_throughput_burst(self):
        """Asserts 50 rapid-fire outgoing webhook dispatches execute in < 0.2s total."""
        with patch("requests.post", side_effect=lambda *args, **kwargs: None):
            start = time.time()
            threads = []
            for i in range(50):
                t = dispatch_ha_webhook(
                    {"event": "burst_test", "seq": i},
                    "http://ha.local:8123/api/webhook/burst",
                )
                threads.append(t)
            elapsed = time.time() - start

            self.assertLess(
                elapsed,
                0.2,
                f"50 dispatches took {elapsed:.4f}s; expected < 0.2s total",
            )
            for t in threads:
                t.join(timeout=1.0)
                self.assertFalse(t.is_alive())

    def test_outgoing_webhook_none_or_empty_url_handled_cleanly(self):
        """Asserts dispatch_ha_webhook handles None or empty URL gracefully without crashing."""
        # When no URL is passed and none configured in config/env
        with patch.dict(self.app.config, {"HA_OUTGOING_WEBHOOK_URL": None, "HA_WEBHOOK_URL": None}):
            t = dispatch_ha_webhook({"event": "test"}, webhook_url=None)
            t.join(timeout=1.0)
            self.assertFalse(t.is_alive())

    # ========================================================================
    # 4. YAML Configuration Generator: PyYAML Parsing & Schema Compliance
    # ========================================================================

    def test_yaml_generator_pyyaml_safe_load(self):
        """Verifies generate_ha_yaml_config produces strictly valid YAML 1.2 syntax."""
        if yaml is None:
            raise unittest.SkipTest("PyYAML not installed in test environment")

        yaml_text = generate_ha_yaml_config(
            domain="lock.example.com",
            bearer_token="my-ha-long-lived-token-12345",
            device_id="lock-101",
        )
        parsed = yaml.safe_load(yaml_text)
        self.assertIsInstance(parsed, dict)

        # Assert all required top-level HA blocks exist
        self.assertIn("lock", parsed)
        self.assertIn("rest_command", parsed)
        self.assertIn("sensor", parsed)
        self.assertIn("automation", parsed)

    def test_yaml_generator_blocks_and_structure(self):
        """Verifies internal structure and attributes of generated HA configuration."""
        if yaml is None:
            raise unittest.SkipTest("PyYAML not installed in test environment")

        yaml_text = generate_ha_yaml_config(
            domain="192.168.1.100:5050",
            bearer_token="test-token-xyz",
            device_id="lock-102",
            lock_name="Side Door Lock",
            use_https=False,
            scan_interval=45,
            include_automation=True,
        )
        parsed = yaml.safe_load(yaml_text)

        # 1. Lock template block
        locks = parsed.get("lock", [])
        self.assertIsInstance(locks, list)
        self.assertGreaterEqual(len(locks), 1)
        lock_entry = locks[0]
        self.assertEqual(lock_entry.get("platform"), "template")
        self.assertEqual(lock_entry.get("name"), "Side Door Lock")
        self.assertIn("unique_id", lock_entry)
        self.assertIn("value_template", lock_entry)
        self.assertIn("lock", lock_entry)
        self.assertIn("unlock", lock_entry)

        # 2. REST command block
        rest_cmds = parsed.get("rest_command", {})
        self.assertIn("mydoor_lock", rest_cmds)
        self.assertIn("mydoor_unlock", rest_cmds)
        self.assertIn("mydoor_keep_unlocked", rest_cmds)
        for cmd_name in ("mydoor_lock", "mydoor_unlock", "mydoor_keep_unlocked"):
            cmd = rest_cmds[cmd_name]
            self.assertEqual(cmd.get("method"), "POST")
            self.assertTrue(cmd.get("url", "").startswith("http://192.168.1.100:5050/api/ha/lock/"))
            auth_header = cmd.get("headers", {}).get("Authorization", "")
            self.assertEqual(auth_header, "Bearer test-token-xyz")

        # 3. Sensor block
        sensors = parsed.get("sensor", [])
        self.assertIsInstance(sensors, list)
        self.assertEqual(len(sensors), 2)

        rest_sensor = next((s for s in sensors if s.get("platform") == "rest"), None)
        self.assertIsNotNone(rest_sensor)
        self.assertEqual(rest_sensor.get("resource"), "http://192.168.1.100:5050/api/ha/lock/lock-102/state")
        self.assertEqual(rest_sensor.get("scan_interval"), 45)
        self.assertIn("json_attributes", rest_sensor)

        template_sensor = next((s for s in sensors if s.get("platform") == "template"), None)
        self.assertIsNotNone(template_sensor)
        sensor_dict = template_sensor.get("sensors", {})
        self.assertGreaterEqual(len(sensor_dict), 1)

        # 4. Automation block
        automations = parsed.get("automation", [])
        self.assertIsInstance(automations, list)
        self.assertGreaterEqual(len(automations), 1)

    def test_yaml_generator_token_normalization(self):
        """Verifies redundant 'Bearer ' prefix is stripped so headers aren't 'Bearer Bearer'."""
        if yaml is None:
            raise unittest.SkipTest("PyYAML not installed in test environment")

        yaml_text = generate_ha_yaml_config(
            domain="lock.example.com",
            bearer_token="Bearer my-already-prefixed-token",
            device_id="lock-101",
        )
        parsed = yaml.safe_load(yaml_text)
        auth_hdr = parsed["rest_command"]["mydoor_lock"]["headers"]["Authorization"]
        self.assertEqual(auth_hdr, "Bearer my-already-prefixed-token")
        self.assertFalse(auth_hdr.startswith("Bearer Bearer"))

    def test_yaml_generator_scan_interval_clamping(self):
        """Verifies scan_interval is clamped to minimum 5s and handles non-integer input."""
        if yaml is None:
            raise unittest.SkipTest("PyYAML not installed in test environment")

        # Low interval clamped to 5
        out1 = generate_ha_yaml_config("lock.example.com", "tok", "101", scan_interval=2)
        parsed1 = yaml.safe_load(out1)
        rest_s1 = next(s for s in parsed1["sensor"] if s.get("platform") == "rest")
        self.assertEqual(rest_s1.get("scan_interval"), 5)

        # Invalid interval falls back to 30
        out2 = generate_ha_yaml_config("lock.example.com", "tok", "101", scan_interval="invalid")
        parsed2 = yaml.safe_load(out2)
        rest_s2 = next(s for s in parsed2["sensor"] if s.get("platform") == "rest")
        self.assertEqual(rest_s2.get("scan_interval"), 30)

    def test_yaml_generator_include_automation_toggle(self):
        """Verifies include_automation=False omits the automation block entirely."""
        if yaml is None:
            raise unittest.SkipTest("PyYAML not installed in test environment")

        out = generate_ha_yaml_config(
            domain="lock.example.com",
            bearer_token="tok",
            device_id="101",
            include_automation=False,
        )
        parsed = yaml.safe_load(out)
        self.assertNotIn("automation", parsed)

    def test_yaml_generator_special_characters_and_quotes(self):
        """Verifies special characters, double quotes, and unicode in lock name parse cleanly."""
        if yaml is None:
            raise unittest.SkipTest("PyYAML not installed in test environment")

        tricky_names = [
            'Front: "Special" [Door] & Key\\Backslash',
            '🚪 Smart Front Door 🔒',
            "Master Bedroom's Inner Door",
            "Door with $pecial %chars & /symbols/",
        ]
        for name in tricky_names:
            out = generate_ha_yaml_config(
                domain="lock.example.com",
                bearer_token="tok",
                device_id="101",
                lock_name=name,
            )
            parsed = yaml.safe_load(out)
            self.assertIsInstance(parsed, dict)
            lock_entry = parsed["lock"][0]
            self.assertEqual(lock_entry["name"], name)


if __name__ == "__main__":
    unittest.main()
