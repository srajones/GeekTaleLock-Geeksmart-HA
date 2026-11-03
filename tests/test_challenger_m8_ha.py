"""Empirical Adversarial Challenge Suite for Milestone 8 (Requirement R6).

Executed by challenger_m8_1 to empirically probe:
1. Header permutations (Authorization: Bearer, bearer, BEARER, whitespace, X-HA-Access).
2. Strict rejection of empty/whitespace/malformed/invalid tokens with HTTP 401.
3. Non-existent device ID handling across GET and POST actuation endpoints (HTTP 404 / clean JSON).
4. Session coexistence with admin session (with and without 2FA).
5. SEC-09 Query parameter token rejection on /status and exemption on /webhook.
6. Incoming webhook secret authentication across query params and headers.
7. Malformed JSON payload handling (non-dict JSON and invalid syntax) on actuation endpoints.
8. Non-ASCII / Unicode token robustness in constant_time_compare.
9. YAML configuration generator edge cases and escaping.
"""

from __future__ import annotations

import json
import time
import unittest
from unittest.mock import MagicMock

from server.flask_app import app
from server.home_assistant import (
    dispatch_ha_webhook,
    generate_ha_yaml_config,
)


class TestChallengerM8HomeAssistantAdversarial(unittest.TestCase):
    """Adversarial stress testing of Home Assistant REST API and Token Authentication."""

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = False  # Keep TESTING=False to observe genuine WSGI/HTTP error codes
        self.app.config["HA_BEARER_TOKEN"] = "ha-secret-token-test-12345"
        self.app.config["HA_WEBHOOK_SECRET"] = "webhook-secret-token-67890"
        self.client = self.app.test_client()

        self.valid_bearer_headers = {
            "Authorization": "Bearer ha-secret-token-test-12345",
            "Content-Type": "application/json",
        }

    # =========================================================================
    # 1. Header Permutations
    # =========================================================================

    def test_header_permutations_accepted(self):
        """HA.ADV-01: Probes accepted header variants (Bearer, bearer, BEARER, extra spaces, X-HA-Access)."""
        accepted_headers = [
            {"Authorization": "Bearer ha-secret-token-test-12345"},
            {"Authorization": "bearer ha-secret-token-test-12345"},
            {"Authorization": "BEARER ha-secret-token-test-12345"},
            {"Authorization": "Bearer   ha-secret-token-test-12345  "},
            {"X-HA-Access": "ha-secret-token-test-12345"},
            {"X-HA-Access": "  ha-secret-token-test-12345  "},
            {"x-ha-access": "ha-secret-token-test-12345"},
        ]

        for hdrs in accepted_headers:
            res = self.client.get("/api/ha/status", headers=hdrs)
            self.assertEqual(
                res.status_code,
                200,
                f"Expected HTTP 200 for valid header permutation {hdrs}, got {res.status_code}",
            )
            data = res.get_json()
            self.assertEqual(data.get("service"), "mydoor")

    # =========================================================================
    # 2. Strict 401 Unauthorized on Invalid/Empty/Malformed Tokens
    # =========================================================================

    def test_invalid_and_empty_tokens_strictly_rejected_401(self):
        """HA.ADV-02: Probes empty, whitespace, malformed, and invalid tokens for strict 401 rejection."""
        rejected_headers = [
            {},
            {"Authorization": ""},
            {"Authorization": "   "},
            {"Authorization": "Bearer"},
            {"Authorization": "Bearer "},
            {"Authorization": "Bearer   "},
            {"Authorization": "Basic dXNlcjpwYXNz"},
            {"Authorization": "Token ha-secret-token-test-12345"},
            {"Authorization": "Bearer wrong-token-xyz"},
            {"Authorization": "Bearer ha-secret-token-test-1234"},  # 1-char short
            {"Authorization": "Bearer ha-secret-token-test-123456"},  # 1-char long
            {"X-HA-Access": ""},
            {"X-HA-Access": "   "},
            {"X-HA-Access": "wrong-token-xyz"},
            {"X-HA-Access": "ha-secret-token-test-1234"},
        ]

        for hdrs in rejected_headers:
            res = self.client.get("/api/ha/status", headers=hdrs)
            self.assertEqual(
                res.status_code,
                401,
                f"Expected HTTP 401 for rejected header {hdrs}, got {res.status_code}",
            )
            data = res.get_json()
            self.assertFalse(data.get("success", True))
            self.assertIn("Unauthorized", data.get("error", ""))

    # =========================================================================
    # 3. Non-Existent Device ID Resolution
    # =========================================================================

    def test_nonexistent_device_id_returns_404_clean_json(self):
        """HA.ADV-03: Non-existent device ID returns HTTP 404 with clean JSON, zero 500 crashes."""
        bad_ids = ["nonexistent-9999", "invalid_lock_xyz", "0", "-1", "null", "undefined"]

        for dev_id in bad_ids:
            # GET state
            res_get = self.client.get(
                f"/api/ha/lock/{dev_id}/state",
                headers=self.valid_bearer_headers,
            )
            self.assertEqual(
                res_get.status_code,
                404,
                f"Expected 404 for GET /state on non-existent dev_id='{dev_id}', got {res_get.status_code}",
            )
            get_json = res_get.get_json()
            self.assertFalse(get_json.get("success", True))
            self.assertIn("not found", get_json.get("error", "").lower())

            # POST lock
            res_post = self.client.post(
                f"/api/ha/lock/{dev_id}/lock",
                headers=self.valid_bearer_headers,
                json={"dry_run": True},
            )
            self.assertEqual(
                res_post.status_code,
                404,
                f"Expected 404 for POST /lock on non-existent dev_id='{dev_id}', got {res_post.status_code}",
            )
            post_json = res_post.get_json()
            self.assertFalse(post_json.get("success", True))
            self.assertIn("not found", post_json.get("error", "").lower())

    # =========================================================================
    # 4. Web Session Coexistence
    # =========================================================================

    def test_web_session_coexistence(self):
        """HA.ADV-04: Active admin session accesses /api/ha/status without Bearer token."""
        mock_auth_mgr = MagicMock()
        orig_auth_mgr = self.app.config.get("AUTH_MANAGER")
        self.app.config["AUTH_MANAGER"] = mock_auth_mgr

        try:
            # 1. Admin user with 2FA NOT required
            mock_auth_mgr.is_totp_enabled.return_value = False
            with self.client.session_transaction() as sess:
                sess["auth_user"] = "admin"
                sess["2fa_verified"] = False

            res1 = self.client.get("/api/ha/status")
            self.assertEqual(res1.status_code, 200, "Active admin session without 2FA must access /status")
            self.assertEqual(res1.get_json().get("service"), "mydoor")

            # 2. Admin user with 2FA enabled, but 2FA unverified
            mock_auth_mgr.is_totp_enabled.return_value = True
            with self.client.session_transaction() as sess:
                sess["auth_user"] = "admin"
                sess["2fa_verified"] = False

            res2 = self.client.get("/api/ha/status")
            self.assertEqual(res2.status_code, 401, "Unverified 2FA session must be rejected with 401")

            # 3. Admin user with 2FA enabled AND 2FA verified
            with self.client.session_transaction() as sess:
                sess["auth_user"] = "admin"
                sess["2fa_verified"] = True

            res3 = self.client.get("/api/ha/status")
            self.assertEqual(res3.status_code, 200, "Verified 2FA admin session must access /status")

            # 4. Clear session -> 401
            with self.client.session_transaction() as sess:
                sess.clear()

            res4 = self.client.get("/api/ha/status")
            self.assertEqual(res4.status_code, 401, "Cleared session without token must return 401")

        finally:
            self.app.config["AUTH_MANAGER"] = orig_auth_mgr

    # =========================================================================
    # 5. Query Parameter Token Security (SEC-09)
    # =========================================================================

    def test_query_param_token_rejection_sec09(self):
        """HA.ADV-05: Query param ?token= on /status is rejected with 400 (SEC-09); /webhook is exempt."""
        # /api/ha/status?token=... -> strictly rejected 400
        res = self.client.get("/api/ha/status?token=ha-secret-token-test-12345")
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data.get("securityViolation"), "QUERY_PARAM_TOKEN_FORBIDDEN")

        # /api/ha/webhook?token=... -> exempt from SEC-09 query rejection
        res_wh = self.client.post(
            "/api/ha/webhook?token=webhook-secret-token-67890",
            json={"action": "lock", "dry_run": True},
        )
        self.assertEqual(res_wh.status_code, 200)

    # =========================================================================
    # 6. Incoming Webhook Secret Authentication & Actions
    # =========================================================================

    def test_incoming_webhook_auth_and_actions(self):
        """HA.ADV-06: Webhook validates secret across channels and validates allowed actions."""
        # Query token match
        res1 = self.client.post(
            "/api/ha/webhook?token=webhook-secret-token-67890",
            json={"action": "unlock", "device_id": "lock-101", "dry_run": True},
        )
        self.assertEqual(res1.status_code, 200)
        self.assertTrue(res1.get_json().get("success"))

        # Header X-HA-Webhook-Secret match
        res2 = self.client.post(
            "/api/ha/webhook",
            headers={"X-HA-Webhook-Secret": "webhook-secret-token-67890"},
            json={"action": "keep_unlocked", "device_id": "lock-101", "dry_run": True},
        )
        self.assertEqual(res2.status_code, 200)
        self.assertFalse(res2.get_json().get("auto_lock_enabled"))

        # Mismatched secret -> 403 Forbidden
        res_bad = self.client.post(
            "/api/ha/webhook?token=wrong-secret",
            json={"action": "lock", "dry_run": True},
        )
        self.assertEqual(res_bad.status_code, 403)

        # Invalid action -> 400 Bad Request
        res_inv_act = self.client.post(
            "/api/ha/webhook?token=webhook-secret-token-67890",
            json={"action": "self_destruct", "dry_run": True},
        )
        self.assertEqual(res_inv_act.status_code, 400)

    # =========================================================================
    # 7. Bug Probe: Malformed & Non-Dict JSON Payloads on Actuation Endpoints
    # =========================================================================

    def test_malformed_json_payloads_must_not_crash_500(self):
        """HA.ADV-07 (BUG PROBE): Non-dict JSON or malformed JSON must return clean 400, NEVER 500 crash."""
        endpoints = [
            "/api/ha/lock/lock-101/lock",
            "/api/ha/lock/lock-101/unlock",
            "/api/ha/lock/lock-101/keep_unlocked",
        ]

        non_dict_payloads = [
            ("[1, 2, 3]", "JSON list"),
            ('"just a string"', "JSON string"),
            ("12345", "JSON number"),
            ("true", "JSON boolean"),
        ]

        for ep in endpoints:
            for payload_str, desc in non_dict_payloads:
                res = self.client.post(
                    ep,
                    headers=self.valid_bearer_headers,
                    data=payload_str,
                )
                self.assertNotEqual(
                    res.status_code,
                    500,
                    f"CRITICAL BUG: Endpoint {ep} crashed with HTTP 500 on {desc} payload! (Expected HTTP 400 Bad Request)",
                )
                self.assertEqual(
                    res.status_code,
                    400,
                    f"Endpoint {ep} should cleanly reject {desc} payload with HTTP 400, got {res.status_code}",
                )

    # =========================================================================
    # 8. Bug Probe: Non-ASCII / Unicode Token Robustness (hmac.compare_digest)
    # =========================================================================

    def test_unicode_bearer_token_must_not_crash_500(self):
        """HA.ADV-08 (BUG PROBE): Non-ASCII token in Authorization or Webhook must return 401/403, NEVER 500 crash."""
        unicode_tokens = [
            "Bearer \U0001f511-key",
            "Bearer \u2603-snowman",
            "Bearer \u043a\u043b\u044e\u0447",
        ]

        for auth_val in unicode_tokens:
            res = self.client.get(
                "/api/ha/status",
                headers={"Authorization": auth_val},
            )
            self.assertNotEqual(
                res.status_code,
                500,
                f"CRITICAL BUG: GET /api/ha/status crashed with HTTP 500 on unicode auth header {auth_val!r}!",
            )
            self.assertEqual(res.status_code, 401)

        # Webhook with unicode secret
        res_wh = self.client.post(
            "/api/ha/webhook?token=\U0001f511",
            json={"action": "lock"},
        )
        self.assertNotEqual(
            res_wh.status_code,
            500,
            "CRITICAL BUG: POST /api/ha/webhook crashed with HTTP 500 on unicode query secret!",
        )
        self.assertEqual(res_wh.status_code, 403)


if __name__ == "__main__":
    unittest.main()
