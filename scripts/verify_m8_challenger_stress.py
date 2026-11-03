#!/usr/bin/env python3
"""Empirical Challenger Stress Harness for Milestone 8 Iteration 2 (Requirement R6).

Executed by challenger_m8_iter2_1 to empirically probe:
1. Malformed JSON syntax and non-dict JSON primitives on actuation endpoints.
2. Empty bodies and valid JSON payloads on actuation endpoints.
3. Unicode / Emoji bearer tokens and webhook secrets in headers, query params, and JSON bodies.
4. Valid Unicode bearer token and webhook secret matching.
5. Direct security.constant_time_compare stress and boundary checks.
6. Webhook status read-only idempotency (Finding 1) and dispatch_ha_webhook safety (Finding 2).
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from unittest.mock import MagicMock

# Ensure repo root is on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from server.flask_app import app
from server.home_assistant import dispatch_ha_webhook
from server.security import constant_time_compare


class TestM8AdversarialStressHarness(unittest.TestCase):
    """Deep adversarial stress tests for Home Assistant and Cryptographic comparisons."""

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = False  # Keep TESTING=False to verify genuine WSGI/HTTP error handling
        self.app.config["HA_BEARER_TOKEN"] = "ha-secret-token-test-12345"
        self.app.config["HA_WEBHOOK_SECRET"] = "webhook-secret-token-67890"
        self.app.config["RATE_LIMIT_ENABLED"] = False
        self.client = self.app.test_client()

        self.valid_headers = {
            "Authorization": "Bearer ha-secret-token-test-12345",
            "Content-Type": "application/json",
        }

    # =========================================================================
    # 1. JSON Payload Stress Tests (Bug 1 Probe)
    # =========================================================================

    def test_empty_and_valid_bodies_on_actuation_endpoints(self):
        """Probes empty body, whitespace, and valid JSON object across /lock, /unlock, /keep_unlocked."""
        endpoints = [
            "/api/ha/lock/lock-101/lock",
            "/api/ha/lock/lock-101/unlock",
            "/api/ha/lock/lock-101/keep_unlocked",
        ]

        empty_bodies = [
            (b"", "empty bytes"),
            ("", "empty string"),
            (b"   ", "whitespace bytes"),
            ("   \n\t  ", "whitespace string"),
        ]

        for ep in endpoints:
            # 1. Valid JSON object with dry_run=True must return HTTP 200
            res_valid = self.client.post(
                ep,
                headers=self.valid_headers,
                data=json.dumps({"dry_run": True}),
            )
            self.assertEqual(
                res_valid.status_code,
                200,
                f"Valid JSON object must return 200 on {ep}, got {res_valid.status_code}",
            )
            data_valid = res_valid.get_json()
            self.assertTrue(data_valid.get("success"))

            # 2. Empty bodies default dry_run=False, verifying default behavior without crash (never 500)
            for body_val, desc in empty_bodies:
                res_empty = self.client.post(
                    ep,
                    headers=self.valid_headers,
                    data=body_val,
                )
                self.assertNotEqual(
                    res_empty.status_code,
                    500,
                    f"Empty body ({desc}) on {ep} caused 500 Internal Server Error!",
                )
                # In test environment without cloud credentials, dry_run=False returns clean 502 (or 429 if rate limited)
                self.assertIn(
                    res_empty.status_code,
                    [200, 429, 502],
                    f"Empty body ({desc}) on {ep} should return 200, 429, or 502, got {res_empty.status_code}",
                )

        # 3. Empty body with mocked device execution succeeds with HTTP 200
        mock_exec = MagicMock(return_value=({"success": True}, 200))
        orig_fn = getattr(self.app, "_execute_device_action", None)
        self.app._execute_device_action = mock_exec
        try:
            for ep in endpoints:
                for body_val, desc in empty_bodies:
                    res_mock = self.client.post(
                        ep,
                        headers=self.valid_headers,
                        data=body_val,
                    )
                    self.assertEqual(
                        res_mock.status_code,
                        200,
                        f"Empty body ({desc}) on {ep} with mock execution must return 200, got {res_mock.status_code}",
                    )
                    self.assertTrue(res_mock.get_json().get("success"))
        finally:
            self.app._execute_device_action = orig_fn

    def test_malformed_json_syntax_rejected_clean_400(self):
        """Probes malformed JSON syntax: must return clean HTTP 400 Bad Request, never 500."""
        endpoints = [
            "/api/ha/lock/lock-101/lock",
            "/api/ha/lock/lock-101/unlock",
            "/api/ha/lock/lock-101/keep_unlocked",
        ]

        malformed_inputs = [
            ("{invalid", "unquoted key syntax"),
            ('{"dry_run":', "truncated JSON"),
            ('{"dry_run": true,}', "trailing comma syntax"),
            ("{'dry_run': True}", "python dict syntax with single quotes"),
            ("<<<NOT_JSON>>>", "random xml/tag syntax"),
            ("\x00\x01\x02", "binary garbage"),
        ]

        for ep in endpoints:
            for bad_input, desc in malformed_inputs:
                res = self.client.post(
                    ep,
                    headers=self.valid_headers,
                    data=bad_input,
                )
                self.assertNotEqual(
                    res.status_code,
                    500,
                    f"CRITICAL: {ep} crashed with 500 on malformed syntax ({desc})!",
                )
                self.assertEqual(
                    res.status_code,
                    400,
                    f"{ep} should reject malformed syntax ({desc}) with 400, got {res.status_code}",
                )
                data = res.get_json()
                self.assertFalse(data.get("success", True))
                self.assertIn("Malformed JSON", data.get("error", ""))

    def test_non_dict_json_primitives_and_lists_rejected_clean_400(self):
        """Probes non-dict JSON primitives/lists: must return clean HTTP 400 Bad Request, never 500."""
        endpoints = [
            "/api/ha/lock/lock-101/lock",
            "/api/ha/lock/lock-101/unlock",
            "/api/ha/lock/lock-101/keep_unlocked",
        ]

        non_dict_inputs = [
            ("[1, 2, 3]", "JSON integer list"),
            ('["a", "b", "c"]', "JSON string list"),
            ("[{}]", "JSON list with empty dict"),
            ('"hello world"', "JSON string primitive"),
            ("12345", "JSON integer primitive"),
            ("3.14159", "JSON float primitive"),
            ("true", "JSON boolean true"),
            ("false", "JSON boolean false"),
            ("null", "JSON null primitive"),
        ]

        for ep in endpoints:
            for raw_val, desc in non_dict_inputs:
                res = self.client.post(
                    ep,
                    headers=self.valid_headers,
                    data=raw_val,
                )
                self.assertNotEqual(
                    res.status_code,
                    500,
                    f"CRITICAL: {ep} crashed with 500 on non-dict payload ({desc})!",
                )
                self.assertEqual(
                    res.status_code,
                    400,
                    f"{ep} should reject non-dict payload ({desc}) with 400, got {res.status_code}",
                )
                data = res.get_json()
                self.assertFalse(data.get("success", True))
                self.assertIn("Malformed JSON", data.get("error", ""))

    def test_webhook_malformed_and_non_dict_json_rejected_clean_400(self):
        """Probes /api/ha/webhook with malformed syntax and non-dict JSON."""
        # 1. Malformed syntax
        res_malformed = self.client.post(
            "/api/ha/webhook?token=webhook-secret-token-67890",
            headers={"Content-Type": "application/json"},
            data="{bad_json",
        )
        self.assertNotEqual(res_malformed.status_code, 500)
        self.assertEqual(res_malformed.status_code, 400)
        self.assertIn("Malformed JSON", res_malformed.get_json().get("error", ""))

        # 2. Non-dict JSON list
        res_list = self.client.post(
            "/api/ha/webhook?token=webhook-secret-token-67890",
            headers={"Content-Type": "application/json"},
            data="[1, 2, 3]",
        )
        self.assertNotEqual(res_list.status_code, 500)
        self.assertEqual(res_list.status_code, 400)
        self.assertIn("Malformed JSON", res_list.get_json().get("error", ""))

        # 3. Empty body on webhook -> missing 'action' parameter -> clean 400
        res_empty = self.client.post(
            "/api/ha/webhook?token=webhook-secret-token-67890",
            headers={"Content-Type": "application/json"},
            data="",
        )
        self.assertNotEqual(res_empty.status_code, 500)
        self.assertEqual(res_empty.status_code, 400)
        self.assertIn("action", res_empty.get_json().get("error", "").lower())

    # =========================================================================
    # 2. Unicode and Emoji Token Tests (Bug 2 Probe)
    # =========================================================================

    def test_unicode_and_emoji_tokens_on_ha_authenticated_endpoints(self):
        """Probes non-ASCII / Unicode tokens on endpoints protected by @ha_authenticated."""
        test_endpoints = [
            ("/api/ha/status", "GET", None),
            ("/api/ha/lock/lock-101/state", "GET", None),
            ("/api/ha/lock/lock-101/lock", "POST", json.dumps({"dry_run": True})),
        ]

        adversarial_tokens = [
            "🔑-token",
            "\u2603",
            "门锁-token",
            "🚀🔥🔒✨",
            "\U0001f511",
            "ñandú-tökën",
            "\u043a\u043b\u044e\u0447",
            "مفتاح-token",
            "בדיקה-token",
            "\u202eRTL_override",
            "token_with_null_\x00_byte",
        ]

        for path, method, body in test_endpoints:
            for tok in adversarial_tokens:
                # 1. Test Authorization: Bearer <tok>
                bearer_hdr = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}
                if method == "GET":
                    res_bearer = self.client.get(path, headers=bearer_hdr)
                else:
                    res_bearer = self.client.post(path, headers=bearer_hdr, data=body)

                self.assertNotEqual(
                    res_bearer.status_code,
                    500,
                    f"CRITICAL: {method} {path} crashed with 500 on Bearer token {tok!r}!",
                )
                self.assertEqual(
                    res_bearer.status_code,
                    401,
                    f"{method} {path} should reject invalid Bearer token {tok!r} with 401, got {res_bearer.status_code}",
                )

                # 2. Test X-HA-Access: <tok>
                x_ha_hdr = {"X-HA-Access": tok, "Content-Type": "application/json"}
                if method == "GET":
                    res_xha = self.client.get(path, headers=x_ha_hdr)
                else:
                    res_xha = self.client.post(path, headers=x_ha_hdr, data=body)

                self.assertNotEqual(
                    res_xha.status_code,
                    500,
                    f"CRITICAL: {method} {path} crashed with 500 on X-HA-Access token {tok!r}!",
                )
                self.assertEqual(
                    res_xha.status_code,
                    401,
                    f"{method} {path} should reject invalid X-HA-Access token {tok!r} with 401, got {res_xha.status_code}",
                )

    def test_unicode_and_emoji_tokens_on_webhook(self):
        """Probes non-ASCII / Unicode tokens on /api/ha/webhook via query param, header, and body."""
        adversarial_secrets = [
            "🔑-token",
            "\u2603",
            "门锁-token",
            "🚀🔥🔒✨",
            "\U0001f511",
            "ñandú-secret",
        ]

        for sec in adversarial_secrets:
            # 1. Via query parameter ?token=...
            res_query = self.client.post(
                f"/api/ha/webhook?token={sec}",
                json={"action": "lock", "dry_run": True},
            )
            self.assertNotEqual(
                res_query.status_code,
                500,
                f"CRITICAL: /api/ha/webhook crashed with 500 on unicode query secret {sec!r}!",
            )
            self.assertEqual(
                res_query.status_code,
                403,
                f"/api/ha/webhook should reject invalid query secret {sec!r} with 403, got {res_query.status_code}",
            )

            # 2. Via header X-HA-Webhook-Secret: ...
            res_hdr = self.client.post(
                "/api/ha/webhook",
                headers={"X-HA-Webhook-Secret": sec},
                json={"action": "lock", "dry_run": True},
            )
            self.assertNotEqual(
                res_hdr.status_code,
                500,
                f"CRITICAL: /api/ha/webhook crashed with 500 on unicode header secret {sec!r}!",
            )
            self.assertEqual(
                res_hdr.status_code,
                403,
                f"/api/ha/webhook should reject invalid header secret {sec!r} with 403, got {res_hdr.status_code}",
            )

            # 3. Via body JSON {"token": ...}
            res_body = self.client.post(
                "/api/ha/webhook",
                json={"token": sec, "action": "lock", "dry_run": True},
            )
            self.assertNotEqual(
                res_body.status_code,
                500,
                f"CRITICAL: /api/ha/webhook crashed with 500 on unicode body secret {sec!r}!",
            )
            self.assertEqual(
                res_body.status_code,
                403,
                f"/api/ha/webhook should reject invalid body secret {sec!r} with 403, got {res_body.status_code}",
            )

    def test_legitimate_unicode_bearer_and_webhook_token_matching(self):
        """Probes legitimate Unicode bearer tokens and webhook secrets when configured."""
        orig_bearer = self.app.config.get("HA_BEARER_TOKEN")
        orig_webhook = self.app.config.get("HA_WEBHOOK_SECRET")

        try:
            # 1. Configure Unicode Bearer Token
            unicode_bearer = "🔑-secret-token-门锁-2026"
            self.app.config["HA_BEARER_TOKEN"] = unicode_bearer

            # Matching Bearer token succeeds
            res_match = self.client.get(
                "/api/ha/status",
                headers={"Authorization": f"Bearer {unicode_bearer}"},
            )
            self.assertEqual(res_match.status_code, 200)
            self.assertEqual(res_match.get_json().get("service"), "mydoor")

            # Mismatched Unicode Bearer token rejected cleanly with 401
            res_mismatch = self.client.get(
                "/api/ha/status",
                headers={"Authorization": "Bearer 🔑-wrong-token-门锁-2026"},
            )
            self.assertEqual(res_mismatch.status_code, 401)

            # 2. Configure Unicode Webhook Secret
            unicode_webhook = "🚀-webhook-secret-守护-999"
            self.app.config["HA_WEBHOOK_SECRET"] = unicode_webhook

            # Matching Webhook secret succeeds
            res_wh_match = self.client.post(
                f"/api/ha/webhook?token={unicode_webhook}",
                json={"action": "lock", "dry_run": True},
            )
            self.assertEqual(res_wh_match.status_code, 200)
            self.assertTrue(res_wh_match.get_json().get("success"))

            # Mismatched Webhook secret rejected cleanly with 403
            res_wh_mismatch = self.client.post(
                "/api/ha/webhook?token=🚀-wrong-secret",
                json={"action": "lock", "dry_run": True},
            )
            self.assertEqual(res_wh_mismatch.status_code, 403)

        finally:
            self.app.config["HA_BEARER_TOKEN"] = orig_bearer
            self.app.config["HA_WEBHOOK_SECRET"] = orig_webhook

    # =========================================================================
    # 3. Cryptographic Constant-Time Comparison Unit Stress
    # =========================================================================

    def test_constant_time_compare_comprehensive_matrix(self):
        """Stress-tests constant_time_compare across types, encodings, and edge cases."""
        # Equivalent Unicode / ASCII / Bytes
        self.assertTrue(constant_time_compare("hello", "hello"))
        self.assertTrue(constant_time_compare("🔑-key", "🔑-key"))
        self.assertTrue(constant_time_compare("门锁", "门锁"))
        self.assertTrue(constant_time_compare(b"raw-bytes-123", b"raw-bytes-123"))
        self.assertTrue(constant_time_compare("same_bytes", b"same_bytes"))
        self.assertTrue(constant_time_compare(b"same_bytes", "same_bytes"))

        # Differences
        self.assertFalse(constant_time_compare("hello", "world"))
        self.assertFalse(constant_time_compare("🔑-key1", "🔑-key2"))
        self.assertFalse(constant_time_compare("门锁", "开锁"))
        self.assertFalse(constant_time_compare("a", "A"))

        # Non-string / Non-bytes types (must fail safely without exception)
        self.assertFalse(constant_time_compare(None, "hello"))
        self.assertFalse(constant_time_compare("hello", None))
        self.assertFalse(constant_time_compare(None, None))
        self.assertFalse(constant_time_compare(12345, "12345"))
        self.assertFalse(constant_time_compare([], "[]"))
        self.assertFalse(constant_time_compare({}, "{}"))

        # Empty & whitespace values
        self.assertFalse(constant_time_compare("", ""))
        self.assertFalse(constant_time_compare("   ", "   "))
        self.assertFalse(constant_time_compare(b"", b""))
        self.assertFalse(constant_time_compare(b"   ", b"   "))
        self.assertFalse(constant_time_compare("", "hello"))
        self.assertFalse(constant_time_compare("hello", ""))

    # =========================================================================
    # 4. Finding 1 & Finding 2 Remediation Verification
    # =========================================================================

    def test_webhook_status_is_strictly_read_only_and_idempotent(self):
        """Verifies Finding 1: action: 'status' does NOT mutate STATE_OVERRIDES or trigger webhooks."""
        orig_overrides = dict(self.app.config.get("STATE_OVERRIDES", {}))
        try:
            self.app.config["STATE_OVERRIDES"] = {"lock-101": "LOCKED"}

            res = self.client.post(
                "/api/ha/webhook?token=webhook-secret-token-67890",
                json={"action": "status", "device_id": "lock-101"},
            )
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data.get("action"), "status")
            self.assertEqual(data.get("state"), "locked")

            # Verify STATE_OVERRIDES was NOT modified to UNLOCKED
            self.assertEqual(
                self.app.config["STATE_OVERRIDES"].get("lock-101"),
                "LOCKED",
                "Finding 1 Regression: action: 'status' mutated STATE_OVERRIDES to UNLOCKED!",
            )
        finally:
            self.app.config["STATE_OVERRIDES"] = orig_overrides

    def test_dispatch_ha_webhook_safely_handles_none_or_malformed_payload(self):
        """Verifies Finding 2: dispatch_ha_webhook(None) does not raise synchronous TypeError."""
        try:
            # None payload must not raise TypeError
            t1 = dispatch_ha_webhook(None, "http://127.0.0.1:9999/dummy")
            self.assertIsNotNone(t1)

            # Non-dict payload must not raise TypeError
            t2 = dispatch_ha_webhook(["not", "a", "dict"], "http://127.0.0.1:9999/dummy")
            self.assertIsNotNone(t2)
        except TypeError as exc:
            self.fail(f"Finding 2 Regression: dispatch_ha_webhook raised TypeError: {exc}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
