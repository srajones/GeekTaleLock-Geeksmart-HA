"""Web API Security Hardening Automated Test Suite (Milestone 6).

Verifies:
1. Constant-time token comparison (SEC-08).
2. Query string credential rejection with HTTP 400 (SEC-09).
3. Header authentication via Authorization Bearer and X-API-Key (SEC-02).
4. Standard HTTP security headers injection (SEC-10).
5. CSRF protection on mutating POST routes (SEC-05).
6. Information disclosure redaction in /api/status (SEC-07).
7. Thread-safe actuation rate limiting (SEC-11).
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.flask_app import create_app
from server.security import constant_time_compare, mask_identifier


class TestServerSecurity(unittest.TestCase):
    """Test suite for server security hardening features."""

    def test_01_constant_time_comparison(self):
        """SEC-08: constant_time_compare works correctly and securely."""
        self.assertTrue(constant_time_compare("secret_token_123", "secret_token_123"))
        self.assertFalse(constant_time_compare("secret_token_123", "wrong_token_456"))
        self.assertFalse(constant_time_compare(None, "secret_token_123"))
        self.assertFalse(constant_time_compare("secret_token_123", None))
        self.assertFalse(constant_time_compare("", ""))

    def test_02_query_string_api_key_rejected(self):
        """SEC-09: API key in query parameters returns HTTP 400 with QUERY_PARAM_TOKEN_FORBIDDEN."""
        app = create_app(csrf_enabled=False)
        app.config["TESTING"] = True
        app.config["API_KEY"] = "my-secret-key-12345"

        with app.test_client() as client:
            res = client.get("/api/devices?api_key=my-secret-key-12345")
            self.assertEqual(res.status_code, 400)
            data = res.get_json()
            self.assertEqual(data.get("securityViolation"), "QUERY_PARAM_TOKEN_FORBIDDEN")
            self.assertFalse(data.get("success"))

    def test_03_header_bearer_and_x_api_key(self):
        """SEC-02: Authenticates via Authorization: Bearer <key> and X-API-Key: <key>."""
        app = create_app(csrf_enabled=False)
        app.config["TESTING"] = True
        app.config["API_KEY"] = "my-secret-key-12345"

        with app.test_client() as client:
            # 1. Without auth -> 401
            res_no_auth = client.get("/api/devices")
            self.assertEqual(res_no_auth.status_code, 401)

            # 2. With Authorization: Bearer
            res_bearer = client.get(
                "/api/devices",
                headers={"Authorization": "Bearer my-secret-key-12345"},
            )
            self.assertEqual(res_bearer.status_code, 200)

            # 3. With X-API-Key
            res_x_key = client.get(
                "/api/devices",
                headers={"X-API-Key": "my-secret-key-12345"},
            )
            self.assertEqual(res_x_key.status_code, 200)

    def test_04_security_headers_present(self):
        """SEC-10: Verifies standard HTTP security headers on responses."""
        app = create_app()
        app.config["TESTING"] = True

        with app.test_client() as client:
            res = client.get("/api/health")
            self.assertEqual(res.status_code, 200)

            headers = res.headers
            self.assertIn("Content-Security-Policy", headers)
            self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
            self.assertEqual(headers.get("X-Frame-Options"), "DENY")
            self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
            self.assertIn("Referrer-Policy", headers)
            self.assertIn("Permissions-Policy", headers)

    def test_05_csrf_protection_on_post_routes(self):
        """SEC-05: State-mutating POST requires valid CSRF cookie and token header."""
        app = create_app(csrf_enabled=True)
        app.config["TESTING"] = True

        with app.test_client() as client:
            # 1. Mutating unlock actuation without CSRF token -> 403
            res_no_csrf = client.post(
                "/api/devices/lock-101/action",
                json={"action": "unlock", "confirmed": True},
            )
            self.assertEqual(res_no_csrf.status_code, 403)
            data = res_no_csrf.get_json()
            self.assertTrue(data.get("csrfRequired"))

            # 2. Acquire CSRF token via GET /
            res_index = client.get("/")
            csrf_cookie = res_index.headers.get("Set-Cookie", "")
            # Extract mydoor_csrf_token value
            cookie = client.get_cookie("mydoor_csrf_token")
            token_val = cookie.value if cookie else None
            self.assertIsNotNone(token_val, "CSRF cookie must be set on client")

            # 3. Mutating unlock actuation with matching X-CSRF-Token header -> succeeds
            res_with_csrf = client.post(
                "/api/devices/lock-101/action",
                headers={"X-CSRF-Token": token_val},
                json={"action": "unlock", "confirmed": True, "dry_run": True},
            )
            self.assertEqual(res_with_csrf.status_code, 200)

    def test_06_status_redaction(self):
        """SEC-07: Information disclosure redaction in /api/status when redact_status=True."""
        app = create_app(redact_status=True)
        app.config["TESTING"] = True

        with app.test_client() as client:
            res = client.get("/api/status")
            self.assertEqual(res.status_code, 200)
            data = res.get_json()

            # Cache file path should be basename only
            cache_file = data["session"]["cacheFile"]
            self.assertNotIn("/", cache_file)
            self.assertNotIn("\\", cache_file)

            # Sensitive secrets must be redacted
            geeksmart = data["accounts"]["geeksmart"]
            self.assertEqual(geeksmart["tokenPreview"], "[REDACTED]")
            self.assertIn("***", geeksmart["email"])

            tuya = data["accounts"]["tuya"]
            self.assertEqual(tuya["appKey"], "[CONFIGURED]")
            self.assertEqual(tuya["homeId"], "[CONFIGURED]")

    def test_07_actuation_rate_limiting(self):
        """SEC-11: Actuation rate limiter throttles excessive actuation commands with 429."""
        app = create_app(rate_limit_enabled=True, csrf_enabled=False)
        app.config["TESTING"] = True

        with app.test_client() as client:
            # First 3 requests succeed
            statuses = []
            for _ in range(4):
                res = client.post(
                    "/api/devices/lock-101/action",
                    json={"action": "status", "confirmed": True},
                )
                statuses.append(res.status_code)

            self.assertEqual(statuses[:3], [200, 200, 200])
            self.assertEqual(statuses[3], 429)

            # Dry-run is exempt from rate limiting
            res_dry = client.post(
                "/api/devices/lock-101/action",
                json={"action": "unlock", "confirmed": True, "dry_run": True},
            )
            self.assertEqual(res_dry.status_code, 200)


if __name__ == "__main__":
    unittest.main()
