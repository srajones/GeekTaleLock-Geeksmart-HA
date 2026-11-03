"""Adversarial Security & CSRF Hardening Verification Test Suite.

Milestone 6 Empirical Challenge Suite:
1. CSRF bypass attempts on physical lock actuation (whitespace bypass, keep_unlocked omission).
2. Query string credential injection (?api_key=, ?token=, casing, encoding).
3. Rate limiting under rapid concurrent bursts (thread safety, alias fragmentation, memory retention).
4. Status endpoint information disclosure redaction (default unredacted exposure, secret masking).
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import sys
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.flask_app import create_app
from server.security import (
    RateLimiter,
    constant_time_compare,
    generate_csrf_token,
    mask_identifier,
    validate_csrf_token,
)



def _load_private_denylist():
    """Optional maintainer-only denylist (one regex per line).

    Personal identifiers are intentionally NOT committed to this public repo.
    Point GEEKDOOR_PRIVATE_DENYLIST at a local file, or create an untracked
    `.private-denylist` in the repo root (it is gitignored).
    """
    import os as _os
    import re as _re
    from pathlib import Path as _Path
    candidates = [_os.environ.get("GEEKDOOR_PRIVATE_DENYLIST", ""),
                  str(_Path(__file__).resolve().parent.parent / ".private-denylist")]
    pats = []
    for c in candidates:
        if c and _os.path.isfile(c):
            for line in open(c, encoding="utf-8"):
                line = line.strip()
                if line and not line.startswith("#"):
                    pats.append(_re.compile(line, _re.IGNORECASE))
            break
    return pats

class TestAdversarialCSRF(unittest.TestCase):
    """Adversarial challenge tests for CSRF protection on lock actuation."""

    def setUp(self):
        self.app = create_app(csrf_enabled=True, rate_limit_enabled=False)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_01_csrf_missing_cookie_rejected_403(self):
        """Missing CSRF cookie must reject physical lock actuation with HTTP 403."""
        res = self.client.post(
            "/api/devices/lock-101/action",
            json={"action": "unlock", "confirmed": True, "dry_run": False},
        )
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertTrue(data.get("csrfRequired"))
        self.assertFalse(data.get("success"))

    def test_02_csrf_missing_header_rejected_403(self):
        """CSRF cookie present but missing header/body token must return HTTP 403."""
        self.client.set_cookie("mydoor_csrf_token", generate_csrf_token())
        res = self.client.post(
            "/api/devices/lock-101/action",
            json={"action": "unlock", "confirmed": True, "dry_run": False},
        )
        self.assertEqual(res.status_code, 403)
        self.assertTrue(res.get_json().get("csrfRequired"))

    def test_03_csrf_token_mismatch_rejected_403(self):
        """Mismatched cookie and header tokens must return HTTP 403."""
        self.client.set_cookie("mydoor_csrf_token", generate_csrf_token())
        res = self.client.post(
            "/api/devices/lock-101/action",
            headers={"X-CSRF-Token": generate_csrf_token()},
            json={"action": "unlock", "confirmed": True, "dry_run": False},
        )
        self.assertEqual(res.status_code, 403)
        self.assertTrue(res.get_json().get("csrfRequired"))

    def test_04_csrf_empty_tokens_rejected_403(self):
        """Empty string tokens must return HTTP 403."""
        self.client.set_cookie("mydoor_csrf_token", "")
        res = self.client.post(
            "/api/devices/lock-101/action",
            headers={"X-CSRF-Token": ""},
            json={"action": "unlock", "confirmed": True, "dry_run": False},
        )
        self.assertEqual(res.status_code, 403)

    def test_05_csrf_whitespace_only_rejected_403(self):
        """Non-empty whitespace tokens must be rejected with HTTP 403 and never bypass validation."""
        cookie_token = " "
        header_token = "   \t  "

        self.assertFalse(
            constant_time_compare(cookie_token, header_token),
            "constant_time_compare must return False for whitespace strings",
        )
        self.assertFalse(
            validate_csrf_token(header_token, cookie_token),
            "validate_csrf_token must return False for whitespace tokens",
        )

        self.client.set_cookie("mydoor_csrf_token", cookie_token)
        res = self.client.post(
            "/api/devices/lock-101/action",
            headers={"X-CSRF-Token": header_token},
            json={"action": "unlock", "confirmed": True, "dry_run": False},
        )
        self.assertEqual(res.status_code, 403)
        self.assertTrue(res.get_json().get("csrfRequired"))

    def test_06_csrf_mutating_actions_enforce_csrf_403(self):
        """Mutating keep_unlocked and auto_lock actions strictly enforce CSRF (HTTP 403)."""
        res_action = self.client.post(
            "/api/devices/lock-101/action",
            json={"action": "keep_unlocked", "confirmed": True, "dry_run": False},
        )
        self.assertEqual(res_action.status_code, 403)
        self.assertTrue(res_action.get_json().get("csrfRequired"))

        res_endpoint = self.client.post(
            "/api/devices/lock-101/keep_unlocked",
            json={"confirmed": True, "dry_run": False},
        )
        self.assertEqual(res_endpoint.status_code, 403)
        self.assertTrue(res_endpoint.get_json().get("csrfRequired"))

        res_auto = self.client.post(
            "/api/devices/lock-101/auto_lock",
            json={"confirmed": True, "dry_run": False, "enabled": False},
        )
        self.assertEqual(res_auto.status_code, 403)
        self.assertTrue(res_auto.get_json().get("csrfRequired"))

    def test_07_csrf_legitimate_double_submit_succeeds(self):
        """Legitimate 64-character hex CSRF token in cookie and header succeeds."""
        token = generate_csrf_token()
        self.client.set_cookie("mydoor_csrf_token", token)
        res = self.client.post(
            "/api/devices/lock-101/action",
            headers={"X-CSRF-Token": token},
            json={"action": "unlock", "confirmed": True, "dry_run": True},
        )
        self.assertEqual(res.status_code, 200)

    def test_08_csrf_api_bearer_token_exemption(self):
        """API clients with valid Bearer token bypass CSRF for automated HA integrations."""
        self.app.config["API_KEY"] = "ha-long-lived-token-999"
        res = self.client.post(
            "/api/devices/lock-101/action",
            headers={"Authorization": "Bearer ha-long-lived-token-999"},
            json={"action": "unlock", "confirmed": True, "dry_run": True},
        )
        self.assertEqual(res.status_code, 200)

    def test_09_csrf_invalid_api_bearer_token_blocked(self):
        """API clients with invalid Bearer token are blocked."""
        self.app.config["API_KEY"] = "ha-long-lived-token-999"
        res = self.client.post(
            "/api/devices/lock-101/action",
            headers={"Authorization": "Bearer wrong-token-000"},
            json={"action": "unlock", "confirmed": True, "dry_run": True},
        )
        self.assertIn(res.status_code, (401, 403))


class TestAdversarialQueryParamCredentials(unittest.TestCase):
    """Adversarial challenge tests for query string credential injection (?api_key=)."""

    def setUp(self):
        self.app = create_app(csrf_enabled=False)
        self.app.config["TESTING"] = True
        self.app.config["API_KEY"] = "super-secret-api-key"
        self.client = self.app.test_client()

    def test_01_query_param_api_key_rejected(self):
        """?api_key= is rejected with HTTP 400 and QUERY_PARAM_TOKEN_FORBIDDEN."""
        res = self.client.get("/api/devices?api_key=super-secret-api-key")
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data.get("securityViolation"), "QUERY_PARAM_TOKEN_FORBIDDEN")
        self.assertFalse(data.get("success"))

    def test_02_query_param_token_rejected(self):
        """?token= is rejected with HTTP 400."""
        res = self.client.get("/api/devices?token=super-secret-api-key")
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.get_json().get("securityViolation"), "QUERY_PARAM_TOKEN_FORBIDDEN")

    def test_03_query_param_access_token_rejected(self):
        """?access_token= is rejected with HTTP 400."""
        res = self.client.get("/api/devices?access_token=super-secret-api-key")
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.get_json().get("securityViolation"), "QUERY_PARAM_TOKEN_FORBIDDEN")

    def test_04_query_param_url_encoded_key_rejected(self):
        """URL-encoded parameter ?%61%70%69%5F%6B%65%79= (api_key) is rejected with HTTP 400."""
        res = self.client.get("/api/devices?%61%70%69%5F%6B%65%79=super-secret-api-key")
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.get_json().get("securityViolation"), "QUERY_PARAM_TOKEN_FORBIDDEN")

    def test_05_query_param_empty_value_rejected(self):
        """?api_key without value is rejected with HTTP 400."""
        res = self.client.get("/api/devices?api_key")
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.get_json().get("securityViolation"), "QUERY_PARAM_TOKEN_FORBIDDEN")

    def test_06_query_param_mixed_params_rejected(self):
        """?foo=bar&api_key=xxx embedded within other parameters is rejected with HTTP 400."""
        res = self.client.get("/api/devices?format=json&api_key=super-secret-api-key&debug=1")
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.get_json().get("securityViolation"), "QUERY_PARAM_TOKEN_FORBIDDEN")

    def test_07_query_param_mixed_case_not_authenticated(self):
        """EMPIRICAL OBSERVATION: Uppercase ?API_KEY= bypasses 400 filter but fails authentication (HTTP 401)."""
        res = self.client.get("/api/devices?API_KEY=super-secret-api-key")
        # The query parameter does NOT authenticate the client; it returns 401 Unauthorized
        self.assertEqual(res.status_code, 401)
        data = res.get_json()
        self.assertFalse(data.get("success"))
        self.assertIn("Unauthorized", data.get("error"))

    def test_08_webhook_query_token_exemption(self):
        """Home Assistant external webhook is properly exempted from query parameter rejection."""
        # /api/ha/webhook route does not return 400 QUERY_PARAM_TOKEN_FORBIDDEN when receiving token
        res = self.client.post("/api/ha/webhook?token=external_webhook_token")
        self.assertNotEqual(res.status_code, 400)


class TestAdversarialRateLimiter(unittest.TestCase):
    """Adversarial stress-testing of RateLimiter under concurrency and edge cases."""

    def test_01_concurrent_burst_thread_safety(self):
        """50 concurrent threads firing simultaneously: exactly 3 succeed, 47 throttled."""
        limiter = RateLimiter()
        results = []

        def worker():
            return limiter.is_allowed("dev-1", max_events=3, window_seconds=30.0)

        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
            futures = [executor.submit(worker) for _ in range(50)]
            for f in concurrent.futures.as_completed(futures):
                results.append(f.result())

        allowed_count = sum(1 for allowed, _ in results if allowed)
        throttled_count = sum(1 for allowed, _ in results if not allowed)

        self.assertEqual(allowed_count, 3, "Exactly 3 requests should be permitted in window")
        self.assertEqual(throttled_count, 47, "Exactly 47 requests should be throttled")

    def test_02_flask_actuation_concurrent_burst(self):
        """Full Flask app test client under concurrent burst of 50 actuation requests."""
        app = create_app(rate_limit_enabled=True, csrf_enabled=False)
        app.config["TESTING"] = True
        client = app.test_client()

        status_codes = []

        def send_req():
            res = client.post(
                "/api/devices/lock-101/action",
                json={"action": "status", "confirmed": True, "dry_run": False},
            )
            return res.status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(send_req) for _ in range(50)]
            for f in concurrent.futures.as_completed(futures):
                status_codes.append(f.result())

        self.assertEqual(status_codes.count(200), 3)
        self.assertEqual(status_codes.count(429), 47)

    def test_03_rate_limiter_retry_after_header(self):
        """Throttled requests return HTTP 429 with valid numeric Retry-After header."""
        app = create_app(rate_limit_enabled=True, csrf_enabled=False)
        app.config["TESTING"] = True
        client = app.test_client()

        # Fire 3 requests to exhaust limit
        for _ in range(3):
            client.post(
                "/api/devices/lock-101/action",
                json={"action": "status", "confirmed": True, "dry_run": False},
            )

        # 4th request must be throttled with Retry-After header
        res = client.post(
            "/api/devices/lock-101/action",
            json={"action": "status", "confirmed": True, "dry_run": False},
        )
        self.assertEqual(res.status_code, 429)
        self.assertIn("Retry-After", res.headers)
        retry_val = float(res.headers["Retry-After"])
        self.assertGreater(retry_val, 0)
        self.assertLessEqual(retry_val, 31)

        data = res.get_json()
        self.assertTrue(data.get("rateLimitExceeded"))
        self.assertGreater(data.get("retryAfter"), 0)

    def test_04_device_alias_rate_limiting_canonicalization(self):
        """Device alias canonicalization ensures all aliases share a unified rate limiting bucket."""
        app = create_app(rate_limit_enabled=True, csrf_enabled=False)
        app.config["TESTING"] = True
        client = app.test_client()

        aliases = ["101", "lock-101", "ebexamplelock001", "livingroom"]
        all_status_codes = []

        for alias in aliases:
            for _ in range(3):
                res = client.post(
                    f"/api/devices/{alias}/action",
                    json={"action": "status", "confirmed": True, "dry_run": False},
                )
                all_status_codes.append(res.status_code)

        self.assertEqual(len(all_status_codes), 12)
        # Exactly 3 requests succeed across all aliases for the same lock; the remaining 9 are throttled (HTTP 429)
        self.assertEqual(all_status_codes.count(200), 3)
        self.assertEqual(all_status_codes.count(429), 9)

    def test_05_rate_limiter_memory_retention(self):
        """RateLimiter dictionary grows unbounded when provided with distinct keys."""
        limiter = RateLimiter()
        for i in range(500):
            limiter.is_allowed(f"ephemeral-key-{i}", 3, 0.001)

        time.sleep(0.01)
        # Even after timestamps expire, dictionary retains all 500 keys
        self.assertEqual(len(limiter._records), 500)


class TestAdversarialStatusRedaction(unittest.TestCase):
    """Adversarial verification of status endpoint redaction and secret scrubbing."""

    def test_01_redacted_status_masks_sensitive_identifiers(self):
        """When redact_status=True, sensitive tokens and file paths are masked."""
        app = create_app(redact_status=True)
        app.config["TESTING"] = True
        client = app.test_client()

        res = client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertTrue(data.get("redacted"))

        # 1. Cache file path is basename only (no directory traversal info)
        cache_file = data["session"]["cacheFile"]
        self.assertNotIn("/", cache_file)
        self.assertNotIn("\\", cache_file)

        # 2. Token preview is fully redacted
        self.assertEqual(data["accounts"]["geeksmart"]["tokenPreview"], "[REDACTED]")

        # 3. Email is masked
        self.assertIn("***", data["accounts"]["geeksmart"]["email"])

        # 4. Tuya secrets are masked
        self.assertEqual(data["accounts"]["tuya"]["appKey"], "[CONFIGURED]")
        self.assertEqual(data["accounts"]["tuya"]["homeId"], "[CONFIGURED]")

    def test_02_default_status_redaction_enforced(self):
        """create_app() defaults redact_status to True, redacting server paths and credentials."""
        app = create_app()
        app.config["TESTING"] = True
        client = app.test_client()

        res = client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # In default mode, status redaction must be enabled
        self.assertTrue(data.get("redacted"), "Default status endpoint must have redaction enabled")
        cache_file = data["session"]["cacheFile"]
        self.assertFalse(os.path.isabs(cache_file), "Default status must not disclose absolute filesystem path")
        self.assertNotIn("/", cache_file)
        self.assertNotIn("\\", cache_file)

        # In default mode, token preview must be fully redacted
        token_preview = data["accounts"]["geeksmart"]["tokenPreview"]
        self.assertEqual(token_preview, "[REDACTED]")

    def test_03_zero_residual_hardcoded_credentials_in_codebase(self):
        """Verify that historical passwords, emails, GPS, and ISP IPs are completely absent from repo."""
        forbidden_regexes = [
            re.compile(r"REDACTED_TEST_PASSWORD"),
            re.compile(r"EXAMPLE_UID_REDACTED"),
        ] + _load_private_denylist()

        scanned_dirs = ["client", "server", "scripts", "tests"]
        found_matches = []

        for folder in scanned_dirs:
            target = REPO_ROOT / folder
            if not target.exists():
                continue
            for f in target.rglob("*"):
                if not f.is_file() or f.name.endswith(".pyc") or f.name.endswith(".pyo"):
                    continue
                # Skip the security audit test file and this file itself which contain the regex strings
                if f.name in ("test_security_audit.py", "test_adversarial_security.py"):
                    continue
                try:
                    text = f.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                for pattern in forbidden_regexes:
                    for line_idx, line in enumerate(text.splitlines(), start=1):
                        if pattern.search(line):
                            found_matches.append(f"{f.relative_to(REPO_ROOT)}:{line_idx} -> {line.strip()[:60]}")

        self.assertEqual(
            len(found_matches),
            0,
            f"Sensitive credentials or PII found in codebase:\n" + "\n".join(found_matches),
        )


if __name__ == "__main__":
    unittest.main()
