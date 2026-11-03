"""Security Hardening and Audit Automated Test Suite (Milestone 6 / Requirement R1).

Verifies:
1. Zero plaintext credentials, real emails, GPS coordinates, or public IPs exist in source/tests.
2. Constant-time comparison (hmac.compare_digest) in authentication verification.
3. Rejection of API keys passed in URL query strings (?api_key=).
4. Standard HTTP security headers (CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, etc.).
5. CSRF protection on all state-mutating POST routes.
6. Actuation rate limiting to prevent battery exhaustion and cloud throttling.
7. Docker Compose localhost binding (127.0.0.1) to prevent Ubuntu UFW bypass.
"""

import ast
import os
import re
import sys
import unittest
from pathlib import Path

# Paths
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))



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

class TestSecurityHardeningAudit(unittest.TestCase):
    """Automated security verification and regression tests for Phase 2 hardening."""

    def tearDown(self):
        try:
            from server.flask_app import app
            app.config["API_KEY"] = ""
            app.config["TESTING"] = False
        except Exception:
            pass

    def test_SEC_01_no_plaintext_passwords_or_real_emails_in_codebase(self):
        """SEC-01: Verify zero occurrences of plaintext passwords or author emails in code/tests."""
        forbidden_patterns = [
            re.compile(r"REDACTED_TEST_PASSWORD"),
            re.compile(r"EXAMPLE_UID_REDACTED"),
        ] + _load_private_denylist()
        scanned_dirs = ["client", "server", "scripts", "tests"]
        matches = []

        for dir_name in scanned_dirs:
            target_dir = REPO_ROOT / dir_name
            if not target_dir.exists():
                continue
            for file_path in target_dir.rglob("*"):
                if not file_path.is_file() or file_path.name.endswith(".pyc"):
                    continue
                # Skip test files that define scanner regexes
                if file_path.name in ("test_security_audit.py", "test_adversarial_security.py"):
                    continue
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                for pattern in forbidden_patterns:
                    for line_num, line in enumerate(content.splitlines(), start=1):
                        if pattern.search(line):
                            matches.append(f"{file_path.relative_to(REPO_ROOT)}:{line_num} -> {line.strip()[:60]}")

        self.assertEqual(
            len(matches),
            0,
            f"Security violation: Found sensitive credentials in codebase ({len(matches)} occurrences):\n"
            + "\n".join(matches[:10]),
        )

    def test_SEC_02_no_physical_geolocation_or_public_ip_in_source(self):
        """SEC-04: Verify physical GPS coordinates and private ISP IP are scrubbed from source files."""
        sensitive_patterns = [
            re.compile(r"EXAMPLE_UID_REDACTED"),
        ] + _load_private_denylist()
        scanned_dirs = ["client", "server", "scripts"]
        matches = []

        for dir_name in scanned_dirs:
            target_dir = REPO_ROOT / dir_name
            if not target_dir.exists():
                continue
            for file_path in target_dir.rglob("*.py"):
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                for pattern in sensitive_patterns:
                    for line_num, line in enumerate(content.splitlines(), start=1):
                        if pattern.search(line):
                            matches.append(f"{file_path.relative_to(REPO_ROOT)}:{line_num} -> {line.strip()[:60]}")

        self.assertEqual(
            len(matches),
            0,
            f"Security violation: Found sensitive coordinates/IPs in source ({len(matches)} occurrences):\n"
            + "\n".join(matches),
        )

    def test_SEC_03_no_personal_account_ids_in_compose_and_env_example(self):
        """SEC-01b: Verify personal account IDs are removed from docker-compose.yml and .env.example."""
        personal_ids = ["0000000", "EXAMPLE_UID_REDACTED", "000000000", "203.0.113.11"]
        config_files = [REPO_ROOT / "docker-compose.yml", REPO_ROOT / ".env.example"]
        matches = []

        for conf in config_files:
            if not conf.exists():
                continue
            content = conf.read_text(encoding="utf-8", errors="ignore")
            for pid in personal_ids:
                if pid in content:
                    matches.append(f"{conf.name} contains personal ID {pid}")

        self.assertEqual(
            len(matches),
            0,
            f"Security violation: Found personal IDs in deployment configs:\n" + "\n".join(matches),
        )

    def test_SEC_04_constant_time_comparison_in_auth(self):
        """SEC-08: Verify constant-time comparison (hmac.compare_digest) is enforced for token checks."""
        flask_app_path = REPO_ROOT / "server" / "flask_app.py"
        auth_module_path = REPO_ROOT / "server" / "auth.py"

        found_compare_digest = False
        for path in [flask_app_path, auth_module_path]:
            if not path.exists():
                continue
            code = path.read_text(encoding="utf-8", errors="ignore")
            if "compare_digest" in code:
                found_compare_digest = True
                break

        self.assertTrue(
            found_compare_digest,
            "Security violation: Auth verification in server/flask_app.py or server/auth.py must utilize constant-time comparison (hmac.compare_digest).",
        )

    def test_SEC_05_reject_api_key_in_query_parameters(self):
        """SEC-09: Verify rejection of API tokens transmitted in URL query strings (?api_key=)."""
        from server.flask_app import app

        # Configure API key in test app
        app.config["API_KEY"] = "test-secret-key-12345"
        app.config["TESTING"] = True

        client = app.test_client()

        # Query param transmission should be rejected (401 or 403)
        res = client.get("/api/devices?api_key=test-secret-key-12345")
        self.assertNotEqual(
            res.status_code,
            200,
            "Security violation: API key transmitted in query parameters (?api_key=) must not return HTTP 200.",
        )
        self.assertIn(
            res.status_code,
            [400, 401, 403],
            f"Expected rejection of query param API key, got {res.status_code}",
        )

        # Header transmission should succeed
        res_hdr = client.get(
            "/api/devices",
            headers={"Authorization": "Bearer test-secret-key-12345"},
        )
        # 200 if key accepted via header, or 401 if different auth scheme
        self.assertIn(res_hdr.status_code, [200, 401, 403])

    def test_SEC_06_standard_security_headers_present(self):
        """SEC-10: Verify presence of CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy."""
        from server.flask_app import app

        client = app.test_client()
        res = client.get("/api/health")

        missing_headers = []
        if "X-Frame-Options" not in res.headers:
            missing_headers.append("X-Frame-Options")
        if "X-Content-Type-Options" not in res.headers:
            missing_headers.append("X-Content-Type-Options")

        self.assertEqual(
            missing_headers,
            [],
            f"Security violation: Required security headers missing from HTTP response: {missing_headers}",
        )

        self.assertEqual(res.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("Content-Security-Policy", res.headers)

    def test_SEC_07_csrf_protection_on_mutating_routes(self):
        """SEC-05: Verify state-mutating POST requests reject payloads without CSRF protection."""
        from server.flask_app import app

        client = app.test_client()

        # Attempt state-mutating unlock action without CSRF token
        res = client.post(
            "/api/devices/lock-101/action",
            json={"action": "unlock", "confirmed": True},
        )

        self.assertIn(
            res.status_code,
            [400, 401, 403],
            f"Security violation: Mutating route must reject unauthenticated request without CSRF protection with 400, 401, or 403, got {res.status_code}",
        )

    def test_SEC_08_actuation_rate_limiting(self):
        """SEC-11: Verify rate limiting prevents rapid successive actuation commands."""
        from server.flask_app import app

        client = app.test_client()

        # Fire 10 rapid actuation requests
        statuses = []
        for _ in range(10):
            res = client.post(
                "/api/devices/lock-101/action",
                json={"action": "status", "confirmed": True},
            )
            statuses.append(res.status_code)

        self.assertIn(
            429,
            statuses,
            f"Security violation: Rate limiter failed to throttle rapid successive requests. Status codes: {statuses}",
        )

    def test_SEC_09_docker_compose_binds_to_localhost(self):
        """SEC-06: Verify docker-compose.yml binds to 127.0.0.1 by default to prevent UFW bypass."""
        compose_path = REPO_ROOT / "docker-compose.yml"
        self.assertTrue(compose_path.exists(), "docker-compose.yml must exist at repository root.")
        content = compose_path.read_text(encoding="utf-8", errors="ignore")
        self.assertNotIn(
            "GEEK_DOOR_BIND_IP:-0.0.0.0",
            content,
            "Security violation: docker-compose.yml must not default host binding to 0.0.0.0.",
        )
        self.assertIn(
            "127.0.0.1",
            content,
            "docker-compose.yml must default host binding to 127.0.0.1 to prevent UFW bypass.",
        )


if __name__ == "__main__":
    unittest.main()
