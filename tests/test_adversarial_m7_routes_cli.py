"""Empirical Adversarial Stress Test Suite for Milestone 7 (Challenger 2).

Verifies Session Security, Route Protection, API Key Coexistence, CSRF Coordination,
and CLI Administration per Requirement R5 and Milestone 7 Interface Contracts:

1. Route Protection Bypass Probes:
   - GET / unauthenticated redirects to /login (302).
   - GET /api/devices unauthenticated MUST return 401 (VULNERABILITY PROBE).
   - GET /api/status unauthenticated MUST return 401 (VULNERABILITY PROBE).
   - POST /api/devices/<id>/lock unauthenticated MUST return 401 (VULNERABILITY PROBE).
   - Spoofed / tampered session cookies MUST be rejected (302 on web, 401 on API).
   - Session expiration (>12h) MUST clear session and reject access.
   - 2FA pending state access restrictions: user authenticated with password but
     NOT verified with 2FA MUST be denied access to /api/devices (401/403).

2. API Key vs Session Dual-Mode Probes:
   - Protected API access with valid Authorization: Bearer <API_KEY> (200).
   - Protected API access with valid X-API-Key: <API_KEY> (200).
   - Protected API access with invalid Bearer token (401).
   - Web session cookie coexistence with API key when CSRF headers present.

3. Double-Submit CSRF & Auth Coordination:
   - POST /api/auth/login succeeds without prior CSRF token.
   - POST /api/auth/verify_2fa succeeds without prior CSRF token.
   - Post-login mutating action without CSRF token is rejected (403).
   - Post-login mutating action with matching CSRF cookie and header succeeds.

4. CLI Administration Stress Probes:
   - reset-admin on non-existent config file creates file with mode 0600.
   - reset-admin with password < 8 characters is rejected with non-zero exit code.
   - reset-admin clears active brute-force lockout.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict

from server.auth import AuthManager
from server.flask_app import create_app
from server.security import generate_csrf_token


def _totp_oracle(secret_b32: str, timestamp: int, step: int = 30) -> str:
    """Computes reference RFC 6238 TOTP code."""
    import hashlib
    import hmac
    import struct

    counter = int(timestamp // step)
    pad_len = (8 - len(secret_b32) % 8) % 8
    secret_bytes = base64.b32decode((secret_b32 + "=" * pad_len).encode("ascii"), casefold=True)
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % 1000000).zfill(6)


class TestAdversarialM7RouteProtection(unittest.TestCase):
    """Adversarial route protection & session security probes."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth_file = Path(self.temp_dir.name) / ".auth_credentials.json"
        self.auth_mgr = AuthManager(auth_file=str(self.auth_file))
        self.auth_mgr.create_admin("admin", "MasterPassword123!")

        self.app = create_app(
            auth_enabled=True,
            auth_file=str(self.auth_file),
            csrf_enabled=True,
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    # --- 1. Web Root Route Protection ---

    def test_web_root_unauthenticated_redirects(self):
        """GET / without authentication redirects to /login."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers.get("Location", ""))

    def test_web_root_tampered_cookie_redirects(self):
        """GET / with spoofed/tampered session cookie redirects to /login."""
        self.client.set_cookie("mydoor_session", "spoofed_signature_token.badpayload")
        res = self.client.get("/")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers.get("Location", ""))

    def test_web_root_expired_session_cleared_and_redirects(self):
        """GET / with session older than 12 hours (43200s) is cleared and redirected."""
        with self.client.session_transaction() as sess:
            sess["auth_user"] = "admin"
            sess["login_time"] = time.time() - 50000  # > 12 hours ago

        res = self.client.get("/")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers.get("Location", ""))
        with self.client.session_transaction() as sess:
            self.assertNotIn("auth_user", sess, "Expired session must be purged")

    def test_web_root_2fa_pending_redirects_to_verify_step(self):
        """GET / with 2FA pending session redirects to /login?step=2fa."""
        self.auth_mgr.generate_totp_secret("admin")
        with self.client.session_transaction() as sess:
            sess["2fa_pending_user"] = "admin"
            sess["2fa_pending_ts"] = time.time()

        res = self.client.get("/")
        self.assertEqual(res.status_code, 302)
        self.assertIn("step=2fa", res.headers.get("Location", ""))

    # --- 2. API Route Protection Probes (Vulnerability Checks) ---

    def test_api_devices_unauthenticated_rejection(self):
        """GET /api/devices without authentication MUST return 401."""
        res = self.client.get("/api/devices")
        self.assertEqual(
            res.status_code,
            401,
            f"GET /api/devices must return 401 when unauthenticated, but returned {res.status_code}",
        )

    def test_api_status_unauthenticated_rejection(self):
        """GET /api/status without authentication MUST return 401."""
        res = self.client.get("/api/status")
        self.assertEqual(
            res.status_code,
            401,
            f"GET /api/status must return 401 when unauthenticated, but returned {res.status_code}",
        )

    def test_api_lock_unauthenticated_rejection(self):
        """POST /api/devices/<id>/lock without authentication MUST return 401."""
        res = self.client.post("/api/devices/123/lock", json={"dry_run": True, "confirmed": True})
        self.assertEqual(
            res.status_code,
            401,
            f"POST /api/devices/123/lock must return 401 when unauthenticated, but returned {res.status_code}",
        )

    def test_api_devices_2fa_pending_rejection(self):
        """GET /api/devices with 2FA pending session MUST return 401 or 403."""
        self.auth_mgr.generate_totp_secret("admin")
        with self.client.session_transaction() as sess:
            sess["2fa_pending_user"] = "admin"
            sess["2fa_pending_ts"] = time.time()

        res = self.client.get("/api/devices")
        self.assertIn(
            res.status_code,
            (401, 403),
            f"GET /api/devices for 2FA-pending user must return 401 or 403, but returned {res.status_code}",
        )

    def test_api_devices_expired_session_rejection(self):
        """GET /api/devices with expired session (>12h) MUST return 401."""
        with self.client.session_transaction() as sess:
            sess["auth_user"] = "admin"
            sess["login_time"] = time.time() - 50000

        res = self.client.get("/api/devices")
        self.assertEqual(
            res.status_code,
            401,
            f"GET /api/devices with expired session must return 401, but returned {res.status_code}",
        )

    def test_api_devices_spoofed_session_rejection(self):
        """GET /api/devices with tampered session cookie MUST return 401."""
        self.client.set_cookie("mydoor_session", "fake_payload_forged_sig.12345")
        res = self.client.get("/api/devices")
        self.assertEqual(
            res.status_code,
            401,
            f"GET /api/devices with forged cookie must return 401, but returned {res.status_code}",
        )


class TestAdversarialM7ApiKeyDualMode(unittest.TestCase):
    """Adversarial probes for API Key vs Session dual-mode coexistence."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth_file = Path(self.temp_dir.name) / ".auth_credentials.json"
        self.auth_mgr = AuthManager(auth_file=str(self.auth_file))
        self.auth_mgr.create_admin("admin", "MasterPassword123!")

        self.api_key = "secure_test_api_key_xyz987654321"
        os.environ["GEEK_DOOR_API_KEY"] = self.api_key

        self.app = create_app(
            auth_enabled=True,
            auth_file=str(self.auth_file),
            csrf_enabled=True,
        )
        self.client = self.app.test_client()

    def tearDown(self):
        os.environ.pop("GEEK_DOOR_API_KEY", None)
        self.temp_dir.cleanup()

    def test_api_key_bearer_header_success(self):
        """Authorization: Bearer <API_KEY> accesses /api/devices without session cookies or 2FA."""
        res = self.client.get(
            "/api/devices",
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))

    def test_api_key_x_api_key_header_success(self):
        """X-API-Key: <API_KEY> accesses /api/devices without session cookies or 2FA."""
        res = self.client.get(
            "/api/devices",
            headers={"X-API-Key": self.api_key},
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))

    def test_api_key_invalid_bearer_rejection(self):
        """Authorization: Bearer with wrong key is rejected with 401."""
        res = self.client.get(
            "/api/devices",
            headers={"Authorization": "Bearer wrong_invalid_key_abc"},
        )
        self.assertEqual(res.status_code, 401)

    def test_api_key_empty_bearer_rejection(self):
        """Authorization: Bearer with empty key is rejected with 401."""
        res = self.client.get(
            "/api/devices",
            headers={"Authorization": "Bearer "},
        )
        self.assertEqual(res.status_code, 401)

    def test_session_coexistence_with_csrf_header(self):
        """Logged-in session user coexists with configured API key when passing CSRF token."""
        with self.client.session_transaction() as sess:
            sess["auth_user"] = "admin"
            sess["2fa_verified"] = True
            sess["login_time"] = time.time()

        csrf_token = generate_csrf_token(self.app.secret_key)
        self.client.set_cookie("mydoor_csrf_token", csrf_token)

        res = self.client.get("/api/devices", headers={"X-CSRF-Token": csrf_token})
        self.assertEqual(res.status_code, 200)


class TestAdversarialM7CsrfCoordination(unittest.TestCase):
    """Adversarial probes for double-submit CSRF and authentication coordination."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth_file = Path(self.temp_dir.name) / ".auth_credentials.json"
        self.auth_mgr = AuthManager(auth_file=str(self.auth_file))
        self.auth_mgr.create_admin("admin", "MasterPassword123!")
        self.totp_data = self.auth_mgr.generate_totp_secret("admin")

        self.app = create_app(
            auth_enabled=True,
            auth_file=str(self.auth_file),
            csrf_enabled=True,
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_login_unblocked_without_csrf_header(self):
        """POST /api/auth/login must succeed without CSRF headers before session establishment."""
        res = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "MasterPassword123!"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertTrue(data.get("requires_2fa"))

    def test_verify_2fa_unblocked_without_csrf_header(self):
        """POST /api/auth/verify_2fa must succeed without CSRF headers during authentication."""
        # Establish pending 2FA session
        self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "MasterPassword123!"},
        )
        code = _totp_oracle(self.totp_data["secret"], int(time.time()))
        res = self.client.post(
            "/api/auth/verify_2fa",
            json={"code": code},
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("authenticated"))

    def test_post_login_mutating_action_blocks_missing_csrf(self):
        """Mutating action after login MUST be blocked with 403 if CSRF token is missing."""
        # Log in
        self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "MasterPassword123!"},
        )
        code = _totp_oracle(self.totp_data["secret"], int(time.time()))
        self.client.post("/api/auth/verify_2fa", json={"code": code})

        # Mutating action without CSRF header or cookie
        res = self.client.post("/api/devices/123/lock", json={"confirmed": True})
        self.assertEqual(res.status_code, 403)
        self.assertTrue(res.get_json().get("csrfRequired"))

    def test_post_login_mutating_action_accepts_valid_csrf(self):
        """Mutating action with valid double-submit CSRF token is accepted."""
        # Log in
        self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "MasterPassword123!"},
        )
        code = _totp_oracle(self.totp_data["secret"], int(time.time()))
        self.client.post("/api/auth/verify_2fa", json={"code": code})

        csrf = generate_csrf_token(self.app.secret_key)
        self.client.set_cookie("mydoor_csrf_token", csrf)

        # Mutating action with matching cookie + header
        res = self.client.post(
            "/api/devices/123/lock",
            json={"confirmed": True, "dry_run": True},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertIn(res.status_code, (200, 400, 404, 502))
        self.assertNotEqual(res.status_code, 403)


class TestAdversarialM7CliAdministration(unittest.TestCase):
    """Adversarial stress tests for CLI reset-admin command."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth_file = Path(self.temp_dir.name) / "deep" / "nested" / ".auth_credentials.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cli_reset_admin_fresh_system_mode_0600(self):
        """CLI reset-admin creates file with mode 0600 on fresh unconfigured system."""
        self.assertFalse(self.auth_file.exists(), "Auth file must not exist initially")

        cmd = [
            "python3", "door_lock_control.py", "reset-admin",
            "--username", "initial_admin",
            "--password", "VeryStrongPassword999!",
            "--auth-file", str(self.auth_file),
            "--json",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"reset-admin failed: {res.stderr}")
        self.assertTrue(self.auth_file.exists(), "Auth file must be created")

        mode = stat.S_IMODE(os.stat(self.auth_file).st_mode)
        self.assertEqual(
            mode & 0o077,
            0,
            f"File mode {oct(mode)} must NOT allow group or other access (must be 0600)",
        )

        # Verify account can authenticate
        mgr = AuthManager(auth_file=str(self.auth_file))
        self.assertTrue(mgr.verify_password("initial_admin", "VeryStrongPassword999!"))

    def test_cli_reset_admin_rejects_password_too_short(self):
        """CLI reset-admin rejects passwords shorter than 8 characters."""
        cmd = [
            "python3", "door_lock_control.py", "reset-admin",
            "--username", "admin",
            "--password", "short1",
            "--auth-file", str(self.auth_file),
            "--json",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0, "Short password must be rejected")
        self.assertIn("at least 8 characters", res.stderr + res.stdout)

    def test_cli_reset_admin_clears_active_lockout(self):
        """CLI reset-admin clears active brute-force lockout for user."""
        # Create user
        mgr = AuthManager(auth_file=str(self.auth_file))
        mgr.create_admin("locked_user", "OldPassword123!")

        # Trigger brute-force lockout
        for _ in range(5):
            mgr.verify_password("locked_user", "wrong_password")
        self.assertTrue(mgr.is_locked_out("locked_user"), "User must be locked out")

        # Run reset-admin via CLI
        cmd = [
            "python3", "door_lock_control.py", "reset-admin",
            "--username", "locked_user",
            "--password", "NewPassword987!",
            "--auth-file", str(self.auth_file),
            "--json",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)

        # Verify lockout is cleared
        mgr_after = AuthManager(auth_file=str(self.auth_file))
        self.assertFalse(
            mgr_after.is_locked_out("locked_user"),
            "reset-admin must clear brute-force lockout",
        )
        self.assertTrue(
            mgr_after.verify_password("locked_user", "NewPassword987!"),
            "New password must be valid immediately",
        )


if __name__ == "__main__":
    unittest.main()
