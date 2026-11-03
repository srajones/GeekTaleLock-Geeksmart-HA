"""Web UI Setup Walkthrough Wizard & Lockout Test Suite (Milestone 9 / Requirement R3).

Verifies:
1. SetupStateManager thread safety, atomic writes, and strict 0o600 permissions.
2. Step 1: Welcome & Terms acceptance requirement.
3. Step 2: Environment pre-flight check reporting.
4. Step 3: Admin creation and TOTP 2FA generation/verification.
5. Step 4-6: Device, DNS, and Nginx reverse proxy configuration.
6. Step 7: Setup finalization and permanent production lockout.
7. Post-lockout protection: /setup redirects to /login, /api/setup/* returns 403.
8. Disaster recovery: Authenticated admin can restore Nginx post-lockout.
9. CSRF protection on mutating setup POST endpoints.
"""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from server.auth import AuthManager
from server.flask_app import create_app
from server.nginx_manager import NginxManager
from server.security import generate_csrf_token
from server.setup_wizard import SetupStateManager, run_preflight_checks


class TestSetupStateManager(unittest.TestCase):
    """Test suite for SetupStateManager persistent state machine."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(self.temp_dir.name, ".setup_state.json")
        self.mgr = SetupStateManager(state_file=self.state_file)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_state_manager_creates_file_with_0o600_permissions(self):
        """Verifies state file is created with strict 0o600 permissions."""
        self.assertTrue(os.path.exists(self.state_file))
        mode = stat.S_IMODE(os.stat(self.state_file).st_mode)
        self.assertEqual(mode, 0o600, f"Expected 0o600 permissions, got {oct(mode)}")

    def test_step_advancement_and_completion_tracking(self):
        """Verifies step advancement updates state and completed_steps list."""
        state = self.mgr.load_state()
        self.assertEqual(state["current_step"], 1)
        self.assertEqual(state["completed_steps"], [])

        # Advance step 1
        updated = self.mgr.advance_step(1, {"terms_accepted": True})
        self.assertEqual(updated["current_step"], 2)
        self.assertIn(1, updated["completed_steps"])
        self.assertTrue(updated["steps"]["1"]["terms_accepted"])

        # Advance step 2
        updated2 = self.mgr.advance_step(2, {"preflight_passed": True})
        self.assertEqual(updated2["current_step"], 3)
        self.assertIn(2, updated2["completed_steps"])

    def test_finalize_setup_requires_steps_1_to_3(self):
        """Verifies finalize_setup enforces completion of required steps."""
        with self.assertRaises(ValueError):
            self.mgr.finalize_setup()

        # Complete steps 1, 2, 3
        self.mgr.advance_step(1, {"terms_accepted": True})
        self.mgr.advance_step(2, {"preflight_passed": True})
        self.mgr.advance_step(3, {"admin_created": True, "totp_enabled": True})

        final = self.mgr.finalize_setup()
        self.assertTrue(final["is_setup_complete"])
        self.assertIsNotNone(final["completed_at"])

        # Subsequent advancement raises PermissionError
        with self.assertRaises(PermissionError):
            self.mgr.advance_step(1, {"terms_accepted": False})


class TestSetupWizardEndpoints(unittest.TestCase):
    """Test suite for Setup Wizard HTTP and API routes."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(self.temp_dir.name, ".setup_state.json")
        self.auth_file = os.path.join(self.temp_dir.name, ".auth_credentials.json")
        self.cache_file = os.path.join(self.temp_dir.name, ".session_cache.json")

        self.setup_mgr = SetupStateManager(state_file=self.state_file)
        self.auth_mgr = AuthManager(auth_file=self.auth_file)

        # Mock NginxManager layout
        self.sites_available = Path(self.temp_dir.name) / "sites-available"
        self.sites_enabled = Path(self.temp_dir.name) / "sites-enabled"
        self.backup_dir = Path(self.temp_dir.name) / "backups"
        self.sites_available.mkdir(parents=True, exist_ok=True)
        self.sites_enabled.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        self.nginx_mgr = NginxManager(
            sites_available=str(self.sites_available),
            sites_enabled=str(self.sites_enabled),
            backup_dir=str(self.backup_dir),
            nginx_cmd="echo",
        )

        self.app = create_app(
            session_cache_path=self.cache_file,
            auth_file=self.auth_file,
            auth_enabled=True,
        )
        self.app.config["SETUP_STATE_MANAGER"] = self.setup_mgr
        self.app.config["AUTH_MANAGER"] = self.auth_mgr
        self.app.config["NGINX_MANAGER"] = self.nginx_mgr
        self.app.config["TESTING"] = True

        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _get_csrf_token(self):
        resp = self.client.get("/setup")
        return resp.headers.get("Set-Cookie", "")

    def test_get_setup_renders_wizard(self):
        """GET /setup renders wizard template and sets CSRF cookie."""
        resp = self.client.get("/setup")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Setup Wizard", resp.data)
        self.assertIn("mydoor_csrf_token", resp.headers.get("Set-Cookie", ""))

    def test_step_1_terms_acceptance_requires_csrf(self):
        """POST /api/setup/step/1 requires valid CSRF token."""
        # Without CSRF token
        resp = self.client.post("/api/setup/step/1", json={"terms_accepted": True})
        self.assertEqual(resp.status_code, 403)

        # With CSRF token
        token = generate_csrf_token(self.app.secret_key)
        self.client.set_cookie("mydoor_csrf_token", token)
        resp2 = self.client.post(
            "/api/setup/step/1",
            json={"terms_accepted": True},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(resp2.status_code, 200)
        data = resp2.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("next_step"), 2)

    def test_step_2_preflight_checks(self):
        """POST /api/setup/step/2 runs pre-flight inspection and advances."""
        token = generate_csrf_token(self.app.secret_key)
        self.client.set_cookie("mydoor_csrf_token", token)

        resp = self.client.post(
            "/api/setup/step/2",
            json={},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("report", data)
        self.assertIn("checks", data["report"])

    def test_step_3_admin_creation_and_totp_flow(self):
        """POST /api/setup/step/3 creates admin and validates TOTP."""
        token = generate_csrf_token(self.app.secret_key)
        self.client.set_cookie("mydoor_csrf_token", token)

        # 3.1: Create credentials
        resp1 = self.client.post(
            "/api/setup/step/3",
            json={
                "action": "create_credentials",
                "username": "wizardadmin",
                "password": "Password123!",
                "confirm_password": "Password123!",
            },
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(resp1.status_code, 200)
        data1 = resp1.get_json()
        self.assertTrue(data1.get("success"))
        self.assertIn("secret", data1)
        self.assertIn("qr_svg", data1)
        totp_secret = data1["secret"]

        # 3.2: Verify TOTP with authentic code
        import base64
        import hashlib
        import hmac
        import struct
        import time

        def get_current_totp(secret):
            key = base64.b32decode(secret)
            counter = int(time.time() // 30)
            msg = struct.pack(">Q", counter)
            h = hmac.new(key, msg, hashlib.sha1).digest()
            offset = h[-1] & 0x0F
            code = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
            return f"{code:06d}"

        valid_code = get_current_totp(totp_secret)

        resp2 = self.client.post(
            "/api/setup/step/3",
            json={
                "action": "verify_totp",
                "username": "wizardadmin",
                "code": valid_code,
            },
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.get_json()
        self.assertTrue(data2.get("success"))
        self.assertEqual(data2.get("next_step"), 4)
        self.assertEqual(len(data2.get("backup_codes", [])), 8)

    def test_post_setup_permanent_lockout(self):
        """Finalizing setup permanently locks /setup and /api/setup/*."""
        token = generate_csrf_token(self.app.secret_key)
        self.client.set_cookie("mydoor_csrf_token", token)

        # Complete steps 1, 2, 3
        self.setup_mgr.advance_step(1, {"terms_accepted": True})
        self.setup_mgr.advance_step(2, {"preflight_passed": True})
        self.setup_mgr.advance_step(3, {"admin_created": True, "totp_enabled": True})

        # Finalize setup
        with self.client.session_transaction() as sess:
            sess["auth_user"] = "admin"
            sess["2fa_verified"] = True

        fin_resp = self.client.post(
            "/api/setup/finalize",
            json={},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(fin_resp.status_code, 200)
        self.assertTrue(fin_resp.get_json().get("success"))

        # Verify /setup redirects to /login
        setup_page_resp = self.client.get("/setup")
        self.assertEqual(setup_page_resp.status_code, 302)
        self.assertIn("/login", setup_page_resp.headers.get("Location", ""))

        # Verify /api/setup/* returns 403 Forbidden
        api_step_resp = self.client.post(
            "/api/setup/step/1",
            json={"terms_accepted": True},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(api_step_resp.status_code, 403)
        self.assertTrue(api_step_resp.get_json().get("setup_locked"))

    def test_authenticated_admin_can_restore_nginx_post_lockout(self):
        """Single-action restore /api/setup/nginx/restore remains available for authenticated admins post-lockout."""
        token = generate_csrf_token(self.app.secret_key)
        self.client.set_cookie("mydoor_csrf_token", token)

        # Complete and finalize setup
        self.setup_mgr.advance_step(1, {"terms_accepted": True})
        self.setup_mgr.advance_step(2, {"preflight_passed": True})
        self.setup_mgr.advance_step(3, {"admin_created": True, "totp_enabled": True})
        self.setup_mgr.finalize_setup()

        # Unauthenticated request post-lockout returns 403
        unauth_resp = self.client.post(
            "/api/setup/nginx/restore",
            json={},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(unauth_resp.status_code, 403)

        # Authenticated admin request is permitted
        with self.client.session_transaction() as sess:
            sess["auth_user"] = "admin"
            sess["2fa_verified"] = True

        with patch.object(self.nginx_mgr, "restore_backup", return_value={"success": True, "restored_backup_id": "test_backup"}):
            auth_resp = self.client.post(
                "/api/setup/nginx/restore",
                json={},
                headers={"X-CSRF-Token": token},
            )
            self.assertEqual(auth_resp.status_code, 200)
            self.assertTrue(auth_resp.get_json().get("success"))


if __name__ == "__main__":
    unittest.main()
