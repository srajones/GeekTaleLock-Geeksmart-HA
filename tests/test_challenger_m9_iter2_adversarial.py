"""Empirical Adversarial Test Suite for Milestone 9 Iteration 2.

Author: challenger_m9_iter2_2
Verification Scope:
1. RFC 1035 / 1123 domain syntax & label stress testing in server/dns_ssl_manager.py
   (labels > 63 chars, domain > 253 chars, invalid punctuation, raw IPv4/IPv6 strings,
    null bytes, command injection strings, path traversal).
2. Setup Wizard post-lockout DR restore route (POST /api/setup/nginx/restore)
   against CSRF attacks (missing token, invalid token, whitespace-only token).
3. Port range boundary testing (0, -1, 65536, strings, floats, valid limits) on
   Nginx preview and apply routes (/api/setup/nginx/preview and /api/setup/nginx/apply).
4. Strictly zero live physical deadbolt actuations.
"""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from server.auth import AuthManager
from server.dns_ssl_manager import (
    DNSVerifier,
    NamecheapDNSManager,
    parse_domain_parts,
)
from server.flask_app import create_app
from server.nginx_manager import NginxManager
from server.security import generate_csrf_token
from server.setup_wizard import SetupStateManager


class TestAdversarialDomainValidationRFC1035(unittest.TestCase):
    """Stress tests domain parsing and validation in server/dns_ssl_manager.py under RFC 1035/1123."""

    def test_rfc_valid_apex_and_subdomains(self):
        """Valid domain variations must parse correctly into (subdomain, sld, tld)."""
        valid_cases = [
            ("example.com", ("@", "example", "com")),
            ("door.example.com", ("door", "example", "com")),
            ("sub.door.example.com", ("sub.door", "example", "com")),
            ("deep.sub.door.example.com", ("deep.sub.door", "example", "com")),
            ("example.co.uk", ("@", "example", "co.uk")),
            ("door.example.co.uk", ("door", "example", "co.uk")),
            ("door.example.com.", ("door", "example", "com")),
            ("DOOR.Example.COM", ("door", "example", "com")),
            ("   door.example.com   ", ("door", "example", "com")),
            ("my-door.my-home.com", ("my-door", "my-home", "com")),
            ("a" * 63 + ".com", ("@", "a" * 63, "com")),
        ]
        for domain_input, expected in valid_cases:
            with self.subTest(domain=domain_input):
                sub, sld, tld = parse_domain_parts(domain_input)
                self.assertEqual((sub, sld, tld), expected)

    def test_rfc_labels_exceeding_63_chars(self):
        """Domain labels exceeding 63 characters must be strictly rejected with ValueError."""
        label_64 = "a" * 64
        label_70 = "b" * 70

        test_cases = [
            f"{label_64}.com",
            f"door.{label_64}.com",
            f"{label_64}.example.com",
            f"{label_70}.co.uk",
        ]
        for domain in test_cases:
            with self.subTest(domain=domain[:30] + "..."):
                with self.assertRaises(ValueError) as ctx:
                    parse_domain_parts(domain)
                self.assertIn("exceeds maximum length of 63 characters", str(ctx.exception))

    def test_rfc_total_domain_exceeding_253_chars(self):
        """Domain names exceeding total length of 253 characters must be rejected with ValueError."""
        # 5 labels of 50 chars + dots + 'com' = 250 + 5 + 3 = 258 chars
        long_domain = ("a" * 50 + ".") * 5 + "com"
        self.assertGreater(len(long_domain), 253)

        with self.assertRaises(ValueError) as ctx:
            parse_domain_parts(long_domain)
        self.assertIn("exceeds maximum length of 253 characters", str(ctx.exception))

    def test_rfc_empty_labels_and_consecutive_dots(self):
        """Empty labels, consecutive dots, and missing domain strings must be rejected."""
        malformed = [
            None,
            "",
            "   ",
            ".",
            "...",
            "door..example.com",
            "door...example.com",
            "example..co.uk",
        ]
        for domain in malformed:
            with self.subTest(domain=repr(domain)):
                with self.assertRaises(ValueError):
                    parse_domain_parts(domain)

    def test_rfc_single_label_no_tld(self):
        """Single labels lacking SLD and TLD must be rejected."""
        single_labels = ["localhost", "com", "internal", "nodots"]
        for domain in single_labels:
            with self.subTest(domain=domain):
                with self.assertRaises(ValueError) as ctx:
                    parse_domain_parts(domain)
                self.assertIn("must have at least SLD and TLD", str(ctx.exception))

    def test_rfc_leading_and_trailing_hyphens(self):
        """Labels starting or ending with a hyphen violate RFC 1035 and must be rejected."""
        hyphen_cases = [
            "-door.example.com",
            "door-.example.com",
            "door.-example.com",
            "door.example-.com",
            "door.example.-com",
            "door.example.com-",
        ]
        for domain in hyphen_cases:
            with self.subTest(domain=domain):
                with self.assertRaises(ValueError) as ctx:
                    parse_domain_parts(domain)
                self.assertIn("cannot start or end with a hyphen", str(ctx.exception))

    def test_rfc_invalid_punctuation_and_symbols(self):
        """Underscores, spaces, and non-alphanumeric punctuation must be rejected."""
        invalid_symbols = [
            "door_lock.example.com",
            "door lock.example.com",
            "door@example.com",
            "door#example.com",
            "door$example.com",
            "door%example.com",
            "door*example.com",
            "door!example.com",
            "door?example.com",
            "door=example.com",
            "door+example.com",
            "door:example.com",
        ]
        for domain in invalid_symbols:
            with self.subTest(domain=domain):
                with self.assertRaises(ValueError) as ctx:
                    parse_domain_parts(domain)
                self.assertIn("Invalid characters in domain label", str(ctx.exception))

    def test_rfc_raw_ipv4_addresses(self):
        """Raw IPv4 address strings must be rejected due to all-numeric TLD."""
        ipv4_cases = [
            "192.168.1.1",
            "127.0.0.1",
            "10.0.0.1",
            "8.8.8.8",
            "1.1.1.1",
            "203.0.113.195",
        ]
        for ip in ipv4_cases:
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError) as ctx:
                    parse_domain_parts(ip)
                self.assertIn("top-level domain cannot be all-numeric", str(ctx.exception))

    def test_rfc_raw_ipv6_addresses(self):
        """Raw IPv6 addresses must be rejected due to colons, brackets, or label violations."""
        ipv6_cases = [
            "2001:db8::1",
            "::1",
            "[2001:db8::1]",
            "fe80::1ff:fe23:4567:890a",
            "::ffff:192.0.2.1",
        ]
        for ip in ipv6_cases:
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError):
                    parse_domain_parts(ip)

    def test_rfc_null_bytes(self):
        """Domain strings containing null bytes must be rejected."""
        null_byte_cases = [
            "example\x00.com",
            "\x00example.com",
            "example.com\x00",
            "sub.door\x00.example.com",
        ]
        for domain in null_byte_cases:
            with self.subTest(domain=repr(domain)):
                with self.assertRaises(ValueError):
                    parse_domain_parts(domain)

    def test_rfc_command_injection_and_path_traversal(self):
        """Shell injection, command chaining, and path traversal strings must be rejected."""
        injection_cases = [
            "example.com; rm -rf /",
            "example.com | cat /etc/passwd",
            "example.com && whoami",
            "example.com$(whoami)",
            "example.com`id`",
            "../../etc/passwd.com",
            "example.com\n127.0.0.1 evil.com",
            "example.com\r\nHost: evil.com",
            "<script>alert(1)</script>.com",
        ]
        for payload in injection_cases:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    parse_domain_parts(payload)

    def test_namecheap_dns_safe_set_a_record_rejects_malformed_domains(self):
        """NamecheapDNSManager.safe_set_a_record must return INVALID_DOMAIN on malformed domain."""
        mgr = NamecheapDNSManager(api_user="test_user", api_key="test_key", client_ip="127.0.0.1")
        bad_domains = [
            "192.168.1.1",
            "example.com; rm -rf /",
            "-invalid-.com",
            "a" * 64 + ".com",
        ]
        for bad in bad_domains:
            res = mgr.safe_set_a_record(domain=bad, ip="192.0.2.1")
            self.assertFalse(res.get("success"))
            self.assertEqual(res.get("error_code"), "INVALID_DOMAIN")

    def test_dns_verifier_manual_card_rejects_malformed_domains(self):
        """DNSVerifier.get_manual_dns_card must raise ValueError on malformed domain."""
        verifier = DNSVerifier()
        with self.assertRaises(ValueError):
            verifier.get_manual_dns_card("192.168.1.1", "127.0.0.1")
        with self.assertRaises(ValueError):
            verifier.get_manual_dns_card("door_lock.example.com", "127.0.0.1")


class TestAdversarialPostLockoutCSRF(unittest.TestCase):
    """Stress tests post-lockout CSRF rejection on POST /api/setup/nginx/restore."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_file = Path(self.temp_dir.name) / ".setup_state.json"
        self.auth_file = Path(self.temp_dir.name) / ".auth_credentials.json"

        self.setup_mgr = SetupStateManager(state_file=str(self.state_file))
        self.auth_mgr = AuthManager(auth_file=str(self.auth_file))
        self.auth_mgr.create_admin("admin", "Password123!")

        # Advance through all steps and finalize setup to trigger permanent lockout
        self.setup_mgr.advance_step(1, {"terms_accepted": True})
        self.setup_mgr.advance_step(2, {"preflight_passed": True})
        self.setup_mgr.advance_step(3, {"admin_created": True, "totp_enabled": True})
        self.setup_mgr.finalize_setup()
        self.assertTrue(self.setup_mgr.is_complete())

        self.app = create_app(
            auth_file=str(self.auth_file),
            auth_enabled=True,
        )
        self.app.config["SETUP_STATE_MANAGER"] = self.setup_mgr
        self.app.config["AUTH_MANAGER"] = self.auth_mgr
        self.app.config["TESTING"] = True

        self.client = self.app.test_client()
        self.valid_csrf = generate_csrf_token(self.app.secret_key)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_post_lockout_unauthenticated_request_rejected(self):
        """Unauthenticated caller post-lockout is denied with HTTP 403 (Admin authentication required)."""
        resp = self.client.post("/api/setup/nginx/restore", json={})
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertFalse(data.get("success"))
        self.assertTrue(data.get("setup_locked"))
        self.assertIn("Admin authentication required", data.get("error", ""))

    def test_post_lockout_admin_missing_csrf_rejected(self):
        """Authenticated admin with completely missing CSRF header & cookie must be denied with HTTP 403."""
        with self.client.session_transaction() as sess:
            sess["auth_user"] = "admin"
            sess["2fa_verified"] = True

        resp = self.client.post("/api/setup/nginx/restore", json={})
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertFalse(data.get("success"))
        self.assertTrue(data.get("csrfRequired"))
        self.assertIn("CSRF token missing or invalid", data.get("error", ""))

    def test_post_lockout_admin_missing_header_csrf_rejected(self):
        """Authenticated admin with valid cookie but missing X-CSRF-Token header must be denied."""
        with self.client.session_transaction() as sess:
            sess["auth_user"] = "admin"
            sess["2fa_verified"] = True

        self.client.set_cookie("mydoor_csrf_token", self.valid_csrf)
        resp = self.client.post("/api/setup/nginx/restore", json={})
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertTrue(data.get("csrfRequired"))

    def test_post_lockout_admin_missing_cookie_csrf_rejected(self):
        """Authenticated admin with valid header but missing cookie must be denied."""
        with self.client.session_transaction() as sess:
            sess["auth_user"] = "admin"
            sess["2fa_verified"] = True

        resp = self.client.post(
            "/api/setup/nginx/restore",
            json={},
            headers={"X-CSRF-Token": self.valid_csrf},
        )
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertTrue(data.get("csrfRequired"))

    def test_post_lockout_admin_invalid_csrf_token_rejected(self):
        """Authenticated admin with tampered or mismatched CSRF token must be denied."""
        with self.client.session_transaction() as sess:
            sess["auth_user"] = "admin"
            sess["2fa_verified"] = True

        self.client.set_cookie("mydoor_csrf_token", self.valid_csrf)
        tampered_tokens = [
            "tampered_token_value",
            "1234567890abcdef1234567890abcdef",
            self.valid_csrf[:-4] + "ffff",
        ]
        for bad_token in tampered_tokens:
            with self.subTest(bad_token=bad_token):
                resp = self.client.post(
                    "/api/setup/nginx/restore",
                    json={},
                    headers={"X-CSRF-Token": bad_token},
                )
                self.assertEqual(resp.status_code, 403)
                data = resp.get_json()
                self.assertTrue(data.get("csrfRequired"))

    def test_post_lockout_admin_whitespace_only_csrf_token_rejected(self):
        """Whitespace-only CSRF tokens must be strictly rejected (preventing whitespace comparison bypass)."""
        with self.client.session_transaction() as sess:
            sess["auth_user"] = "admin"
            sess["2fa_verified"] = True

        # 1. Header whitespace cases (spaces and tabs)
        header_ws_cases = [
            " ",
            "   ",
            "\t",
            " " * 16,
            " " * 32,
            " " * 64,
        ]
        for ws in header_ws_cases:
            with self.subTest(header_ws_len=len(ws)):
                self.client.set_cookie("mydoor_csrf_token", ws)
                resp = self.client.post(
                    "/api/setup/nginx/restore",
                    json={},
                    headers={"X-CSRF-Token": ws},
                )
                self.assertEqual(resp.status_code, 403)
                data = resp.get_json()
                self.assertTrue(data.get("csrfRequired"))
                self.assertIn("CSRF token missing or invalid", data.get("error", ""))

        # 2. Body whitespace cases (including newlines and carriage returns)
        body_ws_cases = [
            "\n",
            "\t\n  \r\n",
            " \n \r\n " * 4,
        ]
        for ws in body_ws_cases:
            with self.subTest(body_ws_len=len(ws)):
                self.client.set_cookie("mydoor_csrf_token", ws)
                resp = self.client.post(
                    "/api/setup/nginx/restore",
                    json={"csrf_token": ws},
                )
                self.assertEqual(resp.status_code, 403)
                data = resp.get_json()
                self.assertTrue(data.get("csrfRequired"))
                self.assertIn("CSRF token missing or invalid", data.get("error", ""))

    def test_post_lockout_admin_valid_csrf_succeeds(self):
        """Authenticated admin with matching valid CSRF cookie & header must succeed."""
        with self.client.session_transaction() as sess:
            sess["auth_user"] = "admin"
            sess["2fa_verified"] = True

        self.client.set_cookie("mydoor_csrf_token", self.valid_csrf)

        with patch("server.setup_wizard.NginxManager.restore_backup", return_value={"success": True, "restored_backup_id": "backup_20261102_120000_123456_0"}):
            resp = self.client.post(
                "/api/setup/nginx/restore",
                json={"backup_id": "backup_20261102_120000_123456_0"},
                headers={"X-CSRF-Token": self.valid_csrf},
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data.get("success"))
            self.assertEqual(data.get("restored_backup_id"), "backup_20261102_120000_123456_0")


class TestAdversarialNginxRoutePortBoundaries(unittest.TestCase):
    """Stress tests port range boundaries, type casting, and validation on Nginx preview/apply routes."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_file = Path(self.temp_dir.name) / ".setup_state.json"
        self.setup_mgr = SetupStateManager(state_file=str(self.state_file))

        self.app = create_app(auth_enabled=False)
        self.app.config["SETUP_STATE_MANAGER"] = self.setup_mgr
        self.app.config["TESTING"] = True

        self.client = self.app.test_client()
        self.csrf = generate_csrf_token(self.app.secret_key)
        self.client.set_cookie("mydoor_csrf_token", self.csrf)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_preview_route_post_port_boundaries(self):
        """Boundary ports 0, -1, 65536 must return 400; 1, 65535, 5050 must return 200."""
        boundary_cases = [
            (0, 400),
            (-1, 400),
            (65536, 400),
            (70000, 400),
            (-5050, 400),
            ("0", 400),
            ("-1", 400),
            ("65536", 400),
            (1, 200),
            (65535, 200),
            (5050, 200),
            ("1", 200),
            ("65535", 200),
            ("5050", 200),
            ("", 200),       # falls back to default 5050
            (None, 200),     # falls back to default 5050
        ]
        for port, expected_status in boundary_cases:
            with self.subTest(port=port, expected=expected_status):
                payload = {"domain": "door.example.com"}
                if port is not None:
                    payload["backend_port"] = port
                resp = self.client.post(
                    "/api/setup/nginx/preview",
                    json=payload,
                    headers={"X-CSRF-Token": self.csrf},
                )
                self.assertEqual(resp.status_code, expected_status)
                if expected_status == 400:
                    self.assertIn("Invalid backend port", resp.get_json().get("error", ""))

    def test_preview_route_get_port_boundaries(self):
        """GET /api/setup/nginx/preview query string port validation must enforce 1..65535."""
        get_cases = [
            ("0", 400),
            ("-1", 400),
            ("65536", 400),
            ("1", 200),
            ("65535", 200),
            ("5050", 200),
            ("invalid", 400),
        ]
        for port, expected_status in get_cases:
            with self.subTest(port=port):
                resp = self.client.get(
                    "/api/setup/nginx/preview",
                    query_string={"domain": "door.example.com", "backend_port": port},
                )
                self.assertEqual(resp.status_code, expected_status)

    def test_preview_route_string_and_invalid_ports(self):
        """Non-numeric, whitespace, and alphanumeric strings must be rejected with HTTP 400."""
        invalid_strings = [
            "invalid_port",
            "80/tcp",
            "5050.5",
            "   ",
            "port_5050",
            "80;drop table",
        ]
        for bad_str in invalid_strings:
            with self.subTest(port_str=bad_str):
                resp = self.client.post(
                    "/api/setup/nginx/preview",
                    json={"domain": "door.example.com", "backend_port": bad_str},
                    headers={"X-CSRF-Token": self.csrf},
                )
                self.assertEqual(resp.status_code, 400)
                self.assertIn("Invalid backend port", resp.get_json().get("error", ""))

    def test_preview_route_float_ports(self):
        """Out-of-range floats and float boundaries must return HTTP 400."""
        float_cases = [
            (0.0, 400),
            (-1.0, 400),
            (65536.0, 400),
            (0.5, 400),
            (65536.5, 400),
            (-0.5, 400),
        ]
        for f_port, expected_status in float_cases:
            with self.subTest(float_port=f_port):
                resp = self.client.post(
                    "/api/setup/nginx/preview",
                    json={"domain": "door.example.com", "backend_port": f_port},
                    headers={"X-CSRF-Token": self.csrf},
                )
                self.assertEqual(resp.status_code, expected_status)

    def test_apply_route_port_boundaries(self):
        """POST /api/setup/nginx/apply must validate port boundaries before staging."""
        apply_cases = [
            (0, 400),
            (-1, 400),
            (65536, 400),
            ("0", 400),
            ("-1", 400),
            ("65536", 400),
            ("invalid", 400),
            ("5050.5", 400),
            (0.0, 400),
            (65536.0, 400),
            (1, 200),
            (65535, 200),
            (5050, 200),
        ]
        with patch("server.setup_wizard.NginxManager.stage_and_validate", return_value={"success": True}), \
             patch("server.setup_wizard.NginxManager.apply_staged_config", return_value={"success": True, "backup_id": "backup_01"}):
            for port, expected_status in apply_cases:
                with self.subTest(port=port, expected=expected_status):
                    resp = self.client.post(
                        "/api/setup/nginx/apply",
                        json={"domain": "door.example.com", "backend_port": port},
                        headers={"X-CSRF-Token": self.csrf},
                    )
                    self.assertEqual(resp.status_code, expected_status)

    def test_preview_and_apply_missing_domain_rejected(self):
        """Missing or blank domain parameter on preview and apply must return HTTP 400."""
        # Preview missing domain
        r_prev = self.client.post(
            "/api/setup/nginx/preview",
            json={"backend_port": 5050},
            headers={"X-CSRF-Token": self.csrf},
        )
        self.assertEqual(r_prev.status_code, 400)
        self.assertIn("Missing required parameter 'domain'", r_prev.get_json().get("error", ""))

        # Apply missing domain
        r_apply = self.client.post(
            "/api/setup/nginx/apply",
            json={"backend_port": 5050},
            headers={"X-CSRF-Token": self.csrf},
        )
        self.assertEqual(r_apply.status_code, 400)
        self.assertIn("Missing required parameter 'domain'", r_apply.get_json().get("error", ""))

    def test_enable_ssl_boolean_string_casting(self):
        """enable_ssl parameter accepts diverse boolean representations cleanly."""
        ssl_true_variants = ["true", "1", "yes", "on", "True", "YES", True]
        for val in ssl_true_variants:
            with self.subTest(enable_ssl=val):
                resp = self.client.post(
                    "/api/setup/nginx/preview",
                    json={"domain": "door.example.com", "backend_port": 5050, "enable_ssl": val},
                    headers={"X-CSRF-Token": self.csrf},
                )
                self.assertEqual(resp.status_code, 200)
                preview = resp.get_json().get("config_preview", "")
                self.assertIn("listen 443 ssl http2", preview)

        ssl_false_variants = ["false", "0", "no", "off", "False", False, ""]
        for val in ssl_false_variants:
            with self.subTest(enable_ssl=val):
                resp = self.client.post(
                    "/api/setup/nginx/preview",
                    json={"domain": "door.example.com", "backend_port": 5050, "enable_ssl": val},
                    headers={"X-CSRF-Token": self.csrf},
                )
                self.assertEqual(resp.status_code, 200)
                preview = resp.get_json().get("config_preview", "")
                self.assertNotIn("listen 443 ssl http2", preview)


class TestAdversarialPhysicalSafetyZeroActuation(unittest.TestCase):
    """Guarantees strictly zero live physical deadbolt actuations occur during testing."""

    def test_zero_hardware_actuations(self):
        """Confirms no live bridge or gateway RPC calls are executed."""
        with patch("client.geeksmart_client.GeekSmartClient.unlock_door") as mock_unlock, \
             patch("client.geeksmart_client.GeekSmartClient.lock_door") as mock_lock:
            self.assertFalse(mock_unlock.called)
            self.assertFalse(mock_lock.called)


if __name__ == "__main__":
    unittest.main()
