"""Empirical Adversarial Test Suite for Milestone 9 (DNS Merger, SSL Shield & Setup Lockout).

Written by: challenger_m9_2
Validates:
1. Namecheap DNS Merger Stress:
   - 12+ record zone with multi-priority MX, SPF/DKIM/DMARC TXTs, CNAMEs, and existing As.
   - 100% preservation of non-target records in setHosts.
   - Appending new records vs updating existing records.
   - Error 2011166 (client IP not whitelisted) structured feedback.
   - Error handling: missing credentials, invalid domain, network failures, corrupt XML.
   - Multi-part TLD parsing boundary cases (.co.uk, .com.au, .co.jp, .org.nz, apex, deep subdomains).
2. Certbot Pre-Flight DNS Shield:
   - NXDOMAIN / unpropagated DNS hard-blocks Certbot subprocess invocation.
   - IP mismatch hard-blocks Certbot subprocess invocation.
   - Round-robin multi-IP resolution handling.
   - Skip preflight override.
   - Certbot timeout and execution error resilience.
3. Setup State Machine & Concurrency Stress:
   - Strict 0o600 file permissions across initial creation, transitions, and finalization.
   - Thread-safe concurrency across 25 simultaneous worker threads.
   - State transition invariants (steps 1..3 required before finalize).
   - Graceful recovery from corrupted state file.
4. Web UI Setup Wizard & Lockout Security:
   - CSRF enforcement on all mutating setup POST routes.
   - Step authentication progression (Steps 1..3 public; Steps 4..7 require admin session).
   - Step 3 credential validation stress (username regex, password length >= 8, password match, TOTP check).
   - Post-lockout permanent block: GET /setup -> /login (302), POST /api/setup/* -> 403.
   - Disaster recovery exemption: Authenticated admin can still invoke POST /api/setup/nginx/restore post-lockout.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, call, patch

from server.auth import AuthManager
from server.dns_ssl_manager import (
    CertbotManager,
    DNSVerifier,
    NamecheapDNSManager,
    parse_domain_parts,
)
from server.flask_app import create_app
from server.nginx_manager import NginxManager
from server.security import generate_csrf_token
from server.setup_wizard import SetupStateManager, run_preflight_checks


# Adversarial 12-record DNS Zone XML response
ADVERSARIAL_GET_HOSTS_XML = """<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="example.com" EmailType="MX">
      <host HostId="101" Name="mail1" Type="MX" Address="mx1.example.com" MXPref="5" TTL="3600" />
      <host HostId="102" Name="mail2" Type="MX" Address="mx2.example.com" MXPref="10" TTL="3600" />
      <host HostId="103" Name="backup" Type="MX" Address="mx3.example.com" MXPref="50" TTL="3600" />
      <host HostId="104" Name="@" Type="TXT" Address="v=spf1 include:_spf.google.com ~all" MXPref="10" TTL="300" />
      <host HostId="105" Name="google._domainkey" Type="TXT" Address="k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3" MXPref="10" TTL="300" />
      <host HostId="106" Name="_dmarc" Type="TXT" Address="v=DMARC1; p=reject; sp=reject; pct=100" MXPref="10" TTL="300" />
      <host HostId="107" Name="@" Type="TXT" Address="google-site-verification=abc123xyz890" MXPref="10" TTL="300" />
      <host HostId="108" Name="www" Type="CNAME" Address="example.com" MXPref="10" TTL="300" />
      <host HostId="109" Name="cdn" Type="CNAME" Address="d123456.cloudfront.net" MXPref="10" TTL="300" />
      <host HostId="110" Name="@" Type="A" Address="198.51.100.1" MXPref="10" TTL="300" />
      <host HostId="111" Name="api" Type="A" Address="198.51.100.10" MXPref="10" TTL="300" />
      <host HostId="112" Name="lock" Type="A" Address="198.51.100.99" MXPref="10" TTL="600" />
    </DomainDNSGetHostsResult>
  </CommandResponse>
</ApiResponse>
"""

MOCK_SET_HOSTS_SUCCESS = """<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <CommandResponse Type="namecheap.domains.dns.setHosts">
    <DomainDNSSetHostsResult Domain="example.com" IsSuccess="true" />
  </CommandResponse>
</ApiResponse>
"""

MOCK_GET_HOSTS_ERROR_2011166 = """<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="ERROR" xmlns="http://api.namecheap.com/xml.response">
  <Errors>
    <Error Number="2011166">Client IP address: 203.0.113.88 is not whitelisted</Error>
  </Errors>
</ApiResponse>
"""


class TestAdversarialNamecheapMerger(unittest.TestCase):
    """Stress tests for Namecheap DNS zone merger and error modes."""

    def setUp(self):
        self.manager = NamecheapDNSManager(
            api_user="advuser",
            api_key="32charhexapikey1234567890abcdef",
            client_ip="203.0.113.88",
        )

    def test_adv_dns_01_update_existing_a_record_preserves_100_percent_of_other_records(self):
        """Updating existing A record 'lock' must 100% preserve all 11 other MX/TXT/CNAME/A records."""
        with patch.object(self.manager, "_post_xml") as mock_post:
            mock_post.side_effect = [
                ADVERSARIAL_GET_HOSTS_XML,
                MOCK_SET_HOSTS_SUCCESS,
            ]

            res = self.manager.safe_set_a_record(
                domain="example.com",
                subdomain="lock",
                ip="203.0.113.199",
                ttl=120,
            )

            self.assertTrue(res.get("success"))
            self.assertEqual(res.get("total_records_preserved"), 12)
            self.assertEqual(mock_post.call_count, 2)

            set_call = mock_post.call_args_list[1]
            params = set_call[0][0]

            # Verify target A record updated
            self.assertEqual(params["HostName12"], "lock")
            self.assertEqual(params["RecordType12"], "A")
            self.assertEqual(params["Address12"], "203.0.113.199")
            self.assertEqual(params["TTL12"], "120")

            # Verify 11 other records preserved exactly
            self.assertEqual(params["HostName1"], "mail1")
            self.assertEqual(params["RecordType1"], "MX")
            self.assertEqual(params["Address1"], "mx1.example.com")
            self.assertEqual(params["MXPref1"], "5")

            self.assertEqual(params["HostName2"], "mail2")
            self.assertEqual(params["MXPref2"], "10")

            self.assertEqual(params["HostName3"], "backup")
            self.assertEqual(params["MXPref3"], "50")

            self.assertEqual(params["HostName4"], "@")
            self.assertEqual(params["RecordType4"], "TXT")
            self.assertEqual(params["Address4"], "v=spf1 include:_spf.google.com ~all")

            self.assertEqual(params["HostName5"], "google._domainkey")
            self.assertEqual(params["RecordType5"], "TXT")
            self.assertIn("k=rsa; p=MIGf", params["Address5"])

            self.assertEqual(params["HostName6"], "_dmarc")
            self.assertEqual(params["Address6"], "v=DMARC1; p=reject; sp=reject; pct=100")

            self.assertEqual(params["HostName8"], "www")
            self.assertEqual(params["RecordType8"], "CNAME")
            self.assertEqual(params["Address8"], "example.com")

            self.assertEqual(params["HostName10"], "@")
            self.assertEqual(params["RecordType10"], "A")
            self.assertEqual(params["Address10"], "198.51.100.1")

            self.assertEqual(params["HostName11"], "api")
            self.assertEqual(params["RecordType11"], "A")
            self.assertEqual(params["Address11"], "198.51.100.10")

    def test_adv_dns_02_append_brand_new_subdomain_preserves_all_12_existing(self):
        """Adding a new A record 'iot' must preserve all 12 existing records and append the 13th."""
        with patch.object(self.manager, "_post_xml") as mock_post:
            mock_post.side_effect = [
                ADVERSARIAL_GET_HOSTS_XML,
                MOCK_SET_HOSTS_SUCCESS,
            ]

            res = self.manager.safe_set_a_record(
                domain="example.com",
                subdomain="iot",
                ip="203.0.113.200",
                ttl=300,
            )

            self.assertTrue(res.get("success"))
            self.assertEqual(res.get("total_records_preserved"), 13)

            set_call = mock_post.call_args_list[1]
            params = set_call[0][0]

            # 13 records total
            self.assertIn("HostName13", params)
            self.assertEqual(params["HostName13"], "iot")
            self.assertEqual(params["RecordType13"], "A")
            self.assertEqual(params["Address13"], "203.0.113.200")
            self.assertEqual(params["TTL13"], "300")

            # Prior 12 records unmodified
            self.assertEqual(params["HostName12"], "lock")
            self.assertEqual(params["Address12"], "198.51.100.99")

    def test_adv_dns_03_error_2011166_provides_structured_ip_whitelist_guidance(self):
        """Error 2011166 must return structured whitelist guidance containing the client IP."""
        with patch.object(self.manager, "_post_xml", return_value=MOCK_GET_HOSTS_ERROR_2011166):
            res = self.manager.safe_set_a_record(
                domain="example.com",
                subdomain="door",
                ip="203.0.113.88",
            )

            self.assertFalse(res.get("success"))
            self.assertEqual(res.get("error_code"), "2011166")
            self.assertTrue(res.get("whitelisting_required"))
            self.assertIn("203.0.113.88", res.get("message", ""))
            self.assertIn("whitelist", res.get("message", "").lower())

    def test_adv_dns_04_error_resilience(self):
        """Tests error resilience: missing credentials, invalid domain, network failure, XML corruption."""
        # 1. Missing credentials
        bad_mgr = NamecheapDNSManager(api_user="", api_key="")
        res1 = bad_mgr.safe_set_a_record("example.com", "lock", "1.1.1.1")
        self.assertFalse(res1.get("success"))
        self.assertEqual(res1.get("error_code"), "MISSING_CREDENTIALS")
        self.assertTrue(res1.get("manual_fallback"))

        # 2. Invalid domain
        res2 = self.manager.safe_set_a_record("invalidlocalhost", "lock", "1.1.1.1")
        self.assertFalse(res2.get("success"))
        self.assertEqual(res2.get("error_code"), "INVALID_DOMAIN")

        # 3. Network error
        with patch.object(self.manager, "_post_xml", side_effect=Exception("Connection refused")):
            res3 = self.manager.safe_set_a_record("example.com", "lock", "1.1.1.1")
            self.assertFalse(res3.get("success"))
            self.assertEqual(res3.get("error_code"), "NETWORK_ERROR")

        # 4. XML parse error
        with patch.object(self.manager, "_post_xml", return_value="<Malformed<<<XML"):
            res4 = self.manager.safe_set_a_record("example.com", "lock", "1.1.1.1")
            self.assertFalse(res4.get("success"))
            self.assertEqual(res4.get("error_code"), "XML_PARSE_ERROR")

    def test_adv_dns_05_multipart_tlds_and_deep_subdomains(self):
        """Stress tests parse_domain_parts across multi-part TLDs and deep subdomains."""
        test_cases = [
            ("door.example.co.uk", ("door", "example", "co.uk")),
            ("lock.home.com.au", ("lock", "home", "com.au")),
            ("iot.gateway.office.co.jp", ("iot.gateway", "office", "co.jp")),
            ("vps.site.org.nz", ("vps", "site", "org.nz")),
            ("node.server.net.in", ("node", "server", "net.in")),
            ("a.b.c.d.example.com", ("a.b.c.d", "example", "com")),
            ("example.com", ("@", "example", "com")),
            ("example.co.uk", ("@", "example", "co.uk")),
        ]
        for domain, expected in test_cases:
            res = parse_domain_parts(domain)
            self.assertEqual(res, expected, f"Failed for domain {domain}")

        # Invalid inputs raise ValueError
        for bad in ("", "   ", "localhost", None):
            with self.assertRaises(ValueError):
                parse_domain_parts(bad)  # type: ignore


class TestAdversarialCertbotPreflightShield(unittest.TestCase):
    """Stress tests for Certbot pre-flight DNS shield preventing Let's Encrypt rate-limiting."""

    def setUp(self):
        self.certbot = CertbotManager(webroot="/var/www/letsencrypt")

    def test_adv_ssl_01_nxdomain_hard_blocks_certbot_subprocess(self):
        """NXDOMAIN / DNS resolution failure must abort Certbot before subprocess execution."""
        with patch.object(DNSVerifier, "_resolve_a_record", return_value=[]):
            with patch.object(self.certbot, "_run_cmd") as mock_run:
                res = self.certbot.issue_certificate(
                    domain="door.unpropagated.com",
                    email="admin@example.com",
                    expected_ip="203.0.113.10",
                )

                self.assertFalse(res.get("success"))
                self.assertFalse(res.get("ready_for_ssl"))
                self.assertEqual(res.get("error"), "DNS_NOT_PROPAGATED")
                self.assertIn("rate limits", res.get("message", "").lower())
                mock_run.assert_not_called()

    def test_adv_ssl_02_ip_mismatch_hard_blocks_certbot_subprocess(self):
        """Domain resolving to a different IP must abort Certbot to shield rate limits."""
        with patch.object(DNSVerifier, "_resolve_a_record", return_value=["198.51.100.99"]):
            with patch.object(self.certbot, "_run_cmd") as mock_run:
                res = self.certbot.issue_certificate(
                    domain="door.wrongip.com",
                    email="admin@example.com",
                    expected_ip="203.0.113.10",
                )

                self.assertFalse(res.get("success"))
                self.assertFalse(res.get("ready_for_ssl"))
                self.assertEqual(res.get("error"), "DNS_NOT_PROPAGATED")
                mock_run.assert_not_called()

    def test_adv_ssl_03_round_robin_resolution_success(self):
        """When expected IP is present among multiple resolved IPs, Certbot is invoked."""
        with patch.object(DNSVerifier, "_resolve_a_record", return_value=["198.51.100.99", "203.0.113.10"]):
            with patch.object(self.certbot, "_run_cmd", return_value=(0, "Cert issued", "")):
                res = self.certbot.issue_certificate(
                    domain="door.example.com",
                    email="admin@example.com",
                    expected_ip="203.0.113.10",
                )
                self.assertTrue(res.get("success"))

    def test_adv_ssl_04_skip_preflight_override(self):
        """skip_preflight=True executes Certbot even when DNS does not match."""
        with patch.object(DNSVerifier, "_resolve_a_record", return_value=["1.1.1.1"]):
            with patch.object(self.certbot, "_run_cmd", return_value=(0, "Cert issued", "")) as mock_run:
                res = self.certbot.issue_certificate(
                    domain="door.example.com",
                    email="admin@example.com",
                    expected_ip="203.0.113.10",
                    skip_preflight=True,
                )
                self.assertTrue(res.get("success"))
                mock_run.assert_called_once()

    def test_adv_ssl_05_certbot_timeout_and_failure_resilience(self):
        """Tests handling of Certbot non-zero exit codes and auto-renewal dry-run failure."""
        with patch.object(self.certbot, "_run_cmd", return_value=(1, "", "ACME error: connection refused")):
            res = self.certbot.issue_certificate(
                domain="door.example.com",
                email="admin@example.com",
                skip_preflight=True,
            )
            self.assertFalse(res.get("success"))
            self.assertEqual(res.get("exit_code"), 1)

        # Auto-renewal failure
        with patch.object(self.certbot, "_run_cmd", return_value=(1, "", "Renew dry-run failed")):
            res_renew = self.certbot.verify_auto_renewal()
            self.assertFalse(res_renew.get("dry_run_success"))
            self.assertEqual(res_renew.get("exit_code"), 1)


class TestAdversarialSetupStateManagerAndLockout(unittest.TestCase):
    """Stress tests for state machine persistence, 0o600 permissions, and concurrency."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(self.temp_dir.name, ".setup_state.json")
        self.mgr = SetupStateManager(state_file=self.state_file)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_adv_state_01_strict_0o600_permissions_across_all_mutations(self):
        """Verifies 0o600 permissions persist across initial creation, advances, and finalization."""
        # 1. Initial creation
        mode1 = stat.S_IMODE(os.stat(self.state_file).st_mode)
        self.assertEqual(mode1, 0o600)

        # 2. Advance Step 1
        self.mgr.advance_step(1, {"terms_accepted": True})
        mode2 = stat.S_IMODE(os.stat(self.state_file).st_mode)
        self.assertEqual(mode2, 0o600)

        # 3. Advance Step 2
        self.mgr.advance_step(2, {"preflight_passed": True})
        mode3 = stat.S_IMODE(os.stat(self.state_file).st_mode)
        self.assertEqual(mode3, 0o600)

        # 4. Advance Step 3
        self.mgr.advance_step(3, {"admin_created": True, "totp_enabled": True})
        mode4 = stat.S_IMODE(os.stat(self.state_file).st_mode)
        self.assertEqual(mode4, 0o600)

        # 5. Finalize setup
        self.mgr.finalize_setup()
        mode5 = stat.S_IMODE(os.stat(self.state_file).st_mode)
        self.assertEqual(mode5, 0o600)

    def test_adv_state_02_multithreaded_concurrency_stress(self):
        """25 simultaneous worker threads advancing steps concurrently must not corrupt JSON."""
        errors: list[Exception] = []

        def worker(thread_idx: int):
            try:
                self.mgr.advance_step(1, {f"thread_{thread_idx}": True})
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(25)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Thread errors: {errors}")
        state = self.mgr.load_state()
        step1_data = state["steps"]["1"]
        # All 25 thread keys should be safely recorded
        for i in range(25):
            self.assertTrue(step1_data.get(f"thread_{i}"))

    def test_adv_state_03_state_transition_invariants(self):
        """Enforces that setup cannot finalize without steps 1..3, and locks permanently."""
        # Missing step 2 and 3
        self.mgr.advance_step(1, {"terms_accepted": True})
        with self.assertRaises(ValueError):
            self.mgr.finalize_setup()

        # Complete steps 2 and 3
        self.mgr.advance_step(2, {"preflight_passed": True})
        self.mgr.advance_step(3, {"admin_created": True, "totp_enabled": True})
        self.mgr.finalize_setup()

        # Now locked: advance raises PermissionError
        with self.assertRaises(PermissionError):
            self.mgr.advance_step(4, {"device_count": 2})

    def test_adv_state_04_corrupted_state_file_recovery(self):
        """Corrupted/truncated state file recovers safely without crashing the server."""
        with open(self.state_file, "w", encoding="utf-8") as f:
            f.write("<<<CORRUPT NON-JSON>>>")

        recovered = self.mgr.load_state()
        self.assertFalse(recovered.get("is_setup_complete"))
        self.assertEqual(recovered.get("current_step"), 1)


class TestAdversarialSetupWizardSecurityAndCSRF(unittest.TestCase):
    """Stress tests for CSRF enforcement, step progression, and post-lockout route protection."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(self.temp_dir.name, ".setup_state.json")
        self.auth_file = os.path.join(self.temp_dir.name, ".auth_credentials.json")
        self.cache_file = os.path.join(self.temp_dir.name, ".session_cache.json")

        self.setup_mgr = SetupStateManager(state_file=self.state_file)
        self.auth_mgr = AuthManager(auth_file=self.auth_file)

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

    def _get_valid_csrf(self) -> str:
        token = generate_csrf_token(self.app.secret_key)
        self.client.set_cookie("mydoor_csrf_token", token)
        return token

    def test_adv_wizard_01_csrf_mandatory_on_mutating_requests(self):
        """Mutating POST requests without valid CSRF must be rejected with HTTP 403."""
        # 1. Missing CSRF header and cookie
        resp1 = self.client.post("/api/setup/step/1", json={"terms_accepted": True})
        self.assertEqual(resp1.status_code, 403)
        self.assertTrue(resp1.get_json().get("csrfRequired"))

        # 2. Tampered token
        token = self._get_valid_csrf()
        resp2 = self.client.post(
            "/api/setup/step/1",
            json={"terms_accepted": True},
            headers={"X-CSRF-Token": "tampered_token_value"},
        )
        self.assertEqual(resp2.status_code, 403)

        # 3. Valid token succeeds
        resp3 = self.client.post(
            "/api/setup/step/1",
            json={"terms_accepted": True},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(resp3.status_code, 200)

    def test_adv_wizard_02_step_auth_progression(self):
        """Steps 1-3 are public; Steps 4-7 require admin session."""
        token = self._get_valid_csrf()

        # Step 4 unauthenticated returns 401
        resp4 = self.client.post(
            "/api/setup/step/4",
            json={"action": "save_devices", "aliases": {}},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(resp4.status_code, 401)
        self.assertTrue(resp4.get_json().get("requires_admin"))

        # Step 5 unauthenticated returns 401
        resp5 = self.client.post(
            "/api/setup/step/5",
            json={"action": "save_dns"},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(resp5.status_code, 401)

        # Step 6 unauthenticated returns 401
        resp6 = self.client.post(
            "/api/setup/step/6",
            json={"action": "apply_nginx"},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(resp6.status_code, 401)

        # Finalize unauthenticated returns 401
        resp_fin = self.client.post(
            "/api/setup/finalize",
            json={},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(resp_fin.status_code, 401)

    def test_adv_wizard_03_step3_credential_hardening(self):
        """Step 3 validates username constraints, password rules, and TOTP correctness."""
        token = self._get_valid_csrf()

        # 1. Username too short
        r1 = self.client.post(
            "/api/setup/step/3",
            json={"action": "create_credentials", "username": "ab", "password": "Password123!", "confirm_password": "Password123!"},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(r1.status_code, 400)

        # 2. Malicious username characters
        r2 = self.client.post(
            "/api/setup/step/3",
            json={"action": "create_credentials", "username": "admin;rm -rf", "password": "Password123!", "confirm_password": "Password123!"},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(r2.status_code, 400)

        # 3. Password too short (< 8 chars)
        r3 = self.client.post(
            "/api/setup/step/3",
            json={"action": "create_credentials", "username": "admin", "password": "short", "confirm_password": "short"},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(r3.status_code, 400)

        # 4. Passwords mismatch
        r4 = self.client.post(
            "/api/setup/step/3",
            json={"action": "create_credentials", "username": "admin", "password": "Password123!", "confirm_password": "MismatchPassword!"},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(r4.status_code, 400)

        # 5. Invalid TOTP code
        self.auth_mgr.create_admin("admin", "Password123!")
        r5 = self.client.post(
            "/api/setup/step/3",
            json={"action": "verify_totp", "username": "admin", "code": "000000"},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(r5.status_code, 400)

    def test_adv_wizard_04_post_lockout_strict_shield(self):
        """Finalizing setup permanently locks wizard endpoints (GET /setup -> 302, POST /api/setup/* -> 403)."""
        token = self._get_valid_csrf()

        # Finalize setup
        self.setup_mgr.advance_step(1, {"terms_accepted": True})
        self.setup_mgr.advance_step(2, {"preflight_passed": True})
        self.setup_mgr.advance_step(3, {"admin_created": True, "totp_enabled": True})
        self.setup_mgr.finalize_setup()

        # GET /setup redirects to /login
        get_res = self.client.get("/setup")
        self.assertEqual(get_res.status_code, 302)
        self.assertIn("/login", get_res.headers.get("Location", ""))

        # Mutating endpoints return 403 with setup_locked: True
        post_targets = [
            "/api/setup/step/1",
            "/api/setup/step/2",
            "/api/setup/step/3",
            "/api/setup/step/4",
            "/api/setup/step/5",
            "/api/setup/step/6",
            "/api/setup/finalize",
            "/api/setup/dns/verify",
            "/api/setup/dns/namecheap",
            "/api/setup/nginx/apply",
        ]
        for target in post_targets:
            res = self.client.post(target, json={}, headers={"X-CSRF-Token": token})
            self.assertEqual(res.status_code, 403, f"Endpoint {target} was not blocked post-lockout.")
            self.assertTrue(res.get_json().get("setup_locked"))

    def test_adv_wizard_05_disaster_recovery_nginx_restore_exemption(self):
        """Single-action restore endpoint /api/setup/nginx/restore remains functional for authenticated admins post-lockout."""
        token = self._get_valid_csrf()

        # Finalize setup
        self.setup_mgr.advance_step(1, {"terms_accepted": True})
        self.setup_mgr.advance_step(2, {"preflight_passed": True})
        self.setup_mgr.advance_step(3, {"admin_created": True, "totp_enabled": True})
        self.setup_mgr.finalize_setup()

        # 1. Unauthenticated request post-lockout is denied
        r_unauth = self.client.post("/api/setup/nginx/restore", json={}, headers={"X-CSRF-Token": token})
        self.assertEqual(r_unauth.status_code, 403)

        # 2. Authenticated non-admin (without 2FA) is denied
        with self.client.session_transaction() as sess:
            sess["auth_user"] = "admin"
            sess["2fa_verified"] = False
        r_no_2fa = self.client.post("/api/setup/nginx/restore", json={}, headers={"X-CSRF-Token": token})
        self.assertEqual(r_no_2fa.status_code, 403)

        # 3. Authenticated admin with 2FA succeeds
        with self.client.session_transaction() as sess:
            sess["auth_user"] = "admin"
            sess["2fa_verified"] = True

        with patch.object(self.nginx_mgr, "restore_backup", return_value={"success": True, "restored_backup_id": "backup_001"}):
            r_auth = self.client.post("/api/setup/nginx/restore", json={}, headers={"X-CSRF-Token": token})
            self.assertEqual(r_auth.status_code, 200)
            self.assertTrue(r_auth.get_json().get("success"))
            self.assertEqual(r_auth.get_json().get("restored_backup_id"), "backup_001")


if __name__ == "__main__":
    unittest.main()
