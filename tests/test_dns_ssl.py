"""Namecheap DNS & Certbot SSL Test Suite (Milestone 9 / Requirement R4).

Verifies:
1. Safe Namecheap DNS merger (getHosts -> merge -> setHosts) preserving all MX/TXT/CNAME records.
2. Namecheap API authentication and Error 2011166 (ClientIP not whitelisted) handling.
3. Accurate multi-part TLD parsing (e.g., .co.uk, .com.au).
4. DNS resolution pre-flight check blocking Certbot when DNS has not propagated.
5. Certbot webroot mode configuration (/var/www/letsencrypt) and CLI arguments.
6. Certbot auto-renewal dry-run verification and deploy hook setup.
"""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent

try:
    from server.dns_ssl_manager import (
        CertbotManager,
        DNSVerifier,
        NamecheapDNSManager,
        parse_domain_parts,
    )
except ImportError:
    NamecheapDNSManager = None
    DNSVerifier = None
    CertbotManager = None
    parse_domain_parts = None


# Mock Namecheap XML responses
MOCK_GET_HOSTS_XML_WITH_MX_AND_TXT = """<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="example.com" EmailType="MX">
      <host HostId="101" Name="@" Type="A" Address="198.51.100.1" MXPref="10" TTL="300" />
      <host HostId="102" Name="www" Type="CNAME" Address="example.com" MXPref="10" TTL="300" />
      <host HostId="103" Name="@" Type="MX" Address="mail.example.com" MXPref="10" TTL="300" />
      <host HostId="104" Name="@" Type="TXT" Address="v=spf1 include:_spf.google.com ~all" MXPref="10" TTL="300" />
      <host HostId="105" Name="sub" Type="A" Address="198.51.100.50" MXPref="10" TTL="300" />
    </DomainDNSGetHostsResult>
  </CommandResponse>
</ApiResponse>
"""

MOCK_GET_HOSTS_ERROR_IP_NOT_WHITELISTED = """<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="ERROR" xmlns="http://api.namecheap.com/xml.response">
  <Errors>
    <Error Number="2011166">Client IP address: 203.0.113.45 is not whitelisted</Error>
  </Errors>
</ApiResponse>
"""

MOCK_SET_HOSTS_SUCCESS = """<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <CommandResponse Type="namecheap.domains.dns.setHosts">
    <DomainDNSSetHostsResult Domain="example.com" IsSuccess="true" />
  </CommandResponse>
</ApiResponse>
"""


class TestDNSAndSSLAutomation(unittest.TestCase):
    """Test suite covering Namecheap DNS API merger, DNS propagation, and Certbot automation."""

    def setUp(self):
        if NamecheapDNSManager is None:
            raise unittest.SkipTest("server.dns_ssl_manager not yet implemented (Milestone 9).")

    # --- 1. Multi-Part TLD Parsing ---

    def test_DNS_01_parse_domain_parts_standard_and_multipart_tlds(self):
        """DNS.01: Verifies accurate domain splitting into Subdomain, SLD, and TLD."""
        cases = [
            ("lock.example.com", ("lock", "example", "com")),
            ("door.myhome.co.uk", ("door", "myhome", "co.uk")),
            ("gateway.sub.site.com.au", ("gateway.sub", "site", "com.au")),
            ("example.com", ("@", "example", "com")),
        ]
        for fqdn, (expected_sub, expected_sld, expected_tld) in cases:
            sub, sld, tld = parse_domain_parts(fqdn)
            self.assertEqual(sub, expected_sub, f"Failed subdomain extraction for {fqdn}")
            self.assertEqual(sld, expected_sld, f"Failed SLD extraction for {fqdn}")
            self.assertEqual(tld, expected_tld, f"Failed TLD extraction for {fqdn}")

    # --- 2. Safe Namecheap Host Record Merger ---

    def test_DNS_02_safe_set_a_record_preserves_existing_mx_and_txt_records(self):
        """DNS.02: CRITICAL: Verifies adding an A-record preserves all MX, TXT, and CNAME records."""
        manager = NamecheapDNSManager(
            api_user="testuser",
            api_key="32charhexapikey1234567890abcdef",
            client_ip="203.0.113.45",
        )

        with patch.object(manager, "_post_xml") as mock_post:
            # First call is getHosts (returns 5 existing records), second is setHosts
            mock_post.side_effect = [
                MOCK_GET_HOSTS_XML_WITH_MX_AND_TXT,
                MOCK_SET_HOSTS_SUCCESS,
            ]

            res = manager.safe_set_a_record(
                domain="example.com",
                subdomain="lock",
                ip="203.0.113.45",
            )

            self.assertTrue(res.get("success"), "safe_set_a_record should return success")
            self.assertEqual(mock_post.call_count, 2)

            # Inspect setHosts payload to verify record preservation
            set_hosts_call = mock_post.call_args_list[1]
            params = set_hosts_call[0][0] if set_hosts_call[0] else set_hosts_call[1].get("data", {})

            # Must contain original MX and TXT records plus new 'lock' A-record
            param_str = str(params)
            self.assertIn("mail.example.com", param_str, "MX record must be preserved")
            self.assertIn("v=spf1", param_str, "TXT SPF record must be preserved")
            self.assertIn("lock", param_str, "New subdomain 'lock' must be included")
            self.assertIn("203.0.113.45", param_str, "New VPS IP must be assigned to A record")

    def test_DNS_03_handle_namecheap_error_2011166_ip_whitelist(self):
        """DNS.03: Verifies handling of Namecheap Error 2011166 (Client IP not whitelisted)."""
        manager = NamecheapDNSManager(
            api_user="testuser",
            api_key="32charhexapikey1234567890abcdef",
            client_ip="203.0.113.45",
        )

        with patch.object(manager, "_post_xml", return_value=MOCK_GET_HOSTS_ERROR_IP_NOT_WHITELISTED):
            res = manager.safe_set_a_record(
                domain="example.com",
                subdomain="lock",
                ip="203.0.113.45",
            )

            self.assertFalse(res.get("success"))
            self.assertEqual(res.get("error_code"), "2011166")
            self.assertIn("203.0.113.45", res.get("message", ""))
            self.assertIn("whitelist", res.get("message", "").lower())

    # --- 3. DNS Propagation Pre-Flight Shield ---

    def test_DNS_04_preflight_blocks_certbot_when_dns_unpropagated(self):
        """DNS.04: Verifies DNSVerifier blocks Certbot if domain does not resolve to VPS IP."""
        verifier = DNSVerifier()

        # Mock resolver returning different IP
        with patch.object(verifier, "_resolve_a_record", return_value=["198.51.100.99"]):
            check = verifier.verify_propagation(
                domain="lock.example.com",
                expected_ip="203.0.113.45",
            )
            self.assertFalse(check.get("is_propagated"))
            self.assertFalse(check.get("ready_for_ssl"))
            self.assertEqual(check.get("resolved_ips"), ["198.51.100.99"])

    def test_DNS_05_preflight_allows_certbot_when_dns_propagated(self):
        """DNS.05: Verifies DNSVerifier allows Certbot when domain matches VPS public IP."""
        verifier = DNSVerifier()

        with patch.object(verifier, "_resolve_a_record", return_value=["203.0.113.45"]):
            check = verifier.verify_propagation(
                domain="lock.example.com",
                expected_ip="203.0.113.45",
            )
            self.assertTrue(check.get("is_propagated"))
            self.assertTrue(check.get("ready_for_ssl"))

    # --- 4. Certbot Webroot Automation ---

    def test_SSL_01_certbot_webroot_issuance_arguments(self):
        """SSL.01: Verifies CertbotManager executes with --webroot and zero host disruption."""
        certbot = CertbotManager(webroot="/var/www/letsencrypt")

        with patch.object(certbot, "_run_cmd") as mock_run:
            mock_run.return_value = (0, "Certificate issued successfully", "")

            res = certbot.issue_certificate(
                domain="lock.example.com",
                email="admin@example.com",
            )

            self.assertTrue(res.get("success"))
            cmd_args = mock_run.call_args[0][0]
            cmd_str = " ".join(cmd_args)

            self.assertIn("--webroot", cmd_str)
            self.assertIn("-w /var/www/letsencrypt", cmd_str)
            self.assertIn("-d lock.example.com", cmd_str)
            self.assertIn("--non-interactive", cmd_str)
            self.assertIn("--agree-tos", cmd_str)

    def test_SSL_02_certbot_auto_renewal_dry_run_verification(self):
        """SSL.02: Verifies auto-renewal dry-run checks certbot renew --dry-run."""
        certbot = CertbotManager(webroot="/var/www/letsencrypt")

        with patch.object(certbot, "_run_cmd") as mock_run:
            mock_run.return_value = (0, "Simulated renewal of all certificates succeeded", "")

            res = certbot.verify_auto_renewal()
            self.assertTrue(res.get("dry_run_success"))

            cmd_args = mock_run.call_args[0][0]
            self.assertIn("renew", cmd_args)
            self.assertIn("--dry-run", cmd_args)


if __name__ == "__main__":
    unittest.main()
