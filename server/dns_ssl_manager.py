"""Namecheap DNS Automation, DNS Verification, and Certbot SSL Manager.

Milestone 9 / Requirement R4 Implementation.
Provides:
1. parse_domain_parts: Multi-part TLD parsing (e.g. .co.uk, .com.au, .com, .org).
2. NamecheapDNSManager: Safe getHosts -> merge -> setHosts preserving all MX/TXT/CNAME records.
3. DNSVerifier: Live DNS propagation checking & manual DNS card generation.
4. CertbotManager: Certbot webroot issuance, DNS pre-flight shield, and auto-renewal dry-run.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
import re
import socket
import subprocess
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

logger = logging.getLogger("mydoor.dns_ssl")

# Multi-part TLD suffixes
MULTIPART_TLDS = {
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "iwi.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ed.jp", "ad.jp",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "co.za", "org.za", "net.za", "gov.za", "ac.za",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "com.mx", "org.mx", "gob.mx", "edu.mx", "net.mx",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "gov.in", "ac.in",
    "co.il", "org.il", "net.il", "ac.il", "gov.il",
    "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr",
    "com.tw", "org.tw", "net.tw", "idv.tw", "gov.tw",
}


def parse_domain_parts(domain_or_fqdn: str) -> Tuple[str, str, str]:
    """Parse a domain or FQDN into (subdomain, sld, tld).

    Supports standard and multi-part TLDs (e.g., .co.uk, .com.au).
    If no subdomain is present, returns "@" for the subdomain.
    Validates RFC 1035/1123 domain syntax and label lengths.
    """
    if not domain_or_fqdn or not isinstance(domain_or_fqdn, str):
        raise ValueError("Domain must be a non-empty string.")

    cleaned = domain_or_fqdn.strip().strip(".").lower()
    if not cleaned:
        raise ValueError("Domain cannot be empty.")

    if len(cleaned) > 253:
        raise ValueError(f"Domain name exceeds maximum length of 253 characters (got {len(cleaned)}).")

    parts = cleaned.split(".")
    if len(parts) < 2:
        raise ValueError(f"Invalid domain '{domain_or_fqdn}': must have at least SLD and TLD.")

    for part in parts:
        if not part:
            raise ValueError(f"Invalid domain '{domain_or_fqdn}': contains empty label.")
        if len(part) > 63:
            raise ValueError(f"Domain label '{part}' exceeds maximum length of 63 characters.")
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$", part):
            raise ValueError(
                f"Invalid characters in domain label '{part}'. "
                "Labels must contain only alphanumeric characters and hyphens, and cannot start or end with a hyphen."
            )

    if parts[-1].isdigit():
        raise ValueError(f"Invalid domain '{domain_or_fqdn}': top-level domain cannot be all-numeric.")

    # Check for multi-part TLD
    is_multipart = False
    if len(parts) >= 3:
        potential_multipart = f"{parts[-2]}.{parts[-1]}"
        if potential_multipart in MULTIPART_TLDS or (
            len(parts[-1]) == 2 and parts[-2] in {"co", "com", "net", "org", "edu", "gov", "gob", "govt", "ac"}
        ):
            is_multipart = True

    if is_multipart:
        tld = f"{parts[-2]}.{parts[-1]}"
        sld = parts[-3]
        sub_parts = parts[:-3]
    else:
        tld = parts[-1]
        sld = parts[-2]
        sub_parts = parts[:-2]

    subdomain = ".".join(sub_parts) if sub_parts else "@"
    return subdomain, sld, tld


class NamecheapDNSManager:
    """Manages Namecheap DNS records via Namecheap API with safe merger."""

    PRODUCTION_API_URL = "https://api.namecheap.com/xml.response"
    SANDBOX_API_URL = "https://api.sandbox.namecheap.com/xml.response"

    def __init__(
        self,
        api_user: str = "",
        api_key: str = "",
        client_ip: str = "",
        username: Optional[str] = None,
        sandbox: bool = False,
        timeout: float = 15.0,
    ) -> None:
        self.api_user = api_user.strip()
        self.api_key = api_key.strip()
        self.client_ip = client_ip.strip()
        self.username = (username or api_user).strip()
        self.sandbox = sandbox
        self.timeout = timeout
        self.api_url = self.SANDBOX_API_URL if sandbox else self.PRODUCTION_API_URL

    def _post_xml(self, data: Dict[str, str]) -> str:
        """Execute HTTPS POST to Namecheap XML API."""
        encoded_data = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(
            self.api_url,
            data=encoded_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.read().decode("utf-8")

    def _extract_elements(self, parent: ET.Element, tag_name: str) -> List[ET.Element]:
        """Find elements matching tag_name ignoring XML namespaces."""
        elements: List[ET.Element] = []
        for elem in parent.iter():
            if elem.tag == tag_name or elem.tag.endswith(f"}}{tag_name}"):
                elements.append(elem)
        return elements

    def get_hosts(self, sld: str, tld: str) -> List[Dict[str, Any]]:
        """Retrieves existing host records for the given SLD and TLD."""
        params = {
            "ApiUser": self.api_user,
            "ApiKey": self.api_key,
            "UserName": self.username,
            "ClientIP": self.client_ip,
            "Command": "namecheap.domains.dns.getHosts",
            "SLD": sld,
            "TLD": tld,
        }
        xml_resp = self._post_xml(params)
        root = ET.fromstring(xml_resp)

        # Check for errors
        errors = self._extract_elements(root, "Error")
        if errors:
            err_num = errors[0].attrib.get("Number", "UNKNOWN")
            err_txt = errors[0].text or "Unknown error"
            raise RuntimeError(f"Namecheap getHosts error ({err_num}): {err_txt}")

        host_elements = self._extract_elements(root, "host")
        hosts = []
        for host in host_elements:
            hosts.append({
                "HostName": host.attrib.get("Name", "@"),
                "RecordType": host.attrib.get("Type", "A"),
                "Address": host.attrib.get("Address", ""),
                "MXPref": host.attrib.get("MXPref", "10"),
                "TTL": host.attrib.get("TTL", "300"),
            })
        return hosts

    def set_hosts(self, sld: str, tld: str, hosts: List[Dict[str, Any]]) -> bool:
        """Sets host records for the given SLD and TLD."""
        params = {
            "ApiUser": self.api_user,
            "ApiKey": self.api_key,
            "UserName": self.username,
            "ClientIP": self.client_ip,
            "Command": "namecheap.domains.dns.setHosts",
            "SLD": sld,
            "TLD": tld,
        }
        for idx, rec in enumerate(hosts, start=1):
            params[f"HostName{idx}"] = rec.get("HostName", "@")
            params[f"RecordType{idx}"] = rec.get("RecordType", "A")
            params[f"Address{idx}"] = rec.get("Address", "")
            params[f"MXPref{idx}"] = str(rec.get("MXPref", "10"))
            params[f"TTL{idx}"] = str(rec.get("TTL", "300"))

        xml_resp = self._post_xml(params)
        root = ET.fromstring(xml_resp)
        status = root.attrib.get("Status", "").upper()
        errors = self._extract_elements(root, "Error")
        if status == "ERROR" or errors:
            err_num = errors[0].attrib.get("Number", "UNKNOWN") if errors else "UNKNOWN"
            err_txt = errors[0].text if errors and errors[0].text else "Unknown error"
            raise RuntimeError(f"Namecheap setHosts error ({err_num}): {err_txt}")
        return True

    def safe_set_a_record(
        self,
        domain: str,
        subdomain: str = "@",
        ip: str = "",
        ttl: int = 300,
    ) -> Dict[str, Any]:
        """Safely set or update an A-record while strictly preserving all existing records."""
        if not self.api_user or not self.api_key:
            return {
                "success": False,
                "error_code": "MISSING_CREDENTIALS",
                "message": "Namecheap API credentials are required. Please switch to manual DNS mode.",
                "manual_fallback": True,
            }

        try:
            parsed_sub, sld, tld = parse_domain_parts(domain)
            target_sub = subdomain if subdomain not in (None, "") else parsed_sub
        except ValueError as e:
            return {"success": False, "error_code": "INVALID_DOMAIN", "message": str(e)}

        # 1. Fetch existing zone records (getHosts)
        get_params = {
            "ApiUser": self.api_user,
            "ApiKey": self.api_key,
            "UserName": self.username,
            "ClientIP": self.client_ip,
            "Command": "namecheap.domains.dns.getHosts",
            "SLD": sld,
            "TLD": tld,
        }

        try:
            xml_resp = self._post_xml(get_params)
        except Exception as e:
            return {
                "success": False,
                "error_code": "NETWORK_ERROR",
                "message": f"Failed to contact Namecheap API: {e}",
            }

        # Parse XML response
        try:
            root = ET.fromstring(xml_resp)
        except ET.ParseError as e:
            return {
                "success": False,
                "error_code": "XML_PARSE_ERROR",
                "message": f"Invalid XML response from Namecheap: {e}",
            }

        status = root.attrib.get("Status", "").upper()

        # Check for errors
        errors = self._extract_elements(root, "Error")
        if status == "ERROR" or errors:
            error_num = errors[0].attrib.get("Number", "") if errors else "UNKNOWN"
            error_text = errors[0].text if errors and errors[0].text else "Unknown Namecheap error"

            if error_num == "2011166" or "not whitelisted" in error_text.lower():
                return {
                    "success": False,
                    "error_code": "2011166",
                    "message": (
                        f"Client IP address: {self.client_ip} is not whitelisted in your "
                        "Namecheap API account. Please add this IP address to your "
                        "API Access Whitelist in the Namecheap console (Profile -> Tools -> Namecheap API Access)."
                    ),
                    "raw_error": error_text,
                    "whitelisting_required": True,
                }
            return {
                "success": False,
                "error_code": error_num,
                "message": f"Namecheap API Error ({error_num}): {error_text}",
            }

        # 2. Extract existing records
        host_elements = self._extract_elements(root, "host")
        existing_records: List[Dict[str, Any]] = []
        for host in host_elements:
            rec = {
                "HostName": host.attrib.get("Name", "@"),
                "RecordType": host.attrib.get("Type", "A"),
                "Address": host.attrib.get("Address", ""),
                "MXPref": host.attrib.get("MXPref", "10"),
                "TTL": host.attrib.get("TTL", "300"),
            }
            existing_records.append(rec)

        # 3. Merge new or updated A-record
        merged_records: List[Dict[str, Any]] = []
        found_target = False
        target_sub_lower = target_sub.lower()

        for rec in existing_records:
            if rec["RecordType"].upper() == "A" and rec["HostName"].lower() == target_sub_lower:
                # Update existing A record
                updated_rec = dict(rec)
                updated_rec["Address"] = ip
                updated_rec["TTL"] = str(ttl)
                merged_records.append(updated_rec)
                found_target = True
            else:
                # Preserve existing record unmodified (MX, TXT, CNAME, other A)
                merged_records.append(rec)

        if not found_target:
            # Append new A record
            merged_records.append({
                "HostName": target_sub,
                "RecordType": "A",
                "Address": ip,
                "MXPref": "10",
                "TTL": str(ttl),
            })

        # 4. Formulate setHosts parameters
        set_params = {
            "ApiUser": self.api_user,
            "ApiKey": self.api_key,
            "UserName": self.username,
            "ClientIP": self.client_ip,
            "Command": "namecheap.domains.dns.setHosts",
            "SLD": sld,
            "TLD": tld,
        }

        for idx, rec in enumerate(merged_records, start=1):
            set_params[f"HostName{idx}"] = rec["HostName"]
            set_params[f"RecordType{idx}"] = rec["RecordType"]
            set_params[f"Address{idx}"] = rec["Address"]
            set_params[f"MXPref{idx}"] = rec.get("MXPref", "10")
            set_params[f"TTL{idx}"] = rec.get("TTL", "300")

        # 5. Call setHosts
        try:
            set_resp_xml = self._post_xml(set_params)
        except Exception as e:
            return {
                "success": False,
                "error_code": "NETWORK_ERROR",
                "message": f"Failed calling setHosts on Namecheap API: {e}",
            }

        try:
            set_root = ET.fromstring(set_resp_xml)
        except ET.ParseError as e:
            return {
                "success": False,
                "error_code": "XML_PARSE_ERROR",
                "message": f"Invalid XML response from setHosts: {e}",
            }

        set_status = set_root.attrib.get("Status", "").upper()
        set_errors = self._extract_elements(set_root, "Error")

        if set_status == "ERROR" or set_errors:
            err_num = set_errors[0].attrib.get("Number", "") if set_errors else "UNKNOWN"
            err_txt = set_errors[0].text if set_errors and set_errors[0].text else "Unknown error"
            return {
                "success": False,
                "error_code": err_num,
                "message": f"Namecheap setHosts failed ({err_num}): {err_txt}",
            }

        return {
            "success": True,
            "message": f"A-record for '{target_sub}.{sld}.{tld}' successfully configured to '{ip}'.",
            "domain": f"{sld}.{tld}",
            "subdomain": target_sub,
            "ip": ip,
            "total_records_preserved": len(merged_records),
        }


class DNSVerifier:
    """Verifies DNS A-record propagation before SSL issuance."""

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def _resolve_a_record(self, domain: str) -> List[str]:
        """Resolve IPv4 A records for domain using socket.getaddrinfo."""
        try:
            addr_info = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
            ips = list(dict.fromkeys(info[4][0] for info in addr_info))
            return ips
        except (socket.gaierror, socket.timeout, Exception):
            return []

    def verify_propagation(
        self,
        domain: str,
        expected_ip: str,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Verify if domain resolves to the expected IP address."""
        resolved_ips = self._resolve_a_record(domain)
        is_propagated = expected_ip in resolved_ips
        ready_for_ssl = is_propagated

        if is_propagated:
            message = f"DNS propagation verified: '{domain}' resolves to {expected_ip}."
            error = None
        elif not resolved_ips:
            message = f"DNS record for '{domain}' not found (NXDOMAIN or DNS timeout)."
            error = "NXDOMAIN"
        else:
            message = f"DNS record points to {resolved_ips}, expected {expected_ip}."
            error = "IP_MISMATCH"

        return {
            "is_propagated": is_propagated,
            "ready_for_ssl": ready_for_ssl,
            "domain": domain,
            "expected_ip": expected_ip,
            "resolved_ips": resolved_ips,
            "message": message,
            "error": error,
        }

    def get_manual_dns_card(self, domain_or_fqdn: str, target_ip: str, ttl: str = "300") -> Dict[str, Any]:
        """Generate structured data for manual DNS entry UI card."""
        sub, sld, tld = parse_domain_parts(domain_or_fqdn)
        return {
            "record_type": "A",
            "host": sub,
            "value": target_ip,
            "ttl": str(ttl),
            "fqdn": f"{sub}.{sld}.{tld}" if sub != "@" else f"{sld}.{tld}",
            "root_domain": f"{sld}.{tld}",
        }


class CertbotManager:
    """Manages Certbot SSL certificate issuance and auto-renewal checks."""

    def __init__(
        self,
        webroot: str = "/var/www/letsencrypt",
        cert_dir: str = "/etc/letsencrypt/live",
        certbot_cmd: str = "certbot",
    ) -> None:
        self.webroot = webroot
        self.cert_dir = cert_dir
        self.certbot_cmd = certbot_cmd

    def _run_cmd(self, cmd_args: List[str]) -> Tuple[int, str, str]:
        """Execute a command and return (exit_code, stdout, stderr)."""
        try:
            proc = subprocess.run(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=120,
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out after 120 seconds."
        except Exception as e:
            return -1, "", str(e)

    def issue_certificate(
        self,
        domain: str,
        email: str,
        deploy_hook: str = "systemctl reload nginx",
        expected_ip: Optional[str] = None,
        skip_preflight: bool = False,
        test_cert: bool = False,
    ) -> Dict[str, Any]:
        """Issue an SSL certificate via Certbot webroot mode with pre-flight DNS shield."""
        # Pre-flight DNS check if expected_ip is provided and skip_preflight is False
        if expected_ip and not skip_preflight:
            verifier = DNSVerifier()
            check = verifier.verify_propagation(domain, expected_ip)
            if not check.get("ready_for_ssl"):
                return {
                    "success": False,
                    "error": "DNS_NOT_PROPAGATED",
                    "ready_for_ssl": False,
                    "message": (
                        f"Pre-flight DNS check failed: '{domain}' does not resolve to '{expected_ip}'. "
                        "Aborting to avoid Let's Encrypt rate limits (5 failures/hour)."
                    ),
                    "dns_check": check,
                }

        cmd = [
            self.certbot_cmd,
            "certonly",
            "--webroot",
            "-w", self.webroot,
            "-d", domain,
            "--non-interactive",
            "--agree-tos",
            "--email", email,
        ]

        if test_cert:
            cmd.append("--test-cert")

        if deploy_hook:
            cmd.extend(["--deploy-hook", deploy_hook])

        code, stdout, stderr = self._run_cmd(cmd)

        if code == 0:
            return {
                "success": True,
                "domain": domain,
                "certificate_path": f"{self.cert_dir}/{domain}/fullchain.pem",
                "private_key_path": f"{self.cert_dir}/{domain}/privkey.pem",
                "webroot": self.webroot,
                "message": f"SSL certificate issued successfully for {domain}.",
                "stdout": stdout,
            }
        else:
            return {
                "success": False,
                "domain": domain,
                "exit_code": code,
                "error": stderr or stdout,
                "message": f"Certbot issuance failed for {domain} (exit code {code}).",
            }

    def verify_auto_renewal(self) -> Dict[str, Any]:
        """Verify automatic certificate renewal using certbot renew --dry-run."""
        cmd = [self.certbot_cmd, "renew", "--dry-run"]
        code, stdout, stderr = self._run_cmd(cmd)

        return {
            "dry_run_success": code == 0,
            "exit_code": code,
            "stdout": stdout,
            "stderr": stderr,
            "message": "Auto-renewal dry-run passed." if code == 0 else "Auto-renewal dry-run failed.",
        }

    def get_certificate_paths(self, domain_or_fqdn: str) -> Dict[str, Optional[str]]:
        """Returns expected or existing certificate paths for domain."""
        clean = domain_or_fqdn.strip().lower()
        cert_path = Path(self.cert_dir) / clean / "fullchain.pem"
        key_path = Path(self.cert_dir) / clean / "privkey.pem"
        return {
            "cert_path": str(cert_path) if cert_path.exists() else None,
            "key_path": str(key_path) if key_path.exists() else None,
            "expected_cert_path": str(cert_path),
            "expected_key_path": str(key_path),
        }

    def setup_renewal_hook(
        self,
        hook_path: str = "/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh",
    ) -> bool:
        """Set up automated deploy hook script for Nginx reload upon cert renewal."""
        try:
            target = Path(hook_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("#!/bin/sh\nsystemctl reload nginx\n", encoding="utf-8")
            os.chmod(target, 0o755)
            return True
        except Exception:
            return False
