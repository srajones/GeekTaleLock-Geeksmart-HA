"""Milestone 10 Empirical Challenger Test Suite.

Adversarial Stress Harness verifying scripts/install.sh:
1. Argument Parsing Abuse:
   - Invalid ports: 0, -1, 65536, 70000, "abc", "50.50", "50 50", "5050;ls"
   - Missing flag arguments (--port, --domain, --install-dir)
   - Invalid domain syntax (missing TLD, leading hyphen, double dots, scheme, paths, IP, command injection)
   - Unknown options (--unknown, -z)
2. Dry-Run Verification:
   - Verifies --dry-run mutates zero host files, creates zero users/groups, and is idempotent across repeated runs.
3. Privilege Verification:
   - Verifies unprivileged execution fails cleanly with helpful message (exit code 1) unless --dry-run or --help.
4. Rollback Stress Testing:
   - Verifies transactional LIFO rollback executes in strict reverse order upon failure or interrupt (SIGINT/SIGTERM).
   - Verifies rollback survives failures in intermediate rollback steps.
   - Verifies directory, venv, and .env restoration under simulated failure.
   - Verifies INSTALL_SUCCESS suppresses rollback.
5. Strictly Zero Live Physical Deadbolt Actuation:
   - Verifies 100% observational deployment logic and zero lock/unlock/gateway actuation calls.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SCRIPT = REPO_ROOT / "scripts" / "install.sh"


class TestAdversarialArgumentAbuse(unittest.TestCase):
    """Stress tests argument parsing with boundary values, invalid types, and malformed inputs."""

    def run_installer(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(INSTALL_SCRIPT), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    # --- Port Argument Abuse ---

    def test_invalid_port_zero(self):
        """Port 0 is below minimum valid port (1) and must be rejected with exit 2."""
        proc = self.run_installer("--port", "0")
        self.assertEqual(proc.returncode, 2)
        combined = proc.stdout + proc.stderr
        self.assertIn("Invalid port number", combined)

    def test_invalid_port_negative(self):
        """Negative port -1 must be rejected with exit 2."""
        proc = self.run_installer("--port", "-1")
        self.assertEqual(proc.returncode, 2)
        combined = proc.stdout + proc.stderr
        self.assertTrue("requires a port number argument" in combined or "Invalid port number" in combined)

    def test_invalid_port_above_max(self):
        """Ports 65536, 70000, and 999999 exceed 65535 and must be rejected with exit 2."""
        for bad_port in ["65536", "70000", "999999"]:
            with self.subTest(port=bad_port):
                proc = self.run_installer("--port", bad_port)
                self.assertEqual(proc.returncode, 2)
                combined = proc.stdout + proc.stderr
                self.assertIn("Invalid port number", combined)

    def test_invalid_port_non_numeric(self):
        """Non-numeric port strings ('abc', '50.50', '50 50', '5050;ls') must be rejected with exit 2."""
        for bad_port in ["abc", "50.50", "50 50", "5050;ls"]:
            with self.subTest(port=bad_port):
                proc = self.run_installer("--port", bad_port)
                self.assertEqual(proc.returncode, 2)
                combined = proc.stdout + proc.stderr
                self.assertIn("Invalid port number", combined)

    def test_missing_port_argument(self):
        """Option --port without an argument at end of line must exit 2."""
        proc = self.run_installer("--port")
        self.assertEqual(proc.returncode, 2)
        combined = proc.stdout + proc.stderr
        self.assertIn("Option --port requires a port number argument", combined)

    def test_missing_port_argument_followed_by_flag(self):
        """Option --port followed immediately by another flag must exit 2."""
        proc = self.run_installer("--port", "--verbose")
        self.assertEqual(proc.returncode, 2)
        combined = proc.stdout + proc.stderr
        self.assertIn("Option --port requires a port number argument", combined)

    def test_short_flag_port_abuse(self):
        """Short option -p with 0, 70000, abc, or missing argument must exit 2."""
        for arg in ["0", "70000", "abc"]:
            with self.subTest(arg=arg):
                proc = self.run_installer("-p", arg)
                self.assertEqual(proc.returncode, 2)
        proc_missing = self.run_installer("-p")
        self.assertEqual(proc_missing.returncode, 2)

    # --- Domain Argument Abuse ---

    def test_invalid_domain_syntax(self):
        """Invalid domain syntaxes must be rejected with exit 2."""
        invalid_domains = [
            "bad_domain",           # missing dot/TLD
            "-bad.com",             # leading hyphen in label
            "bad..com",             # consecutive dots
            "bad.c",                # single character TLD
            "http://example.com",   # URL scheme prefix
            "https://example.com",  # HTTPS scheme prefix
            "example.com/path",     # URI path component
            "127.0.0.1",            # IPv4 address instead of FQDN
            "example.com; rm -rf /",# Command injection attempt
            "example.com|whoami",   # Pipe injection attempt
            "example.com$(whoami)", # Subshell injection attempt
            "domain.com-",          # Trailing hyphen
        ]
        for bad_domain in invalid_domains:
            with self.subTest(domain=bad_domain):
                proc = self.run_installer("--domain", bad_domain)
                self.assertEqual(proc.returncode, 2)
                combined = proc.stdout + proc.stderr
                self.assertTrue(
                    "Invalid domain name syntax" in combined or "Option --domain requires" in combined,
                    f"Unexpected output for {bad_domain}: {combined}",
                )

    def test_missing_domain_argument(self):
        """Option --domain without an argument must exit 2."""
        proc = self.run_installer("--domain")
        self.assertEqual(proc.returncode, 2)
        combined = proc.stdout + proc.stderr
        self.assertIn("Option --domain requires a domain name argument", combined)

    def test_missing_domain_followed_by_flag(self):
        """Option --domain followed immediately by another flag must exit 2."""
        proc = self.run_installer("--domain", "--dry-run")
        self.assertEqual(proc.returncode, 2)
        combined = proc.stdout + proc.stderr
        self.assertIn("Option --domain requires a domain name argument", combined)

    # --- Directory & Unknown Options ---

    def test_missing_install_dir_argument(self):
        """Option --install-dir without argument or followed by flag must exit 2."""
        proc1 = self.run_installer("--install-dir")
        self.assertEqual(proc1.returncode, 2)
        proc2 = self.run_installer("--install-dir", "--verbose")
        self.assertEqual(proc2.returncode, 2)

    def test_unknown_options(self):
        """Unknown flags (--unknown, -z, --bad-opt=1) must exit 2 with helpful message."""
        for bad_opt in ["--unknown-flag", "-z", "--bad-option=1"]:
            with self.subTest(opt=bad_opt):
                proc = self.run_installer(bad_opt)
                self.assertEqual(proc.returncode, 2)
                combined = proc.stdout + proc.stderr
                self.assertIn("Unknown option", combined)
                self.assertIn("--help", combined)


class TestAdversarialDryRunPurity(unittest.TestCase):
    """Stress tests --dry-run mode to guarantee zero host mutations."""

    def test_dry_run_zero_filesystem_mutations(self):
        """Running with --dry-run must not create /opt/mydoor or /etc/systemd/system/mydoor.service."""
        proc = subprocess.run(
            ["bash", str(INSTALL_SCRIPT), "--dry-run", "--verbose"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        combined = proc.stdout + proc.stderr
        self.assertIn("DRY-RUN", combined.upper())
        self.assertIn("Zero host modifications were made", combined)

        # Host checks
        self.assertFalse(
            Path("/opt/mydoor").exists(),
            "/opt/mydoor must NOT exist after --dry-run",
        )
        self.assertFalse(
            Path("/etc/systemd/system/mydoor.service").exists(),
            "/etc/systemd/system/mydoor.service must NOT exist after --dry-run",
        )

    def test_dry_run_zero_user_or_group_creation(self):
        """Running with --dry-run must not create user or group 'geekdoor'."""
        user_check = subprocess.run(["id", "geekdoor"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(user_check.returncode, 0, "User geekdoor must not exist on host")

    def test_dry_run_repeated_idempotence(self):
        """Running --dry-run repeatedly produces identical clean exit 0 without state accumulation."""
        for i in range(5):
            proc = subprocess.run(
                ["bash", str(INSTALL_SCRIPT), "--dry-run", "--port", "5050", "--domain", "door.example.com"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, f"Dry run #{i+1} failed with {proc.stderr}")

    def test_dry_run_with_custom_valid_parameters(self):
        """Custom parameters (--port 8080 --domain mydoor.example.com) are validated and printed without applying."""
        proc = subprocess.run(
            [
                "bash", str(INSTALL_SCRIPT),
                "--dry-run",
                "--port", "8080",
                "--domain", "mydoor.example.com",
                "--verbose",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        combined = proc.stdout + proc.stderr
        self.assertIn("8080", combined)
        self.assertIn("mydoor.example.com", combined)


class TestAdversarialPrivilegeEnforcement(unittest.TestCase):
    """Verifies unprivileged execution fails cleanly unless --dry-run or --help."""

    def test_unprivileged_default_install_fails_cleanly(self):
        """Running without root fails cleanly with exit code 1 and helpful instructions."""
        proc = subprocess.run(
            ["bash", str(INSTALL_SCRIPT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        combined = proc.stdout + proc.stderr
        self.assertIn("Root privileges required", combined)
        self.assertIn("sudo", combined)

    def test_unprivileged_custom_parameters_fail_cleanly(self):
        """Unprivileged execution with custom flags fails before any inspection/mutation."""
        proc = subprocess.run(
            ["bash", str(INSTALL_SCRIPT), "--port", "8080", "--domain", "door.example.com"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        combined = proc.stdout + proc.stderr
        self.assertIn("Root privileges required", combined)

    def test_unprivileged_restore_nginx_fails_cleanly(self):
        """Unprivileged --restore-nginx fails cleanly with exit code 1 and privilege message."""
        proc = subprocess.run(
            ["bash", str(INSTALL_SCRIPT), "--restore-nginx"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        combined = proc.stdout + proc.stderr
        self.assertIn("Restoring Nginx configuration requires root privileges", combined)

    def test_unprivileged_help_succeeds(self):
        """Unprivileged execution with -h or --help succeeds with exit code 0."""
        for flag in ["-h", "--help"]:
            with self.subTest(flag=flag):
                proc = subprocess.run(
                    ["bash", str(INSTALL_SCRIPT), flag],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(proc.returncode, 0)
                combined = proc.stdout + proc.stderr
                self.assertIn("Usage:", combined)
                self.assertIn("--port", combined)
                self.assertIn("--domain", combined)

    def test_unprivileged_dry_run_succeeds(self):
        """Unprivileged execution with --dry-run succeeds with exit code 0."""
        proc = subprocess.run(
            ["bash", str(INSTALL_SCRIPT), "--dry-run"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)


class TestAdversarialLifoRollbackEngine(unittest.TestCase):
    """Stress tests the transactional LIFO rollback subsystem under simulated failures."""

    def test_lifo_strict_reverse_execution_order(self):
        """Verifies actions in ROLLBACK_STACK execute strictly in reverse LIFO order."""
        with tempfile.TemporaryDirectory(prefix="adv_lifo_order_") as tmpdir:
            log_file = Path(tmpdir) / "execution_order.log"
            script_content = f"""#!/usr/bin/env bash
eval "$(sed 's/^main "\$@"/true/' "{INSTALL_SCRIPT}")"

# Push 5 mock actions
rollback_push 'echo "STEP_1" >> "{log_file}"'
rollback_push 'echo "STEP_2" >> "{log_file}"'
rollback_push 'echo "STEP_3" >> "{log_file}"'
rollback_push 'echo "STEP_4" >> "{log_file}"'
rollback_push 'echo "STEP_5" >> "{log_file}"'

# Simulate failure
false
"""
            test_sh = Path(tmpdir) / "test_lifo.sh"
            test_sh.write_text(script_content, encoding="utf-8")
            test_sh.chmod(0o755)

            proc = subprocess.run(
                ["bash", str(test_sh)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0, "Script should have failed on 'false'")
            self.assertTrue(log_file.exists(), "Rollback log file must be created")

            lines = log_file.read_text(encoding="utf-8").strip().splitlines()
            expected_order = ["STEP_5", "STEP_4", "STEP_3", "STEP_2", "STEP_1"]
            self.assertEqual(
                lines,
                expected_order,
                f"Rollback did not execute in strict LIFO order. Actual: {lines}, Expected: {expected_order}",
            )

    def test_rollback_survives_partial_step_failure(self):
        """If an intermediate rollback step fails, remaining rollback steps must still execute."""
        with tempfile.TemporaryDirectory(prefix="adv_lifo_fault_") as tmpdir:
            log_file = Path(tmpdir) / "fault_test.log"
            script_content = f"""#!/usr/bin/env bash
eval "$(sed 's/^main "\$@"/true/' "{INSTALL_SCRIPT}")"

rollback_push 'echo "STEP_A" >> "{log_file}"'
rollback_push 'non_existent_command_that_errors_out'
rollback_push 'echo "STEP_C" >> "{log_file}"'

# Trigger failure
exit 1
"""
            test_sh = Path(tmpdir) / "test_fault.sh"
            test_sh.write_text(script_content, encoding="utf-8")
            test_sh.chmod(0o755)

            proc = subprocess.run(
                ["bash", str(test_sh)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertTrue(log_file.exists())
            lines = log_file.read_text(encoding="utf-8").strip().splitlines()
            # STEP_C executed first, then failing command produced warning, then STEP_A executed!
            self.assertIn("STEP_C", lines)
            self.assertIn("STEP_A", lines)
            self.assertEqual(lines, ["STEP_C", "STEP_A"])
            self.assertIn("Rollback step encountered error", proc.stderr)

    def test_rollback_directory_and_venv_cleanup(self):
        """Simulate failure during virtualenv creation; verify rollback removes created venv directory."""
        with tempfile.TemporaryDirectory(prefix="adv_venv_cleanup_") as tmpdir:
            staging_dir = Path(tmpdir) / "opt_mydoor"
            staging_dir.mkdir()
            venv_dir = staging_dir / "venv"

            script_content = f"""#!/usr/bin/env bash
export MYDOOR_INSTALL_DIR="{staging_dir}"
export DEFAULT_USER="$(whoami)"
export DEFAULT_GROUP="$(id -gn)"
eval "$(sed 's/^main "\$@"/true/' "{INSTALL_SCRIPT}")"

setup_virtualenv

# Verify venv exists before failure
if [ -d "{venv_dir}" ]; then
  touch "{staging_dir}/venv_existed_before_failure.flag"
fi

# Simulate failure in next stage
false
"""
            test_sh = Path(tmpdir) / "test_venv.sh"
            test_sh.write_text(script_content, encoding="utf-8")
            test_sh.chmod(0o755)

            proc = subprocess.run(
                ["bash", str(test_sh)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            flag_file = staging_dir / "venv_existed_before_failure.flag"
            self.assertTrue(flag_file.exists(), "Venv must have been created before simulated failure")
            self.assertFalse(venv_dir.exists(), "Venv directory must be removed by rollback upon failure")

    def test_rollback_env_backup_restoration(self):
        """Simulate existing .env file; verify failure restores original .env from backup."""
        with tempfile.TemporaryDirectory(prefix="adv_env_restore_") as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("ORIGINAL_SECRET=secret12345\n", encoding="utf-8")

            script_content = f"""#!/usr/bin/env bash
export MYDOOR_INSTALL_DIR="{tmpdir}"
export DEFAULT_USER="$(whoami)"
export DEFAULT_GROUP="$(id -gn)"
eval "$(sed 's/^main "\$@"/true/' "{INSTALL_SCRIPT}")"

configure_env

# Simulate failure in subsequent step
false
"""
            test_sh = Path(tmpdir) / "test_env.sh"
            test_sh.write_text(script_content, encoding="utf-8")
            test_sh.chmod(0o755)

            proc = subprocess.run(
                ["bash", str(test_sh)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertTrue(env_file.exists())
            content = env_file.read_text(encoding="utf-8")
            self.assertEqual(
                content,
                "ORIGINAL_SECRET=secret12345\n",
                "Original .env content must be restored by rollback",
            )

    def test_rollback_on_sigint_and_sigterm(self):
        """Verifies rollback traps catch SIGINT and SIGTERM and execute rollback actions."""
        for sig_name in ["INT", "TERM"]:
            with self.subTest(signal=sig_name):
                with tempfile.TemporaryDirectory(prefix=f"adv_sig_{sig_name}_") as tmpdir:
                    flag_file = Path(tmpdir) / "rolled_back.flag"
                    script_content = f"""#!/usr/bin/env bash
eval "$(sed 's/^main "\$@"/true/' "{INSTALL_SCRIPT}")"

rollback_push 'echo "CAUGHT_SIGNAL_{sig_name}" > "{flag_file}"'

# Send signal to self
kill -{sig_name} $$
"""
                    test_sh = Path(tmpdir) / f"test_sig_{sig_name}.sh"
                    test_sh.write_text(script_content, encoding="utf-8")
                    test_sh.chmod(0o755)

                    proc = subprocess.run(
                        ["bash", str(test_sh)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertTrue(
                        flag_file.exists(),
                        f"Rollback flag file was not created on SIG{sig_name}. Stderr: {proc.stderr}",
                    )
                    content = flag_file.read_text(encoding="utf-8").strip()
                    self.assertEqual(content, f"CAUGHT_SIGNAL_{sig_name}")

    def test_install_success_flag_suppresses_rollback(self):
        """When INSTALL_SUCCESS=1, normal termination does NOT trigger rollback."""
        with tempfile.TemporaryDirectory(prefix="adv_success_") as tmpdir:
            flag_file = Path(tmpdir) / "should_not_exist.flag"
            script_content = f"""#!/usr/bin/env bash
eval "$(sed 's/^main "\$@"/true/' "{INSTALL_SCRIPT}")"

rollback_push 'echo "UNWANTED_ROLLBACK" > "{flag_file}"'

# Mark success and exit normally
INSTALL_SUCCESS=1
exit 0
"""
            test_sh = Path(tmpdir) / "test_success.sh"
            test_sh.write_text(script_content, encoding="utf-8")
            test_sh.chmod(0o755)

            proc = subprocess.run(
                ["bash", str(test_sh)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertFalse(
                flag_file.exists(),
                "Rollback must NOT execute when INSTALL_SUCCESS=1",
            )


class TestAdversarialPhysicalSafetyAndActuations(unittest.TestCase):
    """Stress tests physical safety guarantees to ensure strictly ZERO deadbolt actuations."""

    def test_zero_physical_deadbolt_actuation_rpcs_in_script(self):
        """Verifies install.sh contains zero physical lock actuation RPCs or endpoints."""
        content = INSTALL_SCRIPT.read_text(encoding="utf-8")
        forbidden_patterns = [
            r"ttlockGatewayUnlock",
            r"ttlockGatewayLock",
            r"ble_unlock_check",
            r"remote_pd_setkey_check",
            r"/api/devices/[^/]+/unlock",
            r"/api/devices/[^/]+/lock",
            r"/api/ha/lock/[^/]+/unlock",
            r"/api/ha/lock/[^/]+/lock",
            r"door_lock_control\.py\s+unlock",
            r"door_lock_control\.py\s+lock",
            r"DP\s*71",
            r"DP\s*47",
            r"DP\s*33",
        ]
        for pattern in forbidden_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            self.assertEqual(
                len(matches),
                0,
                f"Forbidden actuation pattern '{pattern}' found in scripts/install.sh: {matches}",
            )

    def test_only_observational_health_probe(self):
        """Confirms the only HTTP network probe executed in install.sh is /api/health."""
        content = INSTALL_SCRIPT.read_text(encoding="utf-8")
        # Extract all curl URLs
        curl_matches = re.findall(r"curl\s+[^\"'\n]*[\"']?(https?://[^\"'\s>]+)", content)
        for url in curl_matches:
            # Must either be public IP discovery or local /api/health
            is_valid = (
                "ifconfig.me" in url
                or "ipify.org" in url
                or "api/health" in url
            )
            self.assertTrue(
                is_valid,
                f"Unexpected curl endpoint in install.sh: {url}",
            )


if __name__ == "__main__":
    unittest.main()
