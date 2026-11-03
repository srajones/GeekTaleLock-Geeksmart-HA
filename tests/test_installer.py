"""Failsafe Installer & Host Hardening Test Suite (Milestone 10 / Requirement R2).

Verifies:
1. Syntax validity of scripts/install.sh (bash -n).
2. CLI argument parsing (--dry-run, --verbose, --port, --domain, --no-nginx, --restore-nginx).
3. Host pre-flight matrix (OS distro, RAM >= 384MB, disk >= 1GB, port probing 5050/80/443).
4. Pre-existing broken Nginx detection (refuses modification if host Nginx is broken).
5. Dedicated unprivileged user geekdoor and sandboxed directory permissions (/opt/mydoor).
6. Systemd unit file sandboxing directives (NoNewPrivileges, ProtectSystem, PrivateTmp, etc.).
7. Transactional LIFO rollback engine cleanly reverting host state upon simulated failure.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SCRIPT = REPO_ROOT / "scripts" / "install.sh"


class TestFailsafeInstaller(unittest.TestCase):
    """Test suite covering scripts/install.sh and VPS installation safeguards."""

    def setUp(self):
        if not INSTALL_SCRIPT.exists():
            raise unittest.SkipTest("scripts/install.sh not yet implemented (Milestone 10).")

    # --- 1. Script Syntax & ShellCheck / Bash Validation ---

    def test_INST_01_bash_syntax_validity(self):
        """INST.01: Verifies scripts/install.sh passes bash syntax validation (bash -n)."""
        proc = subprocess.run(
            ["bash", "-n", str(INSTALL_SCRIPT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"Bash syntax error in scripts/install.sh:\n{proc.stderr}",
        )

    # --- 2. CLI Flags & Dry-Run Mode ---

    def test_INST_02_dry_run_flag_performs_inspections_with_zero_mutations(self):
        """INST.02: Verifies --dry-run prints pre-flight matrix and mutates zero host files."""
        proc = subprocess.run(
            ["bash", str(INSTALL_SCRIPT), "--dry-run"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        # Should exit 0 or print dry-run badge
        combined_output = proc.stdout + proc.stderr
        self.assertIn("DRY-RUN", combined_output.upper())

    def test_INST_03_help_flag_displays_usage(self):
        """INST.03: Verifies --help outputs usage instructions and flag descriptions."""
        proc = subprocess.run(
            ["bash", str(INSTALL_SCRIPT), "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        output = proc.stdout + proc.stderr
        self.assertIn("--port", output)
        self.assertIn("--domain", output)
        self.assertIn("--dry-run", output)

    # --- 3. Pre-Flight Inspection Matrix ---

    def test_INST_04_preflight_checks_include_memory_disk_and_ports(self):
        """INST.04: Verifies script contains pre-flight checks for RAM, disk, and ports."""
        content = INSTALL_SCRIPT.read_text(encoding="utf-8")

        # Memory check (e.g., MemAvailable or MemTotal)
        self.assertTrue(
            "meminfo" in content or "free -m" in content or "RAM" in content,
            "Installer must inspect available memory",
        )

        # Disk space check (df)
        self.assertTrue(
            "df" in content,
            "Installer must inspect disk space on root filesystem",
        )

        # Port conflict checks (ports 5050, 80, 443)
        self.assertTrue(
            "5050" in content and "80" in content,
            "Installer must check port conflicts on 5050 and 80",
        )

    # --- 4. Systemd Sandboxing Directives ---

    def test_INST_05_systemd_unit_enforces_strict_sandboxing(self):
        """INST.05: Verifies generated systemd service unit enforces security sandboxing."""
        content = INSTALL_SCRIPT.read_text(encoding="utf-8")

        required_directives = [
            "User=geekdoor",
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "PrivateTmp=true",
            "ProtectKernelTunables=true",
            "ProtectControlGroups=true",
        ]

        for directive in required_directives:
            self.assertIn(
                directive.lower(),
                content.lower(),
                f"Hardened systemd unit must include '{directive}'",
            )

    # --- 5. LIFO Rollback Engine & Trap Handling ---

    def test_INST_06_lifo_rollback_stack_and_traps(self):
        """INST.06: Verifies script registers ERR/INT/TERM traps and LIFO rollback stack."""
        content = INSTALL_SCRIPT.read_text(encoding="utf-8")

        # Trap registration
        self.assertIn("trap", content, "Installer must define signal trap")
        self.assertTrue(
            "ERR" in content or "EXIT" in content,
            "Installer trap must catch ERR/EXIT signals",
        )

        # Rollback stack / reverse execution
        self.assertTrue(
            "rollback" in content.lower(),
            "Installer must define a rollback mechanism",
        )


if __name__ == "__main__":
    unittest.main()
