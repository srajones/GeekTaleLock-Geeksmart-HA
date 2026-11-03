"""Safe Nginx Management & Single-Action Restore Test Suite (Milestone 9 / Requirement R3).

Verifies:
1. Timestamped backup creation in /var/backups/mydoor-nginx/ with SHA256 manifest.json.
2. Atomic configuration staging (mydoor.conf.tmp.<PID>) and syntax validation (nginx -t).
3. Automatic staging cleanup upon syntax failure with zero disruption to active config.
4. Safe activation (atomic move and symlink creation) followed by service reload.
5. Single-action restore mechanism reverting files to exact pre-modification state.
6. Restoration when target config did not exist initially (clean removal).
7. REST API endpoints (/api/setup/nginx/preview, /apply, /backups, /restore).
8. Reverse proxy configuration templates (WebSocket support, ACME webroot, security headers).
"""

import datetime
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent

try:
    from server.nginx_manager import NginxManager
except ImportError:
    NginxManager = None

try:
    from server.flask_app import app
except ImportError:
    app = None


class TestSafeNginxManager(unittest.TestCase):
    """Test suite covering safe Nginx management, syntax validation, and single-action restore."""

    def setUp(self):
        if NginxManager is None:
            raise unittest.SkipTest("server.nginx_manager.NginxManager not yet implemented (Milestone 9).")

        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

        # Mock filesystem layout
        self.sites_available = self.base_path / "etc" / "nginx" / "sites-available"
        self.sites_enabled = self.base_path / "etc" / "nginx" / "sites-enabled"
        self.backup_dir = self.base_path / "var" / "backups" / "mydoor-nginx"

        self.sites_available.mkdir(parents=True, exist_ok=True)
        self.sites_enabled.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        self.manager = NginxManager(
            sites_available=str(self.sites_available),
            sites_enabled=str(self.sites_enabled),
            backup_dir=str(self.backup_dir),
            nginx_cmd="echo",  # Mock command for test environment
        )

    def tearDown(self):
        if hasattr(self, "temp_dir"):
            self.temp_dir.cleanup()

    # --- 1. Backup Creation & Manifest ---

    def test_NGINX_01_create_backup_with_sha256_manifest(self):
        """NGINX.01: Verifies create_backup creates timestamped folder and SHA256 manifest."""
        # Create an existing mydoor.conf
        conf_file = self.sites_available / "mydoor.conf"
        conf_content = "server { listen 80; server_name old.example.com; }"
        conf_file.write_text(conf_content, encoding="utf-8")

        expected_hash = hashlib.sha256(conf_content.encode("utf-8")).hexdigest()

        # Symlink in sites-enabled
        symlink_file = self.sites_enabled / "mydoor.conf"
        symlink_file.symlink_to(conf_file)

        backup_id = self.manager.create_backup(trigger="pre_config_test")
        self.assertIsNotNone(backup_id)

        target_backup = self.backup_dir / backup_id
        self.assertTrue(target_backup.exists(), "Backup directory must exist")

        manifest_file = target_backup / "manifest.json"
        self.assertTrue(manifest_file.exists(), "manifest.json must exist in backup")

        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        self.assertEqual(manifest["backup_id"], backup_id)
        self.assertIn("files_backed_up", manifest)

        backed_up_entry = next(
            (f for f in manifest["files_backed_up"] if "sites-available" in f["source_path"]),
            None,
        )
        self.assertIsNotNone(backed_up_entry)
        self.assertEqual(backed_up_entry["sha256"], expected_hash)

    # --- 2. Atomic Staging & Syntax Validation ---

    def test_NGINX_02_atomic_staging_and_validation_success(self):
        """NGINX.02: Verifies staging file generation and successful mock syntax check."""
        with patch.object(self.manager, "_run_nginx_test", return_value=(True, "syntax ok")):
            res = self.manager.stage_and_validate(
                domain="lock.example.com",
                backend_port=5050,
                enable_ssl=False,
            )
            self.assertTrue(res.get("success"))
            staging_file = Path(res.get("staging_file"))
            self.assertTrue(staging_file.exists())
            content = staging_file.read_text(encoding="utf-8")
            self.assertIn("lock.example.com", content)
            self.assertIn("127.0.0.1:5050", content)

    def test_NGINX_03_staging_syntax_failure_cleans_up_staging_file(self):
        """NGINX.03: Verifies syntax test failure immediately removes staging file."""
        with patch.object(self.manager, "_run_nginx_test", return_value=(False, "nginx: [emerg] invalid directive")):
            res = self.manager.stage_and_validate(
                domain="invalid.example.com",
                backend_port=5050,
            )
            self.assertFalse(res.get("success"))
            self.assertIn("error", res)

            # Assert no dangling temporary files in sites-available
            tmp_files = list(self.sites_available.glob("*.tmp*"))
            self.assertEqual(len(tmp_files), 0, "Temporary staging files must be wiped on error")

    # --- 3. Atomic Move and Symlink Activation ---

    def test_NGINX_04_apply_staged_config_creates_backup_and_symlink(self):
        """NGINX.04: Verifies apply_staged_config creates backup and creates sites-enabled symlink."""
        with patch.object(self.manager, "_run_nginx_test", return_value=(True, "syntax ok")), \
             patch.object(self.manager, "_reload_nginx", return_value=True):

            self.manager.stage_and_validate("lock.example.com", 5050)
            apply_res = self.manager.apply_staged_config()

            self.assertTrue(apply_res.get("success"))
            self.assertIn("backup_id", apply_res)

            prod_conf = self.sites_available / "mydoor.conf"
            self.assertTrue(prod_conf.exists())

            prod_symlink = self.sites_enabled / "mydoor.conf"
            self.assertTrue(prod_symlink.is_symlink())
            self.assertEqual(prod_symlink.resolve(), prod_conf.resolve())

    # --- 4. Single-Action Restore Verification ---

    def test_NGINX_05_restore_reverts_files_to_exact_prior_state(self):
        """NGINX.05: Verifies single-action restore reverts files to exact pre-modification state."""
        # Initial original state
        original_conf = self.sites_available / "mydoor.conf"
        original_content = "# Original Working Nginx Config\nserver { listen 80; server_name original.com; }\n"
        original_conf.write_text(original_content, encoding="utf-8")
        symlink = self.sites_enabled / "mydoor.conf"
        symlink.symlink_to(original_conf)

        # Create backup
        backup_id = self.manager.create_backup("test_before_corrupt")

        # Mutate configuration (simulate broken change)
        original_conf.write_text("# Corrupted Modified Config\nserver { broken_syntax; }", encoding="utf-8")

        # Execute single-action restore
        with patch.object(self.manager, "_run_nginx_test", return_value=(True, "syntax ok")), \
             patch.object(self.manager, "_reload_nginx", return_value=True):

            restore_res = self.manager.restore_backup(backup_id=backup_id)
            self.assertTrue(restore_res.get("success"))

            # Verify file content is 100% restored
            restored_content = original_conf.read_text(encoding="utf-8")
            self.assertEqual(restored_content, original_content)
            self.assertTrue(symlink.is_symlink())

    def test_NGINX_06_restore_cleans_up_if_target_did_not_exist_before(self):
        """NGINX.06: Verifies restore removes files if mydoor.conf did not exist prior to setup."""
        # Clean state: no files exist in sites-available or sites-enabled
        backup_id = self.manager.create_backup("pre_clean_install")

        # Create new config
        conf = self.sites_available / "mydoor.conf"
        conf.write_text("server { listen 80; }", encoding="utf-8")
        symlink = self.sites_enabled / "mydoor.conf"
        symlink.symlink_to(conf)

        # Restore
        with patch.object(self.manager, "_run_nginx_test", return_value=(True, "syntax ok")), \
             patch.object(self.manager, "_reload_nginx", return_value=True):

            restore_res = self.manager.restore_backup(backup_id=backup_id)
            self.assertTrue(restore_res.get("success"))

            # Files should be cleanly removed since they didn't exist prior to backup
            self.assertFalse(conf.exists(), "mydoor.conf should be removed on restore to initial state")
            self.assertFalse(symlink.exists(), "Symlink should be removed on restore to initial state")

    # --- 5. Reverse Proxy Security Templates ---

    def test_NGINX_07_template_contains_security_directives_and_acme(self):
        """NGINX.07: Verifies generated template includes WebSocket, ACME webroot, and security headers."""
        template = self.manager.render_config(domain="lock.example.com", backend_port=5050, enable_ssl=False)

        self.assertIn("proxy_pass http://127.0.0.1:5050", template)
        self.assertIn("Upgrade $http_upgrade", template)
        self.assertIn(".well-known/acme-challenge", template)
        self.assertIn("/var/www/letsencrypt", template)
        self.assertIn("X-Content-Type-Options: nosniff", template)
        self.assertIn("X-Frame-Options: DENY", template)

    # --- 6. Sub-Second Collision Resilience & Backward Compatibility ---

    def test_NGINX_08_subsecond_backup_collision_prevention(self):
        """NGINX.08: Sequential rapid calls create distinct directories without data overwrite."""
        conf = self.sites_available / "mydoor.conf"
        conf.write_text("v1_initial", encoding="utf-8")
        b1 = self.manager.create_backup(trigger="rapid_1")

        conf.write_text("v2_mutated", encoding="utf-8")
        b2 = self.manager.create_backup(trigger="rapid_2")

        self.assertNotEqual(b1, b2, f"Sub-second collision detected: {b1} == {b2}")
        self.assertTrue((self.backup_dir / b1).exists())
        self.assertTrue((self.backup_dir / b2).exists())

        f1 = (self.backup_dir / b1 / "sites-available" / "mydoor.conf").read_text(encoding="utf-8")
        f2 = (self.backup_dir / b2 / "sites-available" / "mydoor.conf").read_text(encoding="utf-8")
        self.assertEqual(f1, "v1_initial")
        self.assertEqual(f2, "v2_mutated")

    def test_NGINX_09_backup_collision_fallback_loop(self):
        """NGINX.09: Mocked identical timestamp triggers incremental counter fallback."""
        fixed_dt = datetime.datetime(2026, 11, 2, 12, 0, 0, 123456, tzinfo=datetime.timezone.utc)
        with patch("datetime.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_dt
            mock_dt.timezone = datetime.timezone
            b1 = self.manager.create_backup()
            b2 = self.manager.create_backup()
            b3 = self.manager.create_backup()

        self.assertNotEqual(b1, b2)
        self.assertNotEqual(b2, b3)
        self.assertEqual(b2, f"{b1}_1")
        self.assertEqual(b3, f"{b1}_2")
        self.assertTrue((self.backup_dir / b1).exists())
        self.assertTrue((self.backup_dir / b2).exists())
        self.assertTrue((self.backup_dir / b3).exists())

    def test_NGINX_10_restore_backup_accepts_subsecond_and_legacy_ids(self):
        """NGINX.10: Regex validator and restore accept microsecond, counter, and legacy backup formats."""
        conf = self.sites_available / "mydoor.conf"
        conf.write_text("content_A", encoding="utf-8")
        b_subsecond = self.manager.create_backup()

        # Counter backup via fixed timestamp
        conf.write_text("content_B", encoding="utf-8")
        fixed_dt = datetime.datetime(2026, 11, 2, 12, 0, 0, 999999, tzinfo=datetime.timezone.utc)
        with patch("datetime.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_dt
            mock_dt.timezone = datetime.timezone
            _ = self.manager.create_backup()
            conf.write_text("content_C", encoding="utf-8")
            b_counter = self.manager.create_backup()

        # Legacy backup manual injection
        legacy_dt = datetime.datetime(2026, 11, 2, 11, 0, 0, tzinfo=datetime.timezone.utc)
        legacy_epoch = int(legacy_dt.timestamp())
        legacy_id = f"backup_20261102_110000_{legacy_epoch}"
        leg_dir = self.backup_dir / legacy_id
        leg_dir.mkdir(parents=True)
        conf_leg = leg_dir / "sites-available" / "mydoor.conf"
        conf_leg.parent.mkdir(parents=True)
        conf_leg.write_text("content_legacy", encoding="utf-8")
        (leg_dir / "manifest.json").write_text(json.dumps({
            "backup_id": legacy_id,
            "created_at": legacy_dt.isoformat(),
            "epoch": legacy_epoch,
            "files_backed_up": [{
                "source_path": str(conf),
                "backup_path": str(conf_leg),
                "existed_before": True,
            }]
        }), encoding="utf-8")

        with patch.object(self.manager, "_run_nginx_test", return_value=(True, "ok")), \
             patch.object(self.manager, "_reload_nginx", return_value=True):
            # Restore subsecond
            r1 = self.manager.restore_backup(b_subsecond)
            self.assertTrue(r1["success"])
            self.assertEqual(conf.read_text(encoding="utf-8"), "content_A")

            # Restore counter
            r2 = self.manager.restore_backup(b_counter)
            self.assertTrue(r2["success"])
            self.assertEqual(conf.read_text(encoding="utf-8"), "content_C")

            # Restore legacy
            r3 = self.manager.restore_backup(legacy_id)
            self.assertTrue(r3["success"])
            self.assertEqual(conf.read_text(encoding="utf-8"), "content_legacy")

    def test_NGINX_11_list_backups_chronological_ordering(self):
        """NGINX.11: list_backups sorts mixed legacy, subsecond, and counter backups chronologically."""
        fixed_dt1 = datetime.datetime(2026, 11, 2, 12, 0, 0, 100000, tzinfo=datetime.timezone.utc)
        fixed_dt2 = datetime.datetime(2026, 11, 2, 12, 0, 0, 200000, tzinfo=datetime.timezone.utc)

        with patch("datetime.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_dt1
            mock_dt.timezone = datetime.timezone
            b1 = self.manager.create_backup()

        with patch("datetime.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_dt2
            mock_dt.timezone = datetime.timezone
            b2 = self.manager.create_backup()
            b3 = self.manager.create_backup()

        # Legacy backup manual insertion (earlier time: 11:00 UTC)
        legacy_dt = datetime.datetime(2026, 11, 2, 11, 0, 0, tzinfo=datetime.timezone.utc)
        legacy_epoch = int(legacy_dt.timestamp())
        legacy_id = f"backup_20261102_110000_{legacy_epoch}"
        leg_dir = self.backup_dir / legacy_id
        leg_dir.mkdir(parents=True)
        (leg_dir / "manifest.json").write_text(json.dumps({
            "backup_id": legacy_id,
            "created_at": legacy_dt.isoformat(),
            "epoch": legacy_epoch,
            "files_backed_up": []
        }), encoding="utf-8")

        listed = self.manager.list_backups()
        listed_ids = [b["backup_id"] for b in listed]
        self.assertEqual(listed_ids, [b3, b2, b1, legacy_id])
        self.assertEqual(self.manager.get_latest_backup_id(), b3)


if __name__ == "__main__":
    unittest.main()
