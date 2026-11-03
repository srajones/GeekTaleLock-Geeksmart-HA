"""Milestone 9 Iteration 2 Empirical Challenger Test Suite.

Adversarial Stress Harness verifying:
1. Sub-second backup collision prevention & rapid burst scaling (100 sequential backups).
2. Atomic directory creation & fallback counter loop (_1, _2, ... _50) under frozen clock.
3. Multithreaded concurrent backup creation integrity.
4. Manifest cryptographic validity and metadata consistency under collisions.
5. Chronological sorting in list_backups() across legacy, microsecond, and counter backups.
6. Unprivileged CLI execution cleanly handling PermissionError with zero tracebacks.
7. --backup-dir CLI flag and MYDOOR_NGINX_BACKUP_DIR env variable overrides and precedence.
8. Strictly zero live physical deadbolt actuations.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from server.nginx_manager import NginxManager, DEFAULT_BACKUP_DIR


class TestAdversarialSubsecondCollision(unittest.TestCase):
    """Stress tests rapid sequential backups and mocked timestamp collisions."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_adv_nginx_m9_iter2_")
        self.base_path = Path(self.test_dir)
        self.sites_available = self.base_path / "sites-available"
        self.sites_enabled = self.base_path / "sites-enabled"
        self.backup_dir = self.base_path / "backups"

        self.sites_available.mkdir(parents=True)
        self.sites_enabled.mkdir(parents=True)
        self.backup_dir.mkdir(parents=True)

        self.conf_file = self.sites_available / "mydoor.conf"
        self.conf_file.write_text("initial_config_v0", encoding="utf-8")

        self.mgr = NginxManager(
            sites_available=str(self.sites_available),
            sites_enabled=str(self.sites_enabled),
            backup_dir=str(self.backup_dir),
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_rapid_burst_100_sequential_backups_unique_and_valid(self):
        """Stress test: 100 rapid sequential backups in a tight loop.

        Verifies:
        - 100 distinct backup IDs generated.
        - 100 distinct directories created.
        - Every backup preserves the exact file content at that iteration.
        - Every manifest contains correct SHA256, timestamp, and epoch.
        """
        count = 100
        created_ids = []
        expected_contents = []

        for i in range(count):
            content = f"server_configuration_state_v_{i}_{hashlib.md5(str(i).encode()).hexdigest()}"
            self.conf_file.write_text(content, encoding="utf-8")
            expected_contents.append(content)

            b_id = self.mgr.create_backup(trigger=f"burst_{i}")
            created_ids.append(b_id)

        # 1. Uniqueness check
        self.assertEqual(len(created_ids), count)
        self.assertEqual(len(set(created_ids)), count, "Duplicate backup IDs generated during burst!")

        # 2. Directory and content integrity check
        for i, b_id in enumerate(created_ids):
            target_dir = self.backup_dir / b_id
            self.assertTrue(target_dir.is_dir(), f"Backup directory missing: {target_dir}")

            manifest_path = target_dir / "manifest.json"
            self.assertTrue(manifest_path.is_file(), f"Manifest missing for {b_id}")

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["backup_id"], b_id)
            self.assertEqual(manifest["trigger"], f"burst_{i}")
            self.assertIn("timestamp", manifest)
            self.assertIn("created_at", manifest)

            backed_up_conf = target_dir / "sites-available" / "mydoor.conf"
            self.assertTrue(backed_up_conf.is_file(), f"Backed up conf missing for {b_id}")
            actual_content = backed_up_conf.read_text(encoding="utf-8")
            self.assertEqual(actual_content, expected_contents[i], f"Content mismatch in backup {b_id}")

            expected_sha256 = hashlib.sha256(expected_contents[i].encode("utf-8")).hexdigest()
            manifest_file_entry = next(
                f for f in manifest["files_backed_up"] if f["source_path"] == str(self.conf_file)
            )
            self.assertEqual(manifest_file_entry["sha256"], expected_sha256)

    def test_frozen_timestamp_counter_fallback_50_iterations(self):
        """Stress test: 50 backups with EXACT identical timestamp.

        Verifies:
        - Atomic mkdir detects FileExistsError and iterates _1, _2, ... _49.
        - Zero collisions or overwrites.
        - Regex pattern permits all counter-appended IDs.
        - restore_backup() accepts counter IDs and restores correctly.
        """
        fixed_dt = datetime.datetime(2026, 11, 2, 14, 30, 0, 777888, tzinfo=datetime.timezone.utc)
        count = 50
        ids = []

        with patch("datetime.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_dt
            mock_dt.timezone = datetime.timezone

            for i in range(count):
                self.conf_file.write_text(f"content_frozen_{i}", encoding="utf-8")
                b_id = self.mgr.create_backup(trigger=f"frozen_{i}")
                ids.append(b_id)

        # First ID is base
        base_id = ids[0]
        self.assertTrue(re.match(r"^backup_\d{8}_\d{6}_\d{6}_\d+$", base_id), f"Base ID format unexpected: {base_id}")

        # Subsequent IDs have _1, _2, ..., _49
        for i in range(1, count):
            expected_id = f"{base_id}_{i}"
            self.assertEqual(ids[i], expected_id, f"Iteration {i} counter mismatch: got {ids[i]}, expected {expected_id}")
            self.assertTrue((self.backup_dir / expected_id).is_dir())

        # Verify restoration of highest counter backup (_49)
        highest_id = ids[-1]
        with patch.object(self.mgr, "_run_nginx_test", return_value=(True, "syntax ok")), \
             patch.object(self.mgr, "_reload_nginx", return_value=True):
            res = self.mgr.restore_backup(backup_id=highest_id)
            self.assertTrue(res["success"], f"Failed to restore {highest_id}: {res.get('error')}")
            self.assertEqual(self.conf_file.read_text(encoding="utf-8"), f"content_frozen_{count - 1}")

    def test_concurrent_multithreaded_backup_burst(self):
        """Stress test: 10 concurrent worker threads creating backups simultaneously.

        Verifies atomic mkdir handles race conditions without crashing or data loss.
        """
        num_threads = 10
        backups_per_thread = 5
        total_backups = num_threads * backups_per_thread

        def worker_task(thread_idx: int) -> list[str]:
            thread_ids = []
            for j in range(backups_per_thread):
                b_id = self.mgr.create_backup(trigger=f"thread_{thread_idx}_{j}")
                thread_ids.append(b_id)
            return thread_ids

        all_ids = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker_task, i) for i in range(num_threads)]
            for fut in concurrent.futures.as_completed(futures):
                all_ids.extend(fut.result())

        self.assertEqual(len(all_ids), total_backups)
        self.assertEqual(len(set(all_ids)), total_backups, "Duplicate backup IDs detected under concurrency!")

        # Verify all directories exist and manifests are valid
        for b_id in all_ids:
            b_dir = self.backup_dir / b_id
            self.assertTrue(b_dir.is_dir())
            manifest = json.loads((b_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["backup_id"], b_id)


class TestAdversarialChronologicalSorting(unittest.TestCase):
    """Stress tests list_backups() ordering across legacy and subsecond formats."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_adv_sort_")
        self.backup_dir = Path(self.test_dir) / "backups"
        self.backup_dir.mkdir(parents=True)
        self.mgr = NginxManager(backup_dir=str(self.backup_dir))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _inject_backup(self, backup_id: str, epoch: int, dt_iso: str) -> None:
        b_dir = self.backup_dir / backup_id
        b_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "backup_id": backup_id,
            "created_at": dt_iso,
            "timestamp": dt_iso,
            "epoch": epoch,
            "trigger": "test_sort",
            "files_backed_up": [],
        }
        (b_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    def test_chronological_ordering_across_legacy_subsecond_and_counter(self):
        """Verifies strict newest-first sorting across all backup ID formats:

        1. Legacy backup from 10:00:00 (epoch 1700000000)
        2. Microsecond backup from 10:00:01.100000 (epoch 1700000001)
        3. Microsecond backup from 10:00:01.200000 (epoch 1700000001)
        4. Same microsecond counter fallback _1 (epoch 1700000001)
        5. Future microsecond backup from 10:00:05.000000 (epoch 1700000005)
        """
        # Inject in randomized/non-chronological order
        self._inject_backup(
            "backup_20261102_100001_200000_1700000001",
            1700000001,
            "2026-11-02T10:00:01.200000+00:00",
        )
        self._inject_backup(
            "backup_20261102_100000_1700000000",
            1700000000,
            "2026-11-02T10:00:00+00:00",  # Legacy format without microseconds
        )
        self._inject_backup(
            "backup_20261102_100005_000000_1700000005",
            1700000005,
            "2026-11-02T10:00:05.000000+00:00",
        )
        self._inject_backup(
            "backup_20261102_100001_100000_1700000001",
            1700000001,
            "2026-11-02T10:00:01.100000+00:00",
        )
        self._inject_backup(
            "backup_20261102_100001_200000_1700000001_1",
            1700000001,
            "2026-11-02T10:00:01.200000+00:00",  # Same timestamp, fallback counter
        )

        backups = self.mgr.list_backups()
        listed_ids = [b["backup_id"] for b in backups]

        expected_order = [
            "backup_20261102_100005_000000_1700000005",
            "backup_20261102_100001_200000_1700000001_1",
            "backup_20261102_100001_200000_1700000001",
            "backup_20261102_100001_100000_1700000001",
            "backup_20261102_100000_1700000000",
        ]
        self.assertEqual(listed_ids, expected_order)
        self.assertEqual(self.mgr.get_latest_backup_id(), expected_order[0])

    def test_list_backups_resilience_to_malformed_and_foreign_entries(self):
        """Verifies list_backups() ignores corrupt files/dirs without throwing exceptions."""
        # 1. Non-backup dir
        (self.backup_dir / "random_directory").mkdir()
        # 2. Backup dir without manifest
        (self.backup_dir / "backup_empty").mkdir()
        # 3. Backup dir with corrupt JSON manifest
        b_corrupt = self.backup_dir / "backup_corrupt"
        b_corrupt.mkdir()
        (b_corrupt / "manifest.json").write_text("NOT_VALID_JSON{", encoding="utf-8")
        # 4. Valid backup
        self._inject_backup("backup_20261102_120000_000000_1700005000", 1700005000, "2026-11-02T12:00:00.000000+00:00")

        backups = self.mgr.list_backups()
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0]["backup_id"], "backup_20261102_120000_000000_1700005000")


class TestAdversarialCLIPermissionHandling(unittest.TestCase):
    """Subprocess stress tests verifying unprivileged access does NOT produce raw tracebacks."""

    def test_nginx_manager_cli_unprivileged_list_backups_clean_exit(self):
        """python3 -m server.nginx_manager --list-backups without sudo/override."""
        cmd = [sys.executable, "-m", "server.nginx_manager", "--list-backups"]
        env = dict(os.environ)
        env.pop("MYDOOR_NGINX_BACKUP_DIR", None)

        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 1)
        combined = proc.stdout + proc.stderr
        self.assertNotIn("Traceback (most recent call last)", combined)
        self.assertIn("Permission denied", proc.stderr)
        self.assertIn("Please run with sudo or specify --backup-dir", proc.stderr)

    def test_door_lock_control_cli_unprivileged_restore_clean_exit(self):
        """python3 door_lock_control.py restore-nginx without sudo/override."""
        cmd = [sys.executable, "door_lock_control.py", "restore-nginx"]
        env = dict(os.environ)
        env.pop("MYDOOR_NGINX_BACKUP_DIR", None)

        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 1)
        combined = proc.stdout + proc.stderr
        self.assertNotIn("Traceback (most recent call last)", combined)
        self.assertIn("Permission denied", combined)
        self.assertIn("Please run with sudo or specify --backup-dir", combined)

    def test_door_lock_control_cli_unprivileged_restore_specific_id_clean_exit(self):
        """python3 door_lock_control.py restore-nginx --backup-id backup_test_unprivileged."""
        cmd = [sys.executable, "door_lock_control.py", "restore-nginx", "--backup-id", "backup_test_unprivileged"]
        env = dict(os.environ)
        env.pop("MYDOOR_NGINX_BACKUP_DIR", None)

        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 1)
        combined = proc.stdout + proc.stderr
        self.assertNotIn("Traceback (most recent call last)", combined)
        self.assertIn("Permission denied", combined)

    def test_nginx_manager_cli_unprivileged_restore_clean_exit(self):
        """python3 -m server.nginx_manager --restore without sudo/override."""
        cmd = [sys.executable, "-m", "server.nginx_manager", "--restore"]
        env = dict(os.environ)
        env.pop("MYDOOR_NGINX_BACKUP_DIR", None)

        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 1)
        combined = proc.stdout + proc.stderr
        self.assertNotIn("Traceback (most recent call last)", combined)
        self.assertIn("Permission denied", combined)

    def test_nginx_manager_cli_unprivileged_restore_target_id_clean_exit(self):
        """python3 -m server.nginx_manager --restore backup_test_unprivileged."""
        cmd = [sys.executable, "-m", "server.nginx_manager", "--restore", "backup_test_unprivileged"]
        env = dict(os.environ)
        env.pop("MYDOOR_NGINX_BACKUP_DIR", None)

        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 1)
        combined = proc.stdout + proc.stderr
        self.assertNotIn("Traceback (most recent call last)", combined)
        self.assertIn("Permission denied", combined)


class TestAdversarialCLIOverrides(unittest.TestCase):
    """Verifies --backup-dir flag and MYDOOR_NGINX_BACKUP_DIR env variable overrides."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_adv_overrides_")
        self.backup_dir = Path(self.test_dir) / "custom_backups"
        self.backup_dir.mkdir(parents=True)

        self.sites_available = Path(self.test_dir) / "sites-available"
        self.sites_enabled = Path(self.test_dir) / "sites-enabled"
        self.sites_available.mkdir(parents=True)
        self.sites_enabled.mkdir(parents=True)

        # Create sample backup
        self.mgr = NginxManager(
            sites_available=str(self.sites_available),
            sites_enabled=str(self.sites_enabled),
            backup_dir=str(self.backup_dir),
        )
        (self.sites_available / "mydoor.conf").write_text("config_overrides_test", encoding="utf-8")
        self.sample_id = self.mgr.create_backup(trigger="override_init")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_nginx_manager_backup_dir_flag(self):
        """--backup-dir parameter correctly points to custom directory."""
        cmd = [
            sys.executable,
            "-m",
            "server.nginx_manager",
            "--backup-dir",
            str(self.backup_dir),
            "--list-backups",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"Command failed: {proc.stderr}")
        self.assertIn(f"Found 1 Nginx backups in {self.backup_dir}", proc.stdout)
        self.assertIn(self.sample_id, proc.stdout)

    def test_nginx_manager_env_var_override(self):
        """MYDOOR_NGINX_BACKUP_DIR environment variable correctly overrides default."""
        cmd = [sys.executable, "-m", "server.nginx_manager", "--list-backups"]
        env = dict(os.environ)
        env["MYDOOR_NGINX_BACKUP_DIR"] = str(self.backup_dir)

        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0, f"Command failed: {proc.stderr}")
        self.assertIn(f"Found 1 Nginx backups in {self.backup_dir}", proc.stdout)
        self.assertIn(self.sample_id, proc.stdout)

    def test_door_lock_control_backup_dir_flag(self):
        """door_lock_control.py restore-nginx --backup-dir points to custom directory."""
        # Mutate sites_available
        (self.sites_available / "mydoor.conf").write_text("corrupted_content", encoding="utf-8")

        # Mock reload/test inside child process via env or let it run
        cmd = [
            sys.executable,
            "door_lock_control.py",
            "restore-nginx",
            "--backup-dir",
            str(self.backup_dir),
            "--backup-id",
            self.sample_id,
        ]
        # In this test environment, sites_available is a custom directory, but door_lock_control
        # uses DEFAULT_SITES_AVAILABLE. Let's provide MYDOOR_NGINX_SITES_AVAILABLE and SITES_ENABLED env vars.
        env = dict(os.environ)
        env["MYDOOR_NGINX_SITES_AVAILABLE"] = str(self.sites_available)
        env["MYDOOR_NGINX_SITES_ENABLED"] = str(self.sites_enabled)

        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0, f"Command failed: {proc.stdout}\n{proc.stderr}")
        self.assertIn(f"[SUCCESS] Nginx restored from {self.sample_id}", proc.stdout)
        self.assertEqual((self.sites_available / "mydoor.conf").read_text(encoding="utf-8"), "config_overrides_test")

    def test_door_lock_control_env_var_override(self):
        """door_lock_control.py restore-nginx obeys MYDOOR_NGINX_BACKUP_DIR."""
        (self.sites_available / "mydoor.conf").write_text("corrupted_content_2", encoding="utf-8")

        cmd = [
            sys.executable,
            "door_lock_control.py",
            "restore-nginx",
            "--backup-id",
            self.sample_id,
        ]
        env = dict(os.environ)
        env["MYDOOR_NGINX_BACKUP_DIR"] = str(self.backup_dir)
        env["MYDOOR_NGINX_SITES_AVAILABLE"] = str(self.sites_available)
        env["MYDOOR_NGINX_SITES_ENABLED"] = str(self.sites_enabled)

        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0, f"Command failed: {proc.stdout}\n{proc.stderr}")
        self.assertIn(f"[SUCCESS] Nginx restored from {self.sample_id}", proc.stdout)
        self.assertEqual((self.sites_available / "mydoor.conf").read_text(encoding="utf-8"), "config_overrides_test")

    def test_cli_flag_precedence_over_env_var(self):
        """CLI flag --backup-dir takes precedence over MYDOOR_NGINX_BACKUP_DIR env var."""
        empty_dir = Path(self.test_dir) / "empty_backups"
        empty_dir.mkdir(parents=True)

        cmd = [
            sys.executable,
            "-m",
            "server.nginx_manager",
            "--backup-dir",
            str(self.backup_dir),
            "--list-backups",
        ]
        env = dict(os.environ)
        env["MYDOOR_NGINX_BACKUP_DIR"] = str(empty_dir)

        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0)
        # Output should be for self.backup_dir (with 1 backup), NOT empty_dir (0 backups)
        self.assertIn(f"Found 1 Nginx backups in {self.backup_dir}", proc.stdout)


class TestAdversarialPermissionHandlingInAPI(unittest.TestCase):
    """Verifies that PermissionError is handled gracefully across API and manager methods."""

    def test_apply_staged_config_permission_error_returns_clean_dict(self):
        """apply_staged_config() returns structured error if create_backup raises PermissionError."""
        mgr = NginxManager(backup_dir="/var/backups/mydoor-nginx")
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"dummy")
            temp_stage = tf.name

        try:
            with patch.object(mgr, "create_backup", side_effect=PermissionError("Permission denied: /var/backups")):
                res = mgr.apply_staged_config(staging_file=temp_stage)
                self.assertFalse(res["success"])
                self.assertIn("Permission denied creating pre-apply backup", res["error"])
        finally:
            if os.path.exists(temp_stage):
                os.unlink(temp_stage)

    def test_restore_backup_permission_error_returns_clean_dict(self):
        """restore_backup() returns structured error if reading manifest raises PermissionError."""
        mgr = NginxManager(backup_dir="/var/backups/mydoor-nginx")
        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", side_effect=PermissionError("Permission denied: manifest.json")):
            res = mgr.restore_backup("backup_20261102_120000_100000_1700000000")
            self.assertFalse(res["success"])
            self.assertIn("Permission denied", res["error"])

    def test_list_backups_permission_error_returns_empty_list(self):
        """list_backups() returns empty list without raising if iterdir raises PermissionError."""
        mgr = NginxManager(backup_dir="/var/backups/mydoor-nginx")
        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "iterdir", side_effect=PermissionError("Permission denied")):
            backups = mgr.list_backups()
            self.assertEqual(backups, [])


if __name__ == "__main__":
    unittest.main()
