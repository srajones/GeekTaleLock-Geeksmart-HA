"""Empirical Adversarial Stress Test Suite for Milestone 7 (Requirement R5).

Executed by challenger_m7_1 to verify:
1. TOTP Clock Drift Boundary Probes (steps -3, -2, -1, 0, +1, +2, +3 and boundary seconds).
2. Adversarial Anti-Replay Probes (immediate duplicate rejection, interleaved step rejection,
   and concurrent multi-threaded replay attacks).
3. Brute-Force Lockout Edge Cases (exact 5-failure threshold, lockout enforcement on correct password,
   lockout expiration, and cross-user isolation).
4. Password Length & Unicode Boundary Probes (0, 1, 7, 8, unicode, non-ASCII, and 1024+ chars).
5. Backup Recovery Code Attack Probes (casing, hyphen normalization, single-use invalidation,
   SQL injection / malformed strings, and cross-user isolation).
6. Multi-instance cross-process disk persistence anti-replay.
"""

import base64
import hashlib
import hmac
import os
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from server.auth import AuthManager


def rfc6238_totp_oracle(secret_b32: str, timestamp: int, step: int = 30) -> str:
    """Authoritative reference implementation of RFC 6238 TOTP (HMAC-SHA1)."""
    counter = int(timestamp // step)
    pad_len = (8 - len(secret_b32) % 8) % 8
    secret_bytes = base64.b32decode((secret_b32 + "=" * pad_len).encode("ascii"), casefold=True)
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % 1000000).zfill(6)


class TestChallengerM7TotpClockDrift(unittest.TestCase):
    """Adversarial boundary stress tests for TOTP clock drift tolerance."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth_file = Path(self.temp_dir.name) / ".auth_credentials.json"
        self.auth_mgr = AuthManager(auth_file=str(self.auth_file))
        self.base_time = 1730559000  # Multiple of 30: 1730559000 % 30 == 0

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_clock_drift_exact_steps_probe(self):
        """Stress-tests relative step offsets [-3, -2, -1, 0, +1, +2, +3].

        Steps [-1, 0, +1] must succeed.
        Steps [-3, -2, +2, +3] must strictly fail.
        """
        offsets = [-3, -2, -1, 0, 1, 2, 3]
        expected_results = {
            -3: False,
            -2: False,
            -1: True,
            0: True,
            1: True,
            2: False,
            3: False,
        }

        for offset in offsets:
            with self.subTest(offset=offset):
                # Use a distinct user for each offset to isolate anti-replay tracking
                username = f"user_drift_{offset}"
                self.auth_mgr.create_admin(username, "Password12345!")
                totp_data = self.auth_mgr.generate_totp_secret(username)
                secret = totp_data["secret"]

                # Generate code at offset timestamp
                offset_timestamp = self.base_time + (offset * 30)
                code = rfc6238_totp_oracle(secret, offset_timestamp)

                # Verify against base_time
                result = self.auth_mgr.verify_totp(username, code, timestamp=self.base_time)
                expected = expected_results[offset]
                self.assertEqual(
                    result,
                    expected,
                    f"Offset {offset} (step {offset_timestamp // 30} vs {self.base_time // 30}) "
                    f"expected {expected} but got {result}",
                )

    def test_clock_drift_second_level_boundaries(self):
        """Tests exact second-level boundaries within and outside the sliding window.

        Window at base_time T0 covers [T0 - 30, T0 + 59]:
        - T0 - 31s (outside, step -2): MUST FAIL
        - T0 - 30s (inside, step -1 start): MUST SUCCEED
        - T0 - 1s  (inside, step -1 end): MUST SUCCEED
        - T0 + 0s  (inside, step 0 start): MUST SUCCEED
        - T0 + 29s (inside, step 0 end): MUST SUCCEED
        - T0 + 30s (inside, step +1 start): MUST SUCCEED
        - T0 + 59s (inside, step +1 end): MUST SUCCEED
        - T0 + 60s (outside, step +2 start): MUST FAIL
        """
        second_probes = [
            (-60, False),  # step -2 start
            (-31, False),  # step -2 boundary
            (-30, True),   # step -1 start
            (-1, True),    # step -1 boundary
            (0, True),     # step 0 start
            (15, True),    # step 0 mid
            (29, True),    # step 0 boundary
            (30, True),    # step +1 start
            (59, True),    # step +1 boundary
            (60, False),   # step +2 start
            (90, False),   # step +3 start
        ]

        for delta_s, should_pass in second_probes:
            with self.subTest(delta_seconds=delta_s):
                user = f"user_sec_{delta_s}"
                self.auth_mgr.create_admin(user, "Password12345!")
                secret = self.auth_mgr.generate_totp_secret(user)["secret"]

                probe_time = self.base_time + delta_s
                code = rfc6238_totp_oracle(secret, probe_time)

                verified = self.auth_mgr.verify_totp(user, code, timestamp=self.base_time)
                self.assertEqual(
                    verified,
                    should_pass,
                    f"Timestamp delta {delta_s}s (code generated at {probe_time}, checked at {self.base_time}) "
                    f"expected {should_pass} but got {verified}",
                )


class TestChallengerM7TotpAntiReplay(unittest.TestCase):
    """Adversarial stress tests for TOTP anti-replay protection and concurrency."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth_file = Path(self.temp_dir.name) / ".auth_credentials.json"
        self.auth_mgr = AuthManager(auth_file=str(self.auth_file))
        self.base_time = 1730559000

        self.user = "replay_target"
        self.auth_mgr.create_admin(self.user, "Password12345!")
        totp_info = self.auth_mgr.generate_totp_secret(self.user)
        self.secret = totp_info["secret"]

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_immediate_duplicate_code_rejection(self):
        """Submitting the exact same TOTP code twice in the same time step must fail."""
        code0 = rfc6238_totp_oracle(self.secret, self.base_time)

        # 1st attempt: Valid
        self.assertTrue(
            self.auth_mgr.verify_totp(self.user, code0, timestamp=self.base_time),
            "First submission of step 0 must succeed",
        )

        # 2nd attempt at exact same second: Rejected
        self.assertFalse(
            self.auth_mgr.verify_totp(self.user, code0, timestamp=self.base_time),
            "Immediate replay of same code at exact same second must fail",
        )

        # 3rd attempt 10 seconds later (still step 0): Rejected
        self.assertFalse(
            self.auth_mgr.verify_totp(self.user, code0, timestamp=self.base_time + 10),
            "Replay of same code later within step 0 must fail",
        )

    def test_interleaved_step_replays(self):
        """Tests submitting step 0, then step -1, then attempting step 0 replay."""
        code0 = rfc6238_totp_oracle(self.secret, self.base_time)
        code_prev = rfc6238_totp_oracle(self.secret, self.base_time - 30)
        code_next = rfc6238_totp_oracle(self.secret, self.base_time + 30)

        # 1. Step 0 succeeds
        self.assertTrue(self.auth_mgr.verify_totp(self.user, code0, timestamp=self.base_time))

        # 2. Step -1 succeeds (was not yet consumed)
        self.assertTrue(self.auth_mgr.verify_totp(self.user, code_prev, timestamp=self.base_time))

        # 3. Step 0 replay MUST FAIL
        self.assertFalse(
            self.auth_mgr.verify_totp(self.user, code0, timestamp=self.base_time),
            "Step 0 replay after step -1 must be strictly rejected",
        )

        # 4. Step -1 replay MUST FAIL
        self.assertFalse(
            self.auth_mgr.verify_totp(self.user, code_prev, timestamp=self.base_time),
            "Step -1 replay must be strictly rejected",
        )

        # 5. Step +1 succeeds
        self.assertTrue(self.auth_mgr.verify_totp(self.user, code_next, timestamp=self.base_time))

        # 6. Step +1 replay MUST FAIL
        self.assertFalse(
            self.auth_mgr.verify_totp(self.user, code_next, timestamp=self.base_time),
            "Step +1 replay must be strictly rejected",
        )

    def test_concurrent_multi_threaded_replay_race(self):
        """Simultaneously submits the same TOTP code across 25 parallel threads.

        Under a race condition, exactly ONE thread must succeed and 24 must fail.
        """
        code = rfc6238_totp_oracle(self.secret, self.base_time)
        num_threads = 25
        results: list[bool] = []
        results_lock = threading.Lock()
        barrier = threading.Barrier(num_threads)

        def worker_attempt():
            barrier.wait()  # Synchronize start across all threads
            success = self.auth_mgr.verify_totp(self.user, code, timestamp=self.base_time)
            with results_lock:
                results.append(success)

        threads = [threading.Thread(target=worker_attempt) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        success_count = sum(1 for r in results if r is True)
        failure_count = sum(1 for r in results if r is False)

        self.assertEqual(
            success_count,
            1,
            f"Race condition failure! Expected exactly 1 success among 25 concurrent requests, but got {success_count}",
        )
        self.assertEqual(
            failure_count,
            num_threads - 1,
            f"Expected {num_threads - 1} failures, got {failure_count}",
        )

    def test_multi_instance_anti_replay_persistence(self):
        """Two distinct AuthManager instances pointing to the same credentials file.

        Instance 1 consumes step 0 -> Instance 2 must immediately reject step 0 replay.
        """
        auth_mgr2 = AuthManager(auth_file=str(self.auth_file))
        code0 = rfc6238_totp_oracle(self.secret, self.base_time)

        # Instance 1 verifies step 0
        self.assertTrue(self.auth_mgr.verify_totp(self.user, code0, timestamp=self.base_time))

        # Instance 2 attempts same code
        self.assertFalse(
            auth_mgr2.verify_totp(self.user, code0, timestamp=self.base_time),
            "Second AuthManager instance must reject replayed code due to disk state",
        )


class TestChallengerM7BruteForceLockout(unittest.TestCase):
    """Adversarial boundary stress tests for brute-force sliding window lockout."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth_file = Path(self.temp_dir.name) / ".auth_credentials.json"
        self.auth_mgr = AuthManager(
            auth_file=str(self.auth_file),
            max_failed_attempts=5,
            lockout_duration_seconds=300.0,
        )
        self.correct_password = "MasterPassword999!"
        self.user = "lockout_victim"
        self.auth_mgr.create_admin(self.user, self.correct_password)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_exact_five_failure_threshold_trigger(self):
        """Verifies account is NOT locked at attempts 1..4, and locks on exactly attempt 5."""
        for attempt in range(1, 5):
            res = self.auth_mgr.verify_password(self.user, f"WrongPass{attempt}")
            self.assertFalse(res)
            self.assertFalse(
                self.auth_mgr.is_locked_out(self.user),
                f"User should NOT be locked out after {attempt} failed attempts",
            )

        # 5th failure: triggers lockout
        res5 = self.auth_mgr.verify_password(self.user, "WrongPass5")
        self.assertFalse(res5)
        self.assertTrue(
            self.auth_mgr.is_locked_out(self.user),
            "User MUST be locked out immediately upon 5th failure",
        )

    def test_correct_password_rejected_during_lockout(self):
        """During active lockout, entering the correct password MUST return False."""
        # Trigger lockout
        for i in range(5):
            self.auth_mgr.verify_password(self.user, f"Bad{i}")
        self.assertTrue(self.auth_mgr.is_locked_out(self.user))

        # Attempt with valid password
        self.assertFalse(
            self.auth_mgr.verify_password(self.user, self.correct_password),
            "Correct password MUST be rejected while lockout is active",
        )

    def test_totp_and_backup_code_rejected_during_lockout(self):
        """During active lockout, TOTP and backup recovery codes must be rejected."""
        totp_info = self.auth_mgr.generate_totp_secret(self.user)
        backup_codes = self.auth_mgr.generate_backup_codes(self.user)
        valid_totp = rfc6238_totp_oracle(totp_info["secret"], int(time.time()))

        # Trigger lockout
        for i in range(5):
            self.auth_mgr.verify_password(self.user, f"Bad{i}")
        self.assertTrue(self.auth_mgr.is_locked_out(self.user))

        # Test TOTP rejection
        self.assertFalse(
            self.auth_mgr.verify_totp(self.user, valid_totp),
            "Valid TOTP code must be rejected during lockout",
        )

        # Test Backup code rejection
        self.assertFalse(
            self.auth_mgr.verify_backup_code(self.user, backup_codes[0]),
            "Valid backup code must be rejected during lockout",
        )

    def test_lockout_expiration_after_duration(self):
        """Simulates time passing beyond the 300s window to verify automatic lockout expiration."""
        # Trigger lockout at t=1000.0
        with patch("time.time", return_value=1000.0):
            for i in range(5):
                self.auth_mgr.verify_password(self.user, f"Bad{i}")
            self.assertTrue(self.auth_mgr.is_locked_out(self.user))

            # At t=1299.0 (299s elapsed): still locked out
            with patch("time.time", return_value=1299.0):
                self.assertTrue(self.auth_mgr.is_locked_out(self.user))
                self.assertFalse(self.auth_mgr.verify_password(self.user, self.correct_password))

            # At t=1301.0 (301s elapsed): lockout expired!
            with patch("time.time", return_value=1301.0):
                self.assertFalse(
                    self.auth_mgr.is_locked_out(self.user),
                    "Lockout should expire after 300 seconds",
                )
                self.assertTrue(
                    self.auth_mgr.verify_password(self.user, self.correct_password),
                    "Correct password should succeed after lockout expiration",
                )

    def test_cross_user_isolation(self):
        """Brute-forcing User A must have zero impact on User B."""
        user_b = "innocent_user"
        pass_b = "BobsSafePassword123!"
        self.auth_mgr.create_admin(user_b, pass_b)

        # Lock out User A
        for i in range(5):
            self.auth_mgr.verify_password(self.user, f"BadPass{i}")
        self.assertTrue(self.auth_mgr.is_locked_out(self.user))

        # Verify User B is completely unaffected
        self.assertFalse(
            self.auth_mgr.is_locked_out(user_b),
            "User B must not be locked out when User A is targeted",
        )
        self.assertTrue(
            self.auth_mgr.verify_password(user_b, pass_b),
            "User B must be able to authenticate successfully",
        )

        # Resetting User A lockout does not clear anything unexpected
        self.auth_mgr.reset_lockout(self.user)
        self.assertFalse(self.auth_mgr.is_locked_out(self.user))

    def test_successful_login_resets_failure_counter(self):
        """A successful login between failed attempts resets the consecutive failure counter."""
        # 4 failed attempts
        for i in range(4):
            self.auth_mgr.verify_password(self.user, "Bad")
        self.assertFalse(self.auth_mgr.is_locked_out(self.user))

        # Successful login resets state
        self.assertTrue(self.auth_mgr.verify_password(self.user, self.correct_password))

        # 4 more failed attempts must NOT trigger lockout
        for i in range(4):
            self.auth_mgr.verify_password(self.user, "Bad")
        self.assertFalse(
            self.auth_mgr.is_locked_out(self.user),
            "Failure counter should have been reset by successful login",
        )

    def test_empty_and_invalid_passwords_count_as_failures(self):
        """Malformed/empty password submissions must record failures and trigger lockout."""
        for _ in range(4):
            self.auth_mgr.verify_password(self.user, "")
        self.assertFalse(self.auth_mgr.is_locked_out(self.user))

        # 5th empty submission triggers lockout
        self.auth_mgr.verify_password(self.user, "")
        self.assertTrue(self.auth_mgr.is_locked_out(self.user))


class TestChallengerM7PasswordPolicyAndBoundaries(unittest.TestCase):
    """Adversarial stress tests for password length policy and boundary conditions."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth_file = Path(self.temp_dir.name) / ".auth_credentials.json"
        self.auth_mgr = AuthManager(auth_file=str(self.auth_file))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_password_length_boundary_rejections(self):
        """Passwords with length < 8 (0, 1, 7 chars) must raise ValueError."""
        invalid_lengths = [
            ("", 0),
            ("a", 1),
            ("12", 2),
            ("abcde", 5),
            ("1234567", 7),
        ]
        for pwd, length in invalid_lengths:
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    self.auth_mgr.create_admin("admin", pwd)

    def test_password_length_eight_succeeds(self):
        """Password with exactly 8 characters must succeed."""
        created = self.auth_mgr.create_admin("admin8", "12345678")
        self.assertTrue(created)
        self.assertTrue(self.auth_mgr.verify_password("admin8", "12345678"))
        self.assertFalse(self.auth_mgr.verify_password("admin8", "12345679"))

    def test_unicode_and_complex_character_sets(self):
        """Passwords containing emojis, CJK, accents, and symbols must hash and verify correctly."""
        test_passwords = [
            ("user_emoji", "🔐DoorLock#2026!✨"),
            ("user_cjk", "门锁安全密码2026!"),
            ("user_accents", "Hôtel-Café-Crème-2026!"),
            ("user_symbols", "~!@#$%^&*()_+{}|:\"<>?`[]\\;',./"),
        ]
        for username, pwd in test_passwords:
            with self.subTest(username=username):
                created = self.auth_mgr.create_admin(username, pwd)
                self.assertTrue(created)
                # Positive verification
                self.assertTrue(self.auth_mgr.verify_password(username, pwd))
                # Negative verification
                self.assertFalse(self.auth_mgr.verify_password(username, pwd + "x"))

    def test_extreme_password_lengths(self):
        """Stress-tests very long passwords (1024 and 4096 characters)."""
        long_1024 = "X" * 1024
        long_4096 = "Y" * 4096

        # 1024 chars
        created = self.auth_mgr.create_admin("user_1024", long_1024)
        self.assertTrue(created)
        self.assertTrue(self.auth_mgr.verify_password("user_1024", long_1024))
        self.assertFalse(self.auth_mgr.verify_password("user_1024", long_1024[:-1] + "Z"))

        # 4096 chars
        created = self.auth_mgr.create_admin("user_4096", long_4096)
        self.assertTrue(created)
        self.assertTrue(self.auth_mgr.verify_password("user_4096", long_4096))
        self.assertFalse(self.auth_mgr.verify_password("user_4096", long_4096[:-1] + "Z"))

    def test_username_boundary_rejections(self):
        """Empty or whitespace-only usernames must raise ValueError."""
        invalid_users = ["", "   ", "\t\n", None]
        for u in invalid_users:
            with self.subTest(user=repr(u)):
                with self.assertRaises(ValueError):
                    self.auth_mgr.create_admin(u, "ValidPassword123!")


class TestChallengerM7BackupRecoveryCodes(unittest.TestCase):
    """Adversarial stress tests for backup recovery code formatting, casing, and invalidation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth_file = Path(self.temp_dir.name) / ".auth_credentials.json"
        self.auth_mgr = AuthManager(auth_file=str(self.auth_file))
        self.user = "backup_target"
        self.auth_mgr.create_admin(self.user, "Password12345!")
        self.codes = self.auth_mgr.generate_backup_codes(self.user, count=8)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_single_use_immediate_invalidation(self):
        """Verifies backup code succeeds once and is immediately rejected on second attempt."""
        code = self.codes[0]

        # First use succeeds
        self.assertTrue(
            self.auth_mgr.verify_backup_code(self.user, code),
            "Unused backup code must succeed",
        )

        # Immediate reuse must fail
        self.assertFalse(
            self.auth_mgr.verify_backup_code(self.user, code),
            "Consumed backup code must be immediately invalidated",
        )

    def test_casing_and_hyphen_permutations(self):
        """Tests that backup code verification is case-insensitive and handles missing hyphen."""
        # Code 1: lowercase with hyphen
        code1 = self.codes[1]
        self.assertTrue(
            self.auth_mgr.verify_backup_code(self.user, code1.lower()),
            f"Lowercase backup code '{code1.lower()}' should be accepted",
        )
        self.assertFalse(self.auth_mgr.verify_backup_code(self.user, code1))

        # Code 2: uppercase without hyphen (8 chars)
        code2 = self.codes[2]
        no_hyphen = code2.replace("-", "")
        self.assertTrue(
            self.auth_mgr.verify_backup_code(self.user, no_hyphen),
            f"Hyphen-omitted code '{no_hyphen}' should be accepted",
        )
        self.assertFalse(self.auth_mgr.verify_backup_code(self.user, code2))

        # Code 3: lowercase without hyphen
        code3 = self.codes[3]
        lower_no_hyphen = code3.replace("-", "").lower()
        self.assertTrue(
            self.auth_mgr.verify_backup_code(self.user, lower_no_hyphen),
            f"Lowercase hyphen-omitted code '{lower_no_hyphen}' should be accepted",
        )

        # Code 4: mixed case with extra whitespace
        code4 = self.codes[4]
        mixed_spaced = f"  {code4[:2].lower()}{code4[2:4].upper()}-{code4[5:7].lower()}{code4[7:].upper()}  "
        self.assertTrue(
            self.auth_mgr.verify_backup_code(self.user, mixed_spaced),
            f"Mixed case with whitespace '{mixed_spaced}' should be accepted",
        )

    def test_adversarial_malformed_and_injection_inputs(self):
        """Submitting SQL injection, null bytes, format strings, and malformed codes returns False."""
        malicious_inputs = [
            "",
            "   ",
            "' OR '1'='1",
            "admin'--",
            "UNION SELECT * FROM users",
            "%s%s%s%s%n",
            "ABCD\x001234",
            "A" * 1000,
            "1234",          # Too short
            "1234567",       # 7 chars
            "123456789",     # 9 chars without hyphen
            "1234-5678-90",  # Multiple hyphens
        ]
        for payload in malicious_inputs:
            with self.subTest(payload=payload):
                self.assertFalse(
                    self.auth_mgr.verify_backup_code(self.user, payload),
                    f"Malicious/malformed input {repr(payload)} must return False",
                )

    def test_cross_user_backup_code_isolation(self):
        """A backup code generated for User A cannot authenticate User B, and remains valid for A."""
        user_b = "backup_victim_b"
        self.auth_mgr.create_admin(user_b, "Password12345!")
        codes_b = self.auth_mgr.generate_backup_codes(user_b, count=8)

        code_a = self.codes[5]

        # Attempt to use User A's code to authenticate User B
        self.assertFalse(
            self.auth_mgr.verify_backup_code(user_b, code_a),
            "User A's backup code must not authenticate User B",
        )

        # User A's code must still be intact and valid for User A
        self.assertTrue(
            self.auth_mgr.verify_backup_code(self.user, code_a),
            "User A's backup code must remain valid after failed attack on User B",
        )

        # Now consumed for User A
        self.assertFalse(
            self.auth_mgr.verify_backup_code(self.user, code_a),
            "User A's backup code must be consumed after legitimate use",
        )


if __name__ == "__main__":
    unittest.main()
