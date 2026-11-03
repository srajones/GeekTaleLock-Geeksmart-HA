"""Comprehensive Unit Tests for Tuya Mobile Client & Session Cache Engine.

Tests:
1. Parameter whitelist filtering and alphabetical sorting.
2. 4-quarter MD5 swap (B + A + D + C) and postData pre-hashing.
3. HMAC-SHA256 and MD5 signature generation.
4. Pure-Python RSA PKCS#1 v1.5 password encryption round-trip.
5. SessionManager atomic write, permissions (0o600), and credential merging.
6. TuyaClient authentication, token exchange, and session caching.
7. Device discovery, DP parsing, battery extraction, and device categorization.
8. Strict dry-run safety enforcement on DP publish.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import tempfile
import time
import unittest
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding

from client.exceptions import (
    GeekSmartCryptoError,
    TuyaApiError,
)
from client.session_manager import SessionManager
from client.tuya_client import (
    DEFAULT_TUYA_APP_KEY,
    DEFAULT_TUYA_APP_SECRET,
    DEFAULT_TUYA_APP_VERSION,
    TUYA_SIGN_WHITELIST,
    TuyaClient,
    TuyaDevice,
    TuyaMobileClient,
)


class TestTuyaCryptographicEngine(unittest.TestCase):
    """Tests reverse-engineered cryptographic primitives and request signing."""

    def test_T3_01_swap_sign_string_quarter_permutation(self):
        """T3.01: Verifies 4-quarter swap B + A + D + C matches Dalvik bytecode permutation."""
        # Chunk A: 01234567, Chunk B: 89abcdef, Chunk C: 01234567, Chunk D: 89abcdef
        test_md5 = "0123456789abcdef0123456789abcdef"
        swapped = TuyaClient.swap_sign_string(test_md5)
        # Expected: B (89abcdef) + A (01234567) + D (89abcdef) + C (01234567)
        expected = "89abcdef0123456789abcdef01234567"
        self.assertEqual(swapped, expected)

    def test_T3_02_swap_sign_string_invalid_length_raises_error(self):
        """T3.02: swap_sign_string raises GeekSmartCryptoError if string is not 32 characters."""
        with self.assertRaises(GeekSmartCryptoError):
            TuyaClient.swap_sign_string("short_string")
        with self.assertRaises(GeekSmartCryptoError):
            TuyaClient.swap_sign_string("0123456789abcdef0123456789abcdef0000")

    def test_T3_03_post_data_md5_hex_computation(self):
        """T3.03: post_data_md5_hex computes MD5 and applies 4-quarter swap."""
        sample_json = '{"countryCode":"1","username":"user@domain.com","isUid":false}'
        raw_md5 = hashlib.md5(sample_json.encode("utf-8")).hexdigest().lower()
        expected = raw_md5[8:16] + raw_md5[0:8] + raw_md5[24:32] + raw_md5[16:24]
        self.assertEqual(TuyaClient.post_data_md5_hex(sample_json), expected)

    def test_T3_04_signature_generation_whitelist_and_sorting(self):
        """T3.04: Signature filters non-whitelisted keys, sorts alphabetically, and signs with HMAC-SHA256."""
        client = TuyaClient(
            app_key="test_app_key",
            app_secret="test_app_secret",
        )
        params = {
            "v": "2.0",
            "a": "thing.m.user.username.token.get",
            "time": "1730390000",
            "clientId": "test_app_key",
            "os": "Android",
            "forbidden_param": "should_be_ignored",
            "empty_param": "",
            "none_param": None,
        }

        sig = client.generate_signature(params, use_hmac=True)

        # Expected string to sign:
        # Whitelisted keys present: a, clientId, os, time, v (alphabetically sorted)
        expected_str = "a=thing.m.user.username.token.get||clientId=test_app_key||os=Android||time=1730390000||v=2.0"
        expected_sig = hmac.new(
            b"test_app_secret",
            expected_str.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest().lower()

        self.assertEqual(sig, expected_sig)

    def test_T3_05_signature_generation_with_post_data(self):
        """T3.05: Signature includes swapped MD5 hash when postData is present."""
        client = TuyaClient(
            app_key="test_app_key",
            app_secret="test_app_secret",
        )
        post_str = '{"gid":12345}'
        params = {
            "a": "m.life.my.group.device.list",
            "v": "2.2",
            "clientId": "test_app_key",
            "time": "1730390000",
            "postData": post_str,
        }

        sig = client.generate_signature(params, use_hmac=True)
        swapped_md5 = client.post_data_md5_hex(post_str)

        expected_str = (
            f"a=m.life.my.group.device.list||clientId=test_app_key||postData={swapped_md5}||time=1730390000||v=2.2"
        )
        expected_sig = hmac.new(
            b"test_app_secret",
            expected_str.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest().lower()

        self.assertEqual(sig, expected_sig)

    def test_T3_06_rsa_pkcs1_encryption_roundtrip(self):
        """T3.06: Pure-Python RSA PKCS#1 v1.5 encryption round-trip with genuine cryptography private key."""
        # Generate 1024-bit RSA key for testing
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
        )
        public_key = private_key.public_key()
        modulus = public_key.public_numbers().n
        exponent = public_key.public_numbers().e

        # Password MD5 hex to encrypt (32 ASCII bytes)
        plaintext = b"22c14f311a60486b36f79f3bc962be66"

        # Encrypt using pure-Python implementation in TuyaClient
        ciphertext_hex = TuyaClient.rsa_encrypt_pkcs1(
            str(modulus),
            str(exponent),
            plaintext,
        )
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)

        # Decrypt using standard cryptography PKCS#1 v1.5 padding to verify compliance
        decrypted = private_key.decrypt(
            ciphertext_bytes,
            asym_padding.PKCS1v15(),
        )
        self.assertEqual(decrypted, plaintext)

    def test_T3_07_rsa_encryption_plaintext_too_long_raises_error(self):
        """T3.07: RSA encryption raises GeekSmartCryptoError if plaintext exceeds modulus capacity."""
        # 1024-bit key = 128 bytes modulus. Max plaintext is 128 - 11 = 117 bytes.
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        pub = private_key.public_key()
        too_long = b"X" * 125

        with self.assertRaises(GeekSmartCryptoError):
            TuyaClient.rsa_encrypt_pkcs1(
                str(pub.public_numbers().n),
                str(pub.public_numbers().e),
                too_long,
            )

    def test_T3_07b_composite_sign_key_and_ch_key_derivation(self):
        """T3.07b: Verifies native libthing_security.so composite HMAC key and chKey derivation."""
        ch_key = TuyaClient.derive_ch_key()
        self.assertEqual(ch_key, "a9e4bfc3")
        composite_key = TuyaClient.derive_composite_sign_key()
        self.assertIn("com.geektechnology.geeksmarthome_", composite_key)
        self.assertIn("9cyampyappggykh8ey3gqf3t7pkjcray", composite_key)
        self.assertTrue(composite_key.endswith(DEFAULT_TUYA_APP_SECRET))


class TestSessionManager(unittest.TestCase):
    """Tests atomic persistence, 0o600 permissions, and multi-hop credential caching."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cache_path = os.path.join(self.temp_dir.name, ".test_session_cache.json")
        self.mgr = SessionManager(self.cache_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_T3_08_session_manager_initial_state(self):
        """T3.08: SessionManager reports non-existent for fresh cache file."""
        self.assertFalse(self.mgr.exists())
        self.assertIsNone(self.mgr.load())

    def test_T3_09_session_manager_atomic_save_and_permissions(self):
        """T3.09: SessionManager saves data atomically with 0o600 permissions."""
        data = {
            "id": 9999999,
            "email": "test@example.com",
            "token": "TEST_TOKEN_123==",
            "tuyaUsername": "test@example.com",
            "tuyaPassword": "secret_password",
            "tuyaUid": "tuya_mock_uid_1099",
        }
        self.mgr.save(data)

        self.assertTrue(self.mgr.exists())
        loaded = self.mgr.load()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.get("id"), 9999999)
        self.assertEqual(loaded.get("token"), "TEST_TOKEN_123==")
        self.assertIn("cached_at", loaded)

        # Verify POSIX file permissions: mode & 0o077 == 0 (no group/other access)
        mode = stat.S_IMODE(os.stat(self.cache_path).st_mode)
        self.assertTrue(
            (mode & 0o077) == 0,
            f"Permissions {oct(mode)} are not owner-only (0o600).",
        )
        self.assertTrue(self.mgr.verify_permissions())

    def test_T3_10_session_manager_merge_preserves_existing_fields(self):
        """T3.10: SessionManager merge preserves existing GeekSmart credentials when adding Tuya session."""
        initial = {
            "id": 9999999,
            "token": "GS_TOKEN==",
            "tuyaUsername": "test@example.com",
        }
        self.mgr.save(initial)

        # Update with Tuya session
        self.mgr.update_tuya_session(
            sid="TUYA_SID_999",
            expires_in=3600,
            uid="az_test_uid",
            home_id=778899,
            home_name="Lakehouse",
        )

        merged = self.mgr.load()
        self.assertEqual(merged.get("id"), 9999999)
        self.assertEqual(merged.get("token"), "GS_TOKEN==")
        self.assertEqual(merged.get("tuyaSid"), "TUYA_SID_999")
        self.assertEqual(merged.get("tuyaHomeId"), 778899)
        self.assertEqual(merged.get("tuya", {}).get("home_name"), "Lakehouse")

    def test_T3_11_get_tuya_session_retrieval(self):
        """T3.11: get_tuya_session returns extracted credentials and active session."""
        data = {
            "tuyaUsername": "testuser@example.com",
            "tuyaPassword": "a1b2c3d4",
            "tuyaUid": "tuya_mock_uid_1099",
            "tuyaCountryCode": 1,
            "tuya": {
                "sid": "ACTIVE_SID_123",
                "expires_at": int(time.time()) + 10000,
                "home_id": 554433,
            },
        }
        self.mgr.save(data)

        session = self.mgr.get_tuya_session()
        self.assertEqual(session["username"], "testuser@example.com")
        self.assertEqual(session["password"], "a1b2c3d4")
        self.assertEqual(session["uid"], "tuya_mock_uid_1099")
        self.assertEqual(session["country_code"], "1")
        self.assertEqual(session["sid"], "ACTIVE_SID_123")
        self.assertEqual(session["home_id"], 554433)


class TestTuyaClientOperations(unittest.TestCase):
    """Tests high-level TuyaClient authentication, discovery, and safety features."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cache_path = os.path.join(self.temp_dir.name, ".test_session_cache.json")
        self.session_mgr = SessionManager(self.cache_path)

        # Seed initial session cache with user credentials
        self.session_mgr.save({
            "tuyaUsername": "testuser@example.com",
            "tuyaPassword": "a1b2c3d4",
            "tuyaCountryCode": 1,
            "tuyaUid": "tuya_mock_uid_1099",
        })

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_T3_12_get_token_flow(self):
        """T3.12: get_token invokes thing.m.user.username.token.get and extracts RSA parameters."""
        captured_calls = []

        def mock_transport(action, version, params, post_str):
            captured_calls.append((action, version, params, post_str))
            return {
                "success": True,
                "result": {
                    "token": "MOCK_TOKEN_RANDOM",
                    "publicKey": "12345678901234567890",
                    "exponent": "65537",
                },
            }

        client = TuyaClient(
            session_cache_path=self.cache_path,
            mock_transport=mock_transport,
        )
        token_bean = client.get_token()

        self.assertEqual(len(captured_calls), 1)
        action, version, params, post_str = captured_calls[0]
        self.assertEqual(action, "thing.m.user.username.token.get")
        self.assertEqual(version, "2.0")
        self.assertIn("username", post_str)
        self.assertEqual(token_bean["token"], "MOCK_TOKEN_RANDOM")
        self.assertEqual(token_bean["publicKey"], "12345678901234567890")

    def test_T3_13_login_email_flow_and_session_caching(self):
        """T3.13: login() executes dynamic RSA encryption and caches sid to session cache."""
        # Generate genuine RSA keypair for mock token exchange
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        n_str = str(key.public_key().public_numbers().n)
        e_str = str(key.public_key().public_numbers().e)

        calls = []

        def mock_transport(action, version, params, post_str):
            calls.append((action, post_str))
            if action == "thing.m.user.username.token.get":
                return {
                    "success": True,
                    "result": {
                        "token": "EPHEMERAL_TOKEN_123",
                        "publicKey": n_str,
                        "exponent": e_str,
                    },
                }
            elif action == "thing.m.user.email.password.login":
                return {
                    "success": True,
                    "result": {
                        "sid": "AUTHENTICATED_TUYA_SID_999",
                        "uid": "tuya_mock_uid_1099",
                        "expiresIn": 2592000,
                    },
                }
            return {"success": False, "errorMsg": "Unexpected action"}

        client = TuyaClient(
            session_cache_path=self.cache_path,
            mock_transport=mock_transport,
        )
        res = client.login(use_cache=False)

        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], "thing.m.user.username.token.get")
        self.assertEqual(calls[1][0], "thing.m.user.email.password.login")
        self.assertEqual(client.sid, "AUTHENTICATED_TUYA_SID_999")

        # Verify session was cached to disk
        cached = self.session_mgr.get_tuya_session()
        self.assertEqual(cached.get("sid"), "AUTHENTICATED_TUYA_SID_999")

    def test_T3_14_login_reuses_active_cached_session(self):
        """T3.14: login(use_cache=True) reuses active cached sid with ZERO network requests."""
        # Seed cache with active sid
        self.session_mgr.update_tuya_session(
            sid="PRE_CACHED_SID_777",
            expires_in=100000,
            uid="tuya_mock_uid_1099",
        )

        calls = []

        def mock_transport(action, version, params, post_str):
            calls.append(action)
            return {"success": True, "result": {}}

        client = TuyaClient(
            session_cache_path=self.cache_path,
            mock_transport=mock_transport,
        )
        res = client.login(use_cache=True)

        self.assertEqual(len(calls), 0, "Network calls must not be made when valid cache exists")
        self.assertEqual(client.sid, "PRE_CACHED_SID_777")
        self.assertTrue(res.get("cached"))

    def test_T3_15_query_home_list_and_device_enumeration(self):
        """T3.15: query_home_list and get_home_device_list discover Smart Plug Gateway and Locks."""
        self.session_mgr.update_tuya_session(
            sid="ACTIVE_SID",
            expires_in=100000,
            uid="tuya_mock_uid_1099",
        )

        mock_homes = [
            {"homeId": 8812345, "name": "Main Residence", "geoName": "US"}
        ]
        mock_devices = [
            {
                "devId": "gw_plug_01",
                "name": "GeekSmart Smart Plug BLE Gateway",
                "productId": "prod_plug_gw",
                "isOnline": True,
                "category": "cz",
                "mac": "AA:BB:CC:98:76:54",
                "dps": {"1": True},
                "dpCodes": {"switch_1": True},
            },
            {
                "devId": "lock_front_01",
                "name": "Front Door Smart Deadbolt",
                "productId": "prod_lock_ble",
                "isOnline": True,
                "category": "ms",
                "parentId": "gw_plug_01",
                "mac": "AA:BB:CC:11:22:33",
                "dps": {"1": True, "8": 88},
                "dpCodes": {"door_state": True, "residual_electricity": 88},
            },
        ]

        def mock_transport(action, version, params, post_str):
            if action == "m.life.group.location.list":
                return {"success": True, "result": mock_homes}
            elif action == "m.life.my.group.device.list":
                return {"success": True, "result": {"devices": mock_devices}}
            return {"success": False, "errorMsg": f"Unexpected {action}"}

        client = TuyaClient(
            session_cache_path=self.cache_path,
            mock_transport=mock_transport,
        )
        client.login(use_cache=True)

        homes = client.query_home_list()
        self.assertEqual(len(homes), 1)
        self.assertEqual(client.home_id, 8812345)

        devices = client.get_home_device_list()
        self.assertEqual(len(devices), 2)

        # Verify gateway categorization
        plug = devices[0]
        self.assertEqual(plug.dev_id, "gw_plug_01")
        self.assertTrue(plug.is_gateway)
        self.assertFalse(plug.is_lock)

        # Verify lock categorization and battery extraction
        lock = devices[1]
        self.assertEqual(lock.dev_id, "lock_front_01")
        self.assertTrue(lock.is_lock)
        self.assertFalse(lock.is_gateway)
        self.assertEqual(lock.battery, 88)
        self.assertEqual(lock.parent_id, "gw_plug_01")

    def test_T3_16_publish_dp_dry_run_safety_guard(self):
        """T3.16: publish_dp with dry_run=True suppresses live network transmission."""
        calls = []

        def mock_transport(action, version, params, post_str):
            calls.append(action)
            return {"success": True, "result": {}}

        client = TuyaClient(
            session_cache_path=self.cache_path,
            mock_transport=mock_transport,
        )
        client.sid = "ACTIVE_SID"

        result = client.publish_dp(
            dev_id="lock_front_01",
            dps={"1": False},
            gw_id="gw_plug_01",
            dry_run=True,
        )

        self.assertEqual(len(calls), 0, "dry_run=True must suppress network calls")
        self.assertTrue(result.get("dry_run"))
        self.assertEqual(result.get("payload", {}).get("devId"), "lock_front_01")

    def test_T3_17_jtmspro_v22_device_parsing(self):
        """T3.17: Verifies TuyaDevice.from_dict parses live v2.2 jtmspro lock schema and DPs."""
        raw_lock = {
            "devId": "ebexamplelock001",
            "name": "livingroom",
            "productId": "a0wnqgxs",
            "category": "jtmspro",
            "categoryCode": "jtmspro_2b_2",
            "cloudOnline": True,
            "localKey": "TU:ESBz-3TXkj-Bq",
            "secKey": "x3f1_wo]G;+&Dg.-",
            "mac": "DC234F000090",
            "uuid": "uuidfake1a2b3c01",
            "deviceTopo": {
                "nodeId": "uuidfake1a2b3c01",
                "parentDevId": "ebexamplegw1a2b3c4d5e6",
            },
            "dataPointInfo": {
                "dps": {
                    "8": 100,
                    "21": "wrong_finger",
                    "31": "normal",
                    "33": False,
                    "36": 5,
                    "46": False,
                    "47": True,
                    "70": "AAH//zEyMzQ1Njc4AP//AA==",
                    "71": "AA==",
                    "73": "AAH//zEyMzQ1Njc4AQABAA==",
                }
            },
        }
        dev = TuyaDevice.from_dict(raw_lock)
        self.assertTrue(dev.is_lock)
        self.assertFalse(dev.is_gateway)
        self.assertTrue(dev.is_online)
        self.assertEqual(dev.parent_id, "ebexamplegw1a2b3c4d5e6")
        self.assertEqual(dev.battery, 100)
        self.assertEqual(dev.dp_codes.get("lock_motor_state"), True)
        self.assertEqual(dev.dp_codes.get("remote_no_dp_key"), "AAH//zEyMzQ1Njc4AP//AA==")
        self.assertEqual(dev.sec_key, "x3f1_wo]G;+&Dg.-")
        self.assertEqual(dev.connection_status, 2)
        self.assertEqual(dev.ble_signal_state, "STRONG_ACTIVE_GATT")
        self.assertEqual(dev.hardware_model, "K01 2")

    def test_T3_18_auto_heal_expired_session_on_user_session_loss(self):
        """T3.18: request() automatically re-authenticates and retries when USER_SESSION_LOSS / USER_SESSION_INVALID occurs."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        n_str = str(key.public_key().public_numbers().n)
        e_str = str(key.public_key().public_numbers().e)

        self.session_mgr.update_tuya_session(
            sid="EXPIRED_SID_000",
            expires_in=86400,
            uid="tuya_mock_uid_1099",
        )

        calls = []

        def mock_transport(action, version, params, post_str):
            calls.append((action, params.get("sid")))
            if action == "m.life.group.location.list":
                if params.get("sid") == "EXPIRED_SID_000":
                    return {
                        "success": False,
                        "errorCode": "USER_SESSION_LOSS",
                        "errorMsg": "User session loss",
                    }
                return {
                    "success": True,
                    "result": [{"homeId": 999999999, "name": "My Home"}],
                }
            elif action == "thing.m.user.username.token.get":
                return {
                    "success": True,
                    "result": {
                        "token": "HEAL_TOKEN_1",
                        "publicKey": n_str,
                        "exponent": e_str,
                    },
                }
            elif action == "thing.m.user.email.password.login":
                return {
                    "success": True,
                    "result": {
                        "sid": "HEALED_FRESH_SID_888",
                        "uid": "tuya_mock_uid_1099",
                        "ecode": "ecode_healed",
                        "expiresIn": 2592000,
                    },
                }
            return {"success": False, "errorMsg": f"Unexpected {action}"}

        client = TuyaClient(
            session_cache_path=self.cache_path,
            mock_transport=mock_transport,
        )
        self.assertEqual(client.sid, "EXPIRED_SID_000")

        homes = client.query_home_list()
        self.assertEqual(len(homes), 1)
        self.assertEqual(homes[0]["homeId"], 999999999)
        self.assertEqual(client.sid, "HEALED_FRESH_SID_888")

        # Verify sequence: initial failed call -> token.get -> email.password.login -> retried call with new sid
        self.assertEqual(calls[0], ("m.life.group.location.list", "EXPIRED_SID_000"))
        self.assertEqual(calls[1][0], "thing.m.user.username.token.get")
        self.assertEqual(calls[2][0], "thing.m.user.email.password.login")
        self.assertEqual(calls[3], ("m.life.group.location.list", "HEALED_FRESH_SID_888"))

        # Verify healed sid was persisted to disk cache
        cached = self.session_mgr.get_tuya_session()
        self.assertEqual(cached.get("sid"), "HEALED_FRESH_SID_888")

    def test_T3_19_auto_retry_on_transient_timeout(self):
        """T3.19: request() automatically retries transient requests.Timeout and succeeds on subsequent attempt."""
        import requests
        from unittest.mock import MagicMock

        self.session_mgr.update_tuya_session(
            sid="ACTIVE_SID_RETRY",
            expires_in=86400,
            uid="tuya_mock_uid_1099",
        )

        mock_session = MagicMock()
        mock_ok_resp = MagicMock()
        mock_ok_resp.status_code = 200
        mock_ok_resp.json.return_value = {
            "success": True,
            "result": [{"homeId": 999999999, "name": "My Home"}],
        }
        # First call raises requests.Timeout, second call succeeds
        mock_session.post.side_effect = [
            requests.Timeout("Transient gateway timeout"),
            mock_ok_resp,
        ]

        client = TuyaClient(
            session_cache_path=self.cache_path,
            session=mock_session,
        )
        client.retry_backoff_delays = (0.01, 0.02, 0.03)

        homes = client.query_home_list()
        self.assertEqual(len(homes), 1)
        self.assertEqual(homes[0]["homeId"], 999999999)
        self.assertEqual(mock_session.post.call_count, 2)

    def test_T3_20_ble_signal_telemetry_rssi_and_dpcache_fallback(self):
        """T3.20: Verifies query_device_rssi and DPCacheBusiness v2.0 fallback on weak BLE signal locks."""
        self.session_mgr.save({
            "tuya": {
                "sid": "ACTIVE_SID_BLE",
                "expires_at": int(time.time()) + 86400,
                "devices": [
                    {
                        "devId": "ebexamplelock002",
                        "name": "bathroom",
                        "productId": "a0wnqgxs",
                        "category": "jtmspro",
                        "isOnline": False,
                        "connectionStatus": 0,
                        "bleSignalState": "WEAK_SIGNAL_STANDBY",
                        "parentId": "ebexamplegw1a2b3c4d5e6",
                        "dps": {"73": "AAL//zEyMzQ1Njc4AQABAA==", "47": False, "8": 100},
                    }
                ],
            }
        })

        calls = []

        def mock_transport(action, version, params, post_str):
            calls.append((action, version, json.loads(post_str) if post_str else {}))
            if action == "thing.m.device.rssi.info.query":
                return {"success": True, "result": {"supported": True, "type": "NETWORK", "value": -70}}
            return {"success": True, "result": True}

        client = TuyaClient(
            session_cache_path=self.cache_path,
            mock_transport=mock_transport,
        )
        rssi = client.query_device_rssi("ebexamplegw1a2b3c4d5e6")
        self.assertEqual(rssi.get("value"), -70)

        pub_res = client.publish_dp(
            dev_id="ebexamplelock002",
            dps={"1": True},
            dry_run=False,
        )
        self.assertTrue(pub_res.get("success"))
        self.assertEqual(pub_res.get("connectionStatus"), 0)
        self.assertEqual(pub_res.get("bleSignalState"), "WEAK_SIGNAL_STANDBY")
        self.assertTrue(pub_res.get("dpCacheQueued"))
        self.assertEqual(calls[1][0], "thing.m.device.dp.publish")
        self.assertEqual(calls[1][1], "1.0")
        self.assertEqual(calls[2][0], "thing.m.device.dp.publish")
        self.assertEqual(calls[2][1], "2.0")
        self.assertEqual(calls[2][2].get("gwId"), "ebexamplegw1a2b3c4d5e6")


if __name__ == "__main__":
    unittest.main()
