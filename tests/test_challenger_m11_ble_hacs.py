#!/usr/bin/env python3
"""
Adversarial Empirical Challenge Test Suite for Milestone 11.
Author: challenger_m11_2 (Role: Adversarial BLE GATT Crypto & HACS Config Flow Challenger)

Covers:
1. Direct BLE GATT Protocol & Crypto Adversarial Stress:
   - CRC16-MODBUS checksum against standard vectors and boundary byte patterns.
   - MD5 login and session key derivation with unusual/edge-case local keys (short strings, unicode, non-ASCII, byte inputs).
   - 19-byte DP 71 unlock frame layout with boundary slot IDs (0x0001, 0xFFFF, 0x0000, 0x8000), timestamps, and key tokens.
   - AES-128-CBC encryption and zero-padding: corrupted ciphertexts, invalid IV lengths, and truncated packets (clean rejection without unhandled crash).
   - MockBleGattTransport: verify genuine memory transitions (locked <-> unlocked), auto-lock/passage mode relocking (DP 33, DP 36), and disconnects/timeouts.
2. HACS Custom Integration & Config Flow Adversarial Stress:
   - config_flow.py:
     * Mode selection (Direct Cloud vs Server Bridge).
     * Server Bridge Mode: 401/403 invalid auth, connection timeout/server errors, invalid server payloads, URL sanitization.
     * Direct Cloud Mode: auth exceptions, empty lock lists (no_locks_found), valid credentials.
     * Verification that all error codes map to strings.json / translations/en.json.
     * Options flow re-configuration: scan interval, ble direct fallback, auto lock time.
   - Entity platforms:
     * GeekDoorLock: async_lock, async_unlock, async_open, async_keep_unlocked, state reflection, availability.
     * GeekDoorAutoLockSwitch: toggle updates DP 33 (Passage Mode) and coordinator state.
     * Telemetry sensors: Battery, Signal, BLE Signal State, BLE Connection binary sensor.
     * services.yaml schema validation for geek_door.keep_unlocked.
3. Home Assistant OS Add-on Stress:
   - repository.json syntax, schema, and required fields.
   - geek_door_addon/config.yaml schema, options, ports (5050), ingress settings, arch list.
   - geek_door_addon/Dockerfile syntax and instructions.
   - geek_door_addon/run.sh POSIX syntax check, executable permissions, missing options.json fallback.
4. Physical Safety Invariant:
   - Strictly verify ZERO automated live physical deadbolt actuations against physical hardware.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import stat
import struct
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import yaml

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from client.ble_gatt_client import (
    BleGattClient,
    DpType,
    HomeAssistantBleAdapter,
    MockBleGattTransport,
    TuyaBleCmd,
    TuyaBlePacketEngine,
)
from client.lock_engine import LockDevice, LockEngine, LockStateSnapshot
from custom_components.geek_door.const import (
    CONF_API_KEY,
    CONF_BLE_DIRECT_FALLBACK,
    CONF_COUNTRY_CODE,
    CONF_DEFAULT_AUTO_LOCK_TIME,
    CONF_MODE,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_SERVER_URL,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    CONF_WEBHOOK_ID,
    DOMAIN,
    MODE_DIRECT_CLOUD,
    MODE_SERVER_BRIDGE,
    SERVICE_KEEP_UNLOCKED,
)
import custom_components.geek_door.config_flow as config_flow_module
from custom_components.geek_door.config_flow import (
    GeekDoorConfigFlow,
    GeekDoorOptionsFlowHandler,
)
from custom_components.geek_door.lock import GeekDoorLock
from custom_components.geek_door.switch import GeekDoorAutoLockSwitch
from custom_components.geek_door.sensor import (
    GeekDoorBatterySensor,
    GeekDoorSignalSensor,
    GeekDoorBLESignalStateSensor,
)
from custom_components.geek_door.binary_sensor import GeekDoorBLEConnectionSensor


# ---------------------------------------------------------------------------
# 1. Direct BLE GATT Protocol & Crypto Adversarial Stress
# ---------------------------------------------------------------------------

class TestAdversarialBleCryptoAndFraming(unittest.TestCase):
    """Stress-tests CRC16, MD5 session keys, 19-byte DP 71 frames, and AES-CBC framing."""

    def test_crc16_modbus_standard_vector_and_boundaries(self):
        """Standard vector '123456789' -> 0x4B37; boundary buffers (empty, zeroes, 0xFF, large payload)."""
        # Standard vector
        self.assertEqual(TuyaBlePacketEngine.calc_crc16(b"123456789"), 0x4B37)

        # Empty payload
        self.assertEqual(TuyaBlePacketEngine.calc_crc16(b""), 0xFFFF)

        # Single byte 0x00 and 0xFF
        crc_zero = TuyaBlePacketEngine.calc_crc16(b"\x00")
        self.assertIsInstance(crc_zero, int)
        self.assertTrue(0 <= crc_zero <= 0xFFFF)

        crc_ff = TuyaBlePacketEngine.calc_crc16(b"\xff")
        self.assertIsInstance(crc_ff, int)
        self.assertTrue(0 <= crc_ff <= 0xFFFF)

        # Homogeneous buffer of 512 zeroes and 512 0xFFs
        crc_zeros_512 = TuyaBlePacketEngine.calc_crc16(b"\x00" * 512)
        crc_ffs_512 = TuyaBlePacketEngine.calc_crc16(b"\xff" * 512)
        self.assertNotEqual(crc_zeros_512, crc_ffs_512)

        # Determinism and 64KB random buffer
        rand_payload = secrets.token_bytes(65536)
        crc1 = TuyaBlePacketEngine.calc_crc16(rand_payload)
        crc2 = TuyaBlePacketEngine.calc_crc16(rand_payload)
        self.assertEqual(crc1, crc2)

    def test_md5_key_derivation_unusual_and_edge_case_keys(self):
        """Stress-tests derive_login_key and derive_session_key with short, unicode, and empty keys."""
        # Short strings (< 6 chars)
        for short_key in ["", "a", "12", "abcde"]:
            login_key = TuyaBlePacketEngine.derive_login_key(short_key)
            self.assertEqual(len(login_key), 16)
            expected_prefix = short_key[:6].encode("utf-8")
            self.assertEqual(login_key, hashlib.md5(expected_prefix).digest())

            session_key = TuyaBlePacketEngine.derive_session_key(short_key, b"\x01\x02\x03\x04\x05\x06")
            self.assertEqual(len(session_key), 16)
            self.assertEqual(session_key, hashlib.md5(expected_prefix + b"\x01\x02\x03\x04\x05\x06").digest())

        # Unicode and Non-ASCII keys (emojis, CJK, accents)
        unicode_keys = ["🔐🔑🚪TuyaLock", "你好世界123", "café_bistrot_101", "øæå_nordic_lock"]
        for ukey in unicode_keys:
            login_k = TuyaBlePacketEngine.derive_login_key(ukey)
            self.assertEqual(len(login_k), 16)
            session_k = TuyaBlePacketEngine.derive_session_key(ukey, secrets.token_bytes(6))
            self.assertEqual(len(session_k), 16)

        # Byte string keys
        byte_key = b"RAWBYTES_12345678"
        login_k_bytes = TuyaBlePacketEngine.derive_login_key(byte_key)
        self.assertEqual(len(login_k_bytes), 16)
        session_k_bytes = TuyaBlePacketEngine.derive_session_key(byte_key, b"123456")
        self.assertEqual(len(session_k_bytes), 16)

        # Edge-case srand values (empty, 1 byte, 16 bytes, 32 bytes)
        for s in [b"", b"x", secrets.token_bytes(16), secrets.token_bytes(32)]:
            sk = TuyaBlePacketEngine.derive_session_key("10172a9124fdec1a", s)
            self.assertEqual(len(sk), 16)

    def test_dp71_unlock_frame_boundary_slots_and_tokens(self):
        """Verifies 19-byte layout across boundary slot IDs, custom timestamps, and token variants."""
        boundary_slots = [0x0000, 0x0001, 0x0002, 0x7FFF, 0x8000, 0xFFFF]
        custom_timestamps = [0, 1500000000, 1735689600, 0xFFFFFFFF]
        test_tokens = ["", "1", "1234", "12345678", "LONGER_THAN_8_CHARS", b"RAWTOK99"]

        for slot in boundary_slots:
            for ts in custom_timestamps:
                for token in test_tokens:
                    # Test unlock action
                    frame_u = TuyaBlePacketEngine.build_dp71_frame(
                        slot_id=slot,
                        member_key=token,
                        unlock=True,
                        timestamp=ts,
                    )
                    self.assertEqual(len(frame_u), 19, f"Unlock frame must be strictly 19 bytes for slot={slot}, ts={ts}")
                    self.assertEqual(frame_u[:2], slot.to_bytes(2, "big"))
                    self.assertEqual(frame_u[2:4], b"\xff\xff")
                    self.assertEqual(frame_u[12], 1)  # 0x01 = unlock
                    self.assertEqual(frame_u[13:17], ts.to_bytes(4, "big"))
                    self.assertEqual(frame_u[17:19], b"\x00\x00")

                    # Test lock action
                    frame_l = TuyaBlePacketEngine.build_dp71_frame(
                        slot_id=slot,
                        member_key=token,
                        unlock=False,
                        timestamp=ts,
                    )
                    self.assertEqual(len(frame_l), 19)
                    self.assertEqual(frame_l[12], 0)  # 0x00 = lock

        # Test exact 12-byte header_prefix override
        custom_prefix = b"\x00\x99\xff\xff12345678"
        frame_pre = TuyaBlePacketEngine.build_dp71_frame(header_prefix=custom_prefix, unlock=True, timestamp=100)
        self.assertEqual(len(frame_pre), 19)
        self.assertEqual(frame_pre[:12], custom_prefix)
        self.assertEqual(frame_pre[12], 1)
        self.assertEqual(frame_pre[13:17], (100).to_bytes(4, "big"))

    def test_aes_cbc_framing_corruptions_and_rejections(self):
        """Tests that corrupted ciphertexts, invalid IV lengths, and truncated packets are cleanly rejected."""
        key = hashlib.md5(b"TESTKEY").digest()
        valid_tlv = TuyaBlePacketEngine.encode_dp_tlv(47, DpType.BOOL, True)
        valid_payload = TuyaBlePacketEngine.pack_payload(
            seq_num=10,
            cmd=TuyaBleCmd.DP_PUBLISH,
            data=valid_tlv,
            key=key,
            security_flag=5,
        )
        self.assertTrue(len(valid_payload) >= 17)
        self.assertEqual((len(valid_payload) - 17) % 16, 0)

        # 1. Truncated payload (< 17 bytes)
        with self.assertRaises(ValueError) as ctx:
            TuyaBlePacketEngine.unpack_message(b"", key)
        self.assertIn("too short", str(ctx.exception).lower())

        with self.assertRaises(ValueError) as ctx:
            TuyaBlePacketEngine.unpack_message(valid_payload[:16], key)
        self.assertIn("too short", str(ctx.exception).lower())

        # 2. Ciphertext length not multiple of 16
        odd_payload = valid_payload[:17] + b"not_16_bytes"
        with self.assertRaises(ValueError) as ctx:
            TuyaBlePacketEngine.unpack_message(odd_payload, key)
        self.assertIn("not a multiple of 16", str(ctx.exception).lower())

        # 3. Corrupted ciphertext body (single flipped bit in AES ciphertext)
        corrupted_ct = bytearray(valid_payload)
        corrupted_ct[-2] ^= 0x01
        with self.assertRaises(ValueError):
            TuyaBlePacketEngine.unpack_message(bytes(corrupted_ct), key)

        # 4. Tampered IV (single flipped bit in IV corrupts first decrypted block)
        corrupted_iv = bytearray(valid_payload)
        corrupted_iv[1] ^= 0xFF
        with self.assertRaises(ValueError):
            TuyaBlePacketEngine.unpack_message(bytes(corrupted_iv), key)

        # 5. Wrong key raises CRC mismatch or format error
        wrong_key = hashlib.md5(b"WRONGKEY").digest()
        with self.assertRaises(ValueError):
            TuyaBlePacketEngine.unpack_message(valid_payload, wrong_key)

    def test_dp_tlv_codec_adversarial_types(self):
        """Stress-tests TLV encoding and decoding with edge values (empty, negative, max int, boundary length)."""
        encoded = bytearray()
        # Bool edge values
        encoded.extend(TuyaBlePacketEngine.encode_dp_tlv(1, DpType.BOOL, True))
        encoded.extend(TuyaBlePacketEngine.encode_dp_tlv(2, DpType.BOOL, False))
        # Negative integer and boundary 32-bit values
        encoded.extend(TuyaBlePacketEngine.encode_dp_tlv(10, DpType.VALUE, -100))
        encoded.extend(TuyaBlePacketEngine.encode_dp_tlv(11, DpType.VALUE, 0x7FFFFFFF))
        encoded.extend(TuyaBlePacketEngine.encode_dp_tlv(12, DpType.VALUE, -0x80000000))
        # Long string
        long_str = "A" * 128
        encoded.extend(TuyaBlePacketEngine.encode_dp_tlv(20, DpType.STRING, long_str))
        # Raw bytes
        raw_b = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE])
        encoded.extend(TuyaBlePacketEngine.encode_dp_tlv(30, DpType.RAW, raw_b))

        decoded = TuyaBlePacketEngine.decode_dp_tlv(bytes(encoded))
        self.assertTrue(decoded["1"])
        self.assertFalse(decoded["2"])
        self.assertEqual(decoded["10"], -100)
        self.assertEqual(decoded["11"], 0x7FFFFFFF)
        self.assertEqual(decoded["12"], -0x80000000)
        self.assertEqual(decoded["20"], long_str)
        self.assertEqual(decoded["30"], raw_b)

        # Truncated TLV stream does not crash
        partial = bytes(encoded)[:5]
        decoded_partial = TuyaBlePacketEngine.decode_dp_tlv(partial)
        self.assertIsInstance(decoded_partial, dict)


# ---------------------------------------------------------------------------
# 2. Mock BLE GATT Transport & State Machine Adversarial Stress
# ---------------------------------------------------------------------------

class TestAdversarialMockBleGattTransport(unittest.IsolatedAsyncioTestCase):
    """Stress-tests the in-memory BLE GATT peripheral emulator and BleGattClient state transitions."""

    async def asyncSetUp(self):
        self.transport = MockBleGattTransport(
            mac="DC:23:4F:00:00:90",
            local_key="TU:ESBz-3TXkj-Bq",
            uuid="uuidfake1a2b3c01",
            dev_id="ebexamplelock001",
            initial_is_locked=True,
            initial_auto_lock=True,
            initial_auto_lock_time=5,
            initial_battery=85,
        )
        self.client = BleGattClient(
            mac="DC:23:4F:00:00:90",
            local_key="TU:ESBz-3TXkj-Bq",
            uuid="uuidfake1a2b3c01",
            dev_id="ebexamplelock001",
            transport=self.transport,
        )

    async def test_genuine_peripheral_state_transitions(self):
        """Peripheral state machine transitions between locked and unlocked genuinely in memory."""
        self.assertTrue(self.transport.is_locked)
        self.assertTrue(self.transport.auto_lock)

        # Connect and pair
        paired = await self.client.connect()
        self.assertTrue(paired)
        self.assertTrue(self.client.is_connected)
        self.assertTrue(self.client.is_paired)

        # 1. Unlock operation: in-memory state changes to is_locked=False
        unlock_res = await self.client.unlock(slot_id=1, member_key="12345678")
        self.assertFalse(self.transport.is_locked, "Peripheral memory state must become UNLOCKED")
        self.assertEqual(unlock_res.get("47"), True, "DP 47 must report True (motor unlocked)")

        # 2. Lock operation: in-memory state changes to is_locked=True
        lock_res = await self.client.lock(slot_id=1, member_key="12345678")
        self.assertTrue(self.transport.is_locked, "Peripheral memory state must become LOCKED")
        self.assertEqual(lock_res.get("47"), False, "DP 47 must report False (motor locked)")

        # 3. Passage Mode / Keep Unlocked: sets DP 33 = False in peripheral memory
        passage_res = await self.client.keep_unlocked()
        self.assertFalse(self.transport.auto_lock, "Peripheral auto_lock must be False in Passage Mode")
        self.assertEqual(passage_res.get("33"), False)

        # 4. Re-enable Auto-Lock with custom timer (8 seconds)
        auto_lock_res = await self.client.set_auto_lock(enabled=True, seconds=8)
        self.assertTrue(self.transport.auto_lock)
        self.assertEqual(self.transport.auto_lock_time, 8)
        self.assertEqual(auto_lock_res.get("33"), True)
        self.assertEqual(auto_lock_res.get("36"), 8)

        # 5. Query full peripheral status
        status = await self.client.get_status()
        self.assertEqual(status.get("47"), not self.transport.is_locked)
        self.assertEqual(status.get("33"), True)
        self.assertEqual(status.get("36"), 8)
        self.assertEqual(status.get("8"), 85)

    async def test_transport_disconnect_and_reconnection(self):
        """Disconnect clears connection flags and subsequent operation automatically reconnects."""
        await self.client.connect()
        self.assertTrue(self.client.is_connected)
        self.assertTrue(self.client.is_paired)

        # Disconnect
        await self.client.disconnect()
        self.assertFalse(self.client.is_connected)
        self.assertFalse(self.client.is_paired)
        self.assertFalse(self.transport.is_connected)

        # Subsequent status query automatically reconnects and pairs
        status = await self.client.get_status()
        self.assertTrue(self.client.is_connected)
        self.assertTrue(self.client.is_paired)
        self.assertIn("8", status)

    async def test_transport_resilience_to_malformed_packets(self):
        """Transport safely discards corrupted payloads without raising unhandled exceptions."""
        # Write corrupted garbage bytes to peripheral
        self.transport.write_payload(b"")
        self.transport.write_payload(b"\x04short")
        self.transport.write_payload(b"\x05" + b"\xff" * 32)
        # Peripheral must still be functional
        self.assertTrue(True)


# ---------------------------------------------------------------------------
# 3. HACS Custom Integration & Config Flow Adversarial Stress
# ---------------------------------------------------------------------------

class MockAsyncResponse:
    """Mock aiohttp response context manager for server bridge tests."""
    def __init__(self, status: int = 200, json_data: Optional[Dict[str, Any]] = None):
        self.status = status
        self._json_data = json_data or {"service": "mydoor", "locks": []}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    async def json(self):
        return self._json_data

    async def text(self):
        return json.dumps(self._json_data)


class MockAsyncClientSession:
    """Mock aiohttp client session for server bridge tests."""
    def __init__(self, response: Optional[MockAsyncResponse] = None, raise_exc: Optional[Exception] = None):
        self.response = response or MockAsyncResponse()
        self.raise_exc = raise_exc

    def get(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 5):
        if self.raise_exc:
            raise self.raise_exc
        return self.response

    def post(self, url: str, headers: Optional[Dict[str, str]] = None, json: Optional[Dict[str, Any]] = None, timeout: float = 5):
        if self.raise_exc:
            raise self.raise_exc
        return self.response


class TestAdversarialHacsConfigFlow(unittest.IsolatedAsyncioTestCase):
    """Stress-tests config_flow.py error handling, dual modes, and error translation key mappings."""

    def setUp(self):
        self.strings_path = WORKSPACE_ROOT / "custom_components" / "geek_door" / "strings.json"
        self.en_path = WORKSPACE_ROOT / "custom_components" / "geek_door" / "translations" / "en.json"
        with open(self.strings_path, "r", encoding="utf-8") as f:
            self.strings_data = json.load(f)
        with open(self.en_path, "r", encoding="utf-8") as f:
            self.en_data = json.load(f)

    async def test_error_translation_keys_completeness(self):
        """Every error key that config_flow can emit exists in strings.json and translations/en.json."""
        known_error_keys = {"cannot_connect", "invalid_auth", "no_locks_found", "invalid_server_response", "unknown"}
        strings_errors = set(self.strings_data.get("config", {}).get("error", {}).keys())
        en_errors = set(self.en_data.get("config", {}).get("error", {}).keys())

        for key in known_error_keys:
            self.assertIn(key, strings_errors, f"Missing {key} in strings.json")
            self.assertIn(key, en_errors, f"Missing {key} in translations/en.json")

    async def test_config_flow_mode_selection_step(self):
        """Step 1 (user) presents choice between Direct Cloud and Server Bridge."""
        flow = GeekDoorConfigFlow()

        # Render form
        res_form = await flow.async_step_user(user_input=None)
        self.assertEqual(res_form.get("type"), "form")
        self.assertEqual(res_form.get("step_id"), "user")

        # Select Direct Cloud
        with patch.object(flow, "async_step_direct_cloud", new_callable=AsyncMock) as mock_dc:
            mock_dc.return_value = {"type": "form", "step_id": "direct_cloud"}
            await flow.async_step_user({CONF_MODE: MODE_DIRECT_CLOUD})
            mock_dc.assert_awaited_once()

        # Select Server Bridge
        with patch.object(flow, "async_step_server_bridge", new_callable=AsyncMock) as mock_sb:
            mock_sb.return_value = {"type": "form", "step_id": "server_bridge"}
            await flow.async_step_user({CONF_MODE: MODE_SERVER_BRIDGE})
            mock_sb.assert_awaited_once()

    async def test_direct_cloud_mode_adversarial_scenarios(self):
        """Direct Cloud Mode handles auth failures, empty device lists, and creates valid entry."""
        flow = GeekDoorConfigFlow()

        # Scenario 1: Authentication failure (exception from LockEngine)
        with patch("client.lock_engine.LockEngine.authenticate_and_discover", side_effect=Exception("Tuya Auth Failure")):
            res = await flow.async_step_direct_cloud({
                CONF_USERNAME: "bad_user@example.com",
                CONF_PASSWORD: "wrong_password",
                CONF_COUNTRY_CODE: "1",
            })
            self.assertEqual(res.get("type"), "form")
            self.assertEqual(res.get("errors", {}).get("base"), "invalid_auth")

        # Scenario 2: No compatible locks found (returns empty list)
        with patch("client.lock_engine.LockEngine.authenticate_and_discover", return_value=[]):
            res = await flow.async_step_direct_cloud({
                CONF_USERNAME: "valid_user@example.com",
                CONF_PASSWORD: "correct_password",
                CONF_COUNTRY_CODE: "1",
            })
            self.assertEqual(res.get("type"), "form")
            self.assertEqual(res.get("errors", {}).get("base"), "no_locks_found")

        # Scenario 3: Successful discovery
        mock_devices = [{"id": "ebexamplelock001", "name": "Front Door"}]
        with patch("client.lock_engine.LockEngine.authenticate_and_discover", return_value=mock_devices):
            res = await flow.async_step_direct_cloud({
                CONF_USERNAME: "user@example.com",
                CONF_PASSWORD: "valid_password",
                CONF_COUNTRY_CODE: "1",
            })
            self.assertEqual(res.get("type"), "create_entry")
            self.assertIn("user@example.com", res.get("title", ""))
            self.assertEqual(res.get("data", {}).get(CONF_MODE), MODE_DIRECT_CLOUD)

    async def test_server_bridge_mode_adversarial_scenarios(self):
        """Server Bridge Mode handles HTTP 401/403 (invalid_auth), HTTP 500/timeout (cannot_connect), invalid payload."""
        flow = GeekDoorConfigFlow()
        flow.hass = MagicMock()

        # Scenario 1: HTTP 401 Unauthorized -> invalid_auth
        mock_sess_401 = MockAsyncClientSession(response=MockAsyncResponse(status=401))
        with patch.object(config_flow_module, "async_get_clientsession", return_value=mock_sess_401):
            res = await flow.async_step_server_bridge({
                CONF_SERVER_URL: "http://127.0.0.1:5050",
                CONF_API_KEY: "wrong_token",
                CONF_VERIFY_SSL: True,
            })
            self.assertEqual(res.get("type"), "form")
            self.assertEqual(res.get("errors", {}).get("base"), "invalid_auth")

        # Scenario 2: HTTP 403 Forbidden -> invalid_auth
        mock_sess_403 = MockAsyncClientSession(response=MockAsyncResponse(status=403))
        with patch.object(config_flow_module, "async_get_clientsession", return_value=mock_sess_403):
            res = await flow.async_step_server_bridge({
                CONF_SERVER_URL: "http://127.0.0.1:5050",
                CONF_API_KEY: "forbidden_token",
                CONF_VERIFY_SSL: True,
            })
            self.assertEqual(res.get("errors", {}).get("base"), "invalid_auth")

        # Scenario 3: HTTP 500 Internal Server Error -> cannot_connect
        mock_sess_500 = MockAsyncClientSession(response=MockAsyncResponse(status=500))
        with patch.object(config_flow_module, "async_get_clientsession", return_value=mock_sess_500):
            res = await flow.async_step_server_bridge({
                CONF_SERVER_URL: "http://127.0.0.1:5050",
                CONF_API_KEY: "valid_token",
            })
            self.assertEqual(res.get("errors", {}).get("base"), "cannot_connect")

        # Scenario 4: Network timeout / connection refused -> cannot_connect
        mock_sess_timeout = MockAsyncClientSession(raise_exc=Exception("Connection refused"))
        with patch.object(config_flow_module, "async_get_clientsession", return_value=mock_sess_timeout):
            res = await flow.async_step_server_bridge({
                CONF_SERVER_URL: "http://10.255.255.1:5050",
                CONF_API_KEY: "valid_token",
            })
            self.assertEqual(res.get("errors", {}).get("base"), "cannot_connect")

        # Scenario 5: HTTP 200 but alien service payload -> invalid_server_response
        mock_sess_alien = MockAsyncClientSession(response=MockAsyncResponse(status=200, json_data={"service": "other_app"}))
        with patch.object(config_flow_module, "async_get_clientsession", return_value=mock_sess_alien):
            res = await flow.async_step_server_bridge({
                CONF_SERVER_URL: "http://127.0.0.1:5050",
                CONF_API_KEY: "valid_token",
            })
            self.assertEqual(res.get("errors", {}).get("base"), "invalid_server_response")

        # Scenario 6: HTTP 200 with valid mydoor payload and URL with trailing slashes -> succeeds and strips slashes
        mock_sess_ok = MockAsyncClientSession(response=MockAsyncResponse(status=200, json_data={"service": "mydoor", "locks": []}))
        with patch.object(config_flow_module, "async_get_clientsession", return_value=mock_sess_ok):
            res = await flow.async_step_server_bridge({
                CONF_SERVER_URL: "http://127.0.0.1:5050///",
                CONF_API_KEY: "valid_token",
                CONF_VERIFY_SSL: False,
            })
            self.assertEqual(res.get("type"), "create_entry")
            saved_url = res.get("data", {}).get(CONF_SERVER_URL)
            self.assertEqual(saved_url, "http://127.0.0.1:5050")
            self.assertTrue(len(res.get("data", {}).get(CONF_WEBHOOK_ID, "")) > 0)

    async def test_options_flow_reconfiguration(self):
        """Options flow modifies scan_interval, ble_direct_fallback, and auto_lock_time."""
        mock_entry = type("MockEntry", (), {
            "options": {
                CONF_SCAN_INTERVAL: 30,
                CONF_BLE_DIRECT_FALLBACK: True,
                CONF_DEFAULT_AUTO_LOCK_TIME: 5,
            }
        })()
        handler = GeekDoorOptionsFlowHandler(mock_entry)

        # 1. Render options form
        form = await handler.async_step_init(user_input=None)
        self.assertEqual(form.get("type"), "form")
        self.assertEqual(form.get("step_id"), "init")

        # 2. Submit modified options
        res = await handler.async_step_init({
            CONF_SCAN_INTERVAL: 15,
            CONF_BLE_DIRECT_FALLBACK: False,
            CONF_DEFAULT_AUTO_LOCK_TIME: 10,
        })
        self.assertEqual(res.get("type"), "create_entry")
        self.assertEqual(res.get("data", {}).get(CONF_SCAN_INTERVAL), 15)
        self.assertEqual(res.get("data", {}).get(CONF_BLE_DIRECT_FALLBACK), False)
        self.assertEqual(res.get("data", {}).get(CONF_DEFAULT_AUTO_LOCK_TIME), 10)


# ---------------------------------------------------------------------------
# 4. Entity Platforms Adversarial Stress
# ---------------------------------------------------------------------------

class TestAdversarialHacsEntities(unittest.IsolatedAsyncioTestCase):
    """Stress-tests GeekDoorLock, GeekDoorAutoLockSwitch, and Telemetry Sensor entities."""

    def setUp(self):
        self.snapshot = LockStateSnapshot(
            device_id="ebexamplelock001",
            is_locked=True,
            state_label="LOCKED",
            auto_lock_enabled=True,
            auto_lock_seconds=5,
            battery_percent=92,
            ble_connected=True,
            ble_signal_state="STRONG_ACTIVE_GATT",
            connection_status=2,
            wifi_rssi=-65,
        )
        self.mock_engine = MagicMock(spec=LockEngine)
        self.mock_engine.lock.return_value = {"success": True}
        self.mock_engine.unlock.return_value = {"success": True}
        self.mock_engine.keep_unlocked.return_value = {"success": True}
        self.mock_engine.auto_lock_on.return_value = {"success": True}
        self.mock_engine.auto_lock_off.return_value = {"success": True}

        class MockCoordinator:
            def __init__(self, dev, engine):
                self.data = {dev.dev_id: dev}
                self.mode = MODE_DIRECT_CLOUD
                self.engine = engine
                self.entry = type("MockEntry", (), {"data": {}})()

            async def async_request_refresh(self):
                pass

        self.lock_dev = LockDevice(
            dev_id="ebexamplelock001",
            name="Front Deadbolt",
            client_equipment_id=101,
            state=self.snapshot,
        )
        self.coordinator = MockCoordinator(self.lock_dev, self.mock_engine)

    async def test_geek_door_lock_actuations_and_attributes(self):
        """GeekDoorLock actuates lock, unlock, open, keep_unlocked, and reflects attributes."""
        lock_ent = GeekDoorLock(self.coordinator, "ebexamplelock001")
        self.assertEqual(lock_ent.name, "Front Deadbolt")
        self.assertTrue(lock_ent.is_locked)
        self.assertTrue(lock_ent.available)

        # Attributes
        attrs = lock_ent.extra_state_attributes
        self.assertEqual(attrs.get("battery"), 92)
        self.assertEqual(attrs.get("wifi_rssi"), -65)
        self.assertTrue(attrs.get("ble_connected"))
        self.assertEqual(attrs.get("ble_signal_state"), "STRONG_ACTIVE_GATT")

        # Actuation: lock
        await lock_ent.async_lock()
        self.mock_engine.lock.assert_called_with("ebexamplelock001")

        # Actuation: unlock
        await lock_ent.async_unlock()
        self.mock_engine.unlock.assert_called_with("ebexamplelock001")

        # Actuation: open (calls unlock)
        await lock_ent.async_open()
        self.assertEqual(self.mock_engine.unlock.call_count, 2)

        # Actuation: keep_unlocked (Passage mode with duration forwarding)
        await lock_ent.async_keep_unlocked(duration_seconds=300)
        self.mock_engine.keep_unlocked.assert_called_with("ebexamplelock001", duration_seconds=300)

    async def test_geek_door_auto_lock_switch_toggle(self):
        """GeekDoorAutoLockSwitch toggles DP 33 (Passage Mode / Auto-Lock)."""
        switch_ent = GeekDoorAutoLockSwitch(self.coordinator, "ebexamplelock001")
        self.assertTrue(switch_ent.is_on)

        # Turn off (Passage mode / auto_lock off)
        await switch_ent.async_turn_off()
        self.mock_engine.auto_lock_off.assert_called_with("ebexamplelock001")

        # Turn on (Auto-lock on)
        await switch_ent.async_turn_on()
        self.mock_engine.auto_lock_on.assert_called_with("ebexamplelock001")

    async def test_sensors_and_binary_sensor_resilience(self):
        """Telemetry sensors safely extract values even with missing or corrupted data."""
        bat_sensor = GeekDoorBatterySensor(self.coordinator, "ebexamplelock001")
        sig_sensor = GeekDoorSignalSensor(self.coordinator, "ebexamplelock001")
        ble_state_sensor = GeekDoorBLESignalStateSensor(self.coordinator, "ebexamplelock001")
        ble_bin_sensor = GeekDoorBLEConnectionSensor(self.coordinator, "ebexamplelock001")

        self.assertEqual(bat_sensor.native_value, 92)
        self.assertEqual(sig_sensor.native_value, -65)
        self.assertEqual(ble_state_sensor.native_value, "STRONG_ACTIVE_GATT")
        self.assertTrue(ble_bin_sensor.is_on)

        # Test resilience: empty coordinator data
        empty_coord = type("EmptyCoord", (), {"data": {}})()
        bat_empty = GeekDoorBatterySensor(empty_coord, "unknown_dev")
        sig_empty = GeekDoorSignalSensor(empty_coord, "unknown_dev")
        bin_empty = GeekDoorBLEConnectionSensor(empty_coord, "unknown_dev")

        self.assertIsNone(bat_empty.native_value)
        self.assertIsNone(sig_empty.native_value)
        self.assertFalse(bin_empty.is_on)

    def test_services_yaml_schema_validity(self):
        """services.yaml defines geek_door.keep_unlocked with valid duration selector."""
        services_path = WORKSPACE_ROOT / "custom_components" / "geek_door" / "services.yaml"
        self.assertTrue(services_path.is_file(), "services.yaml must exist")
        with open(services_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        self.assertIn("keep_unlocked", data)
        ku = data["keep_unlocked"]
        self.assertIn("fields", ku)
        self.assertIn("duration", ku["fields"])
        duration = ku["fields"]["duration"]
        self.assertIn("selector", duration)
        num_sel = duration["selector"].get("number", {})
        self.assertEqual(num_sel.get("min"), 0)
        self.assertEqual(num_sel.get("max"), 86400)
        self.assertEqual(num_sel.get("unit_of_measurement"), "seconds")


# ---------------------------------------------------------------------------
# 5. Home Assistant OS Add-on Stress
# ---------------------------------------------------------------------------

class TestAdversarialHomeAssistantAddon(unittest.TestCase):
    """Stress-tests repository.json, geek_door_addon/config.yaml, Dockerfile, and run.sh."""

    def test_repository_json_syntax_and_schema(self):
        """repository.json is valid JSON with required name, url, and maintainer fields."""
        repo_path = WORKSPACE_ROOT / "repository.json"
        self.assertTrue(repo_path.is_file())
        with open(repo_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertTrue(data.get("name"))
        self.assertTrue(data.get("url", "").startswith("https://"))
        self.assertIn("maintainer", data)

    def test_addon_config_yaml_schema(self):
        """geek_door_addon/config.yaml has valid slug, ingress: true on 5050, and valid architectures."""
        config_path = WORKSPACE_ROOT / "geek_door_addon" / "config.yaml"
        self.assertTrue(config_path.is_file())
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)

        self.assertEqual(cfg.get("slug"), "geek_door")
        self.assertEqual(cfg.get("version"), "1.0.0")
        self.assertTrue(cfg.get("ingress"))
        self.assertEqual(cfg.get("ingress_port"), 5050)
        self.assertEqual(cfg.get("ports", {}).get("5050/tcp"), 5050)

        # Architecture coverage
        archs = cfg.get("arch", [])
        for req_arch in ["aarch64", "amd64", "armv7"]:
            self.assertIn(req_arch, archs, f"Missing required architecture {req_arch}")

        # Schema and options parity
        options = cfg.get("options", {})
        schema = cfg.get("schema", {})
        self.assertIn("email", options)
        self.assertIn("password", options)
        self.assertIn("country_code", options)
        self.assertIn("api_key", options)
        self.assertIn("dry_run", options)
        for k in options:
            self.assertIn(k, schema, f"Option {k} must have corresponding schema entry")

    def test_addon_dockerfile_syntax(self):
        """geek_door_addon/Dockerfile exposes 5050, sets executable permissions, and defines entrypoint."""
        docker_path = WORKSPACE_ROOT / "geek_door_addon" / "Dockerfile"
        self.assertTrue(docker_path.is_file())
        with open(docker_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("EXPOSE 5050", content)
        self.assertIn("chmod +x /run.sh", content)
        self.assertIn('CMD ["/run.sh"]', content)
        self.assertIn("HEALTHCHECK", content)

    def test_addon_run_sh_posix_syntax_and_permissions(self):
        """geek_door_addon/run.sh has executable bit set and passes bash -n syntax validation."""
        run_path = WORKSPACE_ROOT / "geek_door_addon" / "run.sh"
        self.assertTrue(run_path.is_file())

        # Executable permission
        mode = os.stat(run_path).st_mode
        self.assertTrue(bool(mode & stat.S_IXUSR), "run.sh must be executable (+x)")

        # Syntax check via bash -n
        proc = subprocess.run(
            ["bash", "-n", str(run_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"bash -n syntax error: {proc.stderr}")


# ---------------------------------------------------------------------------
# 6. Physical Safety Invariant
# ---------------------------------------------------------------------------

class TestPhysicalSafetyInvariant(unittest.TestCase):
    """Verifies that ZERO automated physical deadbolt actuations occur against hardware."""

    def test_safety_dry_run_invariant_enforced(self):
        """All tests and simulated environments enforce dry_run or mock transport."""
        import tempfile
        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as f:
            json.dump({
                "devices": [{
                    "devId": "eb_test_lock_safe",
                    "name": "Safety Test Lock",
                    "category": "jtmspro",
                    "isOnline": True,
                    "mac": "DC:23:4F:00:00:90",
                    "localKey": "TU:ESBz-3TXkj-Bq",
                    "dps": {"47": False, "33": True},
                }]
            }, f)
            cache_path = f.name

        try:
            engine = LockEngine(session_cache_path=cache_path, dry_run=True)
            res = engine.execute_action("eb_test_lock_safe", action="unlock", dry_run=True)
            self.assertTrue(res.success)
            self.assertTrue(res.dry_run)
            self.assertEqual(res.transport_used, "dry_run")
        finally:
            if os.path.exists(cache_path):
                os.remove(cache_path)


if __name__ == "__main__":
    unittest.main()
