#!/usr/bin/env python3
"""
Unit tests for Direct BLE GATT Client, Packet Engine, and Mock Transport.
Covers:
- TuyaBlePacketEngine (CRC16-MODBUS, key derivation, 19-byte DP 71 frames, TLV codec, pack/unpack)
- MockBleGattTransport (in-memory emulation of Tuya BLE peripheral, state transitions)
- BleGattClient (async connect, pair, unlock, lock, keep_unlocked, set_auto_lock, get_status)
- HomeAssistantBleAdapter (integration adapter for Home Assistant Bluetooth stack)
"""

import asyncio
import os
import struct
import sys
import unittest

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from client.ble_gatt_client import (
    BleGattClient,
    DpType,
    HomeAssistantBleAdapter,
    MockBleGattTransport,
    TuyaBleCmd,
    TuyaBlePacketEngine,
)


class TestTuyaBlePacketEngine(unittest.TestCase):
    """Verifies byte-level cryptography, CRC16, framing, and TLV encoding."""

    def test_crc16_modbus_standard_vector(self):
        """Standard CRC16-MODBUS test vector on ASCII '123456789' is 0x4B37."""
        data = b"123456789"
        crc = TuyaBlePacketEngine.calc_crc16(data)
        self.assertEqual(crc, 0x4B37)

    def test_derive_login_key(self):
        """Login key is MD5 of the first 6 characters of local_key."""
        local_key = "TU:ESBz-3TXkj-Bq"
        login_key = TuyaBlePacketEngine.derive_login_key(local_key)
        self.assertEqual(len(login_key), 16)
        import hashlib
        expected = hashlib.md5(b"TU:ESB").digest()
        self.assertEqual(login_key, expected)

    def test_derive_session_key(self):
        """Session key is MD5 of local_key[:6] concatenated with 6-byte srand."""
        local_key = "TU:ESBz-3TXkj-Bq"
        srand = b"\x01\x02\x03\x04\x05\x06"
        session_key = TuyaBlePacketEngine.derive_session_key(local_key, srand)
        self.assertEqual(len(session_key), 16)
        import hashlib
        expected = hashlib.md5(b"TU:ESB\x01\x02\x03\x04\x05\x06").digest()
        self.assertEqual(session_key, expected)

    def test_build_dp71_unlock_frame_layout(self):
        """Verifies exact 19-byte ble_unlock_check layout for unlock and lock."""
        # Unlock frame
        frame_unlock = TuyaBlePacketEngine.build_dp71_frame(
            slot_id=1,
            member_key="12345678",
            unlock=True,
            timestamp=1700000000,
        )
        self.assertEqual(len(frame_unlock), 19)
        self.assertEqual(frame_unlock[:2], b"\x00\x01")  # Slot 1
        self.assertEqual(frame_unlock[2:4], b"\xff\xff")  # Flags
        self.assertEqual(frame_unlock[4:12], b"12345678")  # Key token
        self.assertEqual(frame_unlock[12:13], b"\x01")  # Action: 1 = unlock
        self.assertEqual(frame_unlock[13:17], (1700000000).to_bytes(4, "big"))  # TS
        self.assertEqual(frame_unlock[17:19], b"\x00\x00")  # Trailer

        # Lock frame
        frame_lock = TuyaBlePacketEngine.build_dp71_frame(
            slot_id=2,
            member_key="ABCDEFGH",
            unlock=False,
            timestamp=1700000000,
        )
        self.assertEqual(len(frame_lock), 19)
        self.assertEqual(frame_lock[:2], b"\x00\x02")
        self.assertEqual(frame_lock[12:13], b"\x00")  # Action: 0 = lock

    def test_tlv_codec_roundtrip(self):
        """Verifies encoding and decoding of BOOL, VALUE, STRING, ENUM, and RAW types."""
        encoded = bytearray()
        encoded.extend(TuyaBlePacketEngine.encode_dp_tlv(47, DpType.BOOL, True))
        encoded.extend(TuyaBlePacketEngine.encode_dp_tlv(33, DpType.BOOL, False))
        encoded.extend(TuyaBlePacketEngine.encode_dp_tlv(36, DpType.VALUE, 10))
        encoded.extend(TuyaBlePacketEngine.encode_dp_tlv(8, DpType.VALUE, 92))
        encoded.extend(TuyaBlePacketEngine.encode_dp_tlv(1, DpType.ENUM, 2))
        encoded.extend(TuyaBlePacketEngine.encode_dp_tlv(2, DpType.STRING, "front_door"))

        decoded = TuyaBlePacketEngine.decode_dp_tlv(bytes(encoded))
        self.assertEqual(decoded["47"], True)
        self.assertEqual(decoded["33"], False)
        self.assertEqual(decoded["36"], 10)
        self.assertEqual(decoded["8"], 92)
        self.assertEqual(decoded["1"], 2)
        self.assertEqual(decoded["2"], "front_door")

    def test_pack_and_unpack_message_roundtrip(self):
        """Verifies AES-128-CBC encryption, PKCS framing, CRC integrity and decryption."""
        key = b"0123456789abcdef"
        data = b"Hello, Tuya BLE GATT smart lock!"
        seq = 42
        cmd = TuyaBleCmd.DP_PUBLISH

        payload = TuyaBlePacketEngine.pack_payload(
            seq_num=seq,
            cmd=cmd,
            data=data,
            key=key,
            security_flag=5,
            response_to=10,
        )
        self.assertGreaterEqual(len(payload), 17)
        self.assertEqual(payload[0], 5)

        dec_seq, dec_resp, dec_cmd, dec_data = TuyaBlePacketEngine.unpack_message(payload, key)
        self.assertEqual(dec_seq, seq)
        self.assertEqual(dec_resp, 10)
        self.assertEqual(dec_cmd, cmd)
        self.assertEqual(dec_data, data)

    def test_unpack_message_corrupt_crc_raises_error(self):
        """Verifies CRC tampering is detected and raises ValueError."""
        key = b"0123456789abcdef"
        payload = bytearray(TuyaBlePacketEngine.pack_payload(
            seq_num=1,
            cmd=TuyaBleCmd.STATUS_QUERY,
            data=b"test",
            key=key,
            security_flag=5,
        ))
        # Tamper with the last byte of ciphertext (will corrupt decrypted plaintext / CRC)
        payload[-1] ^= 0xFF
        with self.assertRaises(Exception):
            TuyaBlePacketEngine.unpack_message(bytes(payload), key)

    def test_unpack_message_short_payload_raises_error(self):
        """Verifies payloads shorter than header requirements raise ValueError."""
        key = b"0123456789abcdef"
        with self.assertRaises(ValueError):
            TuyaBlePacketEngine.unpack_message(b"\x05\x00\x01\x02", key)


class TestMockBleGattTransport(unittest.TestCase):
    """Verifies in-memory simulated peripheral logic and state transitions."""

    def setUp(self):
        self.transport = MockBleGattTransport(
            mac="AA:BB:CC:DD:EE:FF",
            local_key="SECKEY-12345678",
            initial_is_locked=True,
            initial_auto_lock=True,
            initial_auto_lock_time=5,
            initial_battery=80,
        )

    def test_mock_initial_state(self):
        """Initial peripheral parameters match constructor arguments."""
        self.assertEqual(self.transport.mac, "AA:BB:CC:DD:EE:FF")
        self.assertTrue(self.transport.is_locked)
        self.assertTrue(self.transport.auto_lock)
        self.assertEqual(self.transport.auto_lock_time, 5)
        self.assertEqual(self.transport.battery, 80)
        self.assertFalse(self.transport.is_connected)

    def test_mock_connect_and_disconnect(self):
        """Connect and disconnect update transport status."""
        loop = asyncio.new_event_loop()
        try:
            res = loop.run_until_complete(self.transport.connect())
            self.assertTrue(res)
            self.assertTrue(self.transport.is_connected)
            loop.run_until_complete(self.transport.disconnect())
            self.assertFalse(self.transport.is_connected)
            self.assertFalse(self.transport.is_paired)
        finally:
            loop.close()


class TestBleGattClientAsync(unittest.TestCase):
    """Verifies end-to-end async communication between BleGattClient and MockBleGattTransport."""

    def setUp(self):
        self.transport = MockBleGattTransport(
            mac="DC:23:4F:00:00:90",
            local_key="TU:ESBz-3TXkj-Bq",
            initial_is_locked=True,
            initial_auto_lock=True,
            initial_auto_lock_time=5,
            initial_battery=85,
        )
        self.client = BleGattClient(
            mac="DC:23:4F:00:00:90",
            local_key="TU:ESBz-3TXkj-Bq",
            transport=self.transport,
        )

    def test_connect_and_pair(self):
        """Client successfully negotiates device info and pairing handshake."""
        async def run():
            ok = await self.client.connect()
            self.assertTrue(ok)
            self.assertTrue(self.client.is_connected)
            self.assertTrue(self.client.is_paired)
            await self.client.disconnect()
            self.assertFalse(self.client.is_connected)
        asyncio.run(run())

    def test_get_status_query(self):
        """Client queries peripheral state and parses DP report."""
        async def run():
            await self.client.connect()
            status = await self.client.get_status()
            self.assertIn("47", status)
            self.assertIn("33", status)
            self.assertIn("36", status)
            self.assertIn("8", status)
            # Peripheral is locked -> DP 47 (motor state / unlocked) is False
            self.assertFalse(status["47"])
            self.assertTrue(status["33"])
            self.assertEqual(status["8"], 85)
            await self.client.disconnect()
        asyncio.run(run())

    def test_unlock_and_lock_operations(self):
        """Client actuates unlock and lock frames, verifying state transitions on transport."""
        async def run():
            await self.client.connect()
            self.assertTrue(self.transport.is_locked)

            # Unlock
            unlock_res = await self.client.unlock()
            self.assertTrue(unlock_res)
            self.assertFalse(self.transport.is_locked)

            # Query status reflects unlocked
            status = await self.client.get_status()
            self.assertTrue(status["47"])

            # Lock
            lock_res = await self.client.lock()
            self.assertTrue(lock_res)
            self.assertTrue(self.transport.is_locked)

            await self.client.disconnect()
        asyncio.run(run())

    def test_passage_mode_and_auto_lock(self):
        """Client sets auto-lock on and off (passage mode)."""
        async def run():
            await self.client.connect()

            # Passage mode (keep unlocked / auto_lock off)
            ok = await self.client.keep_unlocked()
            self.assertTrue(ok)
            self.assertFalse(self.transport.auto_lock)

            # Re-enable auto-lock
            ok2 = await self.client.set_auto_lock(True, delay_seconds=15)
            self.assertTrue(ok2)
            self.assertTrue(self.transport.auto_lock)
            self.assertEqual(self.transport.auto_lock_time, 15)

            await self.client.disconnect()
        asyncio.run(run())


class TestHomeAssistantBleAdapter(unittest.TestCase):
    """Verifies HomeAssistantBleAdapter bridging."""

    def test_adapter_instantiation_and_client_factory(self):
        """Adapter creates BleGattClient with BLE device or transport."""
        mock_ble_device = type("MockBLEDevice", (), {"address": "11:22:33:44:55:66", "name": "GeekDoor_Lock"})()
        transport = MockBleGattTransport(mac="11:22:33:44:55:66", local_key="LOCALKEY12345678")
        adapter = HomeAssistantBleAdapter(local_key="LOCALKEY12345678")
        client = adapter.async_get_ble_client(mock_ble_device, transport=transport)
        self.assertIsInstance(client, BleGattClient)
        self.assertEqual(client.mac, "11:22:33:44:55:66")


if __name__ == "__main__":
    unittest.main()
