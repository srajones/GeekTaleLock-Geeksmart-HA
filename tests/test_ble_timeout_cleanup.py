#!/usr/bin/env python3
"""Unit tests for BLE Handshake Timeout Cleanup, Deadlock Prevention, and Lifecycle Teardown.

Verifies:
1. DEVICE_INFO timeout guarantees cleanup without leaking futures or leaving client connected.
2. PAIR timeout guarantees cleanup and session key reset.
3. Reconnection after timeout succeeds cleanly without slot exhaustion or duplicate connection collisions.
4. _send_dps and get_status timeouts do not leak futures in _pending_responses.
5. HomeAssistantBleAdapter.async_disconnect_all disconnects all registered clients concurrently.
6. Synchronous disconnect_all safely tears down connections across async and non-async contexts.
"""

from __future__ import annotations

import asyncio
import os
import sys
import unittest

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from client.ble_gatt_client import (
    BleGattClient,
    HomeAssistantBleAdapter,
    MockBleGattTransport,
    TuyaBleCmd,
    TuyaBlePacketEngine,
)

TEST_MAC = "DC:23:4F:00:00:90"
TEST_LOCAL_KEY = "TU:ESBz-3TXkj-Bq"


class TestBleTimeoutCleanup(unittest.TestCase):
    """Verifies BLE pairing timeout cleanup and deadlock-free teardown."""

    def test_device_info_timeout_guarantees_cleanup(self) -> None:
        """When DEVICE_INFO response times out, BleGattClient cleanly resets and cancels pending responses."""
        transport = MockBleGattTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
        # Suppress responses so write_payload does not trigger notify callback
        transport.write_payload = lambda payload: None
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

        async def run():
            with self.assertRaises(asyncio.TimeoutError):
                await client.connect(timeout=0.05)

            self.assertFalse(client.is_connected)
            self.assertFalse(client.is_paired)
            self.assertFalse(transport.is_connected)
            self.assertEqual(len(client._pending_responses), 0)

        asyncio.run(run())

    def test_pair_timeout_guarantees_cleanup(self) -> None:
        """When PAIR response times out after successful DEVICE_INFO, client resets session key and disconnects."""
        transport = MockBleGattTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
        orig_write = transport.write_payload
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

        def selective_write(payload: bytes):
            # Allow DEVICE_INFO through (encrypted with login_key), drop PAIR
            try:
                dec_seq, dec_resp, dec_cmd, dec_data = TuyaBlePacketEngine.unpack_message(payload, client._login_key)
                if dec_cmd == TuyaBleCmd.DEVICE_INFO:
                    orig_write(payload)
                    return
            except Exception:
                pass
            # Drop other frames (PAIR) to force timeout

        transport.write_payload = selective_write

        async def run():
            with self.assertRaises(asyncio.TimeoutError):
                await client.connect(timeout=0.05)

            self.assertFalse(client.is_connected)
            self.assertFalse(client.is_paired)
            self.assertIsNone(client._session_key)
            self.assertFalse(transport.is_connected)
            self.assertEqual(len(client._pending_responses), 0)

        asyncio.run(run())

    def test_reconnect_after_timeout_succeeds_without_collision(self) -> None:
        """After a handshake timeout, a subsequent connect attempt succeeds without state residue."""
        transport = MockBleGattTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
        orig_write = transport.write_payload
        drop_mode = True

        def conditionally_drop(payload: bytes):
            if drop_mode:
                return
            orig_write(payload)

        transport.write_payload = conditionally_drop
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

        async def run():
            # First attempt: drops packets and times out
            with self.assertRaises(asyncio.TimeoutError):
                await client.connect(timeout=0.05)

            self.assertFalse(client.is_connected)
            self.assertEqual(len(client._pending_responses), 0)

            # Second attempt: network restores, connect succeeds
            nonlocal drop_mode
            drop_mode = False
            ok = await client.connect(timeout=2.0)
            self.assertTrue(ok)
            self.assertTrue(client.is_connected)
            self.assertTrue(client.is_paired)
            self.assertEqual(len(client._pending_responses), 0)

            await client.disconnect()

        asyncio.run(run())

    def test_dp_send_and_status_timeout_does_not_leak_futures(self) -> None:
        """_send_dps and get_status timeouts do not leak futures in _pending_responses."""
        transport = MockBleGattTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

        async def run():
            await client.connect(timeout=2.0)
            self.assertTrue(client.is_paired)

            # Silence responses
            transport.write_payload = lambda payload: None

            # Attempt DP publish with very short timeout
            with self.assertRaises(asyncio.TimeoutError):
                await client._send_dps(b"\x00\x01\x01\x00", timeout=0.05)
            self.assertEqual(len(client._pending_responses), 0)

            # Attempt get_status with very short timeout
            with self.assertRaises(asyncio.TimeoutError):
                await client.get_status(timeout=0.05)
            self.assertEqual(len(client._pending_responses), 0)

            await client.disconnect()

        asyncio.run(run())

    def test_adapter_async_disconnect_all_concurrent(self) -> None:
        """HomeAssistantBleAdapter.async_disconnect_all cleanly disconnects all registered clients in parallel."""
        adapter = HomeAssistantBleAdapter(local_key=TEST_LOCAL_KEY)

        transport1 = MockBleGattTransport(mac="11:22:33:44:55:66", local_key=TEST_LOCAL_KEY)
        transport2 = MockBleGattTransport(mac="AA:BB:CC:DD:EE:FF", local_key=TEST_LOCAL_KEY)

        dev1 = type("MockDev", (), {"address": "11:22:33:44:55:66"})()
        dev2 = type("MockDev", (), {"address": "AA:BB:CC:DD:EE:FF"})()

        client1 = adapter.async_get_ble_client(dev1, local_key=TEST_LOCAL_KEY, transport=transport1)
        client2 = adapter.async_get_ble_client(dev2, local_key=TEST_LOCAL_KEY, transport=transport2)

        async def run():
            await client1.connect(timeout=2.0)
            await client2.connect(timeout=2.0)

            self.assertTrue(client1.is_connected)
            self.assertTrue(client2.is_connected)

            await adapter.async_disconnect_all()

            self.assertFalse(client1.is_connected)
            self.assertFalse(client2.is_connected)
            self.assertEqual(len(adapter._clients), 0)

        asyncio.run(run())

    def test_sync_disconnect_all(self) -> None:
        """Synchronous disconnect_all safely tears down client when called from sync context."""
        transport = MockBleGattTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

        async def setup():
            await client.connect(timeout=2.0)

        asyncio.run(setup())
        self.assertTrue(client.is_connected)

        # Call synchronous disconnect_all from sync thread without running loop
        client.disconnect_all()
        self.assertFalse(client.is_connected)


if __name__ == "__main__":
    unittest.main()
