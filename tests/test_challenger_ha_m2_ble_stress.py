#!/usr/bin/env python3
"""Challenger 1 Adversarial Stress Test Suite for Milestone 2: BLE Timeout & Deadlock Resilience.

Rigorously stress-tests:
1. Deadlock Stress Testing:
   - Rapid timeouts in DEVICE_INFO and PAIR handshake under heavy concurrency (25-50 concurrent tasks).
   - Verifies _disconnect_locked() completely prevents lock re-entrancy deadlocks on asyncio.Lock.
   - Verifies client._lock is released and usable after timeouts.
2. Future Leak Stress Testing:
   - 50 rapid sequential connection timeouts on DEVICE_INFO.
   - 50 rapid sequential connection timeouts on PAIR.
   - 50 rapid sequential timeouts on DP_PUBLISH / get_status.
   - Verifies len(self._pending_responses) == 0 after every single timeout.
   - Verifies abrupt disconnection cleanly cancels in-flight futures.
3. Reconnection Collision Testing:
   - Strict single-slot GATT transport raises RuntimeError if connected twice.
   - Reconnecting immediately after handshake timeouts succeeds without GATT radio lockout.
   - Bleak client mock verifies disconnect() is awaited and _bleak_client is set to None.
   - Rapid alternating timeout-and-reconnect cycling (20 cycles).
4. Adapter Lifecycle Teardown:
   - async_disconnect_all() with heterogeneous clients (active, disconnected, timed out).
   - Fault-injection resilience: client disconnect exceptions do not halt teardown of other clients.
   - Concurrent async_disconnect_all() invocations.
   - Synchronous disconnect_all() execution in and out of running event loops.
"""

from __future__ import annotations

import asyncio
import os
import sys
import unittest
from typing import Any, Callable, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from custom_components.geek_door.core.ble_gatt_client import (
    BleGattClient,
    HomeAssistantBleAdapter,
    MockBleGattTransport,
    TuyaBleCmd,
    TuyaBlePacketEngine,
    normalize_ble_mac,
)

TEST_MAC = "DC:23:4F:00:00:90"
TEST_LOCAL_KEY = "TU:ESBz-3TXkj-Bq"
TEST_UUID = "uuidfake1a2b3c01"
TEST_DEV_ID = "ebexamplelock001"


class StrictSlotMockTransport(MockBleGattTransport):
    """Peripheral emulator that strictly enforces a single GATT connection slot.
    
    If connect() is called while is_connected is already True, raises RuntimeError
    to simulate GATT radio lockout / ConnectionSlotsExhausted.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.connection_count = 0
        self.disconnection_count = 0

    async def connect(self) -> bool:
        if self.is_connected:
            raise RuntimeError("GATT radio lockout: connection slot already occupied!")
        self.is_connected = True
        self.connection_count += 1
        return True

    async def disconnect(self) -> None:
        if self.is_connected:
            self.disconnection_count += 1
        self.is_connected = False
        self.is_paired = False


class TestDeadlockStress(unittest.TestCase):
    """Stress tests verifying that rapid timeouts under concurrency never deadlock."""

    def test_rapid_device_info_timeouts_under_heavy_concurrency(self) -> None:
        """25 concurrent tasks attempting connect() while DEVICE_INFO drops; none deadlock."""
        transport = MockBleGattTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
        # Drop all outbound frames so DEVICE_INFO times out
        transport.write_payload = lambda payload: None
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

        async def worker(task_id: int):
            try:
                await client.connect(timeout=0.03)
                return "connected"
            except asyncio.TimeoutError:
                return "timeout"
            except Exception as exc:
                return f"error: {type(exc).__name__}"

        async def run_suite():
            tasks = [asyncio.create_task(worker(i)) for i in range(25)]
            # Bounded wait_for enforces that the entire pool MUST complete within 4 seconds
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=4.0)
            self.assertEqual(len(results), 25)
            # All tasks should experience clean timeout without hang
            for res in results:
                self.assertEqual(res, "timeout")

            # Crucial assertion: Lock must NOT be locked after all tasks complete
            self.assertFalse(client._get_lock().locked(), "asyncio.Lock remained locked after timeout barrage!")
            self.assertEqual(len(client._pending_responses), 0, "Dangling pending response futures remain!")
            self.assertFalse(client.is_connected)
            self.assertFalse(client.is_paired)

        asyncio.run(run_suite())

    def test_rapid_pair_timeouts_under_heavy_concurrency(self) -> None:
        """25 concurrent tasks attempting connect() while PAIR drops; none deadlock."""
        transport = MockBleGattTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
        orig_write = transport.write_payload
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

        def drop_pair_only(payload: bytes):
            try:
                flag = payload[0] if payload else 0
                key = client._login_key if flag == 4 else client._session_key
                if key:
                    seq, resp, cmd, data = TuyaBlePacketEngine.unpack_message(payload, key)
                    if cmd == TuyaBleCmd.DEVICE_INFO:
                        orig_write(payload)
                        return
            except Exception:
                pass
            # Drop everything else (specifically PAIR)

        transport.write_payload = drop_pair_only

        async def worker():
            try:
                await client.connect(timeout=0.03)
                return "connected"
            except asyncio.TimeoutError:
                return "timeout"

        async def run_suite():
            tasks = [asyncio.create_task(worker()) for _ in range(25)]
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=4.0)
            self.assertEqual(len(results), 25)
            for res in results:
                self.assertEqual(res, "timeout")

            self.assertFalse(client._get_lock().locked(), "Lock held after PAIR timeout storm!")
            self.assertEqual(len(client._pending_responses), 0)
            self.assertFalse(client.is_connected)
            self.assertFalse(client.is_paired)
            self.assertIsNone(client._session_key)

        asyncio.run(run_suite())

    def test_mixed_concurrent_operations_with_deadlock_probe(self) -> None:
        """40 concurrent tasks mixing connect, disconnect, _send_dps, get_status with packet loss."""
        transport = MockBleGattTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
        orig_write = transport.write_payload
        drop_all = True

        def selective_write(payload: bytes):
            if drop_all:
                return
            orig_write(payload)

        transport.write_payload = selective_write
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

        async def worker_connect():
            try:
                await client.connect(timeout=0.04)
            except (asyncio.TimeoutError, RuntimeError):
                pass

        async def worker_disconnect():
            await client.disconnect()

        async def worker_status():
            try:
                await client.get_status(timeout=0.04)
            except (asyncio.TimeoutError, RuntimeError, asyncio.CancelledError):
                pass

        async def worker_dps():
            try:
                await client._send_dps(b"\x00\x01\x01\x00", timeout=0.04)
            except (asyncio.TimeoutError, RuntimeError, asyncio.CancelledError):
                pass

        async def run_suite():
            tasks = []
            for i in range(10):
                tasks.append(asyncio.create_task(worker_connect()))
                tasks.append(asyncio.create_task(worker_disconnect()))
                tasks.append(asyncio.create_task(worker_status()))
                tasks.append(asyncio.create_task(worker_dps()))

            # Must all finish within 5.0 seconds without hanging
            await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=5.0)

            # Re-enable traffic and verify client can cleanly connect now
            nonlocal drop_all
            drop_all = False
            self.assertFalse(client._get_lock().locked())
            self.assertEqual(len(client._pending_responses), 0)

            ok = await client.connect(timeout=2.0)
            self.assertTrue(ok)
            self.assertTrue(client.is_connected)
            self.assertTrue(client.is_paired)
            await client.disconnect()

        asyncio.run(run_suite())


class TestFutureLeakStress(unittest.TestCase):
    """Stress tests verifying that repeated timeouts never leak futures in _pending_responses."""

    def test_50_rapid_sequential_device_info_timeouts(self) -> None:
        """50 sequential DEVICE_INFO timeouts; verify len(_pending_responses) == 0 after EVERY iteration."""
        transport = MockBleGattTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
        transport.write_payload = lambda payload: None
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

        async def run():
            for i in range(50):
                with self.assertRaises(asyncio.TimeoutError, msg=f"Iteration {i} failed to raise TimeoutError"):
                    await client.connect(timeout=0.01)

                self.assertEqual(
                    len(client._pending_responses),
                    0,
                    f"Leaked future in _pending_responses on iteration {i}!",
                )
                self.assertFalse(client.is_connected)
                self.assertFalse(client.is_paired)

        asyncio.run(run())

    def test_50_rapid_sequential_pair_timeouts(self) -> None:
        """50 sequential PAIR timeouts; verify len(_pending_responses) == 0 after EVERY iteration."""
        transport = MockBleGattTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
        orig_write = transport.write_payload
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

        def write_device_info_only(payload: bytes):
            try:
                flag = payload[0] if payload else 0
                key = client._login_key if flag == 4 else client._session_key
                if key:
                    seq, resp, cmd, data = TuyaBlePacketEngine.unpack_message(payload, key)
                    if cmd == TuyaBleCmd.DEVICE_INFO:
                        orig_write(payload)
                        return
            except Exception:
                pass

        transport.write_payload = write_device_info_only

        async def run():
            for i in range(50):
                with self.assertRaises(asyncio.TimeoutError, msg=f"Iteration {i} failed to raise TimeoutError"):
                    await client.connect(timeout=0.01)

                self.assertEqual(
                    len(client._pending_responses),
                    0,
                    f"Leaked future in _pending_responses on iteration {i}!",
                )
                self.assertFalse(client.is_connected)
                self.assertFalse(client.is_paired)
                self.assertIsNone(client._session_key)

        asyncio.run(run())

    def test_50_rapid_sequential_dp_timeouts(self) -> None:
        """50 sequential DP_PUBLISH and STATUS_QUERY timeouts; verify len(_pending_responses) == 0."""
        transport = MockBleGattTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

        async def run():
            # Initial clean handshake
            await client.connect(timeout=2.0)
            self.assertTrue(client.is_paired)

            # Silence responses
            transport.write_payload = lambda payload: None

            for i in range(50):
                with self.assertRaises(asyncio.TimeoutError):
                    await client._send_dps(b"\x00\x01\x01\x00", timeout=0.005)
                self.assertEqual(len(client._pending_responses), 0, f"DP leak at iter {i}")

                with self.assertRaises(asyncio.TimeoutError):
                    await client.get_status(timeout=0.005)
                self.assertEqual(len(client._pending_responses), 0, f"Status query leak at iter {i}")

            await client.disconnect()
            self.assertEqual(len(client._pending_responses), 0)

        asyncio.run(run())

    def test_abrupt_disconnect_cancels_all_pending_futures(self) -> None:
        """In-flight waiting futures are cleanly canceled when disconnect() is called abruptly."""
        transport = MockBleGattTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

        async def run():
            await client.connect(timeout=2.0)
            self.assertTrue(client.is_paired)

            transport.write_payload = lambda payload: None

            async def wait_call():
                try:
                    await client._send_dps(b"\x00\x01\x01\x00", timeout=5.0)
                    return "ok"
                except asyncio.CancelledError:
                    return "cancelled"
                except Exception as exc:
                    return f"exc: {exc}"

            tasks = [asyncio.create_task(wait_call()) for _ in range(5)]
            # Let tasks enter wait_for
            await asyncio.sleep(0.05)
            self.assertEqual(len(client._pending_responses), 5)

            # Abrupt disconnect
            await client.disconnect()

            results = await asyncio.gather(*tasks)
            for res in results:
                self.assertEqual(res, "cancelled")

            self.assertEqual(len(client._pending_responses), 0)
            self.assertFalse(client.is_connected)

        asyncio.run(run())


class TestReconnectionCollision(unittest.TestCase):
    """Stress tests verifying that immediate reconnection after timeouts succeeds without GATT radio lockout."""

    def test_immediate_reconnect_after_device_info_timeout_with_strict_slots(self) -> None:
        """Strict transport fails if slot is occupied; reconnect immediately after timeout succeeds."""
        transport = StrictSlotMockTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
        orig_write = transport.write_payload
        drop_packets = True

        def drop_handler(payload: bytes):
            if drop_packets:
                return
            orig_write(payload)

        transport.write_payload = drop_handler
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

        async def run():
            # Attempt 1: drops packets -> times out
            with self.assertRaises(asyncio.TimeoutError):
                await client.connect(timeout=0.03)

            # Transport MUST be disconnected by client._disconnect_locked()
            self.assertFalse(transport.is_connected)
            self.assertEqual(transport.connection_count, 1)
            self.assertEqual(transport.disconnection_count, 1)

            # Attempt 2: Re-enable traffic and immediately reconnect
            nonlocal drop_packets
            drop_packets = False
            ok = await client.connect(timeout=2.0)
            self.assertTrue(ok)
            self.assertTrue(client.is_connected)
            self.assertTrue(transport.is_connected)
            self.assertEqual(transport.connection_count, 2)
            self.assertEqual(transport.disconnection_count, 1)

            await client.disconnect()
            self.assertFalse(transport.is_connected)
            self.assertEqual(transport.disconnection_count, 2)

        asyncio.run(run())

    def test_immediate_reconnect_after_pair_timeout_with_strict_slots(self) -> None:
        """Strict transport: immediate reconnect after PAIR timeout succeeds without collision."""
        transport = StrictSlotMockTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
        orig_write = transport.write_payload
        drop_pair = True

        def selective_write(payload: bytes):
            if drop_pair:
                try:
                    flag = payload[0] if payload else 0
                    key = client._login_key if flag == 4 else client._session_key
                    if key:
                        seq, resp, cmd, data = TuyaBlePacketEngine.unpack_message(payload, key)
                        if cmd == TuyaBleCmd.DEVICE_INFO:
                            orig_write(payload)
                            return
                except Exception:
                    pass
                return
            orig_write(payload)

        transport.write_payload = selective_write
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

        async def run():
            # Attempt 1: drops PAIR -> times out
            with self.assertRaises(asyncio.TimeoutError):
                await client.connect(timeout=0.03)

            self.assertFalse(transport.is_connected)
            self.assertFalse(client.is_connected)

            # Attempt 2: Re-enable PAIR and immediately reconnect
            nonlocal drop_pair
            drop_pair = False
            ok = await client.connect(timeout=2.0)
            self.assertTrue(ok)
            self.assertTrue(client.is_connected)
            self.assertTrue(client.is_paired)

            await client.disconnect()

        asyncio.run(run())

    def test_bleak_client_disconnection_on_handshake_timeout(self) -> None:
        """Simulated BleakClient verifies disconnect() is awaited and _bleak_client is set to None on timeout."""
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=None)

        mock_bleak = AsyncMock()
        mock_bleak.connect = AsyncMock(return_value=True)
        mock_bleak.disconnect = AsyncMock(return_value=True)
        mock_bleak.start_notify = AsyncMock(return_value=True)
        mock_bleak.write_gatt_char = AsyncMock(return_value=None)

        # Inject mock into bleak constructor
        client._bleak_client = mock_bleak

        async def run():
            # Call _disconnect_locked directly to simulate error cleanup
            await client._disconnect_locked()
            mock_bleak.disconnect.assert_awaited_once()
            self.assertIsNone(client._bleak_client)
            self.assertFalse(client.is_connected)
            self.assertFalse(client.is_paired)

        asyncio.run(run())

    def test_rapid_alternating_timeout_and_reconnect_cycle(self) -> None:
        """20 cycles of: timeout -> reconnect -> disconnect; verifies zero state drift."""
        transport = StrictSlotMockTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
        orig_write = transport.write_payload
        should_fail = True

        def toggle_write(payload: bytes):
            if should_fail:
                return
            orig_write(payload)

        transport.write_payload = toggle_write
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

        async def run():
            nonlocal should_fail
            for cycle in range(20):
                # Phase 1: Timeout failure
                should_fail = True
                with self.assertRaises(asyncio.TimeoutError, msg=f"Cycle {cycle} expected TimeoutError"):
                    await client.connect(timeout=0.01)

                self.assertFalse(transport.is_connected)
                self.assertFalse(client.is_connected)
                self.assertEqual(len(client._pending_responses), 0)

                # Phase 2: Immediate successful reconnect
                should_fail = False
                ok = await client.connect(timeout=2.0)
                self.assertTrue(ok, f"Cycle {cycle} reconnect failed")
                self.assertTrue(client.is_connected)
                self.assertTrue(client.is_paired)

                # Phase 3: Clean disconnect
                await client.disconnect()
                self.assertFalse(transport.is_connected)
                self.assertFalse(client.is_connected)
                self.assertEqual(len(client._pending_responses), 0)

        asyncio.run(run())


class TestAdapterLifecycleTeardown(unittest.TestCase):
    """Stress tests for HomeAssistantBleAdapter disconnect lifecycle and error containment."""

    def test_adapter_async_disconnect_all_with_heterogeneous_clients(self) -> None:
        """Adapter manages 10 clients in different states; all cleanly disconnect."""
        adapter = HomeAssistantBleAdapter(local_key=TEST_LOCAL_KEY)
        clients = []

        for i in range(10):
            mac = f"DC:23:4F:00:00:{i:02X}"
            trans = StrictSlotMockTransport(mac=mac, local_key=TEST_LOCAL_KEY)
            dev = type("MockDev", (), {"address": mac})()
            client = adapter.async_get_ble_client(dev, local_key=TEST_LOCAL_KEY, transport=trans)
            clients.append((client, trans))

        async def run():
            # Connect even clients, leave odd clients disconnected
            for i, (client, trans) in enumerate(clients):
                if i % 2 == 0:
                    await client.connect(timeout=2.0)
                    self.assertTrue(client.is_connected)
                else:
                    self.assertFalse(client.is_connected)

            self.assertEqual(len(adapter._clients), 10)

            # Perform async_disconnect_all
            await adapter.async_disconnect_all()

            # Registry must be empty
            self.assertEqual(len(adapter._clients), 0)
            # All clients and transports must be disconnected
            for client, trans in clients:
                self.assertFalse(client.is_connected)
                self.assertFalse(trans.is_connected)

        asyncio.run(run())

    def test_adapter_async_disconnect_all_survives_client_exceptions(self) -> None:
        """One client raising an exception during disconnect does NOT abort teardown of others."""
        adapter = HomeAssistantBleAdapter(local_key=TEST_LOCAL_KEY)

        client1 = MagicMock()
        client1.disconnect = AsyncMock(side_effect=RuntimeError("Bleak radio catastrophic failure"))

        client2 = MagicMock()
        client2.disconnect = AsyncMock(return_value=None)

        adapter._clients["lock_1"] = client1
        adapter._clients["lock_2"] = client2

        async def run():
            # async_disconnect_all should catch/log exceptions and complete without raising
            await adapter.async_disconnect_all()
            self.assertEqual(len(adapter._clients), 0)
            client1.disconnect.assert_awaited_once()
            client2.disconnect.assert_awaited_once()

        asyncio.run(run())

    def test_adapter_concurrent_disconnect_all(self) -> None:
        """Concurrent calls to async_disconnect_all do not race or raise errors."""
        adapter = HomeAssistantBleAdapter(local_key=TEST_LOCAL_KEY)

        for i in range(5):
            mac = f"AA:BB:CC:DD:EE:{i:02X}"
            trans = MockBleGattTransport(mac=mac, local_key=TEST_LOCAL_KEY)
            dev = type("MockDev", (), {"address": mac})()
            adapter.async_get_ble_client(dev, local_key=TEST_LOCAL_KEY, transport=trans)

        async def run():
            # Concurrently trigger 10 disconnect calls
            tasks = [asyncio.create_task(adapter.async_disconnect_all()) for _ in range(10)]
            await asyncio.gather(*tasks)
            self.assertEqual(len(adapter._clients), 0)

        asyncio.run(run())

    def test_adapter_sync_disconnect_all_in_and_out_of_loop(self) -> None:
        """Synchronous disconnect_all safely executes in both sync threads and running loop tasks."""
        adapter = HomeAssistantBleAdapter(local_key=TEST_LOCAL_KEY)
        mac = "11:22:33:44:55:66"
        trans = MockBleGattTransport(mac=mac, local_key=TEST_LOCAL_KEY)
        dev = type("MockDev", (), {"address": mac})()
        client = adapter.async_get_ble_client(dev, local_key=TEST_LOCAL_KEY, transport=trans)

        # 1. From sync thread without loop
        async def connect_client():
            await client.connect(timeout=2.0)

        asyncio.run(connect_client())
        self.assertTrue(client.is_connected)

        adapter.disconnect_all()
        self.assertFalse(client.is_connected)
        self.assertEqual(len(adapter._clients), 0)

        # 2. From within running loop
        async def run_in_loop():
            client2 = adapter.async_get_ble_client(dev, local_key=TEST_LOCAL_KEY, transport=trans)
            await client2.connect(timeout=2.0)
            self.assertTrue(client2.is_connected)

            # Call sync disconnect_all while loop is running
            adapter.disconnect_all()
            # Yield to let scheduled task complete
            await asyncio.sleep(0.05)
            self.assertFalse(client2.is_connected)
            self.assertEqual(len(adapter._clients), 0)

        asyncio.run(run_in_loop())



class TestAdversarialCancellationAndRadioLockout(unittest.TestCase):
    """Adversarial stress-test verifying whether external task cancellation cleans up GATT slots.

    CRITICAL CHALLENGE:
    In Python 3.8+, asyncio.CancelledError inherits from BaseException, NOT Exception.
    BleGattClient.connect() uses:
        except Exception:
            await self._disconnect_locked()
            raise
    When an external caller cancels the connect() coroutine (via asyncio.wait_for,
    Home Assistant coordinator refresh timeout, or entity unload/shutdown),
    CancelledError bypasses except Exception:.
    Consequently, _disconnect_locked() is NOT called, leaving the GATT connection
    active, is_connected True, and the radio slot permanently occupied.
    Subsequent reconnection attempts then fail with GATT radio lockout / ConnectionSlotsExhausted.
    """

    def test_connect_cancellation_bypasses_cleanup_and_causes_radio_lockout(self) -> None:
        """Empirically demonstrates that external cancellation of connect() bypasses _disconnect_locked()."""
        transport = StrictSlotMockTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
        transport.write_payload = lambda payload: None  # hangs during handshake
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

        async def run():
            # Step 1: Launch connect task with a long timeout (simulating standard connect call)
            connect_task = asyncio.create_task(client.connect(timeout=10.0))
            await asyncio.sleep(0.02)  # Allow connect() to establish transport connection and wait on DEVICE_INFO

            # Transport is now connected
            self.assertTrue(transport.is_connected)
            self.assertTrue(client.is_connected)

            # Step 2: External caller cancels the connect task (e.g. HA timeout or user abort)
            connect_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await connect_task

            # EXPECTED CORRECT BEHAVIOR:
            # client.is_connected and transport.is_connected MUST both be False so radio slots are released!
            # ACTUAL OBSERVED DEFECT:
            # because connect() catches 'except Exception:', CancelledError bypasses cleanup!
            # Both client.is_connected and transport.is_connected remain True!
            is_leaked = client.is_connected and transport.is_connected

            if is_leaked:
                # Reconnection fails with RuntimeError: GATT radio lockout: connection slot already occupied!
                with self.assertRaises(RuntimeError) as ctx:
                    await client.connect(timeout=2.0)
                self.assertIn("GATT radio lockout", str(ctx.exception))

                self.fail(
                    "VULNERABILITY CONFIRMED: connect() failed to execute _disconnect_locked() upon "
                    "asyncio.CancelledError! The GATT connection slot remained open and leaked into subsequent "
                    "reconnection attempt causing GATT radio lockout."
                )

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()

