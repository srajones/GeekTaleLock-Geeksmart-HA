#!/usr/bin/env python3
"""Adversarial Stress Harness: Rapid Cancellation Bursts in BleGattClient.connect().

Empirically tests that rapid, concurrent, and jittered cancellations during connection
establishment NEVER leave open GATT slots, leaked client instances, or locked mutexes.
"""

from __future__ import annotations

import asyncio
import os
import random
import sys
import time
from unittest.mock import AsyncMock, MagicMock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from custom_components.geek_door.core.ble_gatt_client import (
    BleGattClient,
    HomeAssistantBleAdapter,
    MockBleGattTransport,
    TuyaBleCmd,
    TuyaBlePacketEngine,
)

TEST_MAC = "DC:23:4F:00:00:90"
TEST_LOCAL_KEY = "TU:ESBz-3TXkj-Bq"
TEST_UUID = "uuidfake1a2b3c01"
TEST_DEV_ID = "ebexamplelock001"


class StrictSlotMockTransport(MockBleGattTransport):
    """Enforces strictly 1 GATT connection slot. Raises RuntimeError if violated."""

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


async def stress_rapid_sequential_cancellation_burst(iterations: int = 50) -> None:
    """Fires 50 sequential connect attempts, each cancelled at jittered delay intervals."""
    print(f"[TEST 1] Running {iterations} rapid sequential cancellation bursts...")
    transport = StrictSlotMockTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
    # Slow down or drop frame writes to guarantee cancellation hits while connect is in flight
    transport.write_payload = lambda payload: None
    client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

    for i in range(iterations):
        # Jitter delay between 0.0005s and 0.015s to hit different phases of connect()
        delay = random.uniform(0.0005, 0.015)
        task = asyncio.create_task(client.connect(timeout=5.0))
        await asyncio.sleep(delay)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass

        # Invariant checks after EVERY iteration:
        assert not client.is_connected, f"Iteration {i}: client.is_connected was True after cancellation!"
        assert not transport.is_connected, f"Iteration {i}: transport.is_connected was True (GATT slot leak)!"
        assert not client._get_lock().locked(), f"Iteration {i}: client lock remained acquired after cancellation!"
        assert len(client._pending_responses) == 0, f"Iteration {i}: pending responses leaked: {client._pending_responses}"
        assert not client.is_paired, f"Iteration {i}: client._is_paired was True after cancellation!"

    # After 50 cancellations, restore normal transport write and verify clean connection succeeds
    orig_write = MockBleGattTransport.write_payload
    transport.write_payload = lambda payload: orig_write(transport, payload)

    ok = await client.connect(timeout=2.0)
    assert ok, "Clean connect failed after 50 rapid cancellation bursts!"
    assert client.is_connected, "client is not connected after clean connect!"
    assert client.is_paired, "client is not paired after clean connect!"
    await client.disconnect()
    assert not client.is_connected
    assert not transport.is_connected
    print(f"[TEST 1] PASSED ({iterations} iterations verified cleanly without slot leaks).")


async def stress_concurrent_cancellation_storm(task_count: int = 30) -> None:
    """Spawns 30 concurrent tasks attempting connect(), cancels them in a sudden burst."""
    print(f"[TEST 2] Running concurrent cancellation storm with {task_count} tasks...")
    transport = StrictSlotMockTransport(mac=TEST_MAC, local_key=TEST_LOCAL_KEY)
    transport.write_payload = lambda payload: None
    client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=transport)

    async def worker():
        try:
            await client.connect(timeout=10.0)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return exc

    tasks = [asyncio.create_task(worker()) for _ in range(task_count)]
    # Allow some tasks to queue up on the mutex lock
    await asyncio.sleep(0.03)

    # Burst cancel all tasks
    for t in tasks:
        t.cancel()

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for idx, r in enumerate(results):
        assert isinstance(r, asyncio.CancelledError), f"Task {idx} did not raise CancelledError: {r}"

    # Mutex and state invariant checks
    assert not client._get_lock().locked(), "Lock is held after concurrent cancellation storm!"
    assert not client.is_connected, "client.is_connected is True after cancellation storm!"
    assert not transport.is_connected, "transport.is_connected is True after cancellation storm!"
    assert len(client._pending_responses) == 0, f"Pending responses leaked: {client._pending_responses}"

    # Verify a subsequent normal connect works immediately
    orig_write = MockBleGattTransport.write_payload
    transport.write_payload = lambda payload: orig_write(transport, payload)
    ok = await client.connect(timeout=2.0)
    assert ok, "Clean connect failed after concurrent cancellation storm!"
    assert client.is_connected
    assert client.is_paired
    await client.disconnect()
    assert not client.is_connected
    assert not transport.is_connected
    print(f"[TEST 2] PASSED ({task_count} concurrent tasks cancelled without deadlock or slot lock).")


async def stress_bleak_client_cancellation_and_teardown() -> None:
    """Simulates real BleakClient with external cancellation during connect() and start_notify()."""
    print("[TEST 3] Running BleakClient mock cancellation stress...")
    mock_bleak = MagicMock()
    mock_bleak_client_inst = MagicMock()
    mock_bleak_client_inst.connect = AsyncMock(return_value=True)
    mock_bleak_client_inst.start_notify = AsyncMock(return_value=None)
    mock_bleak_client_inst.disconnect = AsyncMock(return_value=None)
    mock_bleak_client_inst.write_gatt_char = AsyncMock(return_value=None)
    mock_bleak.BleakClient = MagicMock(return_value=mock_bleak_client_inst)

    sys.modules["bleak"] = mock_bleak
    try:
        client = BleGattClient(mac=TEST_MAC, local_key=TEST_LOCAL_KEY, transport=None)

        # Trigger connect and cancel while waiting for DEVICE_INFO
        task = asyncio.create_task(client.connect(timeout=10.0))
        await asyncio.sleep(0.02)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass

        # Verify BleakClient.disconnect() was called
        mock_bleak_client_inst.disconnect.assert_awaited_once()
        assert client._bleak_client is None, f"_bleak_client was not reset to None: {client._bleak_client}"
        assert not client.is_connected, "client.is_connected is True!"
        assert not client.is_paired, "client.is_paired is True!"
        assert not client._get_lock().locked(), "Lock remained acquired!"
        assert len(client._pending_responses) == 0, "Pending responses leaked!"
    finally:
        sys.modules.pop("bleak", None)

    print("[TEST 3] PASSED (BleakClient disconnect awaited and instance released).")


async def stress_adapter_cancellation_barrage(client_count: int = 10) -> None:
    """Verifies HomeAssistantBleAdapter handles concurrent connects cancelled mid-stream."""
    print(f"[TEST 4] Running adapter cancellation barrage with {client_count} clients...")
    adapter = HomeAssistantBleAdapter(local_key=TEST_LOCAL_KEY)
    clients = []
    transports = []

    for i in range(client_count):
        mac = f"AA:BB:CC:DD:EE:{i:02X}"
        trans = StrictSlotMockTransport(mac=mac, local_key=TEST_LOCAL_KEY)
        trans.write_payload = lambda payload: None  # stall
        dev = type("MockDev", (), {"address": mac})()
        cli = adapter.async_get_ble_client(dev, local_key=TEST_LOCAL_KEY, transport=trans)
        clients.append(cli)
        transports.append(trans)

    tasks = [asyncio.create_task(cli.connect(timeout=10.0)) for cli in clients]
    await asyncio.sleep(0.02)

    # Cancel half of them, and call async_disconnect_all()
    for t in tasks[:5]:
        t.cancel()

    await adapter.async_disconnect_all()

    for t in tasks[5:]:
        t.cancel()

    await asyncio.gather(*tasks, return_exceptions=True)

    # All clients must be disconnected and adapter registry emptied
    assert len(adapter._clients) == 0, f"Adapter clients registry not empty: {len(adapter._clients)}"
    for idx, (cli, trans) in enumerate(zip(clients, transports)):
        assert not cli.is_connected, f"Client {idx} still connected!"
        assert not trans.is_connected, f"Transport {idx} still connected!"
        assert not cli._get_lock().locked(), f"Client {idx} lock held!"

    print(f"[TEST 4] PASSED (Adapter cleanly disarmed all {client_count} clients).")


async def main():
    start = time.time()
    await stress_rapid_sequential_cancellation_burst(50)
    await stress_concurrent_cancellation_storm(30)
    await stress_bleak_client_cancellation_and_teardown()
    await stress_adapter_cancellation_barrage(10)
    elapsed = time.time() - start
    print(f"\nALL EMPIRICAL CANCELLATION BURST STRESS TESTS PASSED in {elapsed:.3f}s!")


if __name__ == "__main__":
    asyncio.run(main())
