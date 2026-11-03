#!/usr/bin/env python3
"""
Empirical Adversarial Test Suite for Milestone 2: Fallback & Concurrency Stress Testing (Challenger 2).
File: tests/test_challenger_ha_m2_2.py

Tasks Verified:
1. Fallback Invariants:
   - prefer_direct_ble=True: attempts BLE first, falls back to Tuya Cloud on BLE timeout/failure,
     and stamps fallbackFromBle=True.
   - prefer_direct_ble=False: attempts Tuya Cloud first, falls back to BLE on cloud failure/timeout,
     and stamps fallbackFromGateway=True.
   - All 4 Topologies:
     a) BLE Only (no gateway / smart plug)
     b) Smart Plug Only (no BLE client / no BLE capability)
     c) Both (BLE + Smart Plug gateway dual-stack)
     d) Neither (no BLE client, no Smart Plug gateway)
   - Action coverage across fallback: unlock, lock, keep_unlocked, auto_lock_on.

2. Cross-Thread Event Loop Safety:
   - Call _safe_run_async from 10 concurrent worker threads when an event loop is running on the main thread.
   - High-throughput stress test: 200 concurrent invocations across 10 threads.
   - Verify zero RuntimeError: Event loop is closed, zero deadlocks, zero lost results.
   - Exception propagation and timeout handling across worker threads.
   - Safe execution when called directly from the main loop thread itself.

3. Token Expiry Propagation:
   - Verify TuyaApiError(USER_SESSION_INVALID) in discover(force_refresh=True) is not swallowed
     and propagates to coordinator.
   - Verify session error propagation across all expired codes: TOKEN_EXPIRED, USER_SESSION_LOSS, etc.
   - Verify offline cache behavior when force_refresh=False vs force_refresh=True.
   - Verify coordinator catches propagated error and raises ConfigEntryAuthFailed upon permanent failure.

Safety:
- Enforce mock transports / dry_run. Zero physical hardware actuation.
- Zero background servers.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import copy
import os
import sys
import tempfile
import threading
import time
import unittest
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import AsyncMock, MagicMock, patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from custom_components.geek_door.const import (
    CONF_BLE_DIRECT_FALLBACK,
    CONF_PREFER_DIRECT_BLE,
    DEFAULT_PREFER_DIRECT_BLE,
)
from custom_components.geek_door.coordinator import (
    ConfigEntryAuthFailed,
    GeekDoorDataUpdateCoordinator,
    UpdateFailed,
)
from custom_components.geek_door.core.exceptions import (
    GeekSmartAuthError,
    GeekSmartControlError,
    TuyaApiError,
)
from custom_components.geek_door.core.lock_engine import (
    GatewayDevice,
    LockDevice,
    LockEngine,
    LockStateSnapshot,
)


class TestMilestone2FallbackInvariants(unittest.TestCase):
    """Stress-tests the bi-directional fallback invariants and stamps across all actions."""

    def setUp(self) -> None:
        self.temp_cache = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.temp_cache.close()

        self.mock_ble = MagicMock()
        self.mock_ble.mac = "DC:23:4F:00:00:90"
        self.mock_ble.unlock = AsyncMock(return_value={"success": True, "action": "ble_unlock"})
        self.mock_ble.lock = AsyncMock(return_value={"success": True, "action": "ble_lock"})
        self.mock_ble.keep_unlocked = AsyncMock(return_value={"success": True, "action": "ble_keep_unlocked"})
        self.mock_ble.set_auto_lock = AsyncMock(return_value={"success": True, "action": "ble_auto_lock"})

        self.mock_tuya = MagicMock()
        self.mock_tuya.publish_dp.return_value = {
            "success": True,
            "action": "tuya_publish",
            "dps": {"71": "AQ=="},
        }
        self.mock_tuya.set_auto_lock.return_value = {
            "success": True,
            "action": "tuya_set_auto_lock",
            "dps": {"33": False},
        }

        self.dual_lock = LockDevice(
            dev_id="lock_dual_stack",
            name="Dual Stack Lock",
            client_equipment_id=101,
            mac="DC:23:4F:00:00:90",
            parent_gateway_id="gw_plug_01",
            is_online=True,
        )
        self.gateway = GatewayDevice(
            dev_id="gw_plug_01",
            name="Smart Plug Gateway",
            client_equipment_id=201,
            is_online=True,
        )

    def tearDown(self) -> None:
        if os.path.exists(self.temp_cache.name):
            os.remove(self.temp_cache.name)

    # ------------------------------------------------------------------------
    # 1. prefer_direct_ble=True: BLE Primary, Fallback to Tuya Cloud
    # ------------------------------------------------------------------------
    def test_prefer_ble_true_attempts_ble_first_and_skips_cloud_on_success(self) -> None:
        """prefer_direct_ble=True attempts BLE first; on BLE success, skips Tuya Cloud and stamps no fallbackFromBle."""
        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=False,
            prefer_direct_ble=True,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[self.dual_lock.dev_id] = self.dual_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        res = engine.unlock(self.dual_lock.dev_id)

        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "direct_ble")
        self.assertFalse(res.get("fallbackFromBle", False))
        self.assertFalse(res.get("fallbackFromGateway", False))
        self.mock_ble.unlock.assert_called_once()
        self.mock_tuya.publish_dp.assert_not_called()

    def test_prefer_ble_true_falls_back_to_cloud_on_ble_timeout_and_stamps_fallbackFromBle(self) -> None:
        """prefer_direct_ble=True falls back to Tuya Cloud on BLE timeout and stamps fallbackFromBle=True."""
        self.mock_ble.unlock = AsyncMock(side_effect=asyncio.TimeoutError("BLE GATT connection timed out after 10s"))

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=False,
            prefer_direct_ble=True,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[self.dual_lock.dev_id] = self.dual_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        res = engine.unlock(self.dual_lock.dev_id)

        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "tuya_cloud")
        self.assertTrue(res.get("fallbackFromBle", False))
        self.assertFalse(res.get("fallbackFromGateway", False))
        self.mock_ble.unlock.assert_called_once()
        self.mock_tuya.publish_dp.assert_called_once()

    def test_prefer_ble_true_falls_back_to_cloud_on_ble_connection_error(self) -> None:
        """prefer_direct_ble=True falls back to Tuya Cloud on BLE ConnectionError / DeviceNotFound."""
        self.mock_ble.lock = AsyncMock(side_effect=ConnectionError("Bluetooth device not found or out of range"))

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=False,
            prefer_direct_ble=True,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[self.dual_lock.dev_id] = self.dual_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        res = engine.lock(self.dual_lock.dev_id)

        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "tuya_cloud")
        self.assertTrue(res.get("fallbackFromBle", False))
        self.mock_ble.lock.assert_called_once()
        self.mock_tuya.publish_dp.assert_called_once()

    # ------------------------------------------------------------------------
    # 2. prefer_direct_ble=False: Tuya Cloud Primary, Fallback to BLE
    # ------------------------------------------------------------------------
    def test_prefer_ble_false_attempts_cloud_first_and_skips_ble_on_success(self) -> None:
        """prefer_direct_ble=False attempts Tuya Cloud first; on success, skips BLE and stamps no fallbackFromGateway."""
        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=False,
            prefer_direct_ble=False,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[self.dual_lock.dev_id] = self.dual_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        res = engine.unlock(self.dual_lock.dev_id)

        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "tuya_cloud")
        self.assertFalse(res.get("fallbackFromGateway", False))
        self.assertFalse(res.get("fallbackFromBle", False))
        self.mock_tuya.publish_dp.assert_called_once()
        self.mock_ble.unlock.assert_not_called()

    def test_prefer_ble_false_falls_back_to_ble_on_cloud_timeout_and_stamps_fallbackFromGateway(self) -> None:
        """prefer_direct_ble=False falls back to BLE on Tuya Cloud timeout and stamps fallbackFromGateway=True."""
        self.mock_tuya.publish_dp.side_effect = TimeoutError("Tuya API request timed out after 10s")

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=False,
            prefer_direct_ble=False,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[self.dual_lock.dev_id] = self.dual_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        res = engine.unlock(self.dual_lock.dev_id)

        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "direct_ble")
        self.assertTrue(res.get("fallbackFromGateway", False))
        self.assertFalse(res.get("fallbackFromBle", False))
        self.mock_tuya.publish_dp.assert_called_once()
        self.mock_ble.unlock.assert_called_once()

    def test_prefer_ble_false_falls_back_to_ble_on_cloud_gateway_504_offline(self) -> None:
        """prefer_direct_ble=False falls back to BLE when Smart Plug Gateway is offline (HTTP 504 / 11001)."""
        self.mock_tuya.publish_dp.side_effect = Exception("504 Gateway Timeout: Smart Plug is offline")

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=False,
            prefer_direct_ble=False,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[self.dual_lock.dev_id] = self.dual_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        res = engine.lock(self.dual_lock.dev_id)

        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "direct_ble")
        self.assertTrue(res.get("fallbackFromGateway", False))
        self.mock_tuya.publish_dp.assert_called_once()
        self.mock_ble.lock.assert_called_once()

    # ------------------------------------------------------------------------
    # 3. Action Invariance: Fallback across keep_unlocked and auto_lock_on
    # ------------------------------------------------------------------------
    def test_keep_unlocked_fallback_from_ble_to_cloud(self) -> None:
        """keep_unlocked falls back from BLE to Tuya Cloud and sets auto-lock override."""
        self.mock_ble.keep_unlocked = AsyncMock(side_effect=asyncio.TimeoutError("BLE timeout"))

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=False,
            prefer_direct_ble=True,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[self.dual_lock.dev_id] = self.dual_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        res = engine.keep_unlocked(self.dual_lock.dev_id)

        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "tuya_cloud")
        self.assertTrue(res.get("fallbackFromBle", False))
        self.assertFalse(self.dual_lock.state.auto_lock_enabled)

    def test_auto_lock_on_fallback_from_cloud_to_ble(self) -> None:
        """auto_lock_on falls back from Tuya Cloud to BLE and sets auto-lock seconds."""
        self.mock_tuya.set_auto_lock.side_effect = Exception("Cloud network error")

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=False,
            prefer_direct_ble=False,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[self.dual_lock.dev_id] = self.dual_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        res = engine.auto_lock_on(self.dual_lock.dev_id, seconds=15)

        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "direct_ble")
        self.assertTrue(res.get("fallbackFromGateway", False))
        self.assertTrue(self.dual_lock.state.auto_lock_enabled)
        self.assertEqual(self.dual_lock.state.auto_lock_seconds, 15)


class TestMilestone2FourTopologies(unittest.TestCase):
    """Stress-tests the 4 topologies: BLE only, Smart Plug only, Both, Neither."""

    def setUp(self) -> None:
        self.temp_cache = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.temp_cache.close()

        self.mock_ble = MagicMock()
        self.mock_ble.mac = "DC:23:4F:00:00:90"
        self.mock_ble.unlock = AsyncMock(return_value={"success": True, "action": "ble_unlock"})
        self.mock_ble.lock = AsyncMock(return_value={"success": True, "action": "ble_lock"})

        self.mock_tuya = MagicMock()
        self.mock_tuya.publish_dp.return_value = {
            "success": True,
            "action": "tuya_unlock",
            "dps": {"71": "AQ=="},
        }

    def tearDown(self) -> None:
        if os.path.exists(self.temp_cache.name):
            os.remove(self.temp_cache.name)

    # ------------------------------------------------------------------------
    # Topology 1: BLE Only (No Gateway / Smart Plug)
    # ------------------------------------------------------------------------
    def test_topology_ble_only_success(self) -> None:
        """Topology 1 (BLE Only): operates cleanly over Direct BLE without touching Cloud."""
        lock = LockDevice(
            dev_id="lock_ble_only",
            name="BLE Only Lock",
            client_equipment_id=102,
            mac="DC:23:4F:00:00:90",
            parent_gateway_id=None,
            is_online=False,  # Cloud offline
        )
        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=False,
            prefer_direct_ble=True,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[lock.dev_id] = lock

        res = engine.unlock(lock.dev_id)
        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "direct_ble")
        self.mock_ble.unlock.assert_called_once()
        self.mock_tuya.publish_dp.assert_not_called()

    def test_topology_ble_only_failure_raises_control_error(self) -> None:
        """Topology 1 (BLE Only): when BLE fails and no cloud gateway exists, raises GeekSmartControlError."""
        self.mock_ble.unlock = AsyncMock(side_effect=Exception("BLE radio down"))
        self.mock_tuya.publish_dp.side_effect = Exception("No cloud gateway for lock")

        lock = LockDevice(
            dev_id="lock_ble_only",
            name="BLE Only Lock",
            client_equipment_id=102,
            mac="DC:23:4F:00:00:90",
            parent_gateway_id=None,
            is_online=False,
        )
        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=False,
            prefer_direct_ble=True,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[lock.dev_id] = lock

        with self.assertRaises(GeekSmartControlError) as ctx:
            engine.unlock(lock.dev_id)
        self.assertIn("All transports failed", str(ctx.exception))
        self.assertIn("BLE radio down", str(ctx.exception))

    # ------------------------------------------------------------------------
    # Topology 2: Smart Plug Only (No BLE Client / No BT Adapter)
    # ------------------------------------------------------------------------
    def test_topology_smart_plug_only_success(self) -> None:
        """Topology 2 (Smart Plug Only): operates over Tuya Cloud even with prefer_direct_ble=True."""
        lock = LockDevice(
            dev_id="lock_plug_only",
            name="Plug Only Lock",
            client_equipment_id=103,
            mac=None,  # No BLE MAC
            parent_gateway_id="gw_plug_02",
            is_online=True,
        )
        gateway = GatewayDevice(
            dev_id="gw_plug_02",
            name="Smart Plug Gateway",
            client_equipment_id=202,
            is_online=True,
        )
        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=None,  # No BLE client
            dry_run=False,
            prefer_direct_ble=True,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[lock.dev_id] = lock
        engine._gateways[gateway.dev_id] = gateway

        res = engine.unlock(lock.dev_id)
        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "tuya_cloud")
        self.mock_tuya.publish_dp.assert_called_once()

    def test_topology_smart_plug_only_failure_raises_control_error(self) -> None:
        """Topology 2 (Smart Plug Only): when Cloud fails, cleanly raises GeekSmartControlError."""
        self.mock_tuya.publish_dp.side_effect = Exception("Tuya API 500 internal error")
        lock = LockDevice(
            dev_id="lock_plug_only",
            name="Plug Only Lock",
            client_equipment_id=103,
            mac=None,
            parent_gateway_id="gw_plug_02",
            is_online=True,
        )
        gateway = GatewayDevice(
            dev_id="gw_plug_02",
            name="Smart Plug Gateway",
            client_equipment_id=202,
            is_online=True,
        )
        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=None,
            dry_run=False,
            prefer_direct_ble=True,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[lock.dev_id] = lock
        engine._gateways[gateway.dev_id] = gateway

        with self.assertRaises(GeekSmartControlError) as ctx:
            engine.unlock(lock.dev_id)
        self.assertIn("All transports failed", str(ctx.exception))
        self.assertEqual(ctx.exception.code, 500)

    # ------------------------------------------------------------------------
    # Topology 3: Both (Dual Stack)
    # ------------------------------------------------------------------------
    def test_topology_both_dual_stack_snapshot_capabilities(self) -> None:
        """Topology 3 (Dual Stack): snapshot correctly reports ble_fallback_available and online status."""
        dual_lock = LockDevice(
            dev_id="lock_dual",
            name="Dual Lock",
            client_equipment_id=104,
            mac="DC:23:4F:00:00:90",
            parent_gateway_id="gw_plug_03",
            is_online=True,
        )
        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=True,
            prefer_direct_ble=True,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[dual_lock.dev_id] = dual_lock

        snapshots = engine.get_all_lock_snapshots()
        self.assertEqual(len(snapshots), 1)
        self.assertTrue(snapshots[0]["ble_fallback_available"])

    # ------------------------------------------------------------------------
    # Topology 4: Neither (No BLE, No Gateway)
    # ------------------------------------------------------------------------
    def test_topology_neither_ble_nor_gateway_fails_cleanly(self) -> None:
        """Topology 4 (Neither): lock has no BLE client and no online gateway; raises GeekSmartControlError cleanly."""
        orphan_lock = LockDevice(
            dev_id="lock_orphan",
            name="Orphan Lock",
            client_equipment_id=105,
            mac=None,
            parent_gateway_id=None,
            is_online=False,
        )
        mock_tuya_fail = MagicMock()
        mock_tuya_fail.publish_dp.side_effect = Exception("No gateway configured")

        engine = LockEngine(
            tuya_client=mock_tuya_fail,
            ble_client=None,
            dry_run=False,
            prefer_direct_ble=True,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[orphan_lock.dev_id] = orphan_lock

        with self.assertRaises(GeekSmartControlError) as ctx:
            engine.unlock(orphan_lock.dev_id)
        self.assertIn("All transports failed", str(ctx.exception))
        self.assertEqual(ctx.exception.code, 500)


class TestMilestone2CrossThreadLoopSafety(unittest.TestCase):
    """Stress-tests _safe_run_async across concurrent worker threads with an active event loop."""

    def test_ten_concurrent_worker_threads_burst_stress(self) -> None:
        """10 concurrent threads each calling _safe_run_async 20 times (200 calls) on running loop.

        Verifies:
        - Zero RuntimeError: Event loop is closed
        - Zero deadlocks
        - 100% correct return values across all threads
        """
        main_loop = asyncio.new_event_loop()
        thread_ready = threading.Event()

        def run_main_loop():
            asyncio.set_event_loop(main_loop)
            thread_ready.set()
            main_loop.run_forever()

        loop_thread = threading.Thread(target=run_main_loop, daemon=True)
        loop_thread.start()
        thread_ready.wait()

        engine = LockEngine(loop=main_loop, dry_run=False)

        total_threads = 10
        calls_per_thread = 20
        results: List[Tuple[int, int, str]] = []
        errors: List[Exception] = []
        results_lock = threading.Lock()

        async def async_worker_task(thread_id: int, call_id: int) -> str:
            # Yield control to event loop to simulate realistic async I/O
            await asyncio.sleep(0.005)
            # Verify we are running on the target loop
            current_running = asyncio.get_running_loop()
            if current_running is not main_loop:
                raise RuntimeError(f"Wrong loop executed: {current_running} vs {main_loop}")
            return f"result_{thread_id}_{call_id}"

        def worker_target(thread_id: int):
            for call_id in range(calls_per_thread):
                try:
                    res = engine._safe_run_async(async_worker_task(thread_id, call_id), timeout=10.0)
                    with results_lock:
                        results.append((thread_id, call_id, res))
                except Exception as exc:
                    with results_lock:
                        errors.append(exc)

        threads = [
            threading.Thread(target=worker_target, args=(t_id,), daemon=True)
            for t_id in range(total_threads)
        ]

        start_time = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15.0)
        elapsed = time.monotonic() - start_time

        # Cleanup loop safely
        main_loop.call_soon_threadsafe(main_loop.stop)
        loop_thread.join(timeout=3.0)
        main_loop.close()

        # Assertions
        self.assertEqual(len(errors), 0, f"Encountered {len(errors)} thread errors: {errors[:5]}")
        self.assertEqual(
            len(results),
            total_threads * calls_per_thread,
            f"Expected {total_threads * calls_per_thread} results, got {len(results)}",
        )
        self.assertLess(elapsed, 15.0, f"Burst stress test took {elapsed:.2f}s (exceeded 15s)")

        # Verify all return strings match exactly
        for thread_id, call_id, res in results:
            self.assertEqual(res, f"result_{thread_id}_{call_id}")

    def test_concurrent_exception_propagation_and_cancellation(self) -> None:
        """Worker threads invoking failing coroutines receive the exact exception cleanly."""
        main_loop = asyncio.new_event_loop()
        thread_ready = threading.Event()

        def run_main_loop():
            asyncio.set_event_loop(main_loop)
            thread_ready.set()
            main_loop.run_forever()

        loop_thread = threading.Thread(target=run_main_loop, daemon=True)
        loop_thread.start()
        thread_ready.wait()

        engine = LockEngine(loop=main_loop, dry_run=False)

        async def failing_coro(val: int):
            await asyncio.sleep(0.002)
            if val % 2 == 0:
                raise ValueError(f"Even value error: {val}")
            raise KeyError(f"Odd value error: {val}")

        caught_exceptions: List[Exception] = []
        threads_lock = threading.Lock()

        def worker(val: int):
            try:
                engine._safe_run_async(failing_coro(val), timeout=5.0)
            except Exception as exc:
                with threads_lock:
                    caught_exceptions.append(exc)

        threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        main_loop.call_soon_threadsafe(main_loop.stop)
        loop_thread.join(timeout=2.0)
        main_loop.close()

        self.assertEqual(len(caught_exceptions), 10)
        value_errors = [e for e in caught_exceptions if isinstance(e, ValueError)]
        key_errors = [e for e in caught_exceptions if isinstance(e, KeyError)]
        self.assertEqual(len(value_errors), 5)
        self.assertEqual(len(key_errors), 5)

    def test_safe_run_async_called_from_main_loop_thread_itself(self) -> None:
        """Calling _safe_run_async directly on the thread running the target event loop does not deadlock."""
        main_loop = asyncio.new_event_loop()
        engine = LockEngine(loop=main_loop, dry_run=False)

        async def sample_coro():
            await asyncio.sleep(0.001)
            return "from_same_loop_thread"

        result_holder: List[str] = []
        error_holder: List[Exception] = []

        async def orchestrator_coro():
            try:
                # Here current_loop IS target_loop
                res = engine._safe_run_async(sample_coro(), timeout=5.0)
                result_holder.append(res)
            except Exception as exc:
                error_holder.append(exc)

        main_loop.run_until_complete(orchestrator_coro())
        main_loop.close()

        self.assertEqual(len(error_holder), 0, f"Error: {error_holder}")
        self.assertEqual(result_holder, ["from_same_loop_thread"])

    def test_safe_run_async_no_target_loop_and_no_running_loop(self) -> None:
        """When no event loop exists anywhere, cleanly executes via asyncio.run()."""
        engine = LockEngine(loop=None, dry_run=False)

        async def stand_alone_coro():
            await asyncio.sleep(0.001)
            return "stand_alone_ok"

        res = engine._safe_run_async(stand_alone_coro(), timeout=5.0)
        self.assertEqual(res, "stand_alone_ok")

    def test_safe_run_async_timeout_raises_timeout_error_and_cancels(self) -> None:
        """When a coroutine exceeds timeout in _safe_run_async, raises concurrent.futures.TimeoutError."""
        main_loop = asyncio.new_event_loop()
        thread_ready = threading.Event()

        def run_main_loop():
            asyncio.set_event_loop(main_loop)
            thread_ready.set()
            main_loop.run_forever()

        loop_thread = threading.Thread(target=run_main_loop, daemon=True)
        loop_thread.start()
        thread_ready.wait()

        engine = LockEngine(loop=main_loop, dry_run=False)

        async def slow_coroutine():
            await asyncio.sleep(5.0)
            return "never_reached"

        try:
            with self.assertRaises(concurrent.futures.TimeoutError):
                engine._safe_run_async(slow_coroutine(), timeout=0.05)
        finally:
            def cancel_all():
                for task in asyncio.all_tasks(main_loop):
                    task.cancel()
                main_loop.call_soon(main_loop.stop)
            main_loop.call_soon_threadsafe(cancel_all)
            loop_thread.join(timeout=2.0)
            main_loop.close()


class TestMilestone2TokenExpiryPropagation(unittest.TestCase):
    """Stress-tests TuyaApiError(USER_SESSION_INVALID) propagation and coordinator healing."""

    def setUp(self) -> None:
        self.temp_cache = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.temp_cache.close()
        self.mock_tuya = MagicMock()

    def tearDown(self) -> None:
        if os.path.exists(self.temp_cache.name):
            os.remove(self.temp_cache.name)

    def test_discover_force_refresh_true_propagates_user_session_invalid_with_cache(self) -> None:
        """With force_refresh=True, TuyaApiError(USER_SESSION_INVALID) is raised even when cache exists."""
        self.mock_tuya.get_home_device_list.side_effect = TuyaApiError(
            error_code="USER_SESSION_INVALID",
            error_msg="Tuya user session token has expired",
        )

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            dry_run=False,
            use_sample_devices=False,
            sample_mode=False,
            session_cache_path=self.temp_cache.name,
        )
        # Seed cache with merge=False
        engine.session_mgr.save({
            "sid": "old_sid",
            "devices": [{"devId": "dev_001", "name": "Cached Lock", "category": "jtmspro"}],
        }, merge=False)

        with self.assertRaises(TuyaApiError) as ctx:
            engine.discover(force_refresh=True, skip_network=False)

        self.assertEqual(ctx.exception.error_code, "USER_SESSION_INVALID")
        self.assertIn("user session token has expired", str(ctx.exception))

    def test_discover_force_refresh_true_propagates_token_expired(self) -> None:
        """With force_refresh=True, TOKEN_EXPIRED is propagated."""
        self.mock_tuya.get_home_device_list.side_effect = TuyaApiError(
            error_code="TOKEN_EXPIRED",
            error_msg="Access token expired",
        )

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            dry_run=False,
            use_sample_devices=False,
            sample_mode=False,
            session_cache_path=self.temp_cache.name,
        )

        with self.assertRaises(TuyaApiError) as ctx:
            engine.discover(force_refresh=True, skip_network=False)

        self.assertEqual(ctx.exception.error_code, "TOKEN_EXPIRED")

    def test_discover_force_refresh_false_with_cache_falls_back_gracefully(self) -> None:
        """With force_refresh=False and valid cache, TuyaApiError is caught and cache is returned."""
        self.mock_tuya.get_home_device_list.side_effect = TuyaApiError(
            error_code="USER_SESSION_INVALID",
            error_msg="Session expired",
        )

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            dry_run=False,
            use_sample_devices=False,
            sample_mode=False,
            session_cache_path=self.temp_cache.name,
        )
        engine.session_mgr.save({
            "sid": "old_sid",
            "devices": [{"devId": "cached_lock_1", "name": "Cached Lock 1", "productId": "prod1", "category": "jtmspro"}],
        }, merge=False)

        res = engine.discover(force_refresh=False, skip_network=False)
        lock_ids = [l["devId"] for l in res.get("locks", [])]
        self.assertIn("cached_lock_1", lock_ids)

    def test_discover_force_refresh_false_without_cache_propagates_error(self) -> None:
        """With force_refresh=False but NO cached devices, TuyaApiError is raised (no fake fallback)."""
        self.mock_tuya.get_home_device_list.side_effect = TuyaApiError(
            error_code="USER_SESSION_INVALID",
            error_msg="Session invalid",
        )

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            dry_run=False,
            use_sample_devices=False,
            sample_mode=False,
            session_cache_path=self.temp_cache.name,
        )
        if os.path.exists(self.temp_cache.name):
            os.remove(self.temp_cache.name)

        with self.assertRaises(TuyaApiError):
            engine.discover(force_refresh=False, skip_network=False)

    def test_coordinator_direct_cloud_update_raises_config_entry_auth_failed_on_fatal_heal(self) -> None:
        """When discover raises TuyaApiError and heal fails with bad credentials, coordinator raises ConfigEntryAuthFailed."""
        mock_entry = MagicMock()
        mock_entry.data = {"username": "user@example.com", "password": "wrong_password"}
        mock_entry.options = {CONF_PREFER_DIRECT_BLE: True}
        mock_entry.title = "Front Door Lock"

        mock_hass = MagicMock()
        mock_hass.loop = asyncio.new_event_loop()
        mock_hass.config.path.return_value = self.temp_cache.name

        # Mock async_add_executor_job to simulate engine.get_all_lock_snapshots raising USER_SESSION_INVALID
        async def fake_executor_job(func, *args, **kwargs):
            raise TuyaApiError(error_code="USER_SESSION_INVALID", error_msg="Session expired")

        mock_hass.async_add_executor_job = fake_executor_job

        try:
            coordinator = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)

            # Mock async_try_heal_session to fail with USER_PASSWD_WRONG
            async def failing_heal():
                coordinator._last_heal_error = TuyaApiError(
                    error_code="USER_PASSWD_WRONG",
                    error_msg="Incorrect account or password",
                )
                return None

            coordinator.async_try_heal_session = failing_heal

            async def run_test():
                with self.assertRaises(ConfigEntryAuthFailed) as ctx:
                    await coordinator._async_update_direct_cloud()
                self.assertIn("Authentication failed permanently", str(ctx.exception))
                self.assertIn("USER_PASSWD_WRONG", str(ctx.exception))

            mock_hass.loop.run_until_complete(run_test())
        finally:
            mock_hass.loop.close()


if __name__ == "__main__":
    unittest.main()
