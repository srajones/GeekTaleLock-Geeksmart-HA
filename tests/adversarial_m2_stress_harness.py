#!/usr/bin/env python3
"""
Adversarial Stress Test Harness for Milestone 2 Iteration 2
File: tests/adversarial_m2_stress_harness.py

Verifies:
1. Actuation Cancellation Invariants:
   - Primary BLE actuation cancellation during _dispatch_actuation() re-raises CancelledError
     and strictly DOES NOT fall back to Tuya Cloud or publish any gateway DP.
   - Fallback BLE actuation cancellation (prefer_direct_ble=False) re-raises CancelledError.
   - All actions tested: unlock, lock, keep_unlocked, auto_lock_on.
   - Concurrently cancelled actuations verify zero state leakage and zero mock Tuya publish calls.

2. _safe_run_async() Timeout Handling:
   - Timeout on ThreadPoolExecutor branch (same loop or active loop) aborts promptly without blocking
     the calling thread (wait=False verification).
   - Timeout on cross-thread asyncio.run_coroutine_threadsafe branch aborts promptly and cancels future.
   - High concurrency stress: 50 concurrent threads timing out simultaneously finish in < 1.0s.

Safety: Mock transports only, dry_run=False with mock clients, zero background processes.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import sys
import tempfile
import threading
import time
import unittest
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from custom_components.geek_door.core.lock_engine import (
    GatewayDevice,
    LockDevice,
    LockEngine,
    LockStateSnapshot,
)


class TestAdversarialActuationCancellation(unittest.TestCase):
    """Stress tests actuation cancellation handling and fallback invariants."""

    def setUp(self) -> None:
        self.temp_cache = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.temp_cache.close()

        self.mock_ble = MagicMock()
        self.mock_ble.mac = "DC:23:4F:00:00:90"
        self.mock_tuya = MagicMock()
        self.mock_gs = MagicMock()

        self.dual_lock = LockDevice(
            dev_id="lock_adversarial_cancel",
            name="Adversarial Test Lock",
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

    def test_cancel_ble_unlock_raises_and_never_falls_back_to_tuya(self) -> None:
        """When BLE unlock raises asyncio.CancelledError, it must re-raise and NOT call Tuya Cloud."""
        self.dual_lock.state.state_label = "LOCKED"
        self.dual_lock.state.is_locked = True
        self.mock_ble.unlock = AsyncMock(side_effect=asyncio.CancelledError("User cancelled unlock"))

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            gs_client=self.mock_gs,
            dry_run=False,
            prefer_direct_ble=True,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[self.dual_lock.dev_id] = self.dual_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        with self.assertRaises(asyncio.CancelledError):
            engine.unlock(self.dual_lock.dev_id)

        self.mock_ble.unlock.assert_called_once()
        self.mock_tuya.publish_dp.assert_not_called()
        self.mock_gs.unlock_door.assert_not_called()
        # Verify no state override was applied; lock remains LOCKED
        self.assertEqual(self.dual_lock.state.state_label, "LOCKED")
        self.assertTrue(self.dual_lock.state.is_locked)

    def test_cancel_ble_lock_raises_and_never_falls_back_to_tuya(self) -> None:
        """When BLE lock raises asyncio.CancelledError, it must re-raise and NOT call Tuya Cloud."""
        self.dual_lock.state.state_label = "UNLOCKED"
        self.dual_lock.state.is_locked = False
        self.mock_ble.lock = AsyncMock(side_effect=asyncio.CancelledError("Task cancelled"))

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            gs_client=self.mock_gs,
            dry_run=False,
            prefer_direct_ble=True,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[self.dual_lock.dev_id] = self.dual_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        with self.assertRaises(asyncio.CancelledError):
            engine.lock(self.dual_lock.dev_id)

        self.mock_ble.lock.assert_called_once()
        self.mock_tuya.publish_dp.assert_not_called()
        self.mock_gs.lock_door.assert_not_called()
        # Verify no state override was applied; lock remains UNLOCKED
        self.assertEqual(self.dual_lock.state.state_label, "UNLOCKED")
        self.assertFalse(self.dual_lock.state.is_locked)

    def test_cancel_ble_keep_unlocked_raises_and_never_falls_back_to_tuya(self) -> None:
        """When BLE keep_unlocked raises concurrent.futures.CancelledError, it re-raises and skips Tuya."""
        self.mock_ble.keep_unlocked = AsyncMock(side_effect=concurrent.futures.CancelledError("Future cancelled"))

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            gs_client=self.mock_gs,
            dry_run=False,
            prefer_direct_ble=True,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[self.dual_lock.dev_id] = self.dual_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        with self.assertRaises(concurrent.futures.CancelledError):
            engine.keep_unlocked(self.dual_lock.dev_id)

        self.mock_ble.keep_unlocked.assert_called_once()
        self.mock_tuya.set_auto_lock.assert_not_called()
        self.mock_tuya.publish_dp.assert_not_called()

    def test_cancel_ble_auto_lock_on_raises_and_never_falls_back_to_tuya(self) -> None:
        """When BLE set_auto_lock raises asyncio.CancelledError, it re-raises and skips Tuya."""
        self.mock_ble.set_auto_lock = AsyncMock(side_effect=asyncio.CancelledError("Auto lock cancelled"))

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            gs_client=self.mock_gs,
            dry_run=False,
            prefer_direct_ble=True,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[self.dual_lock.dev_id] = self.dual_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        with self.assertRaises(asyncio.CancelledError):
            engine.auto_lock_on(self.dual_lock.dev_id, seconds=10)

        self.mock_ble.set_auto_lock.assert_called_once()
        self.mock_tuya.set_auto_lock.assert_not_called()
        self.mock_tuya.publish_dp.assert_not_called()

    def test_cancel_on_fallback_ble_path_when_cloud_fails_re_raises(self) -> None:
        """prefer_direct_ble=False: Cloud fails, and fallback BLE raises CancelledError -> re-raises without loop."""
        self.mock_tuya.publish_dp.side_effect = RuntimeError("Cloud gateway unreachable")
        self.mock_gs.unlock_door.side_effect = RuntimeError("GeekSmart cloud error")
        self.mock_ble.unlock = AsyncMock(side_effect=asyncio.CancelledError("BLE fallback cancelled"))

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            gs_client=self.mock_gs,
            dry_run=False,
            prefer_direct_ble=False,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[self.dual_lock.dev_id] = self.dual_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        with self.assertRaises(asyncio.CancelledError):
            engine.unlock(self.dual_lock.dev_id)

        self.mock_ble.unlock.assert_called_once()
        # Ensure Tuya publish_dp was called once (the initial attempt), not twice
        self.assertEqual(self.mock_tuya.publish_dp.call_count, 1)

    def test_cross_thread_future_cancellation_during_dispatch_actuation(self) -> None:
        """Adversarial cross-thread cancellation while _dispatch_actuation is executing in worker thread."""
        target_loop = asyncio.new_event_loop()
        thread_ready = threading.Event()

        def run_target_loop():
            asyncio.set_event_loop(target_loop)
            thread_ready.set()
            target_loop.run_forever()

        t_loop = threading.Thread(target=run_target_loop, daemon=True)
        t_loop.start()
        thread_ready.wait()

        # Gate coroutine that waits until explicitly cancelled or signaled
        coro_started = threading.Event()

        async def hung_unlock(*args, **kwargs):
            coro_started.set()
            try:
                await asyncio.sleep(10.0)
            except asyncio.CancelledError:
                raise
            return {"success": True}

        self.mock_ble.unlock = hung_unlock

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            gs_client=self.mock_gs,
            loop=target_loop,
            dry_run=False,
            prefer_direct_ble=True,
            session_cache_path=self.temp_cache.name,
        )
        engine._locks[self.dual_lock.dev_id] = self.dual_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        worker_exc: List[Exception] = []

        def worker():
            try:
                engine.unlock(self.dual_lock.dev_id)
            except Exception as e:
                worker_exc.append(e)

        w = threading.Thread(target=worker, daemon=True)
        w.start()

        # Wait for the BLE coroutine to begin execution on target_loop
        self.assertTrue(coro_started.wait(timeout=2.0))

        # Cancel all running tasks on the target event loop
        def cancel_tasks():
            for task in asyncio.all_tasks(target_loop):
                task.cancel()

        target_loop.call_soon_threadsafe(cancel_tasks)
        w.join(timeout=3.0)

        # Cleanup target loop
        def stop_loop():
            target_loop.stop()
        target_loop.call_soon_threadsafe(stop_loop)
        t_loop.join(timeout=2.0)
        target_loop.close()

        # Worker must have caught CancelledError
        self.assertEqual(len(worker_exc), 1)
        self.assertIsInstance(worker_exc[0], (concurrent.futures.CancelledError, asyncio.CancelledError))

        # Crucial Invariant: Tuya Cloud publish_dp was NEVER invoked!
        self.mock_tuya.publish_dp.assert_not_called()


class TestAdversarialSafeRunAsyncTimeout(unittest.TestCase):
    """Stress tests _safe_run_async timeout and non-blocking thread behavior."""

    def test_safe_run_async_timeout_does_not_block_calling_thread_on_active_loop(self) -> None:
        """ThreadPoolExecutor branch: a 5-second sleep coroutine with timeout=0.05 aborts in < 0.2s."""
        main_loop = asyncio.new_event_loop()
        engine = LockEngine(loop=main_loop, dry_run=False)

        async def hung_coro():
            await asyncio.sleep(5.0)
            return "never_reached"

        async def run_in_loop():
            # In this context, current_loop is target_loop (line 1362 branch)
            t0 = time.perf_counter()
            with self.assertRaises(concurrent.futures.TimeoutError):
                engine._safe_run_async(hung_coro(), timeout=0.05)
            elapsed = time.perf_counter() - t0
            return elapsed

        elapsed = main_loop.run_until_complete(run_in_loop())
        main_loop.close()

        # Must abort promptly (< 0.25s) and NOT block for 5 seconds!
        self.assertLess(elapsed, 0.25, f"_safe_run_async blocked for {elapsed:.3f}s on timeout!")

    def test_safe_run_async_timeout_does_not_block_calling_thread_cross_thread(self) -> None:
        """Cross-thread run_coroutine_threadsafe branch: timeout=0.05 aborts in < 0.2s and cancels task."""
        target_loop = asyncio.new_event_loop()
        thread_ready = threading.Event()

        def run_target_loop():
            asyncio.set_event_loop(target_loop)
            thread_ready.set()
            target_loop.run_forever()

        t_loop = threading.Thread(target=run_target_loop, daemon=True)
        t_loop.start()
        thread_ready.wait()

        engine = LockEngine(loop=target_loop, dry_run=False)

        async def hung_coro():
            try:
                await asyncio.sleep(5.0)
                return "never_reached"
            except asyncio.CancelledError:
                raise

        t0 = time.perf_counter()
        with self.assertRaises(concurrent.futures.TimeoutError):
            engine._safe_run_async(hung_coro(), timeout=0.05)
        elapsed = time.perf_counter() - t0

        # Stop target loop
        def cleanup_loop():
            tasks = [t for t in asyncio.all_tasks(target_loop) if not t.done()]
            for task in tasks:
                task.cancel()
            target_loop.stop()

        target_loop.call_soon_threadsafe(cleanup_loop)
        t_loop.join(timeout=2.0)
        target_loop.close()

        self.assertLess(elapsed, 0.25, f"Cross-thread _safe_run_async blocked for {elapsed:.3f}s on timeout!")

    def test_high_concurrency_timeout_stress_50_workers(self) -> None:
        """50 concurrent worker threads each timing out on a 10s coroutine with timeout=0.04 finish in < 1.0s."""
        target_loop = asyncio.new_event_loop()
        thread_ready = threading.Event()

        def run_target_loop():
            asyncio.set_event_loop(target_loop)
            thread_ready.set()
            target_loop.run_forever()

        t_loop = threading.Thread(target=run_target_loop, daemon=True)
        t_loop.start()
        thread_ready.wait()

        engine = LockEngine(loop=target_loop, dry_run=False)

        async def hanging_work(worker_id: int):
            try:
                await asyncio.sleep(10.0)
                return f"done_{worker_id}"
            except asyncio.CancelledError:
                raise

        timeout_counts = 0
        lock = threading.Lock()

        def worker(wid: int):
            nonlocal timeout_counts
            try:
                engine._safe_run_async(hanging_work(wid), timeout=0.04)
            except concurrent.futures.TimeoutError:
                with lock:
                    timeout_counts += 1

        t0 = time.perf_counter()
        threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=2.0)
        total_time = time.perf_counter() - t0

        def cleanup_loop():
            tasks = [t for t in asyncio.all_tasks(target_loop) if not t.done()]
            for task in tasks:
                task.cancel()
            target_loop.stop()

        target_loop.call_soon_threadsafe(cleanup_loop)
        t_loop.join(timeout=2.0)
        target_loop.close()

        self.assertEqual(timeout_counts, 50, "Not all 50 workers timed out properly!")
        self.assertLess(total_time, 1.0, f"50 concurrent timeouts took {total_time:.3f}s, expected < 1.0s!")


if __name__ == "__main__":
    unittest.main()
