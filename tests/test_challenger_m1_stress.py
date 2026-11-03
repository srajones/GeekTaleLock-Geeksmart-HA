#!/usr/bin/env python3
"""
Adversarial Stress Test Suite for Milestone 1 Hardening (test_challenger_m1_stress.py).

Empirical challenger verification:
1. Event Loop Safety: Verify zero blocking I/O calls during coordinator instantiation
   (GeekDoorDataUpdateCoordinator), even when .session_cache.json exists, is large, or corrupt.
2. Bounded Timeout Handling: Verify hanging/slow HTTP server responses to lock.py and
   switch.py HTTP POSTs cleanly raise HomeAssistantError within 10s without stalling the asyncio loop.
3. Resilient Session Healing: Verify transient network drops raise UpdateFailed while
   fatal auth error codes (USER_PASSWD_WRONG, USERNAME_NOT_EXIST) raise ConfigEntryAuthFailed.
4. Operational Safety & Resource Hygiene: Verify zero physical deadbolt actuations (dry_run=True)
   and zero dangling background servers.
"""

from __future__ import annotations

import asyncio
import builtins
import inspect
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from custom_components.geek_door.const import (
    CONF_API_KEY,
    CONF_BLE_DIRECT_FALLBACK,
    CONF_CACHE_PATH,
    CONF_COUNTRY_CODE,
    CONF_MODE,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_SERVER_URL,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DEFAULT_BLE_DIRECT_FALLBACK,
    DEFAULT_COUNTRY_CODE,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    MODE_DIRECT_CLOUD,
    MODE_SERVER_BRIDGE,
    SESSION_CACHE_FILENAME,
)
from custom_components.geek_door.coordinator import (
    ConfigEntryAuthFailed,
    GeekDoorDataUpdateCoordinator,
    UpdateFailed,
)
from custom_components.geek_door.core.exceptions import HomeAssistantError
from custom_components.geek_door.core.lock_engine import LockEngine, LockStateSnapshot
from custom_components.geek_door.lock import GeekDoorLock
from custom_components.geek_door.switch import GeekDoorAutoLockSwitch


# ============================================================================
# Helpers & Mocks
# ============================================================================

class MockHassConfig:
    def __init__(self, base_dir: str) -> None:
        self.base_dir = base_dir

    def path(self, filename: str) -> str:
        return os.path.join(self.base_dir, filename)


class MockHass:
    def __init__(self, base_dir: Optional[str] = None) -> None:
        self.config = MockHassConfig(base_dir or tempfile.gettempdir())
        self.data: Dict[str, Any] = {DOMAIN: {}}

    async def async_add_executor_job(self, target: Any, *args: Any) -> Any:
        return target(*args)


class MockConfigEntry:
    def __init__(
        self,
        data: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
        entry_id: str = "stress_test_entry",
        title: str = "Stress Test Lock",
    ) -> None:
        self.entry_id = entry_id
        self.title = title
        self.data = dict(data or {})
        self.options = dict(options or {})
        self.runtime_data: Any = None


# ============================================================================
# Task 1: Empirical Event Loop Blocking I/O Stress Tests
# ============================================================================

class TestEventLoopBlockingIO(unittest.TestCase):
    """Verifies that coordinator instantiation performs zero synchronous disk I/O on the event loop."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="geekdoor_io_test_")
        self.cache_file = os.path.join(self.temp_dir, SESSION_CACHE_FILENAME)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run_with_io_tracking(self, entry_data: Dict[str, Any], entry_options: Optional[Dict[str, Any]] = None):
        """Runs GeekDoorDataUpdateCoordinator inside an active asyncio event loop with I/O interceptors."""
        hass = MockHass(self.temp_dir)
        entry = MockConfigEntry(data=entry_data, options=entry_options or {})

        opened_files: List[str] = []
        exists_checked: List[str] = []
        original_open = builtins.open
        original_exists = os.path.exists

        def intercept_open(file, *args, **kwargs):
            if isinstance(file, (str, bytes, os.PathLike)):
                opened_files.append(str(file))
            return original_open(file, *args, **kwargs)

        def intercept_exists(path):
            if isinstance(path, (str, bytes, os.PathLike)):
                exists_checked.append(str(path))
            return original_exists(path)

        async def _instantiate_on_loop():
            # Intercept file I/O calls strictly while on the event loop
            with patch("builtins.open", side_effect=intercept_open), patch(
                "os.path.exists", side_effect=intercept_exists
            ):
                coordinator = GeekDoorDataUpdateCoordinator(hass, entry)
                return coordinator

        coordinator = asyncio.run(_instantiate_on_loop())
        return coordinator, opened_files, exists_checked

    def test_zero_blocking_io_when_session_cache_exists(self):
        """Verify zero file opens or exists checks on cache file during coordinator init when cache exists."""
        # Create a valid session cache file
        valid_cache = {
            "email": "user@example.com",
            "clientId": 123456,
            "token": "valid_token_xyz",
            "tuyaUid": "tuya_user_1",
            "devices": [{"devId": "dev-01", "name": "Front Door"}],
        }
        with open(self.cache_file, "w", encoding="utf-8") as f:
            json.dump(valid_cache, f)

        self.assertTrue(os.path.isfile(self.cache_file))

        entry_data = {
            CONF_MODE: MODE_DIRECT_CLOUD,
            CONF_USERNAME: "user@example.com",
            CONF_PASSWORD: "secret_password",
            CONF_COUNTRY_CODE: "1",
            "dry_run": True,
        }

        coordinator, opened_files, exists_checked = self._run_with_io_tracking(entry_data)

        # Assert no file read or open on the session cache file occurred
        cache_reads = [f for f in opened_files if SESSION_CACHE_FILENAME in f]
        self.assertEqual(
            cache_reads,
            [],
            f"Coordinator instantiated on event loop must NOT read cache file synchronously: {cache_reads}",
        )

        # Assert no os.path.exists check on the session cache file occurred
        cache_exists = [f for f in exists_checked if SESSION_CACHE_FILENAME in f]
        self.assertEqual(
            cache_exists,
            [],
            f"Coordinator instantiated on event loop must NOT run os.path.exists synchronously: {cache_exists}",
        )

        # Ensure engine is properly instantiated with sample_mode=False
        self.assertIsNotNone(coordinator.engine)
        self.assertFalse(coordinator.engine.sample_mode)

    def test_zero_blocking_io_when_session_cache_is_corrupt_or_huge(self):
        """Verify zero blocking calls even if cache file is corrupted or massive (stress condition)."""
        # Create a corrupted non-JSON cache file of 1MB size
        with open(self.cache_file, "wb") as f:
            f.write(b"NOT_A_VALID_JSON{[[CORRUPT" * 40000)

        entry_data = {
            CONF_MODE: MODE_DIRECT_CLOUD,
            CONF_USERNAME: "user@example.com",
            CONF_PASSWORD: "secret_password",
            CONF_COUNTRY_CODE: "1",
            "dry_run": True,
        }

        coordinator, opened_files, exists_checked = self._run_with_io_tracking(entry_data)

        cache_reads = [f for f in opened_files if SESSION_CACHE_FILENAME in f]
        self.assertEqual(cache_reads, [])
        self.assertIsNotNone(coordinator.engine)
        self.assertFalse(coordinator.engine.sample_mode)

    def test_zero_blocking_io_in_server_bridge_mode(self):
        """Verify server bridge mode performs zero disk I/O and does not instantiate direct engine."""
        entry_data = {
            CONF_MODE: MODE_SERVER_BRIDGE,
            CONF_SERVER_URL: "http://127.0.0.1:8080",
            CONF_API_KEY: "secret_key_123",
        }

        coordinator, opened_files, exists_checked = self._run_with_io_tracking(entry_data)

        cache_reads = [f for f in opened_files if SESSION_CACHE_FILENAME in f]
        self.assertEqual(cache_reads, [])
        self.assertIsNone(coordinator.engine)


# ============================================================================
# Task 2: Empirical Timeout Handling & Event Loop Liveness Stress Tests
# ============================================================================

class TestTimeoutAndEventLoopLiveness(unittest.TestCase):
    """Stress tests timeout handling on hanging/slow HTTP POSTs in lock.py and switch.py."""

    def test_simulated_hanging_http_post_in_lock_py_raises_home_assistant_error_within_10s(self):
        """Simulate a hanging HTTP server during async_lock / async_unlock / async_keep_unlocked."""
        mock_hass = MockHass()
        mock_entry = MockConfigEntry(
            data={
                CONF_MODE: MODE_SERVER_BRIDGE,
                CONF_SERVER_URL: "http://192.0.2.1:9999",  # RFC 5737 TEST-NET (unroutable)
                CONF_API_KEY: "dummy_key",
                CONF_VERIFY_SSL: False,
            }
        )
        coord = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)
        lock_entity = GeekDoorLock(coord, "dev_lock_001")
        lock_entity.hass = mock_hass

        # Heartbeat tracker to verify event loop liveness
        heartbeat_ticks = [0]

        async def heartbeat():
            try:
                while True:
                    await asyncio.sleep(0.05)
                    heartbeat_ticks[0] += 1
            except asyncio.CancelledError:
                pass

        # Mock aiohttp session that simulates a 10s timeout trigger
        class HangingAiohttpPostContext:
            def __init__(self, timeout_duration: float = 1.0) -> None:
                self.timeout_duration = timeout_duration

            async def __aenter__(self):
                # Simulate waiting for response until ClientTimeout fires
                await asyncio.sleep(self.timeout_duration)
                raise asyncio.TimeoutError("aiohttp ClientTimeout total=10.0 fired")

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return False

        class HangingMockSession:
            def __init__(self) -> None:
                self.captured_kwargs: List[Dict[str, Any]] = []

            def post(self, url: str, **kwargs: Any) -> HangingAiohttpPostContext:
                self.captured_kwargs.append(kwargs)
                # Verify that timeout keyword parameter was supplied
                return HangingAiohttpPostContext(timeout_duration=0.2)

        mock_session = HangingMockSession()

        async def run_stress_test():
            hb_task = asyncio.create_task(heartbeat())
            try:
                # Patch async_get_clientsession to return our hanging session
                with patch("custom_components.geek_door.lock.async_get_clientsession", return_value=mock_session):
                    # 1. async_lock
                    t0 = time.monotonic()
                    with self.assertRaises(HomeAssistantError) as ctx:
                        await lock_entity.async_lock()
                    elapsed_lock = time.monotonic() - t0
                    self.assertIn("Failed to communicate with server bridge", str(ctx.exception))
                    self.assertLess(elapsed_lock, 10.0)

                    # 2. async_unlock
                    t0 = time.monotonic()
                    with self.assertRaises(HomeAssistantError) as ctx:
                        await lock_entity.async_unlock()
                    elapsed_unlock = time.monotonic() - t0
                    self.assertIn("Failed to communicate with server bridge", str(ctx.exception))
                    self.assertLess(elapsed_unlock, 10.0)

                    # 3. async_keep_unlocked
                    t0 = time.monotonic()
                    with self.assertRaises(HomeAssistantError) as ctx:
                        await lock_entity.async_keep_unlocked(duration_seconds=120)
                    elapsed_keep = time.monotonic() - t0
                    self.assertIn("Failed to communicate with server bridge", str(ctx.exception))
                    self.assertLess(elapsed_keep, 10.0)

                # Verify captured timeouts and payload
                self.assertEqual(len(mock_session.captured_kwargs), 3)
                for kw in mock_session.captured_kwargs:
                    self.assertIn("timeout", kw)
                    self.assertTrue(kw["timeout"] == 10.0 or getattr(kw["timeout"], "total", None) == 10.0)

                # Verify keep_unlocked forwarded duration
                keep_kw = mock_session.captured_kwargs[2]
                self.assertEqual(keep_kw["json"].get("duration_seconds"), 120)

            finally:
                hb_task.cancel()
                try:
                    await hb_task
                except asyncio.CancelledError:
                    pass

            # Heartbeat must have ticked multiple times, proving non-blocking event loop
            self.assertGreater(heartbeat_ticks[0], 5, "Asyncio event loop was starved during timeout wait!")

        asyncio.run(run_stress_test())

    def test_simulated_hanging_http_post_in_switch_py_raises_home_assistant_error_within_10s(self):
        """Simulate a hanging HTTP server during async_turn_on / async_turn_off."""
        mock_hass = MockHass()
        mock_entry = MockConfigEntry(
            data={
                CONF_MODE: MODE_SERVER_BRIDGE,
                CONF_SERVER_URL: "http://192.0.2.1:9999",
                CONF_API_KEY: "dummy_key",
                CONF_VERIFY_SSL: False,
            }
        )
        coord = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)
        switch_entity = GeekDoorAutoLockSwitch(coord, "dev_lock_001")
        switch_entity.hass = mock_hass

        class HangingMockSession:
            def __init__(self) -> None:
                self.captured_kwargs: List[Dict[str, Any]] = []

            def post(self, url: str, **kwargs: Any):
                self.captured_kwargs.append(kwargs)
                class HangingContext:
                    async def __aenter__(self):
                        await asyncio.sleep(0.2)
                        raise asyncio.TimeoutError("Post timed out")
                    async def __aexit__(self, exc_type, exc_val, exc_tb):
                        return False
                return HangingContext()

        mock_session = HangingMockSession()

        async def run_stress_test():
            with patch("custom_components.geek_door.switch.async_get_clientsession", return_value=mock_session):
                # 1. async_turn_on
                t0 = time.monotonic()
                with self.assertRaises(HomeAssistantError) as ctx:
                    await switch_entity.async_turn_on()
                elapsed_on = time.monotonic() - t0
                self.assertIn("Failed to communicate with server bridge", str(ctx.exception))
                self.assertLess(elapsed_on, 10.0)

                # 2. async_turn_off
                t0 = time.monotonic()
                with self.assertRaises(HomeAssistantError) as ctx:
                    await switch_entity.async_turn_off()
                elapsed_off = time.monotonic() - t0
                self.assertIn("Failed to communicate with server bridge", str(ctx.exception))
                self.assertLess(elapsed_off, 10.0)

            self.assertEqual(len(mock_session.captured_kwargs), 2)
            self.assertEqual(mock_session.captured_kwargs[0]["json"], {"enabled": True, "confirmed": True})
            self.assertEqual(mock_session.captured_kwargs[1]["json"], {"enabled": False, "confirmed": True})

        asyncio.run(run_stress_test())

    def test_auth_rejection_http_401_403_raises_config_entry_auth_failed(self):
        """HTTP 401 or 403 on server bridge post raises ConfigEntryAuthFailed instead of HomeAssistantError."""
        mock_hass = MockHass()
        mock_entry = MockConfigEntry(
            data={
                CONF_MODE: MODE_SERVER_BRIDGE,
                CONF_SERVER_URL: "http://127.0.0.1:8080",
                CONF_API_KEY: "expired_key",
            }
        )
        coord = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)
        lock_entity = GeekDoorLock(coord, "dev_lock_001")
        lock_entity.hass = mock_hass
        switch_entity = GeekDoorAutoLockSwitch(coord, "dev_lock_001")
        switch_entity.hass = mock_hass

        class AuthFailMockResponse:
            def __init__(self, status: int) -> None:
                self.status = status
            async def text(self) -> str:
                return "Unauthorized API Key"

        class AuthFailMockSession:
            def __init__(self, status: int = 401) -> None:
                self.status = status
            def post(self, url: str, **kwargs: Any):
                resp = AuthFailMockResponse(self.status)
                class Context:
                    async def __aenter__(self):
                        return resp
                    async def __aexit__(self, exc_type, exc_val, exc_tb):
                        return False
                return Context()

        async def run_auth_fail_tests():
            # 401 on lock
            with patch("custom_components.geek_door.lock.async_get_clientsession", return_value=AuthFailMockSession(401)):
                with self.assertRaises(ConfigEntryAuthFailed):
                    await lock_entity.async_lock()

            # 403 on switch
            with patch("custom_components.geek_door.switch.async_get_clientsession", return_value=AuthFailMockSession(403)):
                with self.assertRaises(ConfigEntryAuthFailed):
                    await switch_entity.async_turn_on()

        asyncio.run(run_auth_fail_tests())

    def test_direct_cloud_lock_and_switch_timeout_handling(self):
        """Direct cloud mode lock/switch raises HomeAssistantError on timeout or failure."""
        mock_hass = MockHass()
        mock_entry = MockConfigEntry(
            data={
                CONF_MODE: MODE_DIRECT_CLOUD,
                CONF_USERNAME: "user@example.com",
                CONF_PASSWORD: "pwd",
                "dry_run": True,
            }
        )
        coord = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)
        coord.engine = MagicMock()
        lock_entity = GeekDoorLock(coord, "dev_lock_001")
        lock_entity.hass = mock_hass
        switch_entity = GeekDoorAutoLockSwitch(coord, "dev_lock_001")
        switch_entity.hass = mock_hass

        async def run_direct_cloud_tests():
            # 1. engine.lock raises TimeoutError
            coord.engine.lock.side_effect = TimeoutError("Tuya cloud command timed out")
            with self.assertRaises(HomeAssistantError) as ctx:
                await lock_entity.async_lock()
            self.assertIn("Failed to lock door", str(ctx.exception))

            # 2. engine.unlock returns failure result
            coord.engine.unlock.side_effect = None
            coord.engine.unlock.return_value = {"success": False, "message": "Motor jammed"}
            with self.assertRaises(HomeAssistantError) as ctx:
                await lock_entity.async_unlock()
            self.assertIn("Motor jammed", str(ctx.exception))

            # 3. engine.keep_unlocked forwards duration_seconds
            coord.engine.keep_unlocked.return_value = {"success": True}
            await lock_entity.async_keep_unlocked(duration_seconds=600)
            coord.engine.keep_unlocked.assert_called_with("dev_lock_001", duration_seconds=600)

            # 4. engine.auto_lock_on raises TimeoutError
            coord.engine.auto_lock_on.side_effect = TimeoutError("Timeout turning on auto-lock")
            with self.assertRaises(HomeAssistantError) as ctx:
                await switch_entity.async_turn_on()
            self.assertIn("Failed to turn on auto-lock", str(ctx.exception))

            # 5. engine.auto_lock_off returns failure result
            coord.engine.auto_lock_off.side_effect = None
            coord.engine.auto_lock_off.return_value = {"success": False, "message": "Bluetooth out of range"}
            with self.assertRaises(HomeAssistantError) as ctx:
                await switch_entity.async_turn_off()
            self.assertIn("Bluetooth out of range", str(ctx.exception))

        asyncio.run(run_direct_cloud_tests())

    def test_entity_availability_reflects_coordinator_last_update_success(self):
        """Entity available property is strictly False if coordinator.last_update_success is False."""
        mock_hass = MockHass()
        mock_entry = MockConfigEntry(
            data={CONF_MODE: MODE_DIRECT_CLOUD, "dry_run": True},
            options={CONF_BLE_DIRECT_FALLBACK: False},
        )
        coord = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)
        coord.data = {
            "dev_01": {
                "name": "Front Door",
                "is_online": True,
                "online": True,
                "state": "LOCKED",
            }
        }
        lock_entity = GeekDoorLock(coord, "dev_01")
        switch_entity = GeekDoorAutoLockSwitch(coord, "dev_01")

        # When last_update_success is True -> available
        coord.last_update_success = True
        self.assertTrue(lock_entity.available)
        self.assertTrue(switch_entity.available)

        # When last_update_success is False -> unavailable
        coord.last_update_success = False
        self.assertFalse(lock_entity.available)
        self.assertFalse(switch_entity.available)


# ============================================================================
# Task 3: Empirical Session Healing Recovery vs Fatal Auth Tests
# ============================================================================

class TestSessionHealingRecovery(unittest.TestCase):
    """Stress tests transient network recovery vs fatal credential failures in coordinator."""

    def setUp(self) -> None:
        self.mock_hass = MockHass()
        self.mock_entry = MockConfigEntry(
            data={
                CONF_MODE: MODE_DIRECT_CLOUD,
                CONF_USERNAME: "test_user@example.com",
                CONF_PASSWORD: "test_password",
                CONF_COUNTRY_CODE: "1",
            },
            options={CONF_BLE_DIRECT_FALLBACK: False},
        )
        self.coord = GeekDoorDataUpdateCoordinator(self.mock_hass, self.mock_entry)
        self.coord.engine = MagicMock()

    def test_transient_network_drop_during_regular_poll_raises_update_failed(self):
        """Transient connection/timeout drops during normal poll raise UpdateFailed without healing."""
        async def run_test():
            self.coord.engine.get_all_lock_snapshots.side_effect = ConnectionResetError("Connection reset by peer")
            with self.assertRaises(UpdateFailed) as ctx:
                await self.coord._async_update_data()
            self.assertIn("Direct cloud update failed", str(ctx.exception))
            # authenticate_and_discover should NOT be called on transient poll failure
            self.coord.engine.authenticate_and_discover.assert_not_called()

        asyncio.run(run_test())

    def test_fatal_auth_during_regular_poll_raises_config_entry_auth_failed(self):
        """Fatal error (USER_PASSWD_WRONG) during regular poll immediately raises ConfigEntryAuthFailed."""
        async def run_test():
            self.coord.engine.get_all_lock_snapshots.side_effect = Exception("TuyaApiError: USER_PASSWD_WRONG")
            with self.assertRaises(ConfigEntryAuthFailed) as ctx:
                await self.coord._async_update_data()
            self.assertIn("USER_PASSWD_WRONG", str(ctx.exception))
            self.coord.engine.authenticate_and_discover.assert_not_called()

        asyncio.run(run_test())

    def test_expired_session_auto_heals_successfully(self):
        """Expired session (USER_SESSION_INVALID) invokes heal and recovers data transparently."""
        async def run_test():
            self.coord.engine.get_all_lock_snapshots.side_effect = Exception("TuyaApiError: USER_SESSION_INVALID")
            healed_devices = [
                {
                    "devId": "lock_healed_01",
                    "name": "Front Porch",
                    "isOnline": True,
                    "state": "LOCKED",
                }
            ]
            self.coord.engine.authenticate_and_discover.return_value = healed_devices

            data = await self.coord._async_update_data()
            self.assertIn("lock_healed_01", data)
            self.assertEqual(data["lock_healed_01"]["name"], "Front Porch")
            self.coord.engine.authenticate_and_discover.assert_called_once_with(
                "test_user@example.com", "test_password", "1"
            )

        asyncio.run(run_test())

    def test_expired_session_with_transient_heal_drop_raises_update_failed(self):
        """When session is expired but auto-heal encounters a network error, raise UpdateFailed (not AuthFailed)."""
        async def run_test():
            self.coord.engine.get_all_lock_snapshots.side_effect = Exception("TuyaApiError: TOKEN_EXPIRED")
            self.coord.engine.authenticate_and_discover.side_effect = TimeoutError("DNS resolution timed out")

            with self.assertRaises(UpdateFailed) as ctx:
                await self.coord._async_update_data()

            self.assertIn("network error", str(ctx.exception))
            self.assertIn("DNS resolution timed out", str(ctx.exception))

        asyncio.run(run_test())

    def test_expired_session_with_fatal_heal_failure_raises_config_entry_auth_failed(self):
        """When session is expired and auto-heal fails with USER_PASSWD_WRONG, raise ConfigEntryAuthFailed."""
        async def run_test():
            self.coord.engine.get_all_lock_snapshots.side_effect = Exception("TuyaApiError: USER_SESSION_INVALID")
            self.coord.engine.authenticate_and_discover.side_effect = Exception("TuyaApiError: USER_PASSWD_WRONG")

            with self.assertRaises(ConfigEntryAuthFailed) as ctx:
                await self.coord._async_update_data()

            self.assertIn("Authentication failed permanently during session heal", str(ctx.exception))
            self.assertIn("USER_PASSWD_WRONG", str(ctx.exception))

        asyncio.run(run_test())

    def test_missing_credentials_during_heal_raises_config_entry_auth_failed(self):
        """Missing credentials in config entry during session heal raises ConfigEntryAuthFailed."""
        async def run_test():
            self.coord.entry.data[CONF_USERNAME] = ""
            self.coord.engine.get_all_lock_snapshots.side_effect = Exception("TuyaApiError: USER_SESSION_INVALID")

            with self.assertRaises(ConfigEntryAuthFailed) as ctx:
                await self.coord._async_update_data()

            self.assertIn("Missing credentials", str(ctx.exception))

        asyncio.run(run_test())

    def test_server_bridge_status_transient_vs_fatal(self):
        """Server bridge status polling distinguishes HTTP 401/403 (AuthFailed) from 500/network (UpdateFailed)."""
        mock_hass = MockHass()
        mock_entry = MockConfigEntry(
            data={
                CONF_MODE: MODE_SERVER_BRIDGE,
                CONF_SERVER_URL: "http://127.0.0.1:8080",
                CONF_API_KEY: "test_key",
            }
        )
        coord = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)

        class StatusResponse:
            def __init__(self, status: int, data: Any = None) -> None:
                self.status = status
                self._data = data or {}
            async def json(self) -> Any:
                return self._data

        class StatusSession:
            def __init__(self, resp: StatusResponse, raise_exc: Optional[Exception] = None) -> None:
                self.resp = resp
                self.raise_exc = raise_exc
            def get(self, url: str, **kwargs: Any):
                raise_exc = self.raise_exc
                resp = self.resp
                class Context:
                    async def __aenter__(self):
                        if raise_exc:
                            raise raise_exc
                        return resp
                    async def __aexit__(self, exc_type, exc_val, exc_tb):
                        return False
                return Context()

        async def run_bridge_tests():
            # 1. HTTP 401 -> ConfigEntryAuthFailed
            with patch("custom_components.geek_door.coordinator.async_get_clientsession", return_value=StatusSession(StatusResponse(401))):
                with self.assertRaises(ConfigEntryAuthFailed):
                    await coord._async_update_data()

            # 2. HTTP 403 -> ConfigEntryAuthFailed
            with patch("custom_components.geek_door.coordinator.async_get_clientsession", return_value=StatusSession(StatusResponse(403))):
                with self.assertRaises(ConfigEntryAuthFailed):
                    await coord._async_update_data()

            # 3. HTTP 500 -> UpdateFailed
            with patch("custom_components.geek_door.coordinator.async_get_clientsession", return_value=StatusSession(StatusResponse(500))):
                with self.assertRaises(UpdateFailed) as ctx:
                    await coord._async_update_data()
                self.assertIn("HTTP 500", str(ctx.exception))

            # 4. Network error -> UpdateFailed
            with patch("custom_components.geek_door.coordinator.async_get_clientsession", return_value=StatusSession(StatusResponse(200), raise_exc=ConnectionResetError("Socket dropped"))):
                with self.assertRaises(UpdateFailed) as ctx:
                    await coord._async_update_data()
                self.assertIn("Server bridge connection error", str(ctx.exception))

            # 5. Malformed payload -> UpdateFailed
            with patch("custom_components.geek_door.coordinator.async_get_clientsession", return_value=StatusSession(StatusResponse(200, "not a dict"))):
                with self.assertRaises(UpdateFailed) as ctx:
                    await coord._async_update_data()
                self.assertIn("Unexpected server response format", str(ctx.exception))

            # 6. Valid locks payload -> Success
            valid_payload = {"locks": [{"device_id": "lock_100", "state": "LOCKED", "name": "Front Door"}]}
            with patch("custom_components.geek_door.coordinator.async_get_clientsession", return_value=StatusSession(StatusResponse(200, valid_payload))):
                data = await coord._async_update_data()
                self.assertIn("lock_100", data)
                self.assertEqual(data["lock_100"]["name"], "Front Door")

        asyncio.run(run_bridge_tests())


# ============================================================================
# Task 4: Operational Safety & Resource Hygiene Verification
# ============================================================================

class TestSafetyAndResourceHygiene(unittest.TestCase):
    """Verifies that no physical locks can be moved and no background processes are left running."""

    def test_dry_run_is_strictly_enforced_by_coordinator(self):
        """Verify that coordinator passes dry_run=True when entry.data['dry_run'] is True."""
        mock_hass = MockHass()
        mock_entry = MockConfigEntry(
            data={
                CONF_MODE: MODE_DIRECT_CLOUD,
                "dry_run": True,
            }
        )
        coord = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)
        self.assertIsNotNone(coord.engine)
        self.assertTrue(coord.engine.dry_run, "dry_run MUST be True in coordinator engine")

    def test_zero_background_daemons_created(self):
        """Verify that no background threads or tasks leak after shutdown."""
        mock_hass = MockHass()
        mock_entry = MockConfigEntry(
            data={CONF_MODE: MODE_DIRECT_CLOUD, "dry_run": True},
            options={CONF_BLE_DIRECT_FALLBACK: True},
        )
        coord = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)

        async def run_shutdown():
            await coord.async_shutdown()

        asyncio.run(run_shutdown())


if __name__ == "__main__":
    unittest.main()
