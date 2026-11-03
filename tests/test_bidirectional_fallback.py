#!/usr/bin/env python3
"""Comprehensive test suite for Milestone 2: Bi-directional Fallback Architecture.

Verifies:
1. Universal prefer_direct_ble=True default across LockEngine and coordinator.
2. Bi-directional fallback: Direct BLE -> Tuya Cloud / Smart Plug Gateway.
3. Reverse fallback: Tuya Cloud / Smart Plug Gateway -> Direct BLE.
4. Topology neutrality: BLE-only, Smart Plug-only, and Dual-stack setups.
5. All transports fail error diagnostics.
6. TuyaApiError / GeekSmartAuthError propagation on token expiration during discovery and actuation.
7. Cross-thread event loop safety in _safe_run_async without conflicting event loops.
"""

from __future__ import annotations

import asyncio
import os
import sys
import threading
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from custom_components.geek_door.const import (
    CONF_BLE_DIRECT_FALLBACK,
    CONF_PREFER_DIRECT_BLE,
    DEFAULT_PREFER_DIRECT_BLE,
)
from custom_components.geek_door.coordinator import GeekDoorDataUpdateCoordinator
from custom_components.geek_door.core.exceptions import (
    GeekSmartAuthError,
    GeekSmartControlError,
    TuyaApiError,
)
from custom_components.geek_door.core.lock_engine import (
    GatewayDevice,
    LockDevice,
    LockEngine,
)


class TestBidirectionalFallbackArchitecture(unittest.TestCase):
    """Verifies bi-directional fallback between Direct BLE and Tuya Cloud / Smart Plug."""

    def setUp(self) -> None:
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

        self.test_lock = LockDevice(
            dev_id="ebexamplelock001",
            name="Front Door Lock",
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

    # ------------------------------------------------------------------------
    # 1. Defaults
    # ------------------------------------------------------------------------
    def test_default_is_prefer_direct_ble_true(self) -> None:
        """LockEngine defaults to prefer_direct_ble=True everywhere."""
        engine = LockEngine(dry_run=False)
        self.assertTrue(engine.prefer_direct_ble)
        self.assertEqual(engine.preferred_transport, "direct_ble")

    # ------------------------------------------------------------------------
    # 2. prefer_direct_ble=True: BLE Success -> Skips Cloud
    # ------------------------------------------------------------------------
    def test_prefer_ble_true_ble_success_skips_cloud(self) -> None:
        """When prefer_direct_ble=True, executes BLE first and does not touch Tuya Cloud."""
        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=False,
            prefer_direct_ble=True,
        )
        engine._locks[self.test_lock.dev_id] = self.test_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        res = engine.unlock(self.test_lock.dev_id)

        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "direct_ble")
        self.mock_ble.unlock.assert_called_once()
        self.mock_tuya.publish_dp.assert_not_called()

    # ------------------------------------------------------------------------
    # 3. prefer_direct_ble=True: BLE Fails -> Falls back to Tuya Cloud
    # ------------------------------------------------------------------------
    def test_prefer_ble_true_ble_fails_falls_back_to_cloud(self) -> None:
        """When prefer_direct_ble=True and BLE fails (out of range), automatically falls back to Tuya Cloud."""
        self.mock_ble.unlock = AsyncMock(side_effect=Exception("BLE out of range / timed out"))

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=False,
            prefer_direct_ble=True,
        )
        engine._locks[self.test_lock.dev_id] = self.test_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        res = engine.unlock(self.test_lock.dev_id)

        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "tuya_cloud")
        self.assertTrue(res.get("fallbackFromBle", False))
        self.mock_ble.unlock.assert_called_once()
        self.mock_tuya.publish_dp.assert_called_once()

    # ------------------------------------------------------------------------
    # 4. prefer_direct_ble=False: Cloud Success -> Skips BLE
    # ------------------------------------------------------------------------
    def test_prefer_ble_false_cloud_success_skips_ble(self) -> None:
        """When prefer_direct_ble=False, executes Tuya Cloud first and does not touch BLE."""
        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=False,
            prefer_direct_ble=False,
        )
        engine._locks[self.test_lock.dev_id] = self.test_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        res = engine.unlock(self.test_lock.dev_id)

        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "tuya_cloud")
        self.mock_tuya.publish_dp.assert_called_once()
        self.mock_ble.unlock.assert_not_called()

    # ------------------------------------------------------------------------
    # 5. prefer_direct_ble=False: Cloud Fails -> Falls back to BLE
    # ------------------------------------------------------------------------
    def test_prefer_ble_false_cloud_fails_falls_back_to_ble(self) -> None:
        """When prefer_direct_ble=False and Tuya Cloud fails (plug unplugged), automatically falls back to BLE."""
        self.mock_tuya.publish_dp.side_effect = Exception("Smart plug offline / 504 Gateway Timeout")

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=False,
            prefer_direct_ble=False,
        )
        engine._locks[self.test_lock.dev_id] = self.test_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        res = engine.unlock(self.test_lock.dev_id)

        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "direct_ble")
        self.assertTrue(res.get("fallbackFromGateway", False))
        self.mock_tuya.publish_dp.assert_called_once()
        self.mock_ble.unlock.assert_called_once()

    # ------------------------------------------------------------------------
    # 6. Topology: BLE Only (No Smart Plug)
    # ------------------------------------------------------------------------
    def test_ble_only_user_without_smart_plug(self) -> None:
        """When user has only HA native Bluetooth (no Smart Plug), operates reliably over BLE."""
        ble_only_lock = LockDevice(
            dev_id="eb_ble_only_01",
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
        )
        engine._locks[ble_only_lock.dev_id] = ble_only_lock

        res = engine.unlock(ble_only_lock.dev_id)
        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "direct_ble")
        self.mock_ble.unlock.assert_called_once()
        self.mock_tuya.publish_dp.assert_not_called()

    # ------------------------------------------------------------------------
    # 7. Topology: Smart Plug Only (No HA Bluetooth)
    # ------------------------------------------------------------------------
    def test_smart_plug_only_user_without_ha_ble(self) -> None:
        """When user has only Smart Plug (no local HA Bluetooth adapter), operates reliably over Cloud."""
        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=None,
            dry_run=False,
            prefer_direct_ble=True,
        )
        engine._locks[self.test_lock.dev_id] = self.test_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        res = engine.unlock(self.test_lock.dev_id)
        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "tuya_cloud")
        self.mock_tuya.publish_dp.assert_called_once()

    # ------------------------------------------------------------------------
    # 8. All Transports Fail -> Raises GeekSmartControlError
    # ------------------------------------------------------------------------
    def test_all_transports_fail_raises_control_error(self) -> None:
        """When both BLE and Cloud fail, raises GeekSmartControlError with comprehensive diagnostics."""
        self.mock_ble.unlock = AsyncMock(side_effect=Exception("BLE radio offline"))
        self.mock_tuya.publish_dp.side_effect = Exception("Tuya API 500 error")

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=False,
            prefer_direct_ble=True,
        )
        engine._locks[self.test_lock.dev_id] = self.test_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        with self.assertRaises(GeekSmartControlError) as ctx:
            engine.unlock(self.test_lock.dev_id)
        self.assertIn("All transports failed", str(ctx.exception))
        self.assertIn("BLE radio offline", str(ctx.exception))

    # ------------------------------------------------------------------------
    # 9. Token Expiry in Actuation -> Raises GeekSmartAuthError (401)
    # ------------------------------------------------------------------------
    def test_tuya_session_expired_propagates_auth_error_during_actuation(self) -> None:
        """When Tuya session has expired and all transports fail, raises GeekSmartAuthError(401)."""
        self.mock_ble.unlock = AsyncMock(side_effect=Exception("BLE out of range"))
        self.mock_tuya.publish_dp.side_effect = TuyaApiError(
            error_code="USER_SESSION_INVALID",
            error_msg="User session token has expired",
        )

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            ble_client=self.mock_ble,
            dry_run=False,
            prefer_direct_ble=True,
        )
        engine._locks[self.test_lock.dev_id] = self.test_lock
        engine._gateways[self.gateway.dev_id] = self.gateway

        with self.assertRaises(GeekSmartAuthError) as ctx:
            engine.unlock(self.test_lock.dev_id)
        self.assertEqual(ctx.exception.code, 401)
        self.assertIn("Tuya session expired", str(ctx.exception))

    # ------------------------------------------------------------------------
    # 10. Token Expiry in Discovery -> Propagates TuyaApiError
    # ------------------------------------------------------------------------
    def test_tuya_session_expired_propagates_in_discovery(self) -> None:
        """In discover(), TuyaApiError with session invalidation is propagated, not swallowed."""
        self.mock_tuya.get_home_device_list.side_effect = TuyaApiError(
            error_code="TOKEN_EXPIRED",
            error_msg="Access token has expired",
        )

        engine = LockEngine(
            tuya_client=self.mock_tuya,
            dry_run=False,
            use_sample_devices=False,
            sample_mode=False,
        )

        with self.assertRaises(TuyaApiError) as ctx:
            engine.discover(force_refresh=True, skip_network=False)
        self.assertEqual(ctx.exception.error_code, "TOKEN_EXPIRED")

    # ------------------------------------------------------------------------
    # 11. Cross-Thread Loop Safety in _safe_run_async
    # ------------------------------------------------------------------------
    def test_cross_thread_safe_run_async_with_running_loop(self) -> None:
        """_safe_run_async dispatches coroutines to the target event loop cleanly across threads."""
        bg_loop = asyncio.new_event_loop()
        thread_ready = threading.Event()
        stop_thread = threading.Event()

        def loop_worker():
            asyncio.set_event_loop(bg_loop)
            thread_ready.set()
            bg_loop.run_forever()

        t = threading.Thread(target=loop_worker, daemon=True)
        t.start()
        thread_ready.wait()

        try:
            engine = LockEngine(loop=bg_loop, dry_run=False)

            executed_loop = None

            async def sample_coro():
                nonlocal executed_loop
                executed_loop = asyncio.get_running_loop()
                return "hello_from_bg_loop"

            # Execute from current (worker) thread which has no running loop
            result = engine._safe_run_async(sample_coro())
            self.assertEqual(result, "hello_from_bg_loop")
            self.assertIs(executed_loop, bg_loop)
        finally:
            bg_loop.call_soon_threadsafe(bg_loop.stop)
            t.join(timeout=2.0)
            bg_loop.close()

    # ------------------------------------------------------------------------
    # 12. Coordinator prefer_direct_ble Property & LockEngine Wiring
    # ------------------------------------------------------------------------
    def test_coordinator_prefer_direct_ble_property_and_options(self) -> None:
        """GeekDoorDataUpdateCoordinator properly manages prefer_direct_ble and passes it to LockEngine."""
        mock_entry = MagicMock()
        mock_entry.data = {"username": "test@example.com", "password": "password123"}
        mock_entry.options = {CONF_PREFER_DIRECT_BLE: True}
        mock_entry.title = "Test Lock"

        mock_hass = MagicMock()
        mock_hass.loop = asyncio.new_event_loop()
        mock_hass.config.path.return_value = "/tmp/test_session_cache.json"

        try:
            coordinator = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)
            self.assertTrue(coordinator.prefer_direct_ble)
            self.assertIsNotNone(coordinator.engine)
            self.assertTrue(coordinator.engine.prefer_direct_ble)

            # Change option to False
            mock_entry.options = {CONF_PREFER_DIRECT_BLE: False}
            self.assertFalse(coordinator.prefer_direct_ble)

            # Fallback to legacy CONF_BLE_DIRECT_FALLBACK
            mock_entry.options = {CONF_BLE_DIRECT_FALLBACK: False}
            self.assertFalse(coordinator.prefer_direct_ble)
        finally:
            mock_hass.loop.close()


if __name__ == "__main__":
    unittest.main()
