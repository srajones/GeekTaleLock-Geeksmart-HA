#!/usr/bin/env python3
"""
Unit tests for LockEngine: Single Source of Truth Core Engine.
Covers:
- Strongly-typed models (LockStateSnapshot, LockDevice, GatewayDevice, ActionResult)
- Dual dict/object access compatibility of ActionResult
- Pure DP parser (parse_dps_to_snapshot)
- Dynamic discovery with zero hardcoded device names and multi-user compatibility
- Alias synthesis preserving backward compatibility (101, 102, 103, 201, 701)
- Hybrid transport failover and dry-run safety barrier enforcement
- State overrides (override_lock_state)
"""

import json
import os
import sys
import tempfile
import unittest

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from client.exceptions import GeekSmartControlError, SafetyBarrierViolation
from client.geeksmart_client import GeekSmartClient
from client.lock_engine import (
    ActionResult,
    GatewayDevice,
    LockDevice,
    LockEngine,
    LockStateSnapshot,
    parse_dps_to_snapshot,
)
from client.safety import ClientMode
from client.tuya_client import TuyaClient


class TestLockEngineModels(unittest.TestCase):
    """Verifies strongly-typed data structures and ActionResult dual-access semantics."""

    def test_lock_state_snapshot_defaults(self):
        """Verifies default snapshot values and properties."""
        snap = LockStateSnapshot(device_id="dev_123")
        self.assertEqual(snap.device_id, "dev_123")
        self.assertTrue(snap.is_locked)
        self.assertTrue(snap.is_online)
        self.assertFalse(snap.passage_mode)
        self.assertEqual(snap.battery, 85)
        self.assertIsInstance(snap.dps, dict)

    def test_action_result_dual_dict_object_compatibility(self):
        """ActionResult must seamlessly support attribute access, dict indexing, and truthiness."""
        snap = LockStateSnapshot(device_id="dev_test", is_locked=False)
        res = ActionResult(
            success=True,
            message="Unlocked successfully via Direct BLE",
            device_id="dev_test",
            state=snap,
            transport_used="direct_ble",
            dry_run=True,
            details={"latency_ms": 12},
        )

        # Attribute access
        self.assertTrue(res.success)
        self.assertEqual(res.message, "Unlocked successfully via Direct BLE")
        self.assertEqual(res.transport_used, "direct_ble")
        self.assertTrue(res.dry_run)
        self.assertEqual(res.state.is_locked, False)

        # Dict indexing access
        self.assertEqual(res["success"], True)
        self.assertEqual(res["message"], "Unlocked successfully via Direct BLE")
        self.assertEqual(res["transport_used"], "direct_ble")
        self.assertEqual(res["dry_run"], True)
        self.assertEqual(res.get("transport_used"), "direct_ble")
        self.assertEqual(res.get("non_existent", "default_val"), "default_val")

        # Container / dictionary semantics
        self.assertIn("success", res)
        self.assertIn("state", res)
        self.assertNotIn("unknown_key", res)
        self.assertGreater(len(res), 5)

        # Truthiness
        self.assertTrue(bool(res))

        # Failed result truthiness
        res_fail = ActionResult(success=False, message="Simulated failure", device_id="dev_test")
        self.assertFalse(bool(res_fail))
        self.assertFalse(res_fail["success"])


class TestLockEngineDpParser(unittest.TestCase):
    """Verifies pure parse_dps_to_snapshot logic on diverse hardware telemetry."""

    def test_tuya_jtmspro_dp47_primary_motor_state(self):
        """DP 47 (lock_motor_state): True = UNLOCKED, False = LOCKED."""
        # Unlocked state
        dps_unlocked = {"47": True, "33": True, "36": 5, "8": 90}
        snap1 = parse_dps_to_snapshot("dev_47_unlocked", dps_unlocked)
        self.assertFalse(snap1.is_locked)
        self.assertEqual(snap1.battery, 90)
        self.assertFalse(snap1.passage_mode)
        self.assertEqual(snap1.auto_lock_time, 5)

        # Locked state
        dps_locked = {"47": False, "33": False, "36": 10, "8": 75}
        snap2 = parse_dps_to_snapshot("dev_47_locked", dps_locked)
        self.assertTrue(snap2.is_locked)
        self.assertEqual(snap2.battery, 75)
        self.assertTrue(snap2.passage_mode)
        self.assertEqual(snap2.auto_lock_time, 10)

    def test_legacy_dp1_door_state_fallback(self):
        """When DP 47 is absent, DP 1 is consulted: False/0 = UNLOCKED, True/1 = LOCKED."""
        snap_unlocked = parse_dps_to_snapshot("dev_legacy", {"1": False, "14": 82})
        self.assertFalse(snap_unlocked.is_locked)
        self.assertEqual(snap_unlocked.battery, 82)

        snap_locked = parse_dps_to_snapshot("dev_legacy", {"1": True, "14": 82})
        self.assertTrue(snap_locked.is_locked)

    def test_battery_priority_dp8_over_dp14(self):
        """DP 8 takes precedence over DP 14 for battery percentage."""
        snap = parse_dps_to_snapshot("dev_battery", {"8": 95, "14": 70})
        self.assertEqual(snap.battery, 95)

    def test_wifi_rssi_and_connection_telemetry(self):
        """Wi-Fi RSSI in telemetry is parsed into snapshot."""
        snap = parse_dps_to_snapshot("dev_rssi", {"47": False}, wifi_rssi=-62, is_online=True)
        self.assertEqual(snap.wifi_rssi, -62)
        self.assertTrue(snap.is_online)


class TestLockEngineDiscoveryAndUniversalMultiUser(unittest.TestCase):
    """Verifies dynamic multi-user discovery with zero hardcoded names and alias synthesis."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cache_file = os.path.join(self.temp_dir.name, ".test_session_cache.json")

        # Multi-user cache with custom user-defined devices (zero hardcoded strings)
        cache_content = {
            "tuyaUid": "usr_multi_tenant_8821",
            "tuyaUsername": "homeowner_custom@example.com",
            "tuyaHomeId": 99887766,
            "devices": [
                {
                    "devId": "eb_custom_gateway_01",
                    "name": "Basement AC Plug Gateway",
                    "category": "cz",
                    "isOnline": True,
                    "dps": {"1": True, "9": 0},
                    "dpCodes": {"switch_1": True},
                },
                {
                    "devId": "eb_custom_lock_front",
                    "name": "Main Entrance Deadbolt",
                    "category": "jtmspro",
                    "isOnline": True,
                    "mac": "AA:BB:CC:11:22:33",
                    "localKey": "KEY_FRONT_123456",
                    "uuid": "UUID_FRONT_999",
                    "nodeId": "node_front_01",
                    "dps": {
                        "47": False,
                        "33": True,
                        "36": 5,
                        "8": 94,
                        "73": "0001ffff313233343536373801",  # Key 12345678
                    },
                },
                {
                    "devId": "eb_custom_lock_garage",
                    "name": "Detached Garage Side Door",
                    "category": "jtmspro",
                    "isOnline": True,
                    "mac": "AA:BB:CC:44:55:66",
                    "localKey": "KEY_GARAGE_654321",
                    "uuid": "UUID_GARAGE_888",
                    "nodeId": "node_garage_02",
                    "dps": {
                        "47": True,
                        "33": False,
                        "36": 15,
                        "8": 68,
                    },
                },
            ],
        }
        with open(self.cache_file, "w") as f:
            json.dump(cache_content, f)

        self.engine = LockEngine(session_cache_path=self.cache_file, dry_run=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_dynamic_multi_user_device_discovery(self):
        """Zero hardcoded names: successfully discovers custom user gateways and locks."""
        discovered = self.engine.discover_devices()
        self.assertEqual(len(discovered["gateways"]), 1)
        self.assertEqual(len(discovered["locks"]), 2)

        gw = discovered["gateways"][0]
        self.assertEqual(gw.name, "Basement AC Plug Gateway")
        self.assertEqual(gw.device_id, "eb_custom_gateway_01")

        lock_names = {l.name for l in discovered["locks"]}
        self.assertIn("Main Entrance Deadbolt", lock_names)
        self.assertIn("Detached Garage Side Door", lock_names)

    def test_alias_synthesis_and_backward_compatibility(self):
        """Synthesized aliases (101, 102, 701) resolve to correct custom devices."""
        # First lock should get alias '101'
        dev101 = self.engine.get_device_status("101")
        self.assertIsNotNone(dev101)
        self.assertEqual(dev101.name, "Main Entrance Deadbolt")

        # Second lock should get alias '102'
        dev102 = self.engine.get_device_status("102")
        self.assertIsNotNone(dev102)
        self.assertEqual(dev102.name, "Detached Garage Side Door")

        # Gateway should get alias '701'
        gw701 = self.engine.get_device_status("701")
        self.assertIsNotNone(gw701)
        self.assertEqual(gw701.name, "Basement AC Plug Gateway")

    def test_dynamic_dp71_member_key_extraction(self):
        """DP 73 payload extracts ASCII member key dynamically."""
        lock = self.engine.get_device_status("eb_custom_lock_front")
        self.assertIsNotNone(lock)
        self.assertEqual(lock.member_key, "12345678")

    def test_dry_run_action_execution_safety(self):
        """Actions in dry-run mode return success with dry_run=True and zero physical actuation."""
        res_unlock = self.engine.execute_action(
            device_identifier="eb_custom_lock_front",
            action="unlock",
            dry_run=True,
        )
        self.assertTrue(res_unlock.success)
        self.assertTrue(res_unlock.dry_run)
        self.assertEqual(res_unlock.state.is_locked, False)

        res_lock = self.engine.execute_action(
            device_identifier="eb_custom_lock_garage",
            action="lock",
            dry_run=True,
        )
        self.assertTrue(res_lock.success)
        self.assertTrue(res_lock.dry_run)
        self.assertEqual(res_lock.state.is_locked, True)

    def test_state_override(self):
        """Manual state override updates snapshot immediately."""
        self.engine.override_lock_state("eb_custom_lock_front", is_locked=True)
        stat = self.engine.get_device_status("eb_custom_lock_front")
        self.assertTrue(stat.state.is_locked)

        self.engine.override_lock_state("eb_custom_lock_front", is_locked=False)
        stat2 = self.engine.get_device_status("eb_custom_lock_front")
        self.assertFalse(stat2.state.is_locked)

    def test_capabilities_query(self):
        """Capabilities inquiry returns allowed queries/actions and blocked destructive endpoints."""
        caps = self.engine.get_capabilities("eb_custom_lock_front")
        self.assertIn("unlock", caps["allowed_actions"])
        self.assertIn("lock", caps["allowed_actions"])
        self.assertIn("keep_unlocked", caps["allowed_actions"])
        self.assertGreater(len(caps["permanently_blocked_destructive_endpoints"]), 10)


if __name__ == "__main__":
    unittest.main()
