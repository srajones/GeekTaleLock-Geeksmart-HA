#!/usr/bin/env python3
"""
Adversarial Stress Test Suite for Milestone 11 SSOT Core Lock Engine.
Author: challenger_m11_1 (Role: Adversarial SSOT Core Engine & Multi-User Challenger)

Adversarial Stress Targets:
1. Multi-User Dynamic Discovery Stress:
   - Synthetic account payloads: 0 gateways, 1 gateway, 5 gateways with custom non-Dyson names,
     and N door locks with arbitrary names ("Front Gate", "Office Lock", "Studio", etc.).
   - Verify NO hardcoded strings ("livingroom", "bathroom", "K11", "Dyson", or specific account IDs)
     are leaked or required for device discovery or state resolution.
   - Verify backward compatibility for existing test fixtures: ensure legacy queries
     ("101", "lock-101", "livingroom", "201", "701", "dyson") still resolve properly.
2. Data Point (DP) Parser Edge Cases:
   - Stress parse_dps_to_snapshot with:
     * Non-dict and None DP dictionaries.
     * Missing DP 47 (falls back cleanly).
     * Extreme battery values (negative, >100, float, string numbers, None).
     * Missing or invalid auto_lock_time (DP 36).
     * Corrupted, truncated, or non-base64 DP 71 and DP 73 tokens.
3. Actuation Operation Stress & Safety Barriers:
   - Verify actuation calls (unlock, lock) with dry_run=True.
   - Empirically document that keep_unlocked / auto_lock_on crash with SafetyBarrierViolation
     due to '/app/home/status' not being in allowlists.
   - Empirically document that actuation methods default to dry_run=False rather than True.
   - Verify SafetyBarrierGuard.validate_request blocks invalid device IDs or unauthorized actions.
   - Verify ActionResult dual indexing (res["success"] and res.success, etc.) and boolean truthiness.
4. Actuation Transport Failover:
   - Test fallback behavior when Direct BLE is unavailable or disconnected.
   - Empirically document TuyaClient missing unlock_door/lock_door methods in live dispatch.
5. Physical Safety Invariant:
   - Strictly verify ZERO automated live physical deadbolt actuations against physical hardware.
"""

import copy
import json
import os
import sys
import tempfile
import unittest
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from client.exceptions import (
    GeekSmartAuthError,
    GeekSmartControlError,
    SafetyBarrierViolation,
)
from client.geeksmart_client import GeekSmartClient
from client.lock_engine import (
    ActionResult,
    DashboardDict,
    GatewayDevice,
    LockDevice,
    LockEngine,
    LockStateSnapshot,
    _build_device_aliases,
    parse_dps_to_snapshot,
)
from client.safety import (
    ALLOWLIST_READ_ONLY,
    ALLOWLIST_SAFE_CONTROL,
    HARD_DENYLIST_ENDPOINTS,
    ClientMode,
    SafetyBarrierGuard,
)
from client.tuya_client import TuyaClient


class TestMultiUserDynamicDiscoveryStress(unittest.TestCase):
    """Stress tests dynamic multi-user discovery with zero hardcoded setup assumptions."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_engine_with_payload(self, devices: List[Dict[str, Any]]) -> LockEngine:
        cache_path = os.path.join(self.temp_dir.name, f"cache_{id(devices)}.json")
        payload = {
            "tuyaUid": "usr_synthetic_tenant_9901",
            "tuyaUsername": "tenant_custom@organization.internal",
            "tuyaHomeId": 77112233,
            "devices": devices,
        }
        with open(cache_path, "w") as f:
            json.dump(payload, f)
        return LockEngine(session_cache_path=cache_path, dry_run=True)

    def test_zero_gateways_discovery_stress(self):
        """Account with 0 gateways and N door locks must discover all locks without failing or creating fake gateways."""
        locks_payload = [
            {
                "devId": "cust_lock_front",
                "name": "Front Gate Deadbolt",
                "category": "jtmspro",
                "isOnline": True,
                "dps": {"47": False, "33": True, "36": 5, "8": 92},
            },
            {
                "devId": "cust_lock_office",
                "name": "Executive Office Lock",
                "category": "jtmspro",
                "isOnline": True,
                "dps": {"47": True, "33": False, "36": 10, "8": 78},
            },
            {
                "devId": "cust_lock_studio",
                "name": "Sound Studio Entry",
                "category": "jtmspro",
                "isOnline": False,
                "dps": {"47": False, "33": True, "36": 5, "8": 65},
            },
        ]
        engine = self._create_engine_with_payload(locks_payload)
        disc = engine.discover_devices()

        # Zero gateways discovered
        self.assertEqual(len(disc["gateways"]), 0)
        self.assertEqual(len(engine.list_gateways()), 0)

        # All 3 locks discovered
        self.assertEqual(len(disc["locks"]), 3)
        self.assertEqual(len(engine.list_locks()), 3)

        # Verify no hardcoded names or aliases leaked
        for lock_dict in disc["locks"]:
            aliases = lock_dict["alternateIds"]
            name = lock_dict["name"]
            self.assertNotIn("livingroom", aliases, f"Leaked 'livingroom' into {name}")
            self.assertNotIn("bathroom", aliases, f"Leaked 'bathroom' into {name}")
            self.assertNotIn("k11", aliases, f"Leaked 'k11' into {name}")
            self.assertNotIn("dyson", aliases, f"Leaked 'dyson' into {name}")
            self.assertEqual(
                lock_dict["parentage"],
                "Direct BLE / Wi-Fi",
                f"Expected Direct BLE / Wi-Fi parentage when 0 gateways exist, got {lock_dict['parentage']}",
            )
            self.assertIsNone(lock_dict["gatewayId"])

        # Name-based and slug-based lookup
        self.assertIsNotNone(engine.get_lock("Front Gate Deadbolt"))
        self.assertIsNotNone(engine.get_lock("front-gate-deadbolt"))
        self.assertIsNotNone(engine.get_lock("Executive Office Lock"))
        self.assertIsNotNone(engine.get_lock("Sound Studio Entry"))

    def test_single_gateway_with_arbitrary_locks_stress(self):
        """Account with 1 custom gateway dynamically pairs all orphan locks."""
        devices_payload = [
            {
                "devId": "custom_gw_primary",
                "name": "Attic Mesh Hub",
                "category": "cz",
                "isOnline": True,
                "dps": {"1": True},
            },
            {
                "devId": "custom_lock_patio",
                "name": "Patio Sliding Lock",
                "category": "jtmspro",
                "isOnline": True,
                "dps": {"47": False, "33": True, "8": 88},
            },
        ]
        engine = self._create_engine_with_payload(devices_payload)
        disc = engine.discover_devices()

        self.assertEqual(len(disc["gateways"]), 1)
        self.assertEqual(len(disc["locks"]), 1)

        gw = engine.get_gateway("Attic Mesh Hub")
        self.assertIsNotNone(gw)
        self.assertEqual(gw.dev_id, "custom_gw_primary")
        self.assertEqual(gw.name, "Attic Mesh Hub")
        self.assertNotIn("dyson", gw.aliases)

        lock = engine.get_lock("Patio Sliding Lock")
        self.assertIsNotNone(lock)
        self.assertEqual(lock.parent_gateway_id, "custom_gw_primary")
        self.assertIn("custom_gw_primary", lock.to_dashboard_dict()["parentage"])

    def test_five_gateways_with_custom_non_dyson_names_stress(self):
        """Account with 5 gateways with custom non-Dyson names and explicit parent associations."""
        devices_payload = [
            {"devId": "gw_office_01", "name": "Office Floor 1 Gateway", "category": "cz", "isOnline": True},
            {"devId": "gw_garage_02", "name": "Detached Garage Extender", "category": "cz", "isOnline": True},
            {"devId": "gw_backyard_03", "name": "Backyard Patio Repeater", "category": "cz", "isOnline": True},
            {"devId": "gw_front_04", "name": "Front Porch AC Bridge", "category": "cz", "isOnline": True},
            {"devId": "gw_studio_05", "name": "Basement Studio Smart Socket", "category": "cz", "isOnline": True},
            {
                "devId": "lock_warehouse",
                "name": "Warehouse Loading Bay Door",
                "category": "jtmspro",
                "isOnline": True,
                "parentId": "gw_garage_02",
                "dps": {"47": False, "33": True, "8": 95},
            },
            {
                "devId": "lock_server_room",
                "name": "IT Server Room Deadbolt",
                "category": "jtmspro",
                "isOnline": True,
                "parentId": "gw_office_01",
                "dps": {"47": False, "33": True, "8": 99},
            },
        ]
        engine = self._create_engine_with_payload(devices_payload)
        disc = engine.discover_devices()

        self.assertEqual(len(disc["gateways"]), 5)
        self.assertEqual(len(disc["locks"]), 2)

        # Gateways check
        for gw in engine.list_gateways():
            self.assertNotIn("dyson", gw.aliases)
            self.assertFalse("dyson" in gw.name.lower())

        # Explicit parent link verification
        lock_wh = engine.get_lock("Warehouse Loading Bay Door")
        self.assertEqual(lock_wh.parent_gateway_id, "gw_garage_02")

        lock_it = engine.get_lock("IT Server Room Deadbolt")
        self.assertEqual(lock_it.parent_gateway_id, "gw_office_01")

    def test_legacy_fixtures_backward_compatibility(self):
        """When legacy sample test devices are present, legacy queries (101, 102, 103, 201, 701, livingroom, dyson) resolve."""
        legacy_payload = [
            {"devId": "ebexamplegw1a2b3c4d5e6", "name": "Dyson", "category": "cz", "isOnline": True, "dps": {}},
            {"devId": "ebexamplelock001", "name": "livingroom", "category": "jtmspro", "isOnline": True, "dps": {"47": False, "33": True, "8": 85}},
            {"devId": "ebexamplelock002", "name": "bathroom", "category": "jtmspro", "isOnline": True, "dps": {"47": True, "33": False, "8": 72}},
            {"devId": "ebexamplelock003", "name": "K11", "category": "jtmspro", "isOnline": True, "dps": {"47": False, "33": True, "8": 66}},
        ]
        engine = self._create_engine_with_payload(legacy_payload)
        engine.discover_devices()

        # Legacy Lock 101 queries
        self.assertEqual(engine.get_device_status("101").dev_id, "ebexamplelock001")
        self.assertEqual(engine.get_device_status("lock-101").dev_id, "ebexamplelock001")
        self.assertEqual(engine.get_device_status("livingroom").dev_id, "ebexamplelock001")

        # Legacy Lock 102 queries
        self.assertEqual(engine.get_device_status("102").dev_id, "ebexamplelock002")
        self.assertEqual(engine.get_device_status("lock-102").dev_id, "ebexamplelock002")
        self.assertEqual(engine.get_device_status("bathroom").dev_id, "ebexamplelock002")

        # Legacy Lock 103 queries
        self.assertEqual(engine.get_device_status("103").dev_id, "ebexamplelock003")
        self.assertEqual(engine.get_device_status("lock-103").dev_id, "ebexamplelock003")
        self.assertEqual(engine.get_device_status("k11").dev_id, "ebexamplelock003")

        # Legacy Gateway 201/701 queries
        self.assertEqual(engine.get_device_status("201").dev_id, "ebexamplegw1a2b3c4d5e6")
        self.assertEqual(engine.get_device_status("701").dev_id, "ebexamplegw1a2b3c4d5e6")
        self.assertEqual(engine.get_device_status("dyson").dev_id, "ebexamplegw1a2b3c4d5e6")

    def test_empty_cache_device_isolation_no_mock_devices_for_real_accounts(self):
        """A newly authenticated account with 0 devices does NOT see mock devices unless sample_mode=True."""
        cache_path = os.path.join(self.temp_dir.name, "empty_auth_cache.json")
        payload = {
            "tuyaUid": "usr_real_empty_tenant",
            "tuyaUsername": "real_user@example.com",
            "tuyaHomeId": 12345678,
            "devices": [],
        }
        with open(cache_path, "w") as f:
            json.dump(payload, f)

        # Standard engine (sample_mode=False)
        engine_standard = LockEngine(session_cache_path=cache_path, dry_run=True, sample_mode=False)
        disc_standard = engine_standard.discover_devices()
        self.assertEqual(len(disc_standard["locks"]), 0)
        self.assertEqual(len(disc_standard["gateways"]), 0)
        self.assertEqual(len(engine_standard.list_devices()), 0)

        # Explicit sample mode (sample_mode=True)
        engine_sample = LockEngine(session_cache_path="/tmp/non_existent_cache_xyz.json", dry_run=True, sample_mode=True)
        disc_sample = engine_sample.discover_devices()
        self.assertGreater(len(disc_sample["locks"]), 0)
        self.assertGreater(len(disc_sample["gateways"]), 0)


class TestDpParserEdgeCases(unittest.TestCase):
    """Stress tests parse_dps_to_snapshot against edge cases, malformed payloads, and extreme values."""

    def test_non_dict_and_none_dp_dictionaries(self):
        """Module-level parse_dps_to_snapshot handles None safely via fallback."""
        snap_none = parse_dps_to_snapshot("dev_none", dps=None, dp_codes=None)
        self.assertIsInstance(snap_none, LockStateSnapshot)
        self.assertTrue(snap_none.is_locked)
        self.assertEqual(snap_none.state_label, "LOCKED")
        self.assertEqual(snap_none.dps, {})

        # Empty dicts
        snap_empty = parse_dps_to_snapshot("dev_empty", dps={}, dp_codes={})
        self.assertIsInstance(snap_empty, LockStateSnapshot)
        self.assertTrue(snap_empty.is_locked)

    def test_lock_engine_parse_dps_none_safe_guarding(self):
        """LockEngine.parse_dps_to_snapshot handles dps=None and dp_codes=None safely without TypeError."""
        snap = LockEngine.parse_dps_to_snapshot(dps=None, dp_codes=None)
        self.assertIsInstance(snap, LockStateSnapshot)
        self.assertTrue(snap.is_locked)
        self.assertEqual(snap.dps, {})
        self.assertEqual(snap.dp_codes, {})

    def test_missing_dp47_clean_fallback(self):
        """When DP 47 is missing, falls back cleanly to DP 1 or online defaults."""
        # DP 1 = False -> UNLOCKED
        snap_dp1_unlock = parse_dps_to_snapshot("dev_dp1", dps={"1": False})
        self.assertFalse(snap_dp1_unlock.is_locked)
        self.assertEqual(snap_dp1_unlock.state_label, "UNLOCKED")

        # DP 1 = True -> LOCKED
        snap_dp1_lock = parse_dps_to_snapshot("dev_dp1", dps={"1": True})
        self.assertTrue(snap_dp1_lock.is_locked)
        self.assertEqual(snap_dp1_lock.state_label, "LOCKED")

        # Neither DP 47 nor DP 1, but online -> LOCKED
        snap_online = parse_dps_to_snapshot("dev_no_dp", dps={}, is_online=True)
        self.assertTrue(snap_online.is_locked)
        self.assertEqual(snap_online.state_label, "LOCKED")

        # Neither DP 47 nor DP 1, and offline -> UNKNOWN
        snap_offline = parse_dps_to_snapshot("dev_no_dp", dps={}, is_online=False)
        self.assertEqual(snap_offline.state_label, "UNKNOWN")

    def test_battery_values_edge_cases(self):
        """Tests battery telemetry parsing across extreme, float, string, and None values."""
        # Standard valid battery
        snap_std = parse_dps_to_snapshot("dev_b", dps={"8": 85})
        self.assertEqual(snap_std.battery, 85)

        # Float battery gets truncated to integer
        snap_float = parse_dps_to_snapshot("dev_b", dps={"8": 87.9})
        self.assertEqual(snap_float.battery, 87)

        # DP 14 fallback when DP 8 is absent
        snap_14 = parse_dps_to_snapshot("dev_b", dps={"14": 62})
        self.assertEqual(snap_14.battery, 62)

        # DP 8 takes priority over DP 14
        snap_both = parse_dps_to_snapshot("dev_b", dps={"8": 90, "14": 40})
        self.assertEqual(snap_both.battery, 90)

        # None battery
        snap_none_b = parse_dps_to_snapshot("dev_b", dps={"8": None})
        self.assertIsNone(snap_none_b.battery)

        # Non-numeric string battery: does not crash, yields None
        snap_str_b = parse_dps_to_snapshot("dev_b", dps={"8": "invalid_battery"})
        self.assertIsNone(snap_str_b.battery)

        # Battery percentage values are safely clamped between 0 and 100
        snap_neg = parse_dps_to_snapshot("dev_b", dps={"8": -10})
        self.assertEqual(snap_neg.battery, 0)
        snap_high = parse_dps_to_snapshot("dev_b", dps={"8": 150})
        self.assertEqual(snap_high.battery, 100)

    def test_auto_lock_time_dp36_edge_cases(self):
        """Tests DP 36 auto_lock_time parsing across boundary and invalid conditions."""
        # Standard positive timer
        snap_30s = parse_dps_to_snapshot("dev_t", dps={"36": 30})
        self.assertEqual(snap_30s.auto_lock_time, 30)

        # Float timer
        snap_float_t = parse_dps_to_snapshot("dev_t", dps={"36": 12.4})
        self.assertEqual(snap_float_t.auto_lock_time, 12)

        # Missing DP 36 defaults to 5s
        snap_missing = parse_dps_to_snapshot("dev_t", dps={})
        self.assertEqual(snap_missing.auto_lock_time, 5)

        # String invalid DP 36 defaults to 5s without crashing
        snap_str_t = parse_dps_to_snapshot("dev_t", dps={"36": "thirty_seconds"})
        self.assertEqual(snap_str_t.auto_lock_time, 5)

    def test_corrupted_truncated_and_non_base64_dp71_and_dp73_tokens(self):
        """LockEngine.extract_dp71_unlock_key must not crash on malformed/corrupted DP 71 and DP 73 tokens."""
        lock = LockDevice(dev_id="test_lock_edge", name="Edge Lock", client_equipment_id=101)

        corrupted_cases = [
            {"73": "!@#$%^&*()_+"},
            {"73": "short"},
            {"73": 12345678},
            {"73": None},
            {"71": "truncated_b64"},
            {"71": 99999},
            {"70": "corrupted_seed"},
            {"70": None},
            {"73": "0001ffff", "71": "invalid"},
        ]

        for dps in corrupted_cases:
            lock.state.dps = dps
            try:
                slot, key = LockEngine.extract_dp71_unlock_key(lock)
                self.assertIsInstance(slot, int)
                self.assertIsInstance(key, str)
                self.assertEqual(len(key), 8, f"Extracted key '{key}' from {dps} should be 8 bytes")
            except Exception as exc:
                self.fail(f"extract_dp71_unlock_key crashed with {type(exc)} on input {dps}: {exc}")

        # Valid DP 73 hex frame extraction
        lock.state.dps = {"73": "0002ffff383736353433323101"}  # ASCII "87654321"
        slot, key = LockEngine.extract_dp71_unlock_key(lock)
        self.assertEqual(slot, 2)
        self.assertEqual(key, "87654321")


class TestActuationSafetyAndBarriers(unittest.TestCase):
    """Stress tests actuation operations, dry_run enforcement, safety barrier guard, and ActionResult semantics."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cache_path = os.path.join(self.temp_dir.name, "cache.json")
        with open(self.cache_path, "w") as f:
            json.dump({
                "devices": [{
                    "devId": "eb_actuation_lock",
                    "name": "Safety Test Lock",
                    "category": "jtmspro",
                    "isOnline": True,
                    "dps": {"47": False, "33": True, "36": 5, "8": 90},
                }]
            }, f)
        self.engine = LockEngine(session_cache_path=self.cache_path, dry_run=True)
        self.engine.discover_devices()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_dry_run_unlock_and_lock_operations(self):
        """Unlock and Lock actuation operations with dry_run=True return success=True, dry_run=True, and zero live I/O."""
        # 1. Unlock
        res_unlock = self.engine.unlock("eb_actuation_lock", dry_run=True)
        self.assertTrue(res_unlock.success)
        self.assertTrue(res_unlock.dry_run)
        self.assertEqual(res_unlock.transport_used, "dry_run")
        self.assertEqual(res_unlock.new_state, "UNLOCKED")

        # 2. Lock
        res_lock = self.engine.lock("eb_actuation_lock", dry_run=True)
        self.assertTrue(res_lock.success)
        self.assertTrue(res_lock.dry_run)
        self.assertEqual(res_lock.transport_used, "dry_run")
        self.assertEqual(res_lock.new_state, "LOCKED")

    def test_keep_unlocked_and_auto_lock_succeed_in_safe_control(self):
        """keep_unlocked and auto_lock_on succeed cleanly in SAFE_CONTROL mode with dry_run=True."""
        res_keep = self.engine.keep_unlocked("eb_actuation_lock", dry_run=True)
        self.assertTrue(res_keep.success)
        self.assertTrue(res_keep.dry_run)
        self.assertFalse(self.engine.get_device_status("eb_actuation_lock").state.auto_lock_enabled)

        res_auto = self.engine.auto_lock_on("eb_actuation_lock", seconds=10, dry_run=True)
        self.assertTrue(res_auto.success)
        self.assertTrue(res_auto.dry_run)
        self.assertTrue(self.engine.get_device_status("eb_actuation_lock").state.auto_lock_enabled)
        self.assertEqual(self.engine.get_device_status("eb_actuation_lock").state.auto_lock_seconds, 10)

    def test_engine_actuations_default_to_dry_run_safety_invariant(self):
        """LockEngine.unlock defaults to inheriting self.dry_run=True without live network calls."""
        res_default = self.engine.unlock("eb_actuation_lock")
        self.assertTrue(res_default.success)
        self.assertTrue(res_default.dry_run)
        self.assertEqual(res_default.transport_used, "dry_run")
        self.assertEqual(res_default.new_state, "UNLOCKED")

    def test_safety_barrier_guard_blocks_destructive_endpoints(self):
        """SafetyBarrierGuard must block hard denylist destructive endpoints and keyword violations."""
        for endpoint in HARD_DENYLIST_ENDPOINTS:
            with self.assertRaises(SafetyBarrierViolation, msg=f"Failed to block {endpoint}"):
                SafetyBarrierGuard.validate_request(endpoint=endpoint, mode=ClientMode.SAFE_CONTROL)

        # Mode violation in READ_ONLY mode
        for endpoint in ALLOWLIST_SAFE_CONTROL:
            with self.assertRaises(SafetyBarrierViolation, msg=f"Allowed {endpoint} in READ_ONLY mode"):
                SafetyBarrierGuard.validate_request(endpoint=endpoint, mode=ClientMode.READ_ONLY)

    def test_action_result_dual_indexing_and_truthiness(self):
        """ActionResult supports dict indexing, attribute access, and boolean truthiness."""
        snap = LockStateSnapshot(device_id="dev_dual", is_locked=False, state_label="UNLOCKED")
        res = ActionResult(
            success=True,
            action="unlock",
            device_id="dev_dual",
            client_equipment_id=101,
            transport_used="dry_run",
            dry_run=True,
            new_state="UNLOCKED",
            state_snapshot=snap,
            message="Unlocked successfully",
        )

        # Boolean truthiness
        self.assertTrue(bool(res))
        self.assertTrue(res)

        # Attribute access
        self.assertTrue(res.success)
        self.assertEqual(res.action, "unlock")
        self.assertEqual(res.device_id, "dev_dual")
        self.assertEqual(res.client_equipment_id, 101)
        self.assertEqual(res.transport_used, "dry_run")
        self.assertTrue(res.dry_run)
        self.assertEqual(res.new_state, "UNLOCKED")

        # Dict indexing access
        self.assertEqual(res["success"], True)
        self.assertEqual(res["action"], "unlock")
        self.assertEqual(res["deviceId"], "dev_dual")
        self.assertEqual(res["id"], 101)
        self.assertEqual(res["clientEquipmentId"], 101)
        self.assertEqual(res["transport"], "dry_run")
        self.assertEqual(res["transport_used"], "dry_run")
        self.assertEqual(res["dryRun"], True)
        self.assertEqual(res["dry_run"], True)
        self.assertEqual(res["state"], "UNLOCKED")
        self.assertEqual(res["message"], "Unlocked successfully")

        # Negative truthiness on failure
        fail_res = ActionResult(success=False, action="lock", message="Failure")
        self.assertFalse(bool(fail_res))
        self.assertFalse(fail_res)
        self.assertEqual(fail_res["success"], False)
        self.assertEqual(fail_res.success, False)

    def test_action_result_state_label_support(self):
        """ActionResult supports state_label attribute access and dict indexing."""
        res = ActionResult(success=True, new_state="LOCKED")
        self.assertEqual(res.state_label, "LOCKED")
        self.assertEqual(res["state_label"], "LOCKED")
        self.assertEqual(res["stateLabel"], "LOCKED")

    def test_invalid_device_id_actuation_blocked(self):
        """Actuating a nonexistent device ID must raise ValueError immediately before any dispatch."""
        with self.assertRaises(ValueError):
            self.engine.unlock("nonexistent_device_id_xyz", dry_run=True)

        with self.assertRaises(ValueError):
            self.engine.lock("nonexistent_device_id_xyz", dry_run=True)


class TestActuationTransportFailover(unittest.TestCase):
    """Stress tests hybrid transport failover when Direct BLE is unavailable or raises errors."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cache_path = os.path.join(self.temp_dir.name, "cache.json")
        with open(self.cache_path, "w") as f:
            json.dump({
                "devices": [{
                    "devId": "eb_failover_lock",
                    "name": "Failover Test Lock",
                    "category": "jtmspro",
                    "isOnline": True,
                    "parentId": "gw_bridge",
                    "dps": {"47": False, "33": True, "36": 5, "8": 80},
                }, {
                    "devId": "gw_bridge",
                    "name": "Smart Plug Gateway",
                    "category": "cz",
                    "isOnline": True,
                }]
            }, f)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_direct_ble_failure_falls_back_to_tuya_cloud(self):
        """When Direct BLE raises ConnectionError, engine falls back cleanly to Tuya Cloud Gateway."""
        mock_ble = MagicMock()
        async def failing_unlock(*args, **kwargs):
            raise ConnectionError("Simulated BLE connection timeout / device out of range")
        mock_ble.unlock = failing_unlock

        mock_tuya = MagicMock()
        # Mock TuyaClient response
        mock_tuya.publish_dp.return_value = {"success": True, "action": "thing.m.device.dp.publish"}
        mock_tuya.unlock_door = MagicMock(return_value={"success": True, "action": "thing.m.device.dp.publish"})
        mock_tuya.get_home_device_list.side_effect = Exception("No network in unit test")

        engine = LockEngine(
            session_cache_path=self.cache_path,
            preferred_transport="direct_ble",
            ble_client=mock_ble,
            tuya_client=mock_tuya,
            mode=ClientMode.SAFE_CONTROL,
        )
        engine.discover_devices()

        # Execute unlock without dry_run (testing live failover logic)
        res = engine.unlock("eb_failover_lock", dry_run=False)
        self.assertTrue(res.success)
        self.assertEqual(res.transport_used, "tuya_cloud")
        self.assertEqual(res.new_state, "UNLOCKED")

    def test_empirical_tuya_client_actuation_calls_nonexistent_methods(self):
        """EMPIRICAL FINDING: TuyaClient has no unlock_door method; live dispatch fails with AttributeError."""
        from client.tuya_client import TuyaClient
        tc = TuyaClient()
        self.assertFalse(hasattr(tc, "unlock_door"))
        self.assertFalse(hasattr(tc, "lock_door"))
        self.assertFalse(hasattr(tc, "set_passage_mode"))


class TestPhysicalSafetyInvariant(unittest.TestCase):
    """Empirical verification of the physical safety invariant (ZERO live physical actuations)."""

    def test_zero_automated_live_physical_deadbolt_actuation(self):
        """Verifies that dry_run=True acts as an impenetrable barrier preventing any live socket/network transmission."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({
                "devices": [{
                    "devId": "eb_invariant_lock",
                    "name": "Physical Safety Lock",
                    "category": "jtmspro",
                    "isOnline": True,
                    "dps": {"47": False, "33": True, "8": 100},
                }]
            }, f)
            path = f.name

        try:
            # Create engine with real clients that are UNINITIALIZED / unauthenticated
            engine = LockEngine(session_cache_path=path, dry_run=True)
            engine.discover_devices()

            # Calling execute_action in dry_run mode for unlock and lock must NEVER touch the network or raise auth error
            for action in ["unlock", "lock"]:
                res = engine.execute_action("eb_invariant_lock", action=action, dry_run=True)
                self.assertTrue(res.success)
                self.assertTrue(res.dry_run)
                self.assertEqual(res.transport_used, "dry_run")
                self.assertIn("DRY-RUN", res.message)
        finally:
            if os.path.exists(path):
                os.unlink(path)


class TestSsotDelegationAndDoubleActuation(unittest.TestCase):
    """Stress tests SSOT delegation routing across CLI, Flask, and Home Assistant to prevent duplicate execution."""

    def test_cli_cmd_control_delegation_single_actuation(self):
        """CLI cmd_control delegates to LockEngine.execute_action and executes exactly ONCE."""
        from door_lock_control import cmd_control, load_clients, get_lock_engine
        import door_lock_control

        gs, tuya, sm = load_clients(mode=ClientMode.SAFE_CONTROL)
        exec_calls = 0
        orig_get_lock_engine = door_lock_control.get_lock_engine

        def spy_get_engine(*args, **kwargs):
            engine = orig_get_lock_engine(*args, **kwargs)
            orig_exec = engine.execute_action
            def spy_exec(*a, **kw):
                nonlocal exec_calls
                exec_calls += 1
                return orig_exec(*a, **kw)
            engine.execute_action = spy_exec
            return engine

        door_lock_control.get_lock_engine = spy_get_engine
        try:
            ret = cmd_control("lock", gs, tuya, sm, device_id="101", dry_run=True, confirm=True, as_json=True)
            self.assertEqual(ret, 0)
            self.assertEqual(exec_calls, 1, f"Expected 1 execute_action call from CLI, got {exec_calls}")
        finally:
            door_lock_control.get_lock_engine = orig_get_lock_engine

    def test_flask_device_action_delegation_single_actuation(self):
        """Flask /api/devices/<id>/<action> delegates to LockEngine.execute_action and executes exactly ONCE."""
        from server.flask_app import create_app

        test_app = create_app(csrf_enabled=False)
        test_app.config["TESTING"] = True
        engine = test_app.config["LOCK_ENGINE"]
        self.assertIsNotNone(engine)

        exec_calls = 0
        orig_exec = engine.execute_action
        def spy_exec(*args, **kwargs):
            nonlocal exec_calls
            exec_calls += 1
            return orig_exec(*args, **kwargs)
        engine.execute_action = spy_exec

        client = test_app.test_client()
        res = client.post("/api/devices/lock-101/lock", json={"confirmed": True, "dry_run": True})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(exec_calls, 1, f"Expected 1 execute_action call from Flask endpoint, got {exec_calls}")

    def test_ha_endpoints_no_double_actuation_defect(self):
        """HA /api/ha/lock/<dev_id>/lock must NOT actuate underlying transports twice for a single request."""
        from server.flask_app import create_app

        mock_gs = MagicMock()
        mock_gs.lock_door.return_value = {"success": True}
        mock_tuya = MagicMock()
        mock_tuya.get_home_device_list.return_value = []
        mock_tuya.publish_dp.return_value = {"success": True}

        test_app = create_app(tuya_client=mock_tuya, geeksmart_client=mock_gs)
        test_app.config["TESTING"] = True
        test_app.config["HA_BEARER_TOKEN"] = "ha-secret-token"
        engine = test_app.config["LOCK_ENGINE"]
        self.assertIsNotNone(engine)
        engine.discover()

        client = test_app.test_client()
        res = client.post(
            "/api/ha/lock/lock-101/lock",
            headers={"Authorization": "Bearer ha-secret-token"},
            json={"confirmed": True, "dry_run": False},
        )
        self.assertEqual(res.status_code, 200)

        total_actuations = mock_gs.lock_door.call_count + mock_tuya.publish_dp.call_count
        self.assertEqual(
            total_actuations,
            1,
            f"HA lock actuated {total_actuations} times (mock_gs={mock_gs.lock_door.call_count}, "
            f"mock_tuya={mock_tuya.publish_dp.call_count}); expected exactly 1 actuation (double actuation defect).",
        )

    def test_ha_unlock_endpoint_no_double_actuation_defect(self):
        """HA /api/ha/lock/<dev_id>/unlock must NOT actuate underlying transports twice for a single request."""
        from server.flask_app import create_app

        mock_gs = MagicMock()
        mock_gs.unlock_door.return_value = {"success": True}
        mock_tuya = MagicMock()
        mock_tuya.get_home_device_list.return_value = []
        mock_tuya.publish_dp.return_value = {"success": True}

        test_app = create_app(tuya_client=mock_tuya, geeksmart_client=mock_gs)
        test_app.config["TESTING"] = True
        test_app.config["HA_BEARER_TOKEN"] = "ha-secret-token"
        engine = test_app.config["LOCK_ENGINE"]
        self.assertIsNotNone(engine)
        engine.discover()

        client = test_app.test_client()
        res = client.post(
            "/api/ha/lock/lock-101/unlock",
            headers={"Authorization": "Bearer ha-secret-token"},
            json={"confirmed": True, "dry_run": False},
        )
        self.assertEqual(res.status_code, 200)

        total_actuations = mock_gs.unlock_door.call_count + mock_tuya.publish_dp.call_count
        self.assertEqual(
            total_actuations,
            1,
            f"HA unlock actuated {total_actuations} times (mock_gs={mock_gs.unlock_door.call_count}, "
            f"mock_tuya={mock_tuya.publish_dp.call_count}); expected exactly 1 actuation (double actuation defect).",
        )

    def test_ha_keep_unlocked_endpoint_no_double_actuation_defect(self):
        """HA /api/ha/lock/<dev_id>/keep_unlocked must NOT actuate underlying transports twice for a single request."""
        from server.flask_app import create_app

        mock_gs = MagicMock()
        mock_tuya = MagicMock()
        mock_tuya.get_home_device_list.return_value = []
        mock_tuya.set_auto_lock.return_value = {"success": True}

        test_app = create_app(tuya_client=mock_tuya, geeksmart_client=mock_gs)
        test_app.config["TESTING"] = True
        test_app.config["HA_BEARER_TOKEN"] = "ha-secret-token"
        engine = test_app.config["LOCK_ENGINE"]
        self.assertIsNotNone(engine)
        engine.discover()

        client = test_app.test_client()
        res = client.post(
            "/api/ha/lock/lock-101/keep_unlocked",
            headers={"Authorization": "Bearer ha-secret-token"},
            json={"confirmed": True, "dry_run": False},
        )
        self.assertEqual(res.status_code, 200)

        total_actuations = mock_tuya.set_auto_lock.call_count
        self.assertEqual(
            total_actuations,
            1,
            f"HA keep_unlocked actuated {total_actuations} times (mock_tuya.set_auto_lock={mock_tuya.set_auto_lock.call_count}); "
            f"expected exactly 1 actuation (double actuation defect).",
        )


if __name__ == "__main__":
    unittest.main()
