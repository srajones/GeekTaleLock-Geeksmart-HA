"""Smart Plug BLE Gateway outlet switch (Tuya cz, DP 1 / switch_1) — mocked, no credentials.

Verifies:
  * plug outlet publishes EXACTLY {"1": <bool>} to the plug devId (no gwId, no DP 71/33,
    no v2.0 DPCacheBusiness), even for plug devIds that start with "eb"
  * the lock DP1->DP71 remap in publish_dp() is unchanged for locks
  * hard guards refuse locks / non-cz devices / unknown devices with zero network I/O
  * HA switch entity reflects DP 1 and calls only engine.set_plug_outlet
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from custom_components.geek_door.const import MODE_DIRECT_CLOUD, MODE_SERVER_BRIDGE
from custom_components.geek_door.core.exceptions import SafetyBarrierViolation
from custom_components.geek_door.core.lock_engine import GatewayDevice, LockDevice, LockEngine
from custom_components.geek_door.core.tuya_client import TuyaClient

# Synthetic IDs (not real devices). PLUG_ID deliberately starts with "eb" like real Tuya ids.
PLUG_ID = "ebplugtestfakeplugxyz"
LOCK_ID = "eblocktest0001"
DYSON_LIKE_PLUG = {
    "devId": PLUG_ID,
    "name": "Test Plug",
    "category": "cz",
    "productId": "qvk3ovko8ht800a4",
    "parentId": None,
    "isOnline": True,
    "dps": {"1": True, "9": 0, "38": "memory", "40": "relay", "41": False},
    "dpCodes": {"switch_1": True, "countdown_1": 0},
}
LOCK_DEV = {
    "devId": LOCK_ID,
    "name": "Test Lock",
    "category": "jtmspro",
    "productId": "a0wnqgxs",
    "parentId": PLUG_ID,
    "isOnline": True,
    "dps": {
        "1": "A/8AAgcAAA==",
        "33": False,
        "47": True,
        "70": "AAH//zEyMzQ1Njc4AP//AA==",
        "71": "//8AATEyMzQ1Njc4AWrmKtsAAA==",
        "73": "AAH//zEyMzQ1Njc4AQABAA==",
    },
    "dpCodes": {"lock_motor_state": True},
}


def _write_cache(path: str, devices: List[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"email": "plugtest@example.com", "devices": devices}, f)


class _RecordingTuya(TuyaClient):
    def __init__(self, cache_path: str) -> None:
        super().__init__(session_cache_path=cache_path, load_cache=False)
        self.sid = "mock-sid"
        self.calls: List[Dict[str, Any]] = []

    def request(self, action, version="1.0", post_data=None, requires_session=True, **kw):  # type: ignore[override]
        self.calls.append({"action": action, "version": version, "post_data": dict(post_data or {})})
        return {"success": True, "result": True}


class TestTuyaPlugPublish(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = os.path.join(self.tmp.name, "cache.json")
        _write_cache(self.cache, [DYSON_LIKE_PLUG, LOCK_DEV])
        self.client = _RecordingTuya(self.cache)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_plug_off_publishes_exact_dp1_false(self) -> None:
        res = self.client.publish_plug_switch(PLUG_ID, False)
        self.assertTrue(res["success"])
        self.assertEqual(len(self.client.calls), 1)
        call = self.client.calls[0]
        self.assertEqual(call["action"], "thing.m.device.dp.publish")
        self.assertEqual(call["version"], "1.0")
        self.assertEqual(call["post_data"], {"devId": PLUG_ID, "dps": '{"1":false}'})
        self.assertNotIn("gwId", call["post_data"])

    def test_plug_on_publishes_exact_dp1_true(self) -> None:
        self.client.publish_plug_switch(PLUG_ID, True)
        self.assertEqual(json.loads(self.client.calls[0]["post_data"]["dps"]), {"1": True})

    def test_plug_rejects_non_bool(self) -> None:
        for bad in ("true", 1, None, "AQ=="):
            with self.assertRaises(SafetyBarrierViolation):
                self.client.publish_plug_switch(PLUG_ID, bad)  # type: ignore[arg-type]
        self.assertEqual(self.client.calls, [])

    def test_plug_publish_refuses_lock(self) -> None:
        for on in (True, False):
            with self.assertRaises(SafetyBarrierViolation) as ctx:
                self.client.publish_plug_switch(LOCK_ID, on)
            self.assertIn("lock", str(ctx.exception).lower())
        self.assertEqual(self.client.calls, [])

    def test_plug_publish_refuses_lock_even_if_caller_meta_lies(self) -> None:
        fake_meta = dict(DYSON_LIKE_PLUG, devId=LOCK_ID)
        with self.assertRaises(SafetyBarrierViolation):
            self.client.publish_plug_switch(LOCK_ID, True, device_meta=fake_meta)
        self.assertEqual(self.client.calls, [])

    def test_plug_publish_refuses_unknown_device(self) -> None:
        with self.assertRaises(SafetyBarrierViolation):
            self.client.publish_plug_switch("ebunknown123", True)
        self.assertEqual(self.client.calls, [])

    def test_plug_publish_refuses_non_cz_gateway(self) -> None:
        wg = dict(DYSON_LIKE_PLUG, devId="ebwg2gateway", category="wg2")
        _write_cache(self.cache, [wg])
        with self.assertRaises(SafetyBarrierViolation):
            self.client.publish_plug_switch("ebwg2gateway", True)
        self.assertEqual(self.client.calls, [])

    def test_plug_publish_refuses_cz_with_lock_dps(self) -> None:
        weird = dict(DYSON_LIKE_PLUG, dps={"1": True, "71": "AAAA"})
        _write_cache(self.cache, [weird])
        with self.assertRaises(SafetyBarrierViolation):
            self.client.publish_plug_switch(PLUG_ID, True)
        self.assertEqual(self.client.calls, [])

    def test_dry_run_no_network(self) -> None:
        res = self.client.publish_plug_switch(PLUG_ID, False, dry_run=True)
        self.assertTrue(res["dry_run"])
        self.assertEqual(res["dps"], {"1": False})
        self.assertEqual(self.client.calls, [])

    def test_generic_publish_dp_does_not_remap_plug_dp1(self) -> None:
        """Regression: an "eb..." plug id previously would be rewritten to a DP 71 lock frame."""
        res = self.client.publish_dp(PLUG_ID, {"1": False}, dry_run=True)
        self.assertEqual(res["dps"], {"1": False})
        self.assertNotIn("71", res["dps"])
        self.assertNotIn("33", res["dps"])

    def test_lock_remap_unchanged(self) -> None:
        """Lock path still rewrites boolean DP 1 into DP 71 (+DP 33 on lock) — not touched."""
        # Lock semantics: {"1": False} = unlock intent -> DP 71 frame with op byte 0x01.
        res = self.client.publish_dp(LOCK_ID, {"1": False}, dry_run=True)
        self.assertNotIn("1", res["dps"])
        frame = base64.b64decode(res["dps"]["71"])
        self.assertEqual(len(frame), 19)
        self.assertEqual(frame[12], 0x01)
        self.assertNotIn("33", res["dps"])
        # {"1": True} = lock intent -> DP 71 op byte 0x00 plus DP 33 auto-lock re-enable.
        res2 = self.client.publish_dp(LOCK_ID, {"1": True}, dry_run=True)
        self.assertEqual(base64.b64decode(res2["dps"]["71"])[12], 0x00)
        self.assertTrue(res2["dps"]["33"])
        self.assertEqual(res2["payload"]["gwId"], PLUG_ID)
        self.assertEqual(self.client.calls, [])

    def test_publish_dp_forbidden_dps_raise_safety_violation(self) -> None:
        for dps in ({"2": "x"}, {"3": "x"}, {"51": "x"}, {"1": "rawframe"}):
            with self.assertRaises(SafetyBarrierViolation):
                self.client.publish_dp(LOCK_ID, dps, dry_run=True)


def _make_engine(tuya: Any, cache: str) -> LockEngine:
    eng = LockEngine(
        session_cache_path=cache,
        tuya_client=tuya,
        dry_run=False,
        sample_mode=False,
        use_sample_devices=False,
        load_cache=False,
    )
    gw = GatewayDevice(
        dev_id=PLUG_ID, name="Test Plug", client_equipment_id=201, category="cz",
        product_id="qvk3ovko8ht800a4", raw_data=json.loads(json.dumps(DYSON_LIKE_PLUG)),
    )
    lock = LockDevice(
        dev_id=LOCK_ID, name="Test Lock", client_equipment_id=101,
        parent_gateway_id=PLUG_ID, raw_data=json.loads(json.dumps(LOCK_DEV)),
    )
    eng._gateways = {PLUG_ID: gw}
    eng._locks = {LOCK_ID: lock}
    return eng


class TestEnginePlugOutlet(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = os.path.join(self.tmp.name, "cache.json")
        _write_cache(self.cache, [DYSON_LIKE_PLUG, LOCK_DEV])
        self.tuya = _RecordingTuya(self.cache)
        self.engine = _make_engine(self.tuya, self.cache)
        # Any lock actuation from this feature is a hard failure.
        for name in ("unlock", "lock", "keep_unlocked", "auto_lock_on", "auto_lock_off",
                     "execute_action", "_dispatch_actuation", "_execute_ble_action"):
            setattr(self.engine, name, MagicMock(side_effect=AssertionError(f"{name} must not be called")))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_gateway_snapshot_reflects_dp1(self) -> None:
        snaps = self.engine.get_all_gateway_snapshots()
        self.assertEqual(len(snaps), 1)
        self.assertEqual(snaps[0]["devId"], PLUG_ID)
        self.assertIs(snaps[0]["outletOn"], True)
        self.assertTrue(snaps[0]["plugOutletControllable"])

    def test_set_plug_outlet_off_then_on(self) -> None:
        r = self.engine.set_plug_outlet(PLUG_ID, False)
        self.assertTrue(r["success"])
        self.assertEqual(r["dps"], {"1": False})
        self.assertIs(self.engine.get_all_gateway_snapshots()[0]["outletOn"], False)
        self.engine.set_plug_outlet(PLUG_ID, True)
        self.assertIs(self.engine.get_all_gateway_snapshots()[0]["outletOn"], True)
        sent = [json.loads(c["post_data"]["dps"]) for c in self.tuya.calls]
        self.assertEqual(sent, [{"1": False}, {"1": True}])
        self.assertTrue(all(c["post_data"]["devId"] == PLUG_ID for c in self.tuya.calls))

    def test_pending_state_survives_stale_cloud_poll(self) -> None:
        """Cloud lags ~1-3 s after publish; a stale poll must not flip HA back."""
        self.engine.set_plug_outlet(PLUG_ID, False)
        # Simulate re-discovery returning the stale pre-command DP 1 = True.
        self.engine._gateways[PLUG_ID].raw_data["dps"]["1"] = True
        snap = self.engine.get_all_gateway_snapshots()[0]
        self.assertIs(snap["outletOn"], False)
        self.assertTrue(snap["outletPending"])
        self.assertIs(snap["outletReported"], True)
        # Cloud catches up -> pending cleared.
        self.engine._gateways[PLUG_ID].raw_data["dps"]["1"] = False
        snap = self.engine.get_all_gateway_snapshots()[0]
        self.assertIs(snap["outletOn"], False)
        self.assertFalse(snap["outletPending"])

    def test_pending_state_expires(self) -> None:
        self.engine.set_plug_outlet(PLUG_ID, False)
        self.engine._gateways[PLUG_ID].raw_data["dps"]["1"] = True
        want, ts = self.engine._plug_pending[PLUG_ID]
        self.engine._plug_pending[PLUG_ID] = (want, ts - 100)
        snap = self.engine.get_all_gateway_snapshots()[0]
        self.assertIs(snap["outletOn"], True)  # plug never confirmed -> show real reported state
        self.assertFalse(snap["outletPending"])

    def test_engine_refuses_lock(self) -> None:
        with self.assertRaises(SafetyBarrierViolation):
            self.engine.set_plug_outlet(LOCK_ID, True)
        self.assertEqual(self.tuya.calls, [])

    def test_engine_refuses_alias_or_name(self) -> None:
        for target in ("Test Plug", "201", "test_plug", ""):
            with self.assertRaises(SafetyBarrierViolation):
                self.engine.set_plug_outlet(target, False)
        self.assertEqual(self.tuya.calls, [])

    def test_engine_refuses_non_cz_gateway(self) -> None:
        self.engine._gateways[PLUG_ID].category = "wg2"
        with self.assertRaises(SafetyBarrierViolation):
            self.engine.set_plug_outlet(PLUG_ID, False)
        self.assertEqual(self.tuya.calls, [])

    def test_engine_dry_run(self) -> None:
        r = self.engine.set_plug_outlet(PLUG_ID, False, dry_run=True)
        self.assertTrue(r["dry_run"])
        self.assertEqual(self.tuya.calls, [])
        self.assertIs(self.engine.get_all_gateway_snapshots()[0]["outletOn"], True)


class _FakeCoordinator:
    def __init__(self, engine: Any, mode: str = MODE_DIRECT_CLOUD) -> None:
        self.engine = engine
        self.mode = mode
        self.last_update_success = True
        self.data = {LOCK_ID: {"devId": LOCK_ID, "name": "Test Lock"}}
        self.gateway_data: Dict[str, Any] = {}
        self.refreshes = 0
        self.entry = MagicMock()

    async def async_request_refresh(self) -> None:
        self.refreshes += 1


class TestPlugOutletSwitchEntity(unittest.TestCase):
    def setUp(self) -> None:
        from custom_components.geek_door import switch as sw
        self.sw = sw
        self.tmp = tempfile.TemporaryDirectory()
        cache = os.path.join(self.tmp.name, "cache.json")
        _write_cache(cache, [DYSON_LIKE_PLUG, LOCK_DEV])
        self.tuya = _RecordingTuya(cache)
        self.engine = _make_engine(self.tuya, cache)
        self.coord = _FakeCoordinator(self.engine)
        self.coord.gateway_data = {g["devId"]: g for g in self.engine.get_all_gateway_snapshots()}

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _setup_entities(self, coord: Any) -> List[Any]:
        added: List[Any] = []
        hass = MagicMock()
        hass.data = {"geek_door": {"e1": coord}}
        entry = MagicMock(spec=["entry_id"])
        entry.entry_id = "e1"
        asyncio.run(self.sw.async_setup_entry(hass, entry, lambda ents: added.extend(ents)))
        return added

    def test_setup_adds_one_plug_switch_and_lock_autolock(self) -> None:
        ents = self._setup_entities(self.coord)
        plugs = [e for e in ents if isinstance(e, self.sw.GeekDoorPlugOutletSwitch)]
        autos = [e for e in ents if isinstance(e, self.sw.GeekDoorAutoLockSwitch)]
        self.assertEqual([p.dev_id for p in plugs], [PLUG_ID])
        self.assertEqual([a.dev_id for a in autos], [LOCK_ID])
        self.assertEqual(plugs[0].unique_id if hasattr(plugs[0], "unique_id") else plugs[0]._attr_unique_id,
                         f"geek_door_plug_outlet_{PLUG_ID}")

    def test_no_plug_switch_in_server_bridge_mode(self) -> None:
        self.coord.mode = MODE_SERVER_BRIDGE
        ents = self._setup_entities(self.coord)
        self.assertFalse(any(isinstance(e, self.sw.GeekDoorPlugOutletSwitch) for e in ents))

    def test_entity_state_and_toggle(self) -> None:
        ent = self.sw.GeekDoorPlugOutletSwitch(self.coord, PLUG_ID)
        self.assertTrue(ent.available)
        self.assertIs(ent.is_on, True)
        asyncio.run(ent.async_turn_off())
        self.assertIs(ent.is_on, False)
        asyncio.run(ent.async_turn_on())
        self.assertIs(ent.is_on, True)
        sent = [json.loads(c["post_data"]["dps"]) for c in self.tuya.calls]
        self.assertEqual(sent, [{"1": False}, {"1": True}])
        self.assertEqual(self.coord.refreshes, 2)

    def test_entity_guard_refuses_if_pointed_at_lock(self) -> None:
        ent = self.sw.GeekDoorPlugOutletSwitch(self.coord, LOCK_ID)
        self.coord.gateway_data[LOCK_ID] = dict(self.coord.gateway_data[PLUG_ID], devId=LOCK_ID)
        with self.assertRaises(Exception):
            asyncio.run(ent.async_turn_off())
        self.assertEqual(self.tuya.calls, [])

    def test_entity_unavailable_when_offline(self) -> None:
        self.coord.gateway_data[PLUG_ID]["isOnline"] = False
        ent = self.sw.GeekDoorPlugOutletSwitch(self.coord, PLUG_ID)
        self.assertFalse(ent.available)


class TestCoordinatorGatewayData(unittest.TestCase):
    def test_lock_data_excludes_gateways(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        cache = os.path.join(tmp.name, "cache.json")
        _write_cache(cache, [DYSON_LIKE_PLUG, LOCK_DEV])
        eng = _make_engine(_RecordingTuya(cache), cache)
        ids = {d["devId"] for d in eng.get_all_lock_snapshots(ble_fallback=False)}
        self.assertNotIn(PLUG_ID, ids)
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
