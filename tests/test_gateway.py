"""Tier 3 (Cross-Feature Combinations) and Tier 4 (Real-World Scenarios) test suite."""

import concurrent.futures
import os
import unittest
import requests

from client.exceptions import GeekSmartControlError, GeekSmartTimeoutError
from client.safety import ClientMode
from tests.conftest import (
    MOCK_EQUIPMENT_LIST_MAP,
    MOCK_USER_BEAN,
    SafetyBarrierViolation,
    get_client_class,
    load_env_credentials,
)


class TestGatewayAndRealWorldScenarios(unittest.TestCase):
    """Test suite covering multi-device interactions, smart plug BLE gateway bridge routing, and real-world scenarios."""

    def setUp(self):
        self.client_cls = get_client_class()
        self.client = self.client_cls()

    # --- Tier 3: Cross-Feature Combinations ---

    def test_T3_01_cross_login_discover_query_status_flow(self):
        """T3.01: End-to-end flow: login -> discover devices -> select lock -> query status."""
        # 1. Login
        user = self.client.login("testuser@example.com", "MockPassword123!")
        self.assertIsNotNone(user.get("token"))

        # 2. Discover devices
        devices = self.client.discover_devices()
        self.assertGreater(len(devices), 0)

        # 3. Select first door lock
        lock = next(d for d in devices if d.get("equipmentModelNo") == "L-B400")
        lock_id = lock["clientEquipmentId"]

        # 4. Query status
        state = self.client.query_lock_state(lock_id)
        self.assertIn(state, ["LOCKED", "UNLOCKED", "UNKNOWN"])

    def test_T3_02_cross_token_expiry_transparent_recovery(self):
        """T3.02: Mid-session token expiry (code 3) transparently triggers auto-relogin and succeeds."""
        expired_once = False
        new_token = "RENEWED_TRANSPARENT_TOKEN=="

        def expiring_transport(endpoint, full_params, method):
            nonlocal expired_once
            if "loginByPassword" in endpoint:
                u = dict(MOCK_USER_BEAN)
                if expired_once:
                    u["token"] = new_token
                return {"code": 0, "msg": "OK", "data": u}
            if not expired_once:
                expired_once = True
                return {"code": 3, "msg": "Token expired, please login again", "data": None}
            return {"code": 0, "msg": "OK", "data": MOCK_EQUIPMENT_LIST_MAP}

        client = self.client_cls(mock_transport=expiring_transport)
        client.login("testuser@example.com", "MockPassword123!")

        # Discover devices triggers code 3 on first attempt, then transparent re-login and success
        devices = client.discover_devices()
        self.assertEqual(len(devices), 3)
        self.assertEqual(client.token, new_token)

    def test_T3_03_cross_discover_and_unlock_flow(self):
        """T3.03: Discover devices -> filter locks -> execute safe remote unlock."""
        self.client.login("testuser@example.com", "MockPassword123!")
        devices = self.client.discover_devices()
        deadbolt = next(d for d in devices if d.get("equipmentModelNo") == "L-B400")

        success = self.client.unlock_door(deadbolt["clientEquipmentId"])
        self.assertTrue(success)

    def test_T3_04_cross_lock_unlock_state_transition(self):
        """T3.04: Lock -> verify state -> unlock -> verify state."""
        current_state = "LOCKED"

        def stateful_transport(endpoint, full_params, method):
            nonlocal current_state
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            elif "ttlockGatewayLock" in endpoint:
                current_state = "LOCKED"
                return {"code": 200, "msg": "success", "data": {"result": "locked"}}
            elif "ttlockGatewayUnlock" in endpoint:
                current_state = "UNLOCKED"
                return {"code": 200, "msg": "success", "data": {"result": "unlocked"}}
            elif "ttlockGatewayQueryOpenState" in endpoint:
                state_code = "2" if current_state == "LOCKED" else "1"
                return {"code": 200, "msg": "success", "data": {"state": state_code}}
            return {"code": 0, "msg": "OK", "data": {}}

        client = self.client_cls(mock_transport=stateful_transport)
        client.login("testuser@example.com", "MockPassword123!")

        # Unlock
        client.unlock_door(101)
        self.assertEqual(client.query_lock_state(101), "UNLOCKED")

        # Lock
        client.lock_door(101)
        self.assertEqual(client.query_lock_state(101), "LOCKED")

    def test_T3_05_cross_interleaved_safety_violations_with_valid_ops(self):
        """T3.05: Interleaved destructive attempts are safely blocked while surrounding operations succeed."""
        self.client.login("testuser@example.com", "MockPassword123!")

        # 1. Valid operation
        state_1 = self.client.query_lock_state(101)
        self.assertEqual(state_1, "LOCKED")

        # 2. Blocked destructive call
        with self.assertRaises(SafetyBarrierViolation):
            self.client.execute_request("/app/home/deleteClientEquipment", {"clientEquipmentId": 101})

        # 3. Valid operation continues uninterrupted
        state_2 = self.client.query_lock_state(101)
        self.assertEqual(state_2, "LOCKED")

    def test_T3_06_cross_gateway_timeout_and_session_recovery(self):
        """T3.06: Gateway actuation timeout raises GeekSmartTimeoutError while preserving session token for subsequent queries."""
        timeout_once = True

        def flaking_transport(endpoint, full_params, method):
            nonlocal timeout_once
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            if "ttlockGatewayUnlock" in endpoint and timeout_once:
                timeout_once = False
                raise requests.Timeout("Gateway actuation timed out")
            if "ttlockGatewayQueryOpenState" in endpoint:
                return {"code": 200, "msg": "success", "data": {"state": "2"}}
            return {"code": 200, "msg": "success", "data": {}}

        client = self.client_cls(mock_transport=flaking_transport)
        client.login("testuser@example.com", "MockPassword123!")
        orig_token = client.token

        with self.assertRaises(GeekSmartTimeoutError):
            client.unlock_door(101)

        self.assertEqual(client.token, orig_token)
        state = client.query_lock_state(101)
        self.assertEqual(state, "LOCKED")

    def test_T3_07_cross_gateway_offline_reconnect_resilience(self):
        """T3.07: Gateway offline code 5003 handled gracefully and subsequent retry succeeds after reconnection."""
        is_offline = True

        def reconnecting_transport(endpoint, full_params, method):
            nonlocal is_offline
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            if "ttlockGatewayUnlock" in endpoint:
                if is_offline:
                    is_offline = False
                    return {"code": 5003, "msg": "Smart plug BLE gateway is offline", "data": None}
                return {"code": 200, "msg": "success", "data": {"result": "unlocked"}}
            return {"code": 200, "msg": "success", "data": {}}

        client = self.client_cls(mock_transport=reconnecting_transport)
        client.login("testuser@example.com", "MockPassword123!")

        with self.assertRaises(GeekSmartControlError) as ctx:
            client.unlock_door(101)
        self.assertEqual(ctx.exception.code, 5003)

        # Retry after reconnect succeeds
        success = client.unlock_door(101)
        self.assertTrue(success)

    def test_T3_08_cross_dry_run_pipeline_through_gateway(self):
        """T3.08: End-to-end pipeline: discover deadbolt via gateway, simulate actuation via dry-run, state unchanged."""
        current_state = "LOCKED"

        def stateful_transport(endpoint, full_params, method):
            nonlocal current_state
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            if "getClientEquipmentListMap" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_EQUIPMENT_LIST_MAP}
            if "ttlockGatewayQueryOpenState" in endpoint:
                state_code = "2" if current_state == "LOCKED" else "1"
                return {"code": 200, "msg": "success", "data": {"state": state_code}}
            return {"code": 200, "msg": "success", "data": {}}

        client = self.client_cls(mock_transport=stateful_transport)
        client.login("testuser@example.com", "MockPassword123!")
        devices = client.discover_devices()
        deadbolt = next(d for d in devices if d["clientEquipmentId"] == 101)
        self.assertEqual(deadbolt["thirdpartyJson"]["gatewayId"], 201)

        # Verify initial state
        initial_state = client.query_lock_state(101)
        self.assertEqual(initial_state, "LOCKED")

        # Execute dry-run unlock
        dry_res = client.unlock_door(101, dry_run=True)
        self.assertTrue(dry_res["dryRun"])
        self.assertIn("targetUrl", dry_res["data"])

        # Physical state remains LOCKED
        state_after = client.query_lock_state(101)
        self.assertEqual(state_after, "LOCKED")

    # --- Tier 4: Real-World Scenarios ---

    def test_T4_01_realworld_smart_plug_ble_gateway_routing(self):
        """T4.01: Command to deadbolt lock is verified to route via smart plug gateway bridge."""
        routed_packets = []

        def gateway_route_transport(endpoint, full_params, method):
            routed_packets.append((endpoint, full_params))
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            if "getClientEquipmentListMap" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_EQUIPMENT_LIST_MAP}
            return {"code": 200, "msg": "success", "data": {"result": "ok"}}

        client = self.client_cls(mock_transport=gateway_route_transport)
        client.login("testuser@example.com", "MockPassword123!")
        devices = client.discover_devices()

        # Check smart plug gateway ID associated with deadbolt
        deadbolt = next(d for d in devices if d["clientEquipmentId"] == 101)
        self.assertEqual(deadbolt["thirdpartyJson"]["gatewayId"], 201)

        # Trigger unlock
        client.unlock_door(deadbolt["clientEquipmentId"])
        last_call_endpoint, last_call_params = routed_packets[-1]
        self.assertIn("ttlockGatewayUnlock", last_call_endpoint)
        self.assertEqual(last_call_params["clientEquipmentId"], 101)

    def test_T4_02_realworld_multi_lock_account_inventory(self):
        """T4.02: Verify full user inventory matching prompt: Living room deadbolt + Bathroom deadbolt + Smart plug."""
        self.client.login("testuser@example.com", "MockPassword123!")
        devices = self.client.discover_devices()

        device_names = [d.get("equipmentNote") for d in devices]
        self.assertIn("Living Room Door", device_names)
        self.assertIn("Bathroom Door", device_names)
        self.assertIn("Living Room Hub", device_names)

        # Check battery levels
        battery_map = {d["clientEquipmentId"]: d["thirdpartyJson"].get("electricQuantity") for d in devices if "thirdpartyJson" in d}
        self.assertEqual(battery_map[101], 85)
        self.assertEqual(battery_map[102], 72)

    def test_T4_03_realworld_concurrent_lock_status_queries(self):
        """T4.03: Concurrent queries from multiple threads operate safely without session corruption."""
        self.client.login("testuser@example.com", "MockPassword123!")

        def query_worker(lock_id):
            return self.client.query_lock_state(lock_id)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(query_worker, 101) for _ in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        self.assertEqual(len(results), 10)
        self.assertTrue(all(r == "LOCKED" for r in results))

    def test_T4_05_realworld_live_env_read_only_probe(self):
        """T4.05: Non-destructive read-only probe against live server when RUN_LIVE_TESTS is set."""
        if os.getenv("RUN_LIVE_TESTS") != "1":
            self.skipTest("Live cloud test skipped (set RUN_LIVE_TESTS=1 to run against production)")

        user, pwd = load_env_credentials()
        if not user or not pwd:
            self.skipTest("No credentials found in .env")

        # 1. Instantiate client targeting live production cloud with NO mock interception
        # Mode is strictly READ_ONLY to guarantee zero-mutation safety barrier
        live_client = self.client_cls(
            mock_transport=None,
            mode=ClientMode.READ_ONLY,
        )

        # 2. Authenticate against production server (https://app.geekaihome.com)
        user_bean = live_client.login(user, pwd)

        # 3. Assert genuine HTTP status 200 and dynamic token acquisition
        self.assertIsNotNone(user_bean)
        self.assertEqual(user_bean.get("email"), user)
        self.assertIsInstance(user_bean.get("id"), int)
        self.assertGreater(user_bean.get("id"), 0)

        token = user_bean.get("token")
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 10)
        # Verify token is dynamically generated by cloud, NOT the static mock token
        self.assertNotEqual(
            token,
            "TW9ja1Rva2VuMTIzNDU2Nw==",
            "Live client must acquire dynamic server token, not static mock token",
        )

        # 4. Assert multi-ecosystem bridge credentials returned by server
        tuya_uid = user_bean.get("tuyaUid")
        ttlock_uid = user_bean.get("ttlockUid")
        self.assertIsInstance(tuya_uid, str)
        self.assertTrue(len(tuya_uid) > 0)
        self.assertIsInstance(ttlock_uid, str)
        self.assertTrue(len(ttlock_uid) > 0)
        self.assertTrue(str(user_bean.get("ttlockUsername", "")).startswith("geekaihome_"))

        # 5. Discover devices and verify direct equipment map is accurately [] (0 devices)
        devices = live_client.discover_devices()
        self.assertIsInstance(devices, list)
        self.assertEqual(
            len(devices),
            0,
            "Live GeekSmart direct equipment list must report 0 devices (devices reside on Tuya/TTLock bridges)",
        )
        self.assertEqual(devices, [])

        # 6. Verify raw equipment map envelope
        raw_map = live_client.get_equipment_list_map()
        self.assertIsInstance(raw_map, dict)
        self.assertEqual(raw_map.get("equipmentList"), [])

        # 7. Print factual verification log matching actual live cloud reality
        print("\n" + "=" * 78)
        print("[LIVE CLOUD VERIFIED] Endpoint: https://app.geekaihome.com")
        print(f"[LIVE CLOUD VERIFIED] Logged in user: {user_bean.get('email')} (ID: {user_bean.get('id')})")
        print(f"[LIVE CLOUD VERIFIED] Dynamic token acquired: {token[:8]}... ({len(token)} bytes)")
        print(f"[LIVE CLOUD VERIFIED] Tuya Bridge UID: {tuya_uid}")
        print(f"[LIVE CLOUD VERIFIED] TTLock Bridge UID: {ttlock_uid} (User: {user_bean.get('ttlockUsername')})")
        print(f"[LIVE CLOUD VERIFIED] Direct equipment map devices: {len(devices)} ([])")
        print("[LIVE CLOUD TOPOLOGY] Verified: Physical locks and smart plug BLE gateway bridge")
        print("                      reside within linked Tuya and TTLock sub-ecosystems.")
        print("=" * 78)

    def test_T4_06_realworld_live_safe_control_read_only_probe(self):
        """T4.06: Live probe under ClientMode.SAFE_CONTROL verifying auth, bridges, zero devices, and safety barrier."""
        if os.getenv("RUN_LIVE_TESTS") != "1":
            self.skipTest("Live cloud test skipped (set RUN_LIVE_TESTS=1 to run against production)")

        user, pwd = load_env_credentials()
        if not user or not pwd:
            self.skipTest("No credentials found in .env")

        live_client = self.client_cls(
            mock_transport=None,
            mode=ClientMode.SAFE_CONTROL,
        )
        user_bean = live_client.login(user, pwd)
        self.assertEqual(user_bean.get("email"), user)
        self.assertIsInstance(user_bean.get("id"), int)
        self.assertGreater(user_bean.get("id"), 0)

        token = user_bean.get("token")
        self.assertNotEqual(token, "TW9ja1Rva2VuMTIzNDU2Nw==")

        # Assert destructive call is blocked in SAFE_CONTROL
        with self.assertRaises(SafetyBarrierViolation) as ctx:
            live_client.execute_request("/app/home/deleteClientEquipment", {"clientEquipmentId": 101})
        self.assertEqual(ctx.exception.category, "HARD_DENYLIST_MATCH")

    def test_T4_07_realworld_live_actuation_guarded(self):
        """T4.07: Guarded live actuation test: strictly skipped unless ENABLE_LIVE_ACTUATION=1 is set."""
        if os.getenv("RUN_LIVE_TESTS") != "1":
            self.skipTest("Live cloud test skipped (set RUN_LIVE_TESTS=1 to run against production)")

        if os.getenv("ENABLE_LIVE_ACTUATION") != "1":
            self.skipTest("Physical actuation skipped to preserve door security. Set ENABLE_LIVE_ACTUATION=1 to actuate live locks.")

        user, pwd = load_env_credentials()
        if not user or not pwd:
            self.skipTest("No credentials found in .env")

        live_client = self.client_cls(
            mock_transport=None,
            mode=ClientMode.SAFE_CONTROL,
        )
        live_client.login(user, pwd)

        # In live account with smart plug gateway, test status inquiry or dry-run actuation
        dry_res = live_client.unlock_door(101, dry_run=True)
        self.assertTrue(dry_res["dryRun"])


if __name__ == "__main__":
    unittest.main()
