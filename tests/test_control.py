"""Tier 1 and Tier 2 tests for Safe Remote Lock, Unlock, and Status Inquiry."""

import json
import unittest
import requests

from client.safety import ClientMode, HARD_DENYLIST_ENDPOINTS
from tests.conftest import (
    MOCK_USER_BEAN,
    ControlResult,
    GeekSmartAuthError,
    GeekSmartControlError,
    GeekSmartTimeoutError,
    LockState,
    SafetyBarrierViolation,
    get_client_class,
)


class TestLockControl(unittest.TestCase):
    """Test suite covering safe remote lock, unlock, and status inspection via smart plug gateway bridge."""

    def setUp(self):
        self.client_cls = get_client_class()
        self.client = self.client_cls()
        self.client.login("testuser@example.com", "MockPassword123!")

    # --- Tier 1: Feature Coverage (Status Inquiry & Control) ---

    def test_T1_21_status_query_issues_correct_endpoint(self):
        """T1.21: query_lock_state queries /app/home/ttlockGatewayQueryOpenState."""
        captured_endpoint = None

        def intercept_transport(endpoint, full_params, method):
            nonlocal captured_endpoint
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            captured_endpoint = endpoint
            return {"code": 200, "msg": "success", "data": {"state": "2"}}

        client = self.client_cls(mock_transport=intercept_transport)
        client.login("testuser@example.com", "MockPassword123!")
        client.query_lock_state(101)
        self.assertIn("ttlockGatewayQueryOpenState", captured_endpoint)

    def test_T1_22_status_query_parses_unlocked_state(self):
        """T1.22: State '1' from cloud response parses to 'UNLOCKED'."""
        def unlocked_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            return {"code": 200, "msg": "success", "data": {"state": "1"}}

        client = self.client_cls(mock_transport=unlocked_transport)
        client.login("testuser@example.com", "MockPassword123!")
        state = client.query_lock_state(101)
        self.assertEqual(state, "UNLOCKED")

    def test_T1_23_status_query_parses_locked_state(self):
        """T1.23: State '2' from cloud response parses to 'LOCKED'."""
        def locked_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            return {"code": 200, "msg": "success", "data": {"state": "2"}}

        client = self.client_cls(mock_transport=locked_transport)
        client.login("testuser@example.com", "MockPassword123!")
        state = client.query_lock_state(101)
        self.assertEqual(state, "LOCKED")

    def test_T1_24_status_query_parses_unknown_state(self):
        """T1.24: State '0' or missing state from cloud response parses to 'UNKNOWN'."""
        def unknown_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            return {"code": 200, "msg": "success", "data": {"state": "0"}}

        client = self.client_cls(mock_transport=unknown_transport)
        client.login("testuser@example.com", "MockPassword123!")
        state = client.query_lock_state(101)
        self.assertEqual(state, "UNKNOWN")

    def test_T1_25_status_query_parses_integer_codes(self):
        """T1.25: Integer state values 1 and 2 parse correctly to 'UNLOCKED' and 'LOCKED'."""
        def int_state_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            target_id = full_params.get("clientEquipmentId")
            state_val = 1 if target_id == 101 else 2
            return {"code": 200, "msg": "success", "data": {"state": state_val}}

        client = self.client_cls(mock_transport=int_state_transport)
        client.login("testuser@example.com", "MockPassword123!")
        self.assertEqual(client.query_lock_state(101), "UNLOCKED")
        self.assertEqual(client.query_lock_state(102), "LOCKED")

    def test_T1_26_unlock_issues_correct_endpoint_and_params(self):
        """T1.26 & T1.27: unlock_door calls ttlockGatewayUnlock with clientEquipmentId and account ID 0."""
        captured = {}

        def intercept_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            captured["endpoint"] = endpoint
            captured["params"] = full_params
            return {"code": 200, "msg": "success", "data": {"result": "unlocked"}}

        client = self.client_cls(mock_transport=intercept_transport)
        client.login("testuser@example.com", "MockPassword123!")
        res = client.unlock_door(101)

        self.assertTrue(res)
        self.assertIn("ttlockGatewayUnlock", captured["endpoint"])
        self.assertEqual(captured["params"]["clientEquipmentId"], 101)
        self.assertEqual(captured["params"]["clientEquipmentAccountId"], 0)

    def test_T1_27_unlock_custom_lock_data_params(self):
        """T1.27: unlock_door propagates custom lock_data parameters and account ID override."""
        captured_params = {}

        def lock_data_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            captured_params.update(full_params)
            return {"code": 200, "msg": "success", "data": {"result": "unlocked"}}

        client = self.client_cls(mock_transport=lock_data_transport)
        client.login("testuser@example.com", "MockPassword123!")
        custom_data = {
            "clientEquipmentAccountId": 42,
            "gatewayId": 201,
            "lockKey": "secret_key_123",
        }
        res = client.unlock_door(101, lock_data=custom_data)
        self.assertTrue(res)
        self.assertEqual(captured_params["clientEquipmentAccountId"], 42)
        self.assertEqual(captured_params["gatewayId"], 201)
        self.assertEqual(captured_params["lockKey"], "secret_key_123")

    def test_T1_28_unlock_success_returns_true(self):
        """T1.28: Successful unlock operation returns True."""
        res = self.client.unlock_door(101)
        self.assertTrue(res)

    def test_T1_29_unlock_cloud_error_raises_exception(self):
        """T1.29: Cloud error response on unlock raises GeekSmartControlError."""
        def failure_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            return {"code": 5001, "msg": "Lock unreachable via gateway", "data": None}

        client = self.client_cls(mock_transport=failure_transport)
        client.login("testuser@example.com", "MockPassword123!")
        with self.assertRaises(GeekSmartControlError) as ctx:
            client.unlock_door(101)
        self.assertEqual(ctx.exception.code, 5001)

    def test_T1_30_unlock_invalid_device_id_raises_value_error(self):
        """T1.30: Passing non-positive or non-integer equipment ID to unlock raises ValueError."""
        invalid_ids = [0, -1, -999, "invalid", None, float("inf"), float("-inf"), True, False, 101.5]
        for bad_id in invalid_ids:
            with self.subTest(bad_id=bad_id):
                with self.assertRaises(ValueError):
                    self.client.unlock_door(bad_id)  # type: ignore

    def test_T1_31_lock_issues_correct_endpoint_and_params(self):
        """T1.31 & T1.32: lock_door calls ttlockGatewayLock with clientEquipmentId and account ID 0."""
        captured = {}

        def intercept_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            captured["endpoint"] = endpoint
            captured["params"] = full_params
            return {"code": 200, "msg": "success", "data": {"result": "locked"}}

        client = self.client_cls(mock_transport=intercept_transport)
        client.login("testuser@example.com", "MockPassword123!")
        res = client.lock_door(101)

        self.assertTrue(res)
        self.assertIn("ttlockGatewayLock", captured["endpoint"])
        self.assertEqual(captured["params"]["clientEquipmentId"], 101)
        self.assertEqual(captured["params"]["clientEquipmentAccountId"], 0)

    def test_T1_32_lock_custom_lock_data_params(self):
        """T1.32: lock_door propagates custom lock_data parameters and account ID override."""
        captured_params = {}

        def lock_data_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            captured_params.update(full_params)
            return {"code": 200, "msg": "success", "data": {"result": "locked"}}

        client = self.client_cls(mock_transport=lock_data_transport)
        client.login("testuser@example.com", "MockPassword123!")
        custom_data = {
            "clientEquipmentAccountId": 99,
            "gatewayId": 201,
        }
        res = client.lock_door(101, lock_data=custom_data)
        self.assertTrue(res)
        self.assertEqual(captured_params["clientEquipmentAccountId"], 99)
        self.assertEqual(captured_params["gatewayId"], 201)

    def test_T1_33_lock_success_returns_true(self):
        """T1.33: Successful lock operation returns True."""
        res = self.client.lock_door(101)
        self.assertTrue(res)

    def test_T1_34_lock_failure_raises_exception(self):
        """T1.34: Cloud error response on lock raises GeekSmartControlError."""
        def failure_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            return {"code": 5002, "msg": "Bolt jammed or obstructed", "data": None}

        client = self.client_cls(mock_transport=failure_transport)
        client.login("testuser@example.com", "MockPassword123!")
        with self.assertRaises(GeekSmartControlError) as ctx:
            client.lock_door(101)
        self.assertEqual(ctx.exception.code, 5002)

    def test_T1_35_lock_invalid_device_id_raises_value_error(self):
        """T1.35: Passing non-positive or non-integer equipment ID to lock raises ValueError."""
        invalid_ids = [0, -1, -50, "bad", None, float("inf"), float("-inf"), True, False, 101.5]
        for bad_id in invalid_ids:
            with self.subTest(bad_id=bad_id):
                with self.assertRaises(ValueError):
                    self.client.lock_door(bad_id)  # type: ignore

    # --- Tier 2: Boundary & Corner Cases (Control) ---

    def test_T2_09_boundary_gateway_offline_handling(self):
        """T2.09: Gateway offline returns code 5003 and raises GeekSmartControlError."""
        def offline_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            return {"code": 5003, "msg": "Smart plug BLE gateway is offline", "data": None}

        client = self.client_cls(mock_transport=offline_transport)
        client.login("testuser@example.com", "MockPassword123!")
        with self.assertRaises(GeekSmartControlError) as ctx:
            client.query_lock_state(101)
        self.assertEqual(ctx.exception.code, 5003)

    def test_T2_unauthenticated_control_operations_raise_auth_error(self):
        """Invoking lock, unlock, or status query before login raises GeekSmartAuthError."""
        client = self.client_cls()
        with self.assertRaises(GeekSmartAuthError):
            client.lock_door(101)
        with self.assertRaises(GeekSmartAuthError):
            client.unlock_door(101)
        with self.assertRaises(GeekSmartAuthError):
            client.query_lock_state(101)

    # --- Tier 2: Timeout Handling & Fault Resilience ---

    def test_T2_control_unlock_timeout(self):
        """Timeout during unlock converts to GeekSmartTimeoutError without corrupting session state."""
        def timeout_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            raise requests.Timeout("Gateway communication timed out after 15.0s")

        client = self.client_cls(mock_transport=timeout_transport)
        client.login("testuser@example.com", "MockPassword123!")

        orig_token = client.token
        orig_client_id = client.client_id

        with self.assertRaises(GeekSmartTimeoutError):
            client.unlock_door(101)

        # Verify session state was preserved
        self.assertEqual(client.token, orig_token)
        self.assertEqual(client.client_id, orig_client_id)

    def test_T2_control_lock_timeout(self):
        """Timeout during lock converts to GeekSmartTimeoutError and preserves session state."""
        def timeout_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            raise requests.Timeout("Lock deadbolt actuation timed out")

        client = self.client_cls(mock_transport=timeout_transport)
        client.login("testuser@example.com", "MockPassword123!")

        with self.assertRaises(GeekSmartTimeoutError):
            client.lock_door(101)

        self.assertIsNotNone(client.token)
        self.assertIsNotNone(client.client_id)

    def test_T2_control_status_query_timeout(self):
        """Timeout during status query converts to GeekSmartTimeoutError and preserves session state."""
        def timeout_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            raise requests.Timeout("Status query timed out")

        client = self.client_cls(mock_transport=timeout_transport)
        client.login("testuser@example.com", "MockPassword123!")

        with self.assertRaises(GeekSmartTimeoutError):
            client.query_lock_state(101)

        self.assertIsNotNone(client.token)

    # --- Tier 2: Dry-Run Mode & Safe Simulation ---

    def test_T2_control_unlock_dry_run(self):
        """Dry-run unlock validates safety, encrypts payload, and returns receipt with ZERO socket I/O."""
        call_count = 0

        def spy_transport(endpoint, full_params, method):
            nonlocal call_count
            call_count += 1
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            return {"code": 200, "msg": "success", "data": {"result": "unlocked"}}

        client = self.client_cls(mock_transport=spy_transport)
        client.login("testuser@example.com", "MockPassword123!")
        login_calls = call_count

        res = client.unlock_door(101, dry_run=True)

        # Assert zero transport calls during dry-run
        self.assertEqual(call_count, login_calls)
        self.assertTrue(res)
        self.assertEqual(res, True)
        self.assertTrue(res["dryRun"])
        self.assertEqual(res["action"], "unlock")
        self.assertEqual(res["clientEquipmentId"], 101)
        self.assertIn("encryptedPayload", res["data"])
        self.assertFalse(res["data"]["ioExecuted"])

    def test_T2_control_lock_dry_run(self):
        """Dry-run lock validates safety, encrypts payload, and returns receipt with ZERO socket I/O."""
        call_count = 0

        def spy_transport(endpoint, full_params, method):
            nonlocal call_count
            call_count += 1
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            return {"code": 200, "msg": "success", "data": {"result": "locked"}}

        client = self.client_cls(mock_transport=spy_transport)
        client.login("testuser@example.com", "MockPassword123!")
        login_calls = call_count

        res = client.lock_door(101, dry_run=True)

        self.assertEqual(call_count, login_calls)
        self.assertTrue(res)
        self.assertEqual(res, True)
        self.assertTrue(res["dryRun"])
        self.assertEqual(res["action"], "lock")
        self.assertIn("targetUrl", res["data"])
        self.assertFalse(res["data"]["ioExecuted"])

    def test_T2_control_status_dry_run(self):
        """Dry-run status inquiry simulates payload generation with zero network I/O."""
        call_count = 0

        def spy_transport(endpoint, full_params, method):
            nonlocal call_count
            call_count += 1
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            return {"code": 200, "msg": "success", "data": {"state": "2"}}

        client = self.client_cls(mock_transport=spy_transport)
        client.login("testuser@example.com", "MockPassword123!")
        login_calls = call_count

        state = client.query_lock_state(101, dry_run=True)

        self.assertEqual(call_count, login_calls)
        self.assertTrue(state["dryRun"])
        self.assertEqual(state["state"], "UNKNOWN")
        self.assertIn("targetUrl", state["data"])
        self.assertFalse(state["data"]["ioExecuted"])

    def test_T2_control_dry_run_zero_network_io(self):
        """Verifies zero socket transmissions across multiple sequential dry-run invocations."""
        dispatched_endpoints = []

        def tracking_transport(endpoint, full_params, method):
            dispatched_endpoints.append(endpoint)
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            return {"code": 200, "msg": "success", "data": {}}

        client = self.client_cls(mock_transport=tracking_transport)
        client.login("testuser@example.com", "MockPassword123!")
        self.assertEqual(len(dispatched_endpoints), 1)  # Only login

        client.query_lock_state(101, dry_run=True)
        client.unlock_door(101, dry_run=True)
        client.lock_door(101, dry_run=True)

        self.assertEqual(
            len(dispatched_endpoints),
            1,
            "Dry-run operations must produce strictly ZERO network or mock transport calls",
        )

    # --- Tier 2: Operational Mode Enforcement & Mode Transitions ---

    def test_T2_control_mode_read_only_blocks_unlock(self):
        """ClientMode.READ_ONLY strictly blocks unlock_door pre-flight with MODE_VIOLATION_READ_ONLY."""
        client = self.client_cls(mode=ClientMode.READ_ONLY)
        client.login("testuser@example.com", "MockPassword123!")

        with self.assertRaises(SafetyBarrierViolation) as ctx:
            client.unlock_door(101)

        self.assertEqual(ctx.exception.category, "MODE_VIOLATION_READ_ONLY")

    def test_T2_control_mode_read_only_blocks_lock(self):
        """ClientMode.READ_ONLY strictly blocks lock_door pre-flight with MODE_VIOLATION_READ_ONLY."""
        client = self.client_cls(mode=ClientMode.READ_ONLY)
        client.login("testuser@example.com", "MockPassword123!")

        with self.assertRaises(SafetyBarrierViolation) as ctx:
            client.lock_door(101)

        self.assertEqual(ctx.exception.category, "MODE_VIOLATION_READ_ONLY")

    def test_T2_control_mode_transition_read_only_to_safe_control(self):
        """Switching mode from READ_ONLY to SAFE_CONTROL safely unlocks actuation capabilities."""
        client = self.client_cls(mode=ClientMode.READ_ONLY)
        client.login("testuser@example.com", "MockPassword123!")

        # In READ_ONLY: Actuation is blocked
        with self.assertRaises(SafetyBarrierViolation) as ctx:
            client.unlock_door(101)
        self.assertEqual(ctx.exception.category, "MODE_VIOLATION_READ_ONLY")

        # Transition to SAFE_CONTROL: Actuation succeeds
        client.mode = ClientMode.SAFE_CONTROL
        res = client.unlock_door(101)
        self.assertTrue(res)

    def test_T2_control_safe_control_blocks_all_45_destructive_endpoints(self):
        """In ClientMode.SAFE_CONTROL, all 45 destructive endpoints remain unconditionally blocked."""
        client = self.client_cls(mode=ClientMode.SAFE_CONTROL)
        client.login("testuser@example.com", "MockPassword123!")

        self.assertEqual(len(HARD_DENYLIST_ENDPOINTS), 45)
        for forbidden in HARD_DENYLIST_ENDPOINTS:
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(SafetyBarrierViolation) as ctx:
                    client.execute_request(forbidden, {})
                self.assertEqual(
                    ctx.exception.category,
                    "HARD_DENYLIST_MATCH",
                    f"Endpoint {forbidden} failed to raise HARD_DENYLIST_MATCH in SAFE_CONTROL mode",
                )

    # --- Tier 2: Dual Compatibility Model Testing ---

    def test_T2_control_result_dual_compatibility(self):
        """ControlResult behaves as both a boolean (for legacy tests) and a full dictionary."""
        cr = ControlResult(
            success=True,
            client_equipment_id=101,
            action="unlock",
            message="Unlocked successfully",
            code=200,
            raw_data={"result": "unlocked", "txId": 9876},
        )
        # Boolean behavior & equality/inequality semantics
        self.assertTrue(cr)
        self.assertEqual(cr, True)
        self.assertNotEqual(cr, False)
        self.assertTrue(cr == True)
        self.assertFalse(cr != True)
        self.assertTrue(cr != False)
        # Rich comparison truthiness & non-boolean inequality (PEP 207 / None guard)
        self.assertTrue(cr != None)
        self.assertFalse(cr == None)
        self.assertNotEqual(cr, None)
        self.assertTrue(None != cr)
        self.assertFalse(None == cr)
        self.assertTrue(cr != 123)
        self.assertFalse(cr == 123)
        self.assertTrue(cr != "foo")
        self.assertFalse(cr == "foo")
        self.assertTrue(cr != 1)
        self.assertFalse(cr == 1)
        self.assertTrue(cr != 0)
        self.assertFalse(cr == 0)
        self.assertTrue(123 != cr)
        self.assertTrue("foo" != cr)

        cr_fail = ControlResult(
            success=False,
            client_equipment_id=101,
            action="unlock",
            message="Unlock failed",
            code=5001,
        )
        self.assertFalse(cr_fail)
        self.assertEqual(cr_fail, False)
        self.assertNotEqual(cr_fail, True)
        self.assertTrue(cr_fail == False)
        self.assertFalse(cr_fail != False)
        self.assertTrue(cr_fail != True)
        self.assertTrue(cr_fail != None)
        self.assertFalse(cr_fail == None)
        self.assertNotEqual(cr_fail, None)
        self.assertTrue(None != cr_fail)
        self.assertFalse(None == cr_fail)
        self.assertTrue(cr_fail != 123)
        self.assertFalse(cr_fail == 123)

        # Dictionary behavior
        self.assertIsInstance(cr, dict)
        self.assertEqual(cr["clientEquipmentId"], 101)
        self.assertEqual(cr["action"], "unlock")
        self.assertEqual(cr["txId"], 9876)

        # Serialization
        serialized = json.dumps(cr)
        parsed = json.loads(serialized)
        self.assertEqual(parsed["success"], True)
        self.assertEqual(parsed["clientEquipmentId"], 101)

    def test_T2_lock_state_dual_compatibility(self):
        """LockState behaves as both a string state and a full dictionary."""
        ls = LockState(
            state="UNLOCKED",
            client_equipment_id=101,
            raw_state_code="1",
            message="success",
            code=200,
            raw_data={"state": "1"},
        )
        # String behavior
        self.assertEqual(ls, "UNLOCKED")
        self.assertNotEqual(ls, "LOCKED")
        self.assertTrue(ls == "UNLOCKED")
        self.assertFalse(ls != "UNLOCKED")
        self.assertTrue(ls != "LOCKED")
        self.assertIn(ls, ["LOCKED", "UNLOCKED", "UNKNOWN"])
        self.assertEqual(str(ls), "UNLOCKED")
        # Rich comparison truthiness & non-string inequality (PEP 207 / None guard)
        self.assertTrue(ls != None)
        self.assertFalse(ls == None)
        self.assertNotEqual(ls, None)
        self.assertTrue(None != ls)
        self.assertFalse(None == ls)
        self.assertTrue(ls != False)
        self.assertFalse(ls == False)
        self.assertTrue(ls != True)
        self.assertFalse(ls == True)
        self.assertNotEqual(ls, False)
        self.assertNotEqual(ls, True)
        self.assertTrue(False != ls)
        self.assertTrue(True != ls)
        self.assertTrue(ls != 1)
        self.assertFalse(ls == 1)
        self.assertTrue(ls != 0)
        self.assertFalse(ls == 0)
        self.assertTrue(ls != 2)
        self.assertFalse(ls == 2)
        self.assertTrue(ls != 123)
        self.assertFalse(ls == 123)
        self.assertTrue(ls != ["UNLOCKED"])
        self.assertFalse(ls == ["UNLOCKED"])

        # Explicit verification of LOCKED state comparison
        ls_locked = LockState(
            state="LOCKED",
            client_equipment_id=101,
            raw_state_code="2",
            message="success",
            code=200,
            raw_data={"state": "2"},
        )
        self.assertTrue(ls_locked == "LOCKED")
        self.assertFalse(ls_locked != "LOCKED")
        self.assertTrue(ls_locked != "UNLOCKED")
        self.assertEqual(ls_locked, "LOCKED")
        self.assertNotEqual(ls_locked, "UNLOCKED")
        self.assertTrue(ls_locked != None)
        self.assertFalse(ls_locked == None)
        self.assertNotEqual(ls_locked, None)
        self.assertTrue(ls_locked != False)
        self.assertFalse(ls_locked == False)
        self.assertTrue(ls_locked != True)
        self.assertFalse(ls_locked == True)
        self.assertTrue(ls_locked != 2)
        self.assertFalse(ls_locked == 2)
        self.assertNotEqual(ls_locked, False)
        self.assertNotEqual(ls_locked, True)

        # Dictionary behavior
        self.assertIsInstance(ls, dict)
        self.assertEqual(ls["clientEquipmentId"], 101)
        self.assertEqual(ls["rawStateCode"], "1")

        # Serialization
        serialized = json.dumps(ls)
        parsed = json.loads(serialized)
        self.assertEqual(parsed["state"], "UNLOCKED")

    def test_T2_control_remediation_parameter_and_lock_data_validation(self):
        """Verifies specific remediation checks: float('inf'), boolean rejection, and lock_data type."""
        # float('inf') raises ValueError
        with self.assertRaises(ValueError):
            self.client.unlock_door(float("inf"))
        with self.assertRaises(ValueError):
            self.client.lock_door(float("inf"))
        with self.assertRaises(ValueError):
            self.client.query_lock_state(float("inf"))

        # booleans raise ValueError
        with self.assertRaises(ValueError):
            self.client.unlock_door(True)
        with self.assertRaises(ValueError):
            self.client.unlock_door(False)
        with self.assertRaises(ValueError):
            self.client.lock_door(True)
        with self.assertRaises(ValueError):
            self.client.query_lock_state(True)

        # non-dict lock_data raises TypeError
        with self.assertRaises(TypeError):
            self.client.unlock_door(101, lock_data="string")
        with self.assertRaises(TypeError):
            self.client.unlock_door(101, lock_data=123)
        with self.assertRaises(TypeError):
            self.client.lock_door(101, lock_data="string")
        with self.assertRaises(TypeError):
            self.client.lock_door(101, lock_data=["invalid"])

    def test_T2_rich_comparison_truthiness_and_notimplemented_matrix(self):
        """Hardens rich comparisons across types to guarantee Law of Excluded Middle and PEP 207 compliance."""
        objects = [
            ControlResult(True, 101, "unlock"),
            ControlResult(False, 101, "unlock"),
            LockState("LOCKED", 101),
            LockState("UNLOCKED", 101),
            LockState("UNKNOWN", 101),
        ]
        test_operands = [
            None,
            True,
            False,
            0,
            1,
            2,
            123,
            "foo",
            "LOCKED",
            "UNLOCKED",
            "UNKNOWN",
            [],
            [1],
            {"random": "dict"},
        ]
        for obj in objects:
            for op in test_operands:
                with self.subTest(obj=repr(obj), op=repr(op)):
                    eq_val = (obj == op)
                    ne_val = (obj != op)
                    self.assertIsInstance(eq_val, bool)
                    self.assertIsInstance(ne_val, bool)
                    self.assertNotEqual(
                        eq_val,
                        ne_val,
                        f"Law of Excluded Middle violated for {obj!r} == {op!r} ({eq_val}) vs != ({ne_val})",
                    )
                    self.assertEqual(eq_val, (op == obj), f"Symmetry violated for == with {obj!r} and {op!r}")
                    self.assertEqual(ne_val, (op != obj), f"Symmetry violated for != with {obj!r} and {op!r}")


if __name__ == "__main__":
    unittest.main()
