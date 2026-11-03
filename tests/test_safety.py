"""Tier 1 and Tier 2 tests for Safety Barrier Guard (Prohibition of Destructive Operations)."""

import unittest
from tests.conftest import (
    FORBIDDEN_ENDPOINTS,
    SafetyBarrierViolation,
    get_client_class,
)


class TestSafetyBarrier(unittest.TestCase):
    """Test suite ensuring absolute prohibition of destructive operations on GeekSmart door locks."""

    def setUp(self):
        self.client_cls = get_client_class()
        self.client = self.client_cls()
        self.client.login("testuser@example.com", "MockPassword123!")

    # --- Tier 1: Feature Coverage (Safety Barrier Guard) ---

    def test_T1_36_safety_barrier_blocks_delete_client_equipment(self):
        """T1.36: Attempt to invoke deleteClientEquipment raises SafetyBarrierViolation immediately."""
        with self.assertRaises(SafetyBarrierViolation) as ctx:
            self.client.execute_request("/app/home/deleteClientEquipment", {"clientEquipmentId": 101})
        self.assertIn("CRITICAL SAFETY VIOLATION", str(ctx.exception))

    def test_T1_37_safety_barrier_blocks_remove_lock(self):
        """T1.37: Attempt to invoke removeLock raises SafetyBarrierViolation immediately."""
        with self.assertRaises(SafetyBarrierViolation) as ctx:
            self.client.execute_request("app/doorbellLock/removeLock", {"lockId": 101})
        self.assertIn("CRITICAL SAFETY VIOLATION", str(ctx.exception))

    def test_T1_38_safety_barrier_blocks_bind_lock(self):
        """T1.38: Attempt to invoke bindLock raises SafetyBarrierViolation immediately."""
        with self.assertRaises(SafetyBarrierViolation) as ctx:
            self.client.execute_request("app/doorbellLock/bindLock", {"lockId": 101})
        self.assertIn("CRITICAL SAFETY VIOLATION", str(ctx.exception))

    def test_T1_39_safety_barrier_blocks_add_and_alter_equipment(self):
        """T1.39: Attempt to invoke addEquipment or alterEquipmentRoom/Note raises SafetyBarrierViolation."""
        dangerous_calls = [
            "/app/home/addEquipment",
            "/app/home/addEquipmentToClient",
            "/app/home/alterEquipmentNote",
            "/app/home/alterEquipmentRoom",
        ]
        for ep in dangerous_calls:
            with self.subTest(endpoint=ep):
                with self.assertRaises(SafetyBarrierViolation):
                    self.client.execute_request(ep, {"id": 101})

    def test_T1_40_safety_barrier_blocks_destructive_credentials_operations(self):
        """T1.40: Destructive credential modifications (fingerprint reset, passcode deletion) are blocked."""
        dangerous_ops = [
            "/app/home/addClientEquipmentAccountOperation",
            "resetLock",
            "clearFingerprints",
            "deletePasscode",
        ]
        for op in dangerous_ops:
            with self.subTest(operation=op):
                with self.assertRaises(SafetyBarrierViolation):
                    self.client.execute_request(op, {})

    # --- Tier 2: Boundary & Corner Cases (Safety Barrier) ---

    def test_T2_safety_barrier_blocks_all_forbidden_endpoints_in_list(self):
        """Verify every single endpoint in FORBIDDEN_ENDPOINTS is blocked."""
        for endpoint in FORBIDDEN_ENDPOINTS:
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(SafetyBarrierViolation):
                    self.client.execute_request(endpoint, {})

    def test_T2_safety_barrier_blocks_with_whitespace_and_slashes(self):
        """Safety barrier catches variations with leading/trailing slashes or spaces."""
        variations = [
            "  /app/home/deleteClientEquipment  ",
            "///app/home/deleteClientEquipment",
            "app/home/deleteClientEquipment",
        ]
        for v in variations:
            with self.subTest(variation=v):
                with self.assertRaises(SafetyBarrierViolation):
                    self.client.execute_request(v, {})

    def test_T2_safety_violation_does_not_corrupt_session_state(self):
        """A blocked dangerous call must not invalidate the active session or alter valid client state."""
        original_token = self.client.token
        original_client_id = self.client.client_id

        # Trigger blocked call
        with self.assertRaises(SafetyBarrierViolation):
            self.client.execute_request("/app/home/deleteClientEquipment", {})

        # Assert session state is intact
        self.assertEqual(self.client.token, original_token)
        self.assertEqual(self.client.client_id, original_client_id)

        # Subsequent valid call must succeed normally
        devices = self.client.discover_devices()
        self.assertIsInstance(devices, list)


if __name__ == "__main__":
    unittest.main()
