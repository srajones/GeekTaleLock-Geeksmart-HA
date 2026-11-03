"""
Adversarial Safety Barrier Challenge Suite.
Empirically stress-tests the GeekSmart SDK Safety Barrier Guard against bypass techniques:
- URL directory traversal (dot-dot attacks, backslashes, percent-encoding)
- Multiple slashes and separator variations
- URL casing variations (uppercase, lowercase, camelCase, mixedCase)
- Query parameter smuggling and URL fragments
- Parameter injection (password alter parameters, authType wipe codes)
- Strict Zero Network I/O verification on all violations
- Mode enforcement (READ_ONLY vs SAFE_CONTROL vs TEST_MOCK)
- Session immutability across repeated attack failures
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch
import urllib.parse

from client.safety import (
    ClientMode,
    SafetyBarrierGuard,
    SafetyBarrierViolation,
    HARD_DENYLIST_ENDPOINTS,
    ALLOWLIST_READ_ONLY,
    ALLOWLIST_SAFE_CONTROL,
    FORBIDDEN_KEYWORD_REGEX,
)
from client.geeksmart_client import GeekSmartClient, UserInfo


class TestAdversarialSafetyBarrier(unittest.TestCase):
    """
    Adversarial challenge test harness for SafetyBarrierGuard and GeekSmartClient.
    """

    def setUp(self):
        # Create a mock transport that records any call.
        # If any network I/O or mock transport call occurs during a safety violation,
        # transport_called will be True.
        self.mock_network_calls = []

        def spy_transport(endpoint, params, method):
            self.mock_network_calls.append({
                "endpoint": endpoint,
                "params": params,
                "method": method,
            })
            return {"code": 0, "msg": "OK", "data": {}}

        self.spy_transport = spy_transport
        self.client_read_only = GeekSmartClient(
            mode=ClientMode.READ_ONLY,
            mock_transport=self.spy_transport,
        )
        self.client_read_only.token = "TEST_ACTIVE_TOKEN_12345"
        self.client_read_only.client_id = 999999
        self.client_read_only.user_info = UserInfo({"id": 999999, "email": "test@example.com", "token": "TEST_ACTIVE_TOKEN_12345"})

        self.client_safe_control = GeekSmartClient(
            mode=ClientMode.SAFE_CONTROL,
            mock_transport=self.spy_transport,
        )
        self.client_safe_control.token = "TEST_ACTIVE_TOKEN_12345"
        self.client_safe_control.client_id = 999999
        self.client_safe_control.user_info = UserInfo({"id": 999999, "email": "test@example.com", "token": "TEST_ACTIVE_TOKEN_12345"})

    def assert_zero_network_io(self):
        """Asserts that zero network or transport calls were issued."""
        self.assertEqual(
            len(self.mock_network_calls),
            0,
            f"Zero Network I/O violated! Calls observed: {self.mock_network_calls}"
        )

    # =========================================================================
    # 1. URL Directory Traversal Bypass Attempts
    # =========================================================================
    def test_adv_traversal_parent_directory_denylist(self):
        """Test directory traversal attempting to reach destructive endpoints from safe prefixes."""
        traversal_attempts = [
            "/app/client/../home/deleteClientEquipment",
            "/app/client/../../app/home/deleteClientEquipment",
            "/app/home/getClientEquipmentList/../deleteClientEquipment",
            "/app/doorbellLock/getLockList/../../home/deleteClientEquipment",
            "/app/client/loginByPassword/../../../app/home/deleteClientEquipment",
            "/app/home/./deleteClientEquipment",
            "/app/home/../home/deleteClientEquipment",
            "/app/../app/home/deleteClientEquipment",
            "/app/client/../home/alterEquipmentNote",
            "/app/client/../home/clearOrCoverClientEquipmentAuth",
            "/app/client/../home/deleteClientEquipmentAuthAccount",
            "/app/client/../home/alterPassword",
            "/app/client/../doorbellLock/removeLock",
            "/app/client/../doorbellLock/bindLock",
        ]
        for ep in traversal_attempts:
            with self.subTest(endpoint=ep):
                self.mock_network_calls.clear()
                with self.assertRaises(SafetyBarrierViolation) as ctx:
                    self.client_read_only.execute_request(ep, {"id": 101})
                self.assert_zero_network_io()
                self.assertIn("CRITICAL SAFETY VIOLATION", str(ctx.exception))

    def test_adv_traversal_with_trailing_and_embedded_dots(self):
        """Test edge cases with single dot, trailing dots, or excessive dot segments."""
        dot_attempts = [
            "/app/home/deleteClientEquipment/.",
            "/app/home/deleteClientEquipment/./",
            "/app/home/deleteClientEquipment/../deleteClientEquipment",
            "/app/home/deleteClientEquipment/.../",
            "/app/home/deleteClientEquipment/....",
            "/./app/./home/./deleteClientEquipment",
            "../app/home/deleteClientEquipment",
            "../../../../app/home/deleteClientEquipment",
        ]
        for ep in dot_attempts:
            with self.subTest(endpoint=ep):
                self.mock_network_calls.clear()
                with self.assertRaises(SafetyBarrierViolation):
                    self.client_read_only.execute_request(ep)
                self.assert_zero_network_io()

    def test_adv_traversal_encoded_dots_and_slashes(self):
        """Test URL-encoded traversal sequences (%2e%2e, %2f)."""
        encoded_attempts = [
            "/app/client/%2e%2e/home/deleteClientEquipment",
            "/app/client/%2E%2E/home/deleteClientEquipment",
            "/app/client/..%2fhome/deleteClientEquipment",
            "/app/home/%2e%2e%2fhome/deleteClientEquipment",
            "/app/home/%64%65%6c%65%74%65ClientEquipment",  # 'delete' hex-encoded
        ]
        for ep in encoded_attempts:
            with self.subTest(endpoint=ep):
                self.mock_network_calls.clear()
                with self.assertRaises(SafetyBarrierViolation):
                    self.client_read_only.execute_request(ep)
                self.assert_zero_network_io()

    # =========================================================================
    # 2. Multiple Slashes & Whitespace Bypass Attempts
    # =========================================================================
    def test_adv_multiple_slashes_and_separators(self):
        """Test multiple slash variations to bypass path matching."""
        slash_attempts = [
            "///app///home///deleteClientEquipment",
            "//app//home//deleteClientEquipment",
            "////app/home/deleteClientEquipment",
            "//////////app/home/deleteClientEquipment",
            "/app//home//deleteClientEquipment//",
            "/app///doorbellLock///removeLock",
            "///resetLock",
            "////clearFingerprints",
            "//app//client//alterPassword",
        ]
        for ep in slash_attempts:
            with self.subTest(endpoint=ep):
                self.mock_network_calls.clear()
                with self.assertRaises(SafetyBarrierViolation):
                    self.client_read_only.execute_request(ep)
                self.assert_zero_network_io()

    def test_adv_whitespace_and_newline_padding(self):
        """Test leading, trailing, and embedded whitespace / control chars."""
        whitespace_attempts = [
            "   /app/home/deleteClientEquipment   ",
            "\t/app/home/deleteClientEquipment\n",
            "\r\n/app/home/deleteClientEquipment\r\n",
            " /app/doorbellLock/removeLock ",
            "  /resetLock  ",
            "  /app/client/alterPassword  ",
        ]
        for ep in whitespace_attempts:
            with self.subTest(endpoint=ep):
                self.mock_network_calls.clear()
                with self.assertRaises(SafetyBarrierViolation):
                    self.client_read_only.execute_request(ep)
                self.assert_zero_network_io()

    # =========================================================================
    # 3. URL Casing Variations Bypass Attempts
    # =========================================================================
    def test_adv_casing_variations_all_denylist_endpoints(self):
        """Test case mutations (uppercase, mixedCase, CamelCase) across forbidden endpoints."""
        cases = [
            "/APP/HOME/DELETECLIENTEQUIPMENT",
            "/App/Home/DeleteClientEquipment",
            "/aPp/hOmE/dElEtEcLiEnTeQuIpMeNt",
            "/APP/DOORBELLLOCK/REMOVELOCK",
            "/App/DoorbellLock/BindLock",
            "/APP/HOME/ADDEQUIPMENT",
            "/APP/HOME/ALTEREQUIPMENTNOTE",
            "/APP/HOME/ALTEREQUIPMENTROOM",
            "/RESETLOCK",
            "/ResetLock",
            "/CLEARFINGERPRINTS",
            "/ClearAllFingerprints",
            "/DELETEFINGERPRINT",
            "/DELETEPASSCODE",
            "/SETADMIN",
            "/APP/CLIENT/ALTERPASSWORD",
            "/App/Client/AlterPassword",
            "/APP/CLIENT/FINDBACKPASSWORD",
            "/APP/CLIENT/BINDEMAIL",
            "/APP/SYSTEM/CLIENTDELETEMESSAGE",
        ]
        for ep in cases:
            with self.subTest(endpoint=ep):
                self.mock_network_calls.clear()
                with self.assertRaises(SafetyBarrierViolation):
                    self.client_read_only.execute_request(ep)
                self.assert_zero_network_io()

    # =========================================================================
    # 4. Query Parameter Smuggling & Fragments
    # =========================================================================
    def test_adv_query_param_and_fragment_smuggling(self):
        """Test query parameter injection and URI fragments appended to dangerous endpoints."""
        query_fragment_attempts = [
            "/app/home/deleteClientEquipment?foo=bar",
            "/app/home/deleteClientEquipment?bypass=true&force=1",
            "/app/home/deleteClientEquipment#top",
            "/app/home/deleteClientEquipment?foo=bar#section",
            "/app/doorbellLock/removeLock?lockId=123",
            "/resetLock?factory=true#force",
            "/app/client/alterPassword?old=1&new=2",
            "https://app.geekaihome.com/app/home/deleteClientEquipment?foo=bar#section",
            "http://app.geekaihome.com/app/home/deleteClientEquipment",
        ]
        for ep in query_fragment_attempts:
            with self.subTest(endpoint=ep):
                self.mock_network_calls.clear()
                with self.assertRaises(SafetyBarrierViolation):
                    self.client_read_only.execute_request(ep)
                self.assert_zero_network_io()

    def test_adv_query_smuggling_attempt_on_safe_endpoints(self):
        """
        Verify that attaching query strings with destructive endpoints or params
        onto safe endpoints either normalizes safely or gets blocked without executing destructive actions.
        """
        # Testing safe endpoint with destructive query string:
        # e.g. /app/home/getClientEquipmentList?action=deleteClientEquipment
        # normalize_endpoint strips the query and normalizes to /app/home/getclientequipmentlist
        res_endpoint = SafetyBarrierGuard.normalize_endpoint("/app/home/getClientEquipmentList?action=deleteClientEquipment")
        self.assertEqual(res_endpoint, "/app/home/getclientequipmentlist")

        # But if destructive parameter name is in params dictionary, parameter inspection blocks it:
        with self.assertRaises(SafetyBarrierViolation):
            self.client_read_only.execute_request(
                "/app/home/getClientEquipmentList",
                {"newPassword": "malicious_override"}
            )
        self.assert_zero_network_io()

    # =========================================================================
    # 5. Parameter Injection Attacks
    # =========================================================================
    def test_adv_parameter_injection_password_tampering(self):
        """Test parameter injection targeting credential or password modification."""
        malicious_params = [
            {"newPassword": "AttackerPassword123!"},
            {"newpassword": "AttackerPassword123!"},
            {"NEWPASSWORD": "AttackerPassword123!"},
            {"nEwPaSsWoRd": "AttackerPassword123!"},
            {"alterPassword": "true"},
            {"alterpassword": "1"},
            {"ALTERPASSWORD": "1"},
            {"user_newpassword": "xyz"},
            {"confirm_newpassword": "xyz"},
        ]
        safe_endpoint = "/app/home/getClientEquipmentList"
        for p in malicious_params:
            with self.subTest(params=p):
                self.mock_network_calls.clear()
                with self.assertRaises(SafetyBarrierViolation) as ctx:
                    self.client_read_only.execute_request(safe_endpoint, p)
                self.assert_zero_network_io()
                self.assertIn("PARAMETER_VIOLATION", ctx.exception.category)

    def test_adv_parameter_injection_authtype_wipe(self):
        """Test dangerous authType parameter values (5, 6, 7) used in biometric/passcode wipe."""
        wipe_codes = [5, 6, 7, "5", "6", "7"]
        safe_endpoint = "/app/home/getClientEquipmentList"
        for code in wipe_codes:
            for key_variant in ["authType", "authtype", "AUTHTYPE", "AuthType"]:
                with self.subTest(key=key_variant, code=code):
                    self.mock_network_calls.clear()
                    with self.assertRaises(SafetyBarrierViolation) as ctx:
                        self.client_read_only.execute_request(safe_endpoint, {key_variant: code})
                    self.assert_zero_network_io()
                    self.assertIn("PARAMETER_VIOLATION", ctx.exception.category)

    # =========================================================================
    # 6. Zero Network I/O Guarantee & Socket Mock Verification
    # =========================================================================
    def test_adv_zero_network_io_requests_session_never_called(self):
        """
        Verify with MagicMock on requests.Session that neither get() nor post()
        is ever called when a safety barrier violation occurs.
        """
        mock_session = MagicMock()
        client = GeekSmartClient(
            session=mock_session,
            mode=ClientMode.READ_ONLY,
        )
        client.token = "TEST_TOKEN"
        client.client_id = 12345

        test_attack_vectors = [
            ("/app/home/deleteClientEquipment", {}),
            ("/app/client/../home/deleteClientEquipment", {}),
            ("///app///home///deleteClientEquipment", {}),
            ("/APP/HOME/DELETECLIENTEQUIPMENT", {}),
            ("/app/home/getClientEquipmentList", {"newPassword": "hack"}),
            ("/app/home/getClientEquipmentList", {"authType": 6}),
            ("/app/home/ttlockGatewayUnlock", {}),  # Blocked in READ_ONLY mode
        ]

        for ep, params in test_attack_vectors:
            with self.subTest(endpoint=ep, params=params):
                mock_session.reset_mock()
                with self.assertRaises(SafetyBarrierViolation):
                    client.execute_request(ep, params)
                # Confirm requests.Session.get and post were NOT called
                mock_session.get.assert_not_called()
                mock_session.post.assert_not_called()
                mock_session.request.assert_not_called()

    # =========================================================================
    # 7. Operational Mode Boundary Verification
    # =========================================================================
    def test_adv_mode_enforcement_read_only_blocks_actuation(self):
        """Test that actuation endpoints (unlock/lock) are blocked in READ_ONLY mode."""
        actuation_endpoints = [
            "/app/home/ttlockGatewayUnlock",
            "/app/home/ttlockGatewayLock",
            "/app/home/ttlockgatewayunlock",
            "/app/home/ttlockgatewaylock",
        ]
        for ep in actuation_endpoints:
            with self.subTest(endpoint=ep):
                self.mock_network_calls.clear()
                with self.assertRaises(SafetyBarrierViolation) as ctx:
                    self.client_read_only.execute_request(ep)
                self.assert_zero_network_io()
                self.assertIn("MODE_VIOLATION_READ_ONLY", ctx.exception.category)

    def test_adv_mode_enforcement_read_only_blocks_unauthorized_endpoints(self):
        """Test that any endpoint not in ALLOWLIST_READ_ONLY is blocked in READ_ONLY mode."""
        random_endpoints = [
            "/app/unknown/someService",
            "/app/custom/endpoint",
            "/api/v1/backdoor",
            "/app/home/someNewEndpoint",
        ]
        for ep in random_endpoints:
            with self.subTest(endpoint=ep):
                self.mock_network_calls.clear()
                with self.assertRaises(SafetyBarrierViolation) as ctx:
                    self.client_read_only.execute_request(ep)
                self.assert_zero_network_io()
                self.assertIn("ALLOWLIST_VIOLATION", ctx.exception.category)

    def test_adv_mode_enforcement_safe_control_blocks_destructive_endpoints(self):
        """
        Test that SAFE_CONTROL mode permits actuation, but PERMANENTLY blocks all destructive endpoints.
        """
        # Actuation endpoints ARE allowed in SAFE_CONTROL
        self.mock_network_calls.clear()
        code, msg, data = self.client_safe_control.execute_request("/app/home/ttlockGatewayUnlock")
        self.assertEqual(len(self.mock_network_calls), 1)

        # Destructive endpoints REMAIN STRICTLY BLOCKED in SAFE_CONTROL
        destructive_endpoints = [
            "/app/home/deleteClientEquipment",
            "/app/doorbellLock/removeLock",
            "/app/home/alterPassword",
            "/resetLock",
            "/clearFingerprints",
        ]
        for ep in destructive_endpoints:
            with self.subTest(endpoint=ep):
                self.mock_network_calls.clear()
                with self.assertRaises(SafetyBarrierViolation):
                    self.client_safe_control.execute_request(ep)
                self.assert_zero_network_io()

    # =========================================================================
    # 8. Complete Hard Denylist & Destructive Verbs Coverage
    # =========================================================================
    def test_adv_all_hard_denylist_endpoints_blocked_unconditionally(self):
        """Verify that every single endpoint defined in HARD_DENYLIST_ENDPOINTS is blocked."""
        for ep in HARD_DENYLIST_ENDPOINTS:
            with self.subTest(endpoint=ep):
                self.mock_network_calls.clear()
                with self.assertRaises(SafetyBarrierViolation):
                    self.client_safe_control.execute_request(ep)
                self.assert_zero_network_io()

    def test_adv_destructive_verb_keyword_regex_defense_in_depth(self):
        """
        Test Defense-in-Depth regex blocking arbitrary endpoints containing destructive verbs
        (delete, remove, bind, clear, reset, alter, init, destroy, unpair, unbind).
        """
        arbitrary_dangerous = [
            "/app/experimental/deleteEverything",
            "/app/test/removeUser",
            "/app/service/bindBackdoor",
            "/app/admin/clearMemory",
            "/app/device/resetSettings",
            "/app/profile/alterSettings",
            "/app/crypto/initMasterKey",
            "/app/cloud/destroyContainer",
            "/app/bluetooth/unpairDevice",
            "/app/lock/unbindGateway",
        ]
        for ep in arbitrary_dangerous:
            with self.subTest(endpoint=ep):
                self.mock_network_calls.clear()
                with self.assertRaises(SafetyBarrierViolation) as ctx:
                    self.client_safe_control.execute_request(ep)
                self.assert_zero_network_io()
                self.assertIn("VIOLATION", ctx.exception.category)

    # =========================================================================
    # 9. Session Immutability Across Repeated Attack Failures
    # =========================================================================
    def test_adv_session_state_immutability_under_continuous_fuzzing(self):
        """
        Verify that client session token, client_id, and user profile remain completely
        unaltered after receiving hundreds of continuous adversarial bypass attacks.
        """
        original_token = self.client_read_only.token
        original_client_id = self.client_read_only.client_id
        original_user_info = self.client_read_only.user_info

        fuzz_endpoints = [
            "/app/client/../home/deleteClientEquipment",
            "///app///home///deleteClientEquipment",
            "/APP/HOME/DELETECLIENTEQUIPMENT",
            "/app/home/deleteClientEquipment?param=1#frag",
            "/app/doorbellLock/removeLock",
            "/resetLock",
            "/clearFingerprints",
            "/app/client/alterPassword",
        ]

        for i in range(10):
            for ep in fuzz_endpoints:
                with self.assertRaises(SafetyBarrierViolation):
                    self.client_read_only.execute_request(ep, {"newPassword": "foo", "authType": 6})

        # Check immutability
        self.assertEqual(self.client_read_only.token, original_token)
        self.assertEqual(self.client_read_only.client_id, original_client_id)
        self.assertEqual(self.client_read_only.user_info, original_user_info)
        self.assert_zero_network_io()

        # Legitimate read-only operation succeeds immediately without issue
        self.mock_network_calls.clear()
        code, msg, data = self.client_read_only.execute_request("/app/home/getClientEquipmentListMap")
        self.assertEqual(code, 0)
        self.assertEqual(len(self.mock_network_calls), 1)


if __name__ == "__main__":
    unittest.main()
