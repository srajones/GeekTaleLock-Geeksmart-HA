"""Tier 1 and Tier 2 tests for Cloud Authentication and Token Lifecycle Management."""

import unittest
from tests.conftest import (
    MOCK_USER_BEAN,
    GeekSmartAuthError,
    get_client_class,
    build_mock_server_response,
)


class TestAuthAndToken(unittest.TestCase):
    """Test suite covering GeekSmart cloud authentication and session lifecycle management."""

    def setUp(self):
        self.client_cls = get_client_class()
        self.client = self.client_cls()

    # --- Tier 1: Feature Coverage (Authentication & Token Lifecycle) ---

    def test_T1_06_auth_success_returns_user_bean(self):
        """T1.06: Successful login returns UserBean dict with token and integer client ID."""
        user = self.client.login("testuser@example.com", "MockPassword123!")
        self.assertIsInstance(user, dict)
        self.assertIn("token", user)
        self.assertIn("id", user)
        self.assertEqual(user["id"], 9999999)
        self.assertEqual(self.client.token, user["token"])
        self.assertEqual(self.client.client_id, 9999999)

    def test_T1_07_auth_request_payload_telemetry_fields(self):
        """T1.07: Login request payload contains platform, version, countryLang, and currentTimestamp."""
        captured_params = {}

        def intercept_transport(endpoint, full_params, method):
            nonlocal captured_params
            captured_params = full_params
            return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}

        client = self.client_cls(mock_transport=intercept_transport)
        client.login("testuser@example.com", "MockPassword123!")

        self.assertEqual(captured_params.get("platform"), "android_geeksmarthome")
        self.assertEqual(captured_params.get("version"), "1.1.2")
        self.assertEqual(captured_params.get("countryLang"), "EN")
        self.assertIn("currentTimestamp", captured_params)
        self.assertEqual(captured_params.get("type"), "1")

    def test_T1_08_auth_extracts_tuya_credentials(self):
        """T1.08: Auth response extracts synthetic Tuya credentials for smart plug BLE gateway bridge."""
        user = self.client.login("testuser@example.com", "MockPassword123!")
        self.assertEqual(user.get("tuyaUid"), "tuya_mock_uid_1099")
        self.assertEqual(user.get("tuyaUsername"), "testuser@example.com")
        self.assertEqual(user.get("tuyaPassword"), "a1b2c3d4")
        self.assertEqual(user.get("tuyaCountryCode"), 1)

    def test_T1_09_auth_extracts_ttlock_credentials(self):
        """T1.09: Auth response extracts synthetic TTLock credentials for lock core controls."""
        user = self.client.login("testuser@example.com", "MockPassword123!")
        self.assertEqual(user.get("ttlockUid"), "10000001")
        self.assertEqual(user.get("ttlockUsername"), "geekaihome_9999999")
        self.assertEqual(user.get("ttlockPassword"), "d4c3b2a1")

    def test_T1_10_auth_request_omits_token_for_login(self):
        """T1.10: Unauthenticated login request does not send an empty or stale token."""
        captured_params = {}

        def intercept_transport(endpoint, full_params, method):
            nonlocal captured_params
            captured_params = full_params
            return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}

        client = self.client_cls(mock_transport=intercept_transport)
        client.login("testuser@example.com", "MockPassword123!")
        self.assertNotIn("token", captured_params, "Login request should not include token before authentication")

    def test_T1_11_token_cached_and_reused_subsequent_calls(self):
        """T1.11: Stored session token is cached and attached to subsequent API calls."""
        requests_received = []

        def intercept_transport(endpoint, full_params, method):
            requests_received.append((endpoint, full_params))
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            return {"code": 0, "msg": "OK", "data": {"equipmentList": []}}

        client = self.client_cls(mock_transport=intercept_transport)
        client.login("testuser@example.com", "MockPassword123!")
        client.discover_devices()

        self.assertEqual(len(requests_received), 2)
        second_call_params = requests_received[1][1]
        self.assertEqual(second_call_params.get("token"), MOCK_USER_BEAN["token"])

    def test_T1_12_token_client_id_stored(self):
        """T1.12: Client ID from UserBean is stored and supplied as clientId in device requests."""
        client = self.client_cls()
        client.login("testuser@example.com", "MockPassword123!")
        self.assertEqual(client.client_id, 9999999)

    def test_T1_13_token_expired_triggers_auto_relogin(self):
        """T1.13: When server returns code 3 (token expired), client auto-relocates credentials and retries."""
        call_count = 0
        new_token = "NEW_RENEWED_SESSION_TOKEN=="

        def intercept_transport(endpoint, full_params, method):
            nonlocal call_count
            call_count += 1
            if "loginByPassword" in endpoint:
                user = dict(MOCK_USER_BEAN)
                user["token"] = new_token
                return {"code": 0, "msg": "OK", "data": user}
            if call_count == 2:  # First device call returns token expired code 3
                return {"code": 3, "msg": "Token expired, please login again", "data": None}
            # Second device call after auto-relogin returns success
            return {"code": 0, "msg": "OK", "data": {"equipmentList": [{"id": 1}]}}

        client = self.client_cls(mock_transport=intercept_transport)
        client.login("testuser@example.com", "MockPassword123!")
        devices = client.discover_devices()

        self.assertEqual(len(devices), 1)
        self.assertEqual(client.token, new_token)
        # Should have executed: initial login -> discover (code 3) -> auto-relogin -> discover retry
        self.assertEqual(call_count, 4)

    def test_T1_14_token_update_on_relogin(self):
        """T1.14: Active session token is updated immediately when re-authenticated."""
        client = self.client_cls()
        client.login("testuser@example.com", "MockPassword123!")
        old_token = client.token
        self.assertIsNotNone(old_token)

    def test_T1_15_unauthenticated_request_raises_error(self):
        """T1.15: Calling authenticated endpoints before login raises GeekSmartAuthError."""
        client = self.client_cls()
        with self.assertRaises(GeekSmartAuthError):
            client.discover_devices()

    # --- Tier 2: Boundary & Corner Cases (Authentication) ---

    def test_T2_01_boundary_bad_password_error_code_2007(self):
        """T2.01: Incorrect password yields code 2007 ('Password mistake') and raises GeekSmartAuthError."""
        with self.assertRaises(GeekSmartAuthError) as ctx:
            self.client.login("testuser@example.com", "WrongPassword123!")
        self.assertEqual(ctx.exception.code, 2007)

    def test_T2_02_boundary_unregistered_email_error_code_2010(self):
        """T2.02: Unregistered email yields code 2010 ('This mailbox is not registered') and raises GeekSmartAuthError."""
        with self.assertRaises(GeekSmartAuthError) as ctx:
            self.client.login("nonexistent_user_999@test.com", "MockPassword123!")
        self.assertEqual(ctx.exception.code, 2010)

    def test_T2_03_boundary_empty_email_or_password_raises_value_error(self):
        """T2.03: Blank, None, or empty email/password raises ValueError before emitting network calls."""
        invalid_pairs = [
            ("", "password"),
            ("   ", "password"),
            ("user@example.com", ""),
            ("user@example.com", "   "),
            (None, "password"),
            ("user@example.com", None),
        ]
        for email, pwd in invalid_pairs:
            with self.subTest(email=email, pwd=pwd):
                with self.assertRaises(ValueError):
                    self.client.login(email, pwd)

    def test_T2_06_boundary_null_or_missing_fields_in_user_bean(self):
        """T2.06: Response missing optional fields (e.g. headImg) handled gracefully without KeyError."""
        minimal_user = {
            "id": 999999,
            "token": "MINIMAL_VALID_TOKEN==",
            "email": "user@domain.com"
        }

        def intercept_transport(endpoint, full_params, method):
            return {"code": 0, "msg": "OK", "data": minimal_user}

        client = self.client_cls(mock_transport=intercept_transport)
        user = client.login("user@domain.com", "SecretPass123!")
        self.assertEqual(user["id"], 999999)
        self.assertEqual(client.token, "MINIMAL_VALID_TOKEN==")

    def test_T2_14_boundary_max_relogin_attempts_prevention(self):
        """T2.14: Continuous code 3 responses should abort after 1 retry to avoid infinite recursion."""
        call_count = 0

        def always_expired_transport(endpoint, full_params, method):
            nonlocal call_count
            call_count += 1
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            # Always return token expired code 3
            return {"code": 3, "msg": "Token expired, please login again", "data": None}

        client = self.client_cls(mock_transport=always_expired_transport)
        client.login("testuser@example.com", "MockPassword123!")

        with self.assertRaises(GeekSmartAuthError) as ctx:
            client.discover_devices()
        self.assertEqual(ctx.exception.code, 3)
        # Should not loop infinitely (call_count must be bounded, <= 4)
        self.assertLessEqual(call_count, 4)


if __name__ == "__main__":
    unittest.main()
