#!/usr/bin/env python3
"""
Empirical Adversarial Test Suite for Milestone 1 Hardening (Challenger 2).
File: tests/test_challenger_ha_m1_2.py

Covers:
1. Reauth Flow Validation:
   - async_step_reauth & async_step_reauth_confirm under MODE_DIRECT_CLOUD & MODE_SERVER_BRIDGE
   - Form schemas, placeholders, step IDs, error keys (invalid_auth, cannot_connect, invalid_server_response)
   - reload triggers and data propagation (async_update_reload_and_abort / async_abort)
   - config entry resolution mechanisms (_get_reauth_entry via hass, context, or entry data)

2. Webhook Ingestion Boundary Testing:
   - async_handle_webhook: HTTP 400 rejection for malformed JSON, non-dict payloads (string, list, int, float, bool, None)
   - async_handle_webhook: HTTP 500 rejection without unhandled crash when coordinator throws
   - async_handle_push_data: Boundary testing with non-dict payloads, empty/missing/numeric device IDs, malformed states, null fields

3. Entity Availability Invariant Testing:
   - GeekDoorLock & GeekDoorAutoLockSwitch availability invariants
   - Transitions: coordinator.last_update_success True -> False -> True
   - Edge cases: coordinator is None, device missing from data, offline device with/without BLE direct fallback

Safety:
- Zero physical deadbolt actuations (enforced via mock objects and dry_run)
- Zero lingering background server processes
"""

from __future__ import annotations

import asyncio
import os
import sys
import unittest
from typing import Any, Dict, Mapping, Optional
from unittest.mock import AsyncMock, MagicMock, patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from custom_components.geek_door.const import (
    CONF_API_KEY,
    CONF_BLE_DIRECT_FALLBACK,
    CONF_COUNTRY_CODE,
    CONF_MODE,
    CONF_PASSWORD,
    CONF_SERVER_URL,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    CONF_WEBHOOK_ID,
    DEFAULT_BLE_DIRECT_FALLBACK,
    DEFAULT_COUNTRY_CODE,
    DOMAIN,
    MODE_DIRECT_CLOUD,
    MODE_SERVER_BRIDGE,
)
from custom_components.geek_door.config_flow import GeekDoorConfigFlow
from custom_components.geek_door.coordinator import GeekDoorDataUpdateCoordinator
from custom_components.geek_door.lock import GeekDoorLock
from custom_components.geek_door.switch import GeekDoorAutoLockSwitch
from custom_components.geek_door.core.lock_engine import LockDevice, LockStateSnapshot


# ============================================================================
# Task 1: Reauth Flow Validation (Direct Cloud & Server Bridge)
# ============================================================================

class TestReauthFlowValidation(unittest.IsolatedAsyncioTestCase):
    """Adversarial stress-testing of reauth flow in config_flow.py."""

    def setUp(self):
        self.flow = GeekDoorConfigFlow()
        self.mock_hass = MagicMock()
        self.flow.hass = self.mock_hass

    # --- Direct Cloud Mode ---

    async def test_reauth_direct_cloud_initial_prompt_schema(self):
        """async_step_reauth with Direct Cloud entry returns reauth_confirm form with username placeholder."""
        entry_data = {
            CONF_MODE: MODE_DIRECT_CLOUD,
            CONF_USERNAME: "alice@example.com",
            CONF_PASSWORD: "old_password_123",
            CONF_COUNTRY_CODE: "1",
        }
        mock_entry = MagicMock()
        mock_entry.data = entry_data
        self.flow._reauth_entry = mock_entry

        # Test with mock voluptuous to verify schema construction
        mock_vol = MagicMock()
        mock_vol.Required = lambda k: k
        mock_vol.Schema = lambda s: MagicMock(schema=s)

        with patch("custom_components.geek_door.config_flow.vol", mock_vol):
            res = await self.flow.async_step_reauth(entry_data)
            self.assertEqual(res["type"], "form")
            self.assertEqual(res["step_id"], "reauth_confirm")
            self.assertEqual(res.get("description_placeholders", {}).get("username"), "alice@example.com")
            self.assertIsNotNone(res.get("data_schema"))
            self.assertIn(CONF_PASSWORD, res.get("data_schema").schema)

        # Also test graceful fallback when vol is None
        with patch("custom_components.geek_door.config_flow.vol", None):
            res_no_vol = await self.flow.async_step_reauth(entry_data)
            self.assertEqual(res_no_vol["type"], "form")
            self.assertEqual(res_no_vol["step_id"], "reauth_confirm")
            self.assertIsNone(res_no_vol.get("data_schema"))

    async def test_reauth_direct_cloud_mode_inference_when_mode_key_missing(self):
        """When CONF_MODE is missing, reauth infers Direct Cloud from absence of server URL."""
        entry_data = {
            CONF_USERNAME: "bob@example.com",
            CONF_PASSWORD: "old_password_abc",
        }
        res = await self.flow.async_step_reauth(entry_data)
        self.assertEqual(res["type"], "form")
        self.assertEqual(res["step_id"], "reauth_confirm")
        self.assertEqual(res.get("description_placeholders", {}).get("username"), "bob@example.com")

    async def test_reauth_direct_cloud_empty_or_whitespace_password_rejection(self):
        """Direct cloud reauth rejects empty or whitespace-only passwords with invalid_auth."""
        entry_data = {
            CONF_MODE: MODE_DIRECT_CLOUD,
            CONF_USERNAME: "alice@example.com",
            CONF_PASSWORD: "old_password",
        }
        await self.flow.async_step_reauth(entry_data)

        for empty_val in ["", "   ", "\t\n"]:
            res = await self.flow.async_step_reauth_confirm(user_input={CONF_PASSWORD: empty_val})
            self.assertEqual(res["type"], "form")
            self.assertEqual(res.get("errors", {}).get("base"), "invalid_auth")

    async def test_reauth_direct_cloud_auth_failure_exceptions(self):
        """Direct cloud reauth maps credentials/signature/auth errors to invalid_auth error key."""
        entry_data = {
            CONF_MODE: MODE_DIRECT_CLOUD,
            CONF_USERNAME: "alice@example.com",
            CONF_PASSWORD: "old_password",
        }
        await self.flow.async_step_reauth(entry_data)

        auth_exceptions = [
            Exception("USER_PASSWD_WRONG"),
            Exception("USERNAME_NOT_EXIST"),
            Exception("Invalid credentials provided"),
            Exception("Signature verification failed: 1004"),
            Exception("Permission denied for client equipment"),
        ]

        self.mock_hass.async_add_executor_job = AsyncMock()

        for exc in auth_exceptions:
            self.mock_hass.async_add_executor_job.side_effect = exc
            res = await self.flow.async_step_reauth_confirm(user_input={CONF_PASSWORD: "bad_password"})
            self.assertEqual(res["type"], "form", f"Expected form for {exc}")
            self.assertEqual(res.get("errors", {}).get("base"), "invalid_auth", f"Expected invalid_auth for {exc}")

    async def test_reauth_direct_cloud_network_and_timeout_exceptions(self):
        """Direct cloud reauth maps connection drops, unreachable hosts, and timeouts to cannot_connect."""
        entry_data = {
            CONF_MODE: MODE_DIRECT_CLOUD,
            CONF_USERNAME: "alice@example.com",
            CONF_PASSWORD: "old_password",
        }
        await self.flow.async_step_reauth(entry_data)

        net_exceptions = [
            TimeoutError("Connection timed out to tuya gateway"),
            Exception("connect ECONNREFUSED 198.51.100.1:443"),
            Exception("Host unreachable"),
            Exception("Network connection reset by peer"),
            Exception("read timed out after 10.0 seconds"),
        ]

        self.mock_hass.async_add_executor_job = AsyncMock()

        for exc in net_exceptions:
            self.mock_hass.async_add_executor_job.side_effect = exc
            res = await self.flow.async_step_reauth_confirm(user_input={CONF_PASSWORD: "new_password"})
            self.assertEqual(res["type"], "form", f"Expected form for {exc}")
            self.assertEqual(res.get("errors", {}).get("base"), "cannot_connect", f"Expected cannot_connect for {exc}")

    async def test_reauth_direct_cloud_success_with_async_update_reload_and_abort(self):
        """On successful reauth, calls async_update_reload_and_abort with updated password and preserved fields."""
        entry_data = {
            CONF_MODE: MODE_DIRECT_CLOUD,
            CONF_USERNAME: "alice@example.com",
            CONF_PASSWORD: "old_password",
            CONF_COUNTRY_CODE: "86",
            "custom_metadata": "preserved_value",
        }
        mock_entry = MagicMock()
        mock_entry.data = dict(entry_data)
        self.flow._reauth_entry = mock_entry

        # Mock async_update_reload_and_abort on flow
        self.flow.async_update_reload_and_abort = MagicMock(return_value={
            "type": "abort",
            "reason": "reauth_successful",
        })

        await self.flow.async_step_reauth(entry_data)

        self.mock_hass.async_add_executor_job = AsyncMock(return_value=[{"devId": "lock_99"}])

        res = await self.flow.async_step_reauth_confirm(user_input={CONF_PASSWORD: "brand_new_secret"})
        self.assertEqual(res["type"], "abort")
        self.assertEqual(res["reason"], "reauth_successful")

        self.flow.async_update_reload_and_abort.assert_called_once()
        call_args = self.flow.async_update_reload_and_abort.call_args
        self.assertEqual(call_args[0][0], mock_entry)
        updated_data = call_args[1]["data"]
        self.assertEqual(updated_data[CONF_PASSWORD], "brand_new_secret")
        self.assertEqual(updated_data[CONF_USERNAME], "alice@example.com")
        self.assertEqual(updated_data[CONF_COUNTRY_CODE], "86")
        self.assertEqual(updated_data.get("custom_metadata"), "preserved_value")

    async def test_reauth_entry_resolution_from_hass_config_entries_context(self):
        """_get_reauth_entry resolves entry from hass.config_entries when context entry_id is present."""
        mock_entry = MagicMock()
        mock_entry.data = {
            CONF_MODE: MODE_DIRECT_CLOUD,
            CONF_USERNAME: "context_user@example.com",
            CONF_PASSWORD: "old_pwd",
        }
        self.mock_hass.config_entries = MagicMock()
        self.mock_hass.config_entries.async_get_entry.return_value = mock_entry
        self.flow.context = {"entry_id": "entry_uuid_12345"}

        resolved = self.flow._get_reauth_entry()
        self.assertEqual(resolved, mock_entry)
        self.mock_hass.config_entries.async_get_entry.assert_called_with("entry_uuid_12345")

    # --- Server Bridge Mode ---

    async def test_reauth_server_bridge_initial_prompt_schema(self):
        """async_step_reauth with Server Bridge entry returns reauth_confirm form with server_url placeholder."""
        entry_data = {
            CONF_MODE: MODE_SERVER_BRIDGE,
            CONF_SERVER_URL: "https://hub.local:5050",
            CONF_API_KEY: "old_secret_key",
            CONF_VERIFY_SSL: False,
        }
        mock_entry = MagicMock()
        mock_entry.data = entry_data
        self.flow._reauth_entry = mock_entry

        # Test with mock voluptuous to verify schema construction
        mock_vol = MagicMock()
        mock_vol.Required = lambda k: k
        mock_vol.Schema = lambda s: MagicMock(schema=s)

        with patch("custom_components.geek_door.config_flow.vol", mock_vol):
            res = await self.flow.async_step_reauth(entry_data)
            self.assertEqual(res["type"], "form")
            self.assertEqual(res["step_id"], "reauth_confirm")
            self.assertEqual(res.get("description_placeholders", {}).get("server_url"), "https://hub.local:5050")
            self.assertIsNotNone(res.get("data_schema"))
            self.assertIn(CONF_API_KEY, res.get("data_schema").schema)

        # Also test graceful fallback when vol is None
        with patch("custom_components.geek_door.config_flow.vol", None):
            res_no_vol = await self.flow.async_step_reauth(entry_data)
            self.assertEqual(res_no_vol["type"], "form")
            self.assertEqual(res_no_vol["step_id"], "reauth_confirm")
            self.assertIsNone(res_no_vol.get("data_schema"))

    async def test_reauth_server_bridge_empty_api_key_rejection(self):
        """Server bridge reauth rejects blank or whitespace API key with invalid_auth."""
        entry_data = {
            CONF_MODE: MODE_SERVER_BRIDGE,
            CONF_SERVER_URL: "http://127.0.0.1:5050",
            CONF_API_KEY: "old_key",
        }
        await self.flow.async_step_reauth(entry_data)

        for blank in ["", "    ", "\n"]:
            res = await self.flow.async_step_reauth_confirm(user_input={CONF_API_KEY: blank})
            self.assertEqual(res["type"], "form")
            self.assertEqual(res.get("errors", {}).get("base"), "invalid_auth")

    async def test_reauth_server_bridge_http_401_403_rejection(self):
        """Server bridge reauth maps HTTP 401 and 403 server status to invalid_auth."""
        entry_data = {
            CONF_MODE: MODE_SERVER_BRIDGE,
            CONF_SERVER_URL: "http://127.0.0.1:5050",
            CONF_API_KEY: "old_key",
        }
        await self.flow.async_step_reauth(entry_data)

        for status_code in [401, 403]:
            class MockResp:
                status = status_code
                async def json(self): return {"error": "unauthorized"}
                async def __aenter__(self): return self
                async def __aexit__(self, *args): pass

            class MockSession:
                def get(self, *args, **kwargs): return MockResp()

            with patch("custom_components.geek_door.config_flow.async_get_clientsession", return_value=MockSession()):
                res = await self.flow.async_step_reauth_confirm(user_input={CONF_API_KEY: "rejected_key"})
                self.assertEqual(res["type"], "form")
                self.assertEqual(res.get("errors", {}).get("base"), "invalid_auth")

    async def test_reauth_server_bridge_http_500_and_network_failures(self):
        """Server bridge reauth maps HTTP 500, 502, 503, and connection exceptions to cannot_connect."""
        entry_data = {
            CONF_MODE: MODE_SERVER_BRIDGE,
            CONF_SERVER_URL: "http://127.0.0.1:5050",
            CONF_API_KEY: "old_key",
        }
        await self.flow.async_step_reauth(entry_data)

        # 1. Non-200 HTTP responses
        for status_code in [500, 502, 503, 504]:
            class MockResp:
                status = status_code
                async def json(self): return {"error": "server error"}
                async def __aenter__(self): return self
                async def __aexit__(self, *args): pass

            class MockSession:
                def get(self, *args, **kwargs): return MockResp()

            with patch("custom_components.geek_door.config_flow.async_get_clientsession", return_value=MockSession()):
                res = await self.flow.async_step_reauth_confirm(user_input={CONF_API_KEY: "valid_key"})
                self.assertEqual(res["type"], "form")
                self.assertEqual(res.get("errors", {}).get("base"), "cannot_connect")

        # 2. Connection exceptions
        class BrokenSession:
            def get(self, *args, **kwargs):
                raise ConnectionResetError("Connection refused by target host")

        with patch("custom_components.geek_door.config_flow.async_get_clientsession", return_value=BrokenSession()):
            res = await self.flow.async_step_reauth_confirm(user_input={CONF_API_KEY: "valid_key"})
            self.assertEqual(res["type"], "form")
            self.assertEqual(res.get("errors", {}).get("base"), "cannot_connect")

    async def test_reauth_server_bridge_invalid_server_payload(self):
        """Server bridge reauth validates that server response contains service=='mydoor'."""
        entry_data = {
            CONF_MODE: MODE_SERVER_BRIDGE,
            CONF_SERVER_URL: "http://127.0.0.1:5050",
            CONF_API_KEY: "old_key",
        }
        await self.flow.async_step_reauth(entry_data)

        bad_payloads = [
            {"service": "other_service", "status": "ok"},
            {"status": "ok"},  # missing 'service' key
            ["list", "response"],  # non-dict
            "string response",  # non-dict
        ]

        for payload in bad_payloads:
            class MockResp:
                status = 200
                async def json(self): return payload
                async def __aenter__(self): return self
                async def __aexit__(self, *args): pass

            class MockSession:
                def get(self, *args, **kwargs): return MockResp()

            with patch("custom_components.geek_door.config_flow.async_get_clientsession", return_value=MockSession()):
                res = await self.flow.async_step_reauth_confirm(user_input={CONF_API_KEY: "valid_key"})
                self.assertEqual(res["type"], "form")
                self.assertEqual(res.get("errors", {}).get("base"), "invalid_server_response")

    async def test_reauth_server_bridge_success_path(self):
        """Server bridge reauth completes successfully and updates API key and URL."""
        entry_data = {
            CONF_MODE: MODE_SERVER_BRIDGE,
            CONF_SERVER_URL: "http://127.0.0.1:5050/",
            CONF_API_KEY: "old_key",
            CONF_VERIFY_SSL: False,
        }
        mock_entry = MagicMock()
        mock_entry.data = dict(entry_data)
        self.flow._reauth_entry = mock_entry

        self.flow.async_update_reload_and_abort = MagicMock(return_value={
            "type": "abort",
            "reason": "reauth_successful",
        })

        await self.flow.async_step_reauth(entry_data)

        class MockResp:
            status = 200
            async def json(self): return {"service": "mydoor", "locks": []}
            async def __aenter__(self): return self
            async def __aexit__(self, *args): pass

        class MockSession:
            def get(self, *args, **kwargs): return MockResp()

        with patch("custom_components.geek_door.config_flow.async_get_clientsession", return_value=MockSession()):
            res = await self.flow.async_step_reauth_confirm(user_input={CONF_API_KEY: "fresh_secret_key"})
            self.assertEqual(res["type"], "abort")
            self.assertEqual(res["reason"], "reauth_successful")

            self.flow.async_update_reload_and_abort.assert_called_once()
            call_data = self.flow.async_update_reload_and_abort.call_args[1]["data"]
            self.assertEqual(call_data[CONF_API_KEY], "fresh_secret_key")
            self.assertEqual(call_data[CONF_SERVER_URL], "http://127.0.0.1:5050")
            self.assertFalse(call_data[CONF_VERIFY_SSL])


# ============================================================================
# Task 2: Webhook Ingestion Boundary Testing
# ============================================================================

class MockHttpResponse:
    def __init__(self, status: int = 200, text: str = ""):
        self.status = status
        self.text = text


class TestWebhookIngestionBoundary(unittest.IsolatedAsyncioTestCase):
    """Stress-tests async_handle_webhook in __init__.py and async_handle_push_data in coordinator.py."""

    def setUp(self):
        from custom_components import geek_door
        self.mock_web_module = MagicMock()
        self.mock_web_module.Response = MockHttpResponse
        self.patcher_web = patch.object(geek_door, "web", self.mock_web_module)
        self.patcher_web.start()

        self.mock_webhook_module = MagicMock()
        self.patcher_webhook = patch.object(geek_door, "webhook", self.mock_webhook_module)
        self.patcher_webhook.start()

    def tearDown(self):
        self.patcher_web.stop()
        self.patcher_webhook.stop()

    async def _setup_and_capture_webhook_handler(self, mock_coordinator: Any) -> Any:
        """Helper to invoke async_setup_entry and capture the registered webhook callback."""
        from custom_components.geek_door import async_setup_entry

        mock_hass = MagicMock()
        mock_hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
        mock_entry = MagicMock()
        mock_entry.entry_id = "test_entry_wh"
        mock_entry.title = "GeekDoor Test"
        mock_entry.data = {
            CONF_MODE: MODE_SERVER_BRIDGE,
            CONF_WEBHOOK_ID: "wh_unique_id_xyz",
        }
        mock_entry.options = {}
        mock_entry.runtime_data = mock_coordinator

        registered_handler = None

        def register_hook(hass, domain, name, wh_id, handler):
            nonlocal registered_handler
            registered_handler = handler

        self.mock_webhook_module.async_register = MagicMock(side_effect=register_hook)
        mock_coordinator.async_config_entry_first_refresh = AsyncMock(return_value=None)

        with patch("custom_components.geek_door.GeekDoorDataUpdateCoordinator", return_value=mock_coordinator):
            await async_setup_entry(mock_hass, mock_entry)

        self.assertIsNotNone(registered_handler, "Webhook handler was not registered")
        return registered_handler

    async def test_webhook_malformed_syntax_returns_http_400(self):
        """When request.json() raises an exception (malformed syntax), webhook returns HTTP 400."""
        mock_coord = MagicMock()
        handler = await self._setup_and_capture_webhook_handler(mock_coord)

        class MalformedRequest:
            async def json(self):
                raise ValueError("JSONDecodeError: Expecting value: line 1 column 1 (char 0)")

        resp = await handler(MagicMock(), "wh_unique_id_xyz", MalformedRequest())
        self.assertEqual(resp.status, 400)
        self.assertIn("Malformed JSON", resp.text)
        mock_coord.async_handle_push_data.assert_not_called()

    async def test_webhook_non_dict_payloads_clean_http_400_rejection(self):
        """Strings, arrays, ints, floats, bools, and None return HTTP 400 without crashing."""
        mock_coord = MagicMock()
        handler = await self._setup_and_capture_webhook_handler(mock_coord)

        malformed_payloads = [
            "just a raw string",
            [1, 2, 3],
            [{"device_id": "lock_1"}],
            12345,
            3.14159,
            True,
            False,
            None,
        ]

        for payload in malformed_payloads:
            class FakeReq:
                async def json(self):
                    return payload

            resp = await handler(MagicMock(), "wh_unique_id_xyz", FakeReq())
            self.assertEqual(resp.status, 400, f"Expected HTTP 400 for payload type {type(payload)}")
            self.assertIn("expected JSON object", resp.text)
            mock_coord.async_handle_push_data.assert_not_called()

    async def test_webhook_unhandled_coordinator_exception_returns_http_500(self):
        """If coordinator.async_handle_push_data raises unexpectedly, returns HTTP 500 without loop crash."""
        mock_coord = MagicMock()
        mock_coord.async_handle_push_data.side_effect = RuntimeError("Simulated crash in push handler")
        handler = await self._setup_and_capture_webhook_handler(mock_coord)

        class ValidReq:
            async def json(self):
                return {"device_id": "lock_1", "new_state": "locked"}

        resp = await handler(MagicMock(), "wh_unique_id_xyz", ValidReq())
        self.assertEqual(resp.status, 500)
        self.assertIn("Internal Error", resp.text)

    async def test_webhook_valid_payload_returns_http_200(self):
        """Valid JSON object payload returns HTTP 200 and forwards to coordinator."""
        mock_coord = MagicMock()
        handler = await self._setup_and_capture_webhook_handler(mock_coord)

        class ValidReq:
            async def json(self):
                return {"device_id": "lock_1", "new_state": "unlocked"}

        resp = await handler(MagicMock(), "wh_unique_id_xyz", ValidReq())
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.text, "OK")
        mock_coord.async_handle_push_data.assert_called_once_with({"device_id": "lock_1", "new_state": "unlocked"})

    def _create_coordinator(self) -> GeekDoorDataUpdateCoordinator:
        mock_entry = MagicMock()
        mock_entry.data = {CONF_MODE: MODE_SERVER_BRIDGE}
        mock_entry.options = {}
        return GeekDoorDataUpdateCoordinator(MagicMock(), mock_entry)

    # --- async_handle_push_data Direct Stress Tests ---

    def test_push_data_with_non_dict_and_none_types_is_noop(self):
        """coordinator.async_handle_push_data safely ignores non-dict inputs without exceptions."""
        coord = self._create_coordinator()
        coord.data = {"d1": {"state": "locked"}}

        for bad in [None, "", "string", 42, 3.14, [], [1], (1, 2), True, False, object()]:
            coord.async_handle_push_data(bad)
            # Ensure existing data is unaltered
            self.assertEqual(coord.data, {"d1": {"state": "locked"}})

    def test_push_data_with_missing_or_blank_device_id_is_noop(self):
        """Missing, empty, or whitespace device IDs in dict payload are safely discarded."""
        coord = self._create_coordinator()
        coord.data = {"d1": {"state": "locked"}}

        bad_payloads = [
            {},
            {"new_state": "unlocked"},
            {"device_id": ""},
            {"device_id": "   "},
            {"device_id": None},
            {"devId": ""},
            {"id": None, "device_id": ""},
        ]

        for p in bad_payloads:
            coord.async_handle_push_data(p)
            self.assertEqual(coord.data, {"d1": {"state": "locked"}})

    def test_push_data_device_id_field_variations(self):
        """Supports device_id, devId, id, and numeric device IDs."""
        coord = self._create_coordinator()
        coord.data = {}

        # 1. 'device_id'
        coord.async_handle_push_data({"device_id": "lock_alpha", "new_state": "locked"})
        self.assertIn("lock_alpha", coord.data)
        self.assertEqual(coord.data["lock_alpha"]["state"], "locked")

        # 2. 'devId'
        coord.async_handle_push_data({"devId": "lock_beta", "new_state": "unlocked"})
        self.assertIn("lock_beta", coord.data)
        self.assertEqual(coord.data["lock_beta"]["state"], "unlocked")

        # 3. 'id'
        coord.async_handle_push_data({"id": "lock_gamma", "battery": 77})
        self.assertIn("lock_gamma", coord.data)
        self.assertEqual(coord.data["lock_gamma"]["battery"], 77)

        # 4. Numeric integer device ID
        coord.async_handle_push_data({"device_id": 101, "new_state": "locked"})
        self.assertIn("101", coord.data)

    def test_push_data_state_and_telemetry_normalization(self):
        """Verifies state normalization (case-insensitivity, is_locked boolean) and telemetry fields."""
        coord = self._create_coordinator()
        coord.data = {
            "d1": {"state": "unlocked", "is_locked": False, "battery": 50, "auto_lock_enabled": True}
        }

        # Uppercase LOCKED -> state: 'locked', is_locked: True
        coord.async_handle_push_data({
            "device_id": "d1",
            "new_state": "LOCKED",
            "battery": 92,
            "auto_lock_enabled": False,
        })
        self.assertEqual(coord.data["d1"]["state"], "locked")
        self.assertTrue(coord.data["d1"]["is_locked"])
        self.assertEqual(coord.data["d1"]["battery"], 92)
        self.assertFalse(coord.data["d1"]["auto_lock_enabled"])

        # UNLOCKED -> state: 'unlocked', is_locked: False
        coord.async_handle_push_data({
            "device_id": "d1",
            "new_state": "  UNLOCKED  ",
        })
        self.assertEqual(coord.data["d1"]["state"], "unlocked")
        self.assertFalse(coord.data["d1"]["is_locked"])
        # battery and auto_lock_enabled preserved
        self.assertEqual(coord.data["d1"]["battery"], 92)
        self.assertFalse(coord.data["d1"]["auto_lock_enabled"])

    def test_push_data_initialization_when_coordinator_data_is_none(self):
        """coordinator.async_handle_push_data safely initializes coordinator.data when starting as None."""
        coord = self._create_coordinator()
        coord.data = None

        coord.async_handle_push_data({"device_id": "fresh_lock", "new_state": "locked"})
        self.assertIsNotNone(coord.data)
        self.assertIn("fresh_lock", coord.data)
        self.assertEqual(coord.data["fresh_lock"]["state"], "locked")


# ============================================================================
# Task 3: Entity Availability Invariant Testing
# ============================================================================

class TestEntityAvailabilityInvariants(unittest.TestCase):
    """Stress-tests availability invariants for GeekDoorLock and GeekDoorAutoLockSwitch."""

    def setUp(self):
        self.mock_entry = MagicMock()
        self.mock_entry.options = {CONF_BLE_DIRECT_FALLBACK: True}

        self.mock_coord = MagicMock()
        self.mock_coord.entry = self.mock_entry
        self.mock_coord.last_update_success = True
        self.mock_coord.data = {
            "lock_online": {
                "name": "Front Door",
                "online": True,
                "mac": "AA:BB:CC:DD:EE:01",
                "local_key": "secret_key_1",
            },
            "lock_offline_with_ble": {
                "name": "Side Door",
                "online": False,
                "mac": "AA:BB:CC:DD:EE:02",
                "local_key": "secret_key_2",
                "ble_fallback_available": True,
            },
            "lock_offline_no_ble": {
                "name": "Back Door",
                "online": False,
            },
        }

        self.lock_online = GeekDoorLock(self.mock_coord, "lock_online")
        self.switch_online = GeekDoorAutoLockSwitch(self.mock_coord, "lock_online")

        self.lock_offline_ble = GeekDoorLock(self.mock_coord, "lock_offline_with_ble")
        self.switch_offline_ble = GeekDoorAutoLockSwitch(self.mock_coord, "lock_offline_with_ble")

        self.lock_offline_no_ble = GeekDoorLock(self.mock_coord, "lock_offline_no_ble")
        self.switch_offline_no_ble = GeekDoorAutoLockSwitch(self.mock_coord, "lock_offline_no_ble")

    def test_invariant_online_entities_follow_coordinator_success_transition(self):
        """Online entities transition available True -> False -> True strictly matching coordinator."""
        # 1. Initial State: last_update_success = True
        self.assertTrue(self.lock_online.available)
        self.assertTrue(self.lock_online.is_online)
        self.assertTrue(self.switch_online.available)

        # 2. Coordinator poll failure: last_update_success = False
        self.mock_coord.last_update_success = False
        self.assertFalse(self.lock_online.available, "Lock entity must be unavailable when last_update_success is False")
        self.assertFalse(self.lock_online.is_online, "Lock is_online must match available property")
        self.assertFalse(self.switch_online.available, "Switch entity must be unavailable when last_update_success is False")

        # 3. Coordinator poll recovered: last_update_success = True
        self.mock_coord.last_update_success = True
        self.assertTrue(self.lock_online.available)
        self.assertTrue(self.lock_online.is_online)
        self.assertTrue(self.switch_online.available)

    def test_invariant_offline_device_with_ble_fallback(self):
        """When device is offline but BLE fallback is active, coordinator failure still forces unavailable."""
        # When coordinator succeeds: BLE fallback keeps entity available
        self.mock_coord.last_update_success = True
        self.assertTrue(self.lock_offline_ble.available)
        self.assertTrue(self.switch_offline_ble.available)

        # When coordinator fails: entity MUST become unavailable regardless of BLE parameters
        self.mock_coord.last_update_success = False
        self.assertFalse(self.lock_offline_ble.available)
        self.assertFalse(self.switch_offline_ble.available)

    def test_invariant_offline_device_without_ble_parameters(self):
        """When device is offline and has no BLE keys, entity is unavailable even if coordinator succeeds."""
        self.mock_coord.last_update_success = True
        self.assertFalse(self.lock_offline_no_ble.available)
        self.assertFalse(self.switch_offline_no_ble.available)

        self.mock_coord.last_update_success = False
        self.assertFalse(self.lock_offline_no_ble.available)
        self.assertFalse(self.switch_offline_no_ble.available)

    def test_invariant_offline_device_when_ble_fallback_option_disabled(self):
        """When CONF_BLE_DIRECT_FALLBACK is False in entry options, offline devices with BLE become unavailable."""
        self.mock_entry.options = {CONF_BLE_DIRECT_FALLBACK: False}
        self.mock_coord.last_update_success = True

        self.assertFalse(self.lock_offline_ble.available)
        self.assertFalse(self.switch_offline_ble.available)

    def test_invariant_coordinator_is_none(self):
        """When coordinator reference is None, entities safely return available == False."""
        orphan_lock = GeekDoorLock(None, "lock_online")
        orphan_switch = GeekDoorAutoLockSwitch(None, "lock_online")

        self.assertFalse(orphan_lock.available)
        self.assertFalse(orphan_lock.is_online)
        self.assertFalse(orphan_switch.available)

    def test_invariant_device_missing_from_coordinator_data(self):
        """When device ID is completely absent from coordinator.data, entity behaves safely."""
        missing_lock = GeekDoorLock(self.mock_coord, "nonexistent_dev_id")
        missing_switch = GeekDoorAutoLockSwitch(self.mock_coord, "nonexistent_dev_id")

        # When coordinator succeeded
        self.mock_coord.last_update_success = True
        self.assertTrue(missing_lock.available)  # Empty dict defaults online=True
        self.assertTrue(missing_switch.available)

        # When coordinator failed
        self.mock_coord.last_update_success = False
        self.assertFalse(missing_lock.available)
        self.assertFalse(missing_switch.available)


# ============================================================================
# Task 4 & 5: Operational Safety Verification
# ============================================================================

class TestSafetyAndProcessHygiene(unittest.TestCase):
    """Verifies safety invariant: zero deadbolt actuations and zero leaked server processes."""

    def test_zero_physical_actuation_invariants(self):
        """Verifies SafetyBarrierGuard prevents actuation when in READ_ONLY mode and blocks destructive endpoints."""
        from custom_components.geek_door.core.safety import SafetyBarrierGuard, ClientMode
        from custom_components.geek_door.core.exceptions import SafetyBarrierViolation

        # 1. READ_ONLY mode blocks actuation endpoints
        with self.assertRaises(SafetyBarrierViolation):
            SafetyBarrierGuard.validate_request("/app/home/sendlockorder", mode=ClientMode.READ_ONLY)

        # 2. Destructive endpoints permanently blocked across all modes
        destructive_endpoints = [
            "/resetlock",
            "/clearfingerprints",
            "/removedevice",
            "/resetfactory",
            "/app/client/alterpassword",
        ]
        for ep in destructive_endpoints:
            with self.assertRaises(SafetyBarrierViolation):
                SafetyBarrierGuard.validate_request(ep, mode=ClientMode.SAFE_CONTROL)

    def test_no_rogue_server_processes_spawned(self):
        """Verify that testing has not spawned orphaned background server processes on port 5050."""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        # Port 5050 must NOT be listening
        result = sock.connect_ex(("127.0.0.1", 5050))
        sock.close()
        self.assertNotEqual(result, 0, "Port 5050 should not be open or listening")


if __name__ == "__main__":
    unittest.main()
