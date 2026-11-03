#!/usr/bin/env python3
"""
Unit tests for HACS Custom Integration and Home Assistant OS Add-on.
Covers:
- hacs.json and repository.json structure and validity
- custom_components/geek_door/manifest.json and strings.json / en.json parity
- custom_components/geek_door/services.yaml specification
- custom_components/geek_door/config_flow.py (Config Flow & Options Flow logic)
- custom_components/geek_door/coordinator.py (DataUpdateCoordinator)
- custom_components/geek_door entity classes (Lock, Switch, Sensor, BinarySensor)
- geek_door_addon/config.yaml, Dockerfile, and run.sh add-on structure
"""

import json
import os
import stat
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Any, Dict

import yaml

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from custom_components.geek_door.const import (
    CONF_API_KEY,
    CONF_CACHE_PATH,
    CONF_CONNECTION_MODE,
    CONF_DEFAULT_GW,
    CONF_HOST,
    CONF_MODE,
    CONF_PORT,
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    MODE_DIRECT_CLOUD,
    MODE_SERVER_BRIDGE,
)
from client.lock_engine import LockDevice, LockEngine, LockStateSnapshot


class TestHacsAndAddonMetadata(unittest.TestCase):
    """Verifies schema validity and structural compliance of HACS and Add-on manifests."""

    def test_hacs_json_manifest(self):
        """hacs.json exists, is valid JSON, and adheres to HACS publishing requirements."""
        hacs_path = os.path.join(WORKSPACE_ROOT, "hacs.json")
        self.assertTrue(os.path.isfile(hacs_path), "hacs.json must exist at root")
        with open(hacs_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data.get("name"), "GeekSmart Door Lock")
        self.assertTrue(data.get("render_readme"))
        self.assertIn("homeassistant", data)
        self.assertGreaterEqual(data["homeassistant"], "2024.1.0")

    def test_addon_repository_json(self):
        """repository.json exists at root and conforms to HA Add-on repository specs."""
        repo_path = os.path.join(WORKSPACE_ROOT, "repository.json")
        self.assertTrue(os.path.isfile(repo_path), "repository.json must exist at root")
        with open(repo_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIn("name", data)
        self.assertIn("url", data)
        self.assertIn("maintainer", data)

    def test_custom_component_manifest(self):
        """custom_components/geek_door/manifest.json conforms to HA core component specifications."""
        manifest_path = os.path.join(WORKSPACE_ROOT, "custom_components", "geek_door", "manifest.json")
        self.assertTrue(os.path.isfile(manifest_path))
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data.get("domain"), DOMAIN)
        self.assertTrue(data.get("config_flow"))
        self.assertIn("bluetooth", data.get("after_dependencies", []))
        self.assertNotIn("bluetooth", data.get("dependencies", []))
        self.assertTrue(any("cryptography" in r for r in data.get("requirements", [])))
        self.assertTrue(any("requests" in r for r in data.get("requirements", [])))
        self.assertEqual(data.get("integration_type"), "hub")
        self.assertIn("codeowners", data)
        self.assertIn("documentation", data)
        self.assertIn("version", data)

    def test_translations_parity(self):
        """custom_components/geek_door/strings.json matches translations/en.json parity."""
        strings_path = os.path.join(WORKSPACE_ROOT, "custom_components", "geek_door", "strings.json")
        en_path = os.path.join(WORKSPACE_ROOT, "custom_components", "geek_door", "translations", "en.json")
        self.assertTrue(os.path.isfile(strings_path))
        self.assertTrue(os.path.isfile(en_path))

        with open(strings_path, "r", encoding="utf-8") as f1, open(en_path, "r", encoding="utf-8") as f2:
            s_data = json.load(f1)
            en_data = json.load(f2)

        self.assertEqual(
            s_data.get("config", {}).get("step", {}).keys(),
            en_data.get("config", {}).get("step", {}).keys(),
            "strings.json and en.json steps must match identically",
        )

    def test_services_yaml_validity(self):
        """custom_components/geek_door/services.yaml defines keep_unlocked service."""
        services_path = os.path.join(WORKSPACE_ROOT, "custom_components", "geek_door", "services.yaml")
        self.assertTrue(os.path.isfile(services_path))
        with open(services_path, "r", encoding="utf-8") as f:
            services = yaml.safe_load(f)

        self.assertIn("keep_unlocked", services)
        self.assertIn("description", services["keep_unlocked"])

    def test_addon_config_yaml_and_run_sh(self):
        """geek_door_addon/config.yaml and run.sh conform to HA OS supervisor specs."""
        config_path = os.path.join(WORKSPACE_ROOT, "geek_door_addon", "config.yaml")
        docker_path = os.path.join(WORKSPACE_ROOT, "geek_door_addon", "Dockerfile")
        run_path = os.path.join(WORKSPACE_ROOT, "geek_door_addon", "run.sh")

        self.assertTrue(os.path.isfile(config_path))
        self.assertTrue(os.path.isfile(docker_path))
        self.assertTrue(os.path.isfile(run_path))

        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)

        self.assertEqual(cfg.get("slug"), "geek_door")
        self.assertTrue(cfg.get("ingress"))
        self.assertEqual(cfg.get("ingress_port"), 5050)
        self.assertIn("aarch64", cfg.get("arch", []))
        self.assertIn("amd64", cfg.get("arch", []))

        # run.sh executable permission check
        mode = os.stat(run_path).st_mode
        self.assertTrue(bool(mode & stat.S_IXUSR), "run.sh must be executable (+x)")


class TestConfigFlow(unittest.TestCase):
    """Verifies UI Config Flow and Options Flow execution paths."""

    def test_config_flow_instantiation(self):
        """ConfigFlow class instantiates and offers connection modes."""
        from custom_components.geek_door.config_flow import GeekDoorConfigFlow
        flow = GeekDoorConfigFlow()
        self.assertEqual(flow.VERSION, 1)

    def test_options_flow_handler(self):
        """OptionsFlowHandler instantiates with mock config entry."""
        from custom_components.geek_door.config_flow import GeekDoorOptionsFlowHandler
        mock_entry = type("MockEntry", (), {"data": {CONF_SCAN_INTERVAL: 15}, "options": {}})()
        handler = GeekDoorOptionsFlowHandler(mock_entry)
        self.assertEqual(handler.config_entry.data[CONF_SCAN_INTERVAL], 15)


class TestCoordinatorAndEntities(unittest.TestCase):
    """Verifies DataUpdateCoordinator, Lock, Switch, Sensor, and BinarySensor classes."""

    def setUp(self):
        # Create a mock lock device
        self.snapshot = LockStateSnapshot(
            device_id="ebexamplelock001",
            is_locked=True,
            state_label="LOCKED",
            auto_lock_enabled=True,
            auto_lock_seconds=5,
            battery_percent=88,
            ble_connected=True,
            ble_signal_state="STRONG_ACTIVE_GATT",
            connection_status=2,
            wifi_rssi=-68,
        )
        self.lock_dev = LockDevice(
            dev_id="ebexamplelock001",
            name="Living Room Lock",
            client_equipment_id=101,
            state=self.snapshot,
        )

        class MockCoordinator:
            def __init__(self, dev):
                self.data = {dev.dev_id: dev}
                self.lock_engine = None

            def async_set_updated_data(self, data):
                self.data = data

            async def async_request_refresh(self):
                pass

        self.coordinator = MockCoordinator(self.lock_dev)

    def test_geek_door_lock_entity(self):
        """GeekDoorLock entity reflects lock state and attributes."""
        from custom_components.geek_door.lock import GeekDoorLock
        lock_entity = GeekDoorLock(self.coordinator, self.lock_dev.dev_id)
        self.assertEqual(lock_entity.name, "Living Room Lock")
        self.assertTrue(lock_entity.is_locked)
        self.assertTrue(lock_entity.is_online)

        attrs = lock_entity.extra_state_attributes
        self.assertEqual(attrs.get("battery"), 88)
        self.assertEqual(attrs.get("wifi_rssi"), -68)
        self.assertTrue(attrs.get("auto_lock_enabled"))

    def test_geek_door_auto_lock_switch_entity(self):
        """GeekDoorAutoLockSwitch entity controls DP 33 (Passage Mode / Auto-Lock)."""
        from custom_components.geek_door.switch import GeekDoorAutoLockSwitch
        switch_entity = GeekDoorAutoLockSwitch(self.coordinator, self.lock_dev.dev_id)
        self.assertEqual(switch_entity.name, "Living Room Lock Auto-Lock")
        self.assertTrue(switch_entity.is_on)

    def test_geek_door_battery_sensor_entity(self):
        """GeekDoorBatterySensor entity reports battery telemetry."""
        from custom_components.geek_door.sensor import GeekDoorBatterySensor
        sensor = GeekDoorBatterySensor(self.coordinator, self.lock_dev.dev_id)
        self.assertEqual(sensor.native_value, 88)
        self.assertEqual(sensor.native_unit_of_measurement, "%")

    def test_geek_door_ble_connection_binary_sensor(self):
        """GeekDoorBLEConnectionSensor entity reports Bluetooth connectivity."""
        from custom_components.geek_door.binary_sensor import GeekDoorBLEConnectionSensor
        bin_sensor = GeekDoorBLEConnectionSensor(self.coordinator, self.lock_dev.dev_id)
        self.assertTrue(bin_sensor.is_on)


class TestMilestone1Hardening(unittest.IsolatedAsyncioTestCase):
    """Exhaustive unit test suite verifying Milestone 1 Core & Platforms hardening."""

    def test_manifest_alphabetical_key_ordering(self):
        """Hassfest rule: manifest keys after 'domain' and 'name' must be strictly sorted alphabetically."""
        manifest_path = os.path.join(WORKSPACE_ROOT, "custom_components", "geek_door", "manifest.json")
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest_dict = json.load(f)
        keys = list(manifest_dict.keys())
        self.assertEqual(keys[0], "domain")
        self.assertEqual(keys[1], "name")
        remaining_keys = keys[2:]
        self.assertEqual(remaining_keys, sorted(remaining_keys), "Keys after domain and name must be sorted alphabetically")

    def test_strings_and_translations_reauth_parity(self):
        """reauth_confirm step schema and reauth_successful abort reasons match across strings.json and translations/en.json."""
        strings_path = os.path.join(WORKSPACE_ROOT, "custom_components", "geek_door", "strings.json")
        en_path = os.path.join(WORKSPACE_ROOT, "custom_components", "geek_door", "translations", "en.json")
        with open(strings_path, "r", encoding="utf-8") as f1, open(en_path, "r", encoding="utf-8") as f2:
            s_data = json.load(f1)
            en_data = json.load(f2)

        self.assertIn("reauth_confirm", s_data["config"]["step"])
        self.assertIn("reauth_confirm", en_data["config"]["step"])
        self.assertIn("reauth_successful", s_data["config"]["abort"])
        self.assertIn("reauth_successful", en_data["config"]["abort"])
        self.assertEqual(s_data["config"]["step"]["reauth_confirm"], en_data["config"]["step"]["reauth_confirm"])
        self.assertEqual(s_data["config"]["abort"]["reauth_successful"], en_data["config"]["abort"]["reauth_successful"])

    async def test_config_flow_reauth_direct_cloud_happy_path(self):
        """Config flow initiates reauth for direct cloud and updates credentials on success."""
        from custom_components.geek_door.config_flow import GeekDoorConfigFlow
        from custom_components.geek_door.const import CONF_USERNAME, CONF_PASSWORD, CONF_COUNTRY_CODE

        flow = GeekDoorConfigFlow()
        flow.hass = MagicMock()
        mock_entry = MagicMock()
        mock_entry.data = {
            CONF_MODE: MODE_DIRECT_CLOUD,
            CONF_USERNAME: "test_user@example.com",
            CONF_PASSWORD: "old_password",
            CONF_COUNTRY_CODE: "1",
        }
        flow._reauth_entry = mock_entry

        # Step 1: async_step_reauth triggers confirmation form
        res1 = await flow.async_step_reauth(mock_entry.data)
        self.assertEqual(res1["type"], "form")
        self.assertEqual(res1["step_id"], "reauth_confirm")

        # Step 2: async_step_reauth_confirm with valid password
        with patch("custom_components.geek_door.core.lock_engine.LockEngine.authenticate_and_discover", return_value=[{"devId": "lock_1"}]):
            flow.hass.async_add_executor_job = AsyncMock(side_effect=lambda fn, *a: fn(*a))
            res2 = await flow.async_step_reauth_confirm(user_input={CONF_PASSWORD: "new_valid_password"})
            self.assertEqual(res2["type"], "abort")
            self.assertEqual(res2["reason"], "reauth_successful")
            self.assertEqual(res2["data"][CONF_PASSWORD], "new_valid_password")

    async def test_config_flow_reauth_direct_cloud_auth_failure(self):
        """Config flow handles invalid credentials during reauth."""
        from custom_components.geek_door.config_flow import GeekDoorConfigFlow
        from custom_components.geek_door.const import CONF_PASSWORD

        flow = GeekDoorConfigFlow()
        flow.hass = MagicMock()
        mock_entry = MagicMock()
        mock_entry.data = {
            CONF_MODE: MODE_DIRECT_CLOUD,
            "username": "user@example.com",
            CONF_PASSWORD: "old_password",
        }
        flow._reauth_entry = mock_entry
        await flow.async_step_reauth(mock_entry.data)

        with patch("custom_components.geek_door.core.lock_engine.LockEngine.authenticate_and_discover", side_effect=Exception("USER_PASSWD_WRONG")):
            flow.hass.async_add_executor_job = AsyncMock(side_effect=lambda fn, *a: fn(*a))
            res = await flow.async_step_reauth_confirm(user_input={CONF_PASSWORD: "wrong_password"})
            self.assertEqual(res["type"], "form")
            self.assertEqual(res["errors"].get("base"), "invalid_auth")

    async def test_config_flow_reauth_server_bridge_flow(self):
        """Config flow handles server bridge reauthentication."""
        from custom_components.geek_door.config_flow import GeekDoorConfigFlow
        from custom_components.geek_door.const import CONF_SERVER_URL, CONF_API_KEY

        flow = GeekDoorConfigFlow()
        flow.hass = MagicMock()
        mock_entry = MagicMock()
        mock_entry.data = {
            CONF_MODE: MODE_SERVER_BRIDGE,
            CONF_SERVER_URL: "http://127.0.0.1:5050",
            CONF_API_KEY: "old_key",
        }
        flow._reauth_entry = mock_entry

        res1 = await flow.async_step_reauth(mock_entry.data)
        self.assertEqual(res1["type"], "form")
        self.assertEqual(res1["step_id"], "reauth_confirm")

        class MockResp:
            status = 200
            async def json(self): return {"service": "mydoor"}
            async def __aenter__(self): return self
            async def __aexit__(self, *args): pass

        class MockSession:
            def get(self, *args, **kwargs): return MockResp()

        with patch("custom_components.geek_door.config_flow.async_get_clientsession", return_value=MockSession()):
            res2 = await flow.async_step_reauth_confirm(user_input={CONF_API_KEY: "valid_new_key"})
            self.assertEqual(res2["type"], "abort")
            self.assertEqual(res2["reason"], "reauth_successful")

    def test_coordinator_init_zero_disk_io(self):
        """Coordinator instantiation does not execute synchronous file I/O on event loop."""
        import builtins
        from custom_components.geek_door.coordinator import GeekDoorDataUpdateCoordinator

        mock_hass = MagicMock()
        mock_entry = MagicMock()
        mock_entry.data = {CONF_MODE: MODE_DIRECT_CLOUD}
        mock_entry.options = {}

        open_calls = []
        orig_open = builtins.open
        def open_spy(*args, **kwargs):
            open_calls.append(args[0])
            return orig_open(*args, **kwargs)

        with patch("builtins.open", side_effect=open_spy):
            coord = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)
            self.assertEqual(len(open_calls), 0, "No files should be opened synchronously during coordinator __init__")

    async def test_coordinator_session_heal_transient_vs_fatal(self):
        """Coordinator raises UpdateFailed on network glitch, ConfigEntryAuthFailed on permanent rejection."""
        from custom_components.geek_door.coordinator import (
            GeekDoorDataUpdateCoordinator,
            ConfigEntryAuthFailed,
            UpdateFailed,
        )

        mock_hass = MagicMock()
        mock_entry = MagicMock()
        mock_entry.data = {
            CONF_MODE: MODE_DIRECT_CLOUD,
            "username": "user@example.com",
            "password": "pwd",
        }
        mock_entry.options = {}
        coord = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)
        coord.engine = MagicMock()

        # Simulate expired session on snapshot query
        coord.engine.get_all_lock_snapshots.side_effect = Exception("USER_SESSION_INVALID")

        async def run_executor(func, *args, **kwargs):
            return func(*args, **kwargs)

        mock_hass.async_add_executor_job = AsyncMock(side_effect=run_executor)

        # 1. Transient network error during heal attempt -> UpdateFailed
        coord.engine.authenticate_and_discover.side_effect = TimeoutError("Connection timed out to Tuya API")
        with self.assertRaises(UpdateFailed):
            await coord._async_update_data()

        # 2. Fatal credential rejection during heal attempt -> ConfigEntryAuthFailed
        coord.engine.authenticate_and_discover.side_effect = Exception("USER_PASSWD_WRONG")
        with self.assertRaises(ConfigEntryAuthFailed):
            await coord._async_update_data()

    def test_coordinator_webhook_guards(self):
        """Coordinator handles malformed and non-dict push data without exceptions."""
        from custom_components.geek_door.coordinator import GeekDoorDataUpdateCoordinator

        mock_hass = MagicMock()
        mock_entry = MagicMock()
        mock_entry.data = {CONF_MODE: MODE_SERVER_BRIDGE}
        mock_entry.options = {}
        coord = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)
        coord.data = {"lock_1": {"state": "LOCKED", "is_locked": True}}

        # Non-dict inputs are safely discarded
        coord.async_handle_push_data(None)
        coord.async_handle_push_data([])
        coord.async_handle_push_data("invalid_string")
        coord.async_handle_push_data(12345)

        # Valid push updates state
        coord.async_handle_push_data({"device_id": "lock_1", "new_state": "UNLOCKED", "battery": 90})
        self.assertEqual(coord.data["lock_1"]["state"], "unlocked")
        self.assertFalse(coord.data["lock_1"]["is_locked"])
        self.assertEqual(coord.data["lock_1"]["battery"], 90)

    def test_entity_availability_incorporates_coordinator_success(self):
        """Lock and switch entities report unavailable when coordinator.last_update_success is False."""
        from custom_components.geek_door.lock import GeekDoorLock
        from custom_components.geek_door.switch import GeekDoorAutoLockSwitch

        mock_coord = MagicMock()
        mock_coord.data = {"lock_1": {"online": True, "name": "Test Lock"}}
        mock_coord.last_update_success = True

        lock = GeekDoorLock(mock_coord, "lock_1")
        switch = GeekDoorAutoLockSwitch(mock_coord, "lock_1")

        self.assertTrue(lock.available)
        self.assertTrue(switch.available)

        # When coordinator fails last update
        mock_coord.last_update_success = False
        self.assertFalse(lock.available)
        self.assertFalse(switch.available)

    async def test_keep_unlocked_duration_forwarding(self):
        """async_keep_unlocked forwards duration_seconds to LockEngine and server bridge."""
        from custom_components.geek_door.lock import GeekDoorLock

        mock_coord = MagicMock()
        mock_coord.mode = MODE_DIRECT_CLOUD
        mock_coord.data = {"lock_1": {"online": True}}
        mock_coord.engine = MagicMock()
        mock_coord.engine.keep_unlocked.return_value = {"success": True}

        lock = GeekDoorLock(mock_coord, "lock_1")
        lock.hass = MagicMock()
        lock.hass.async_add_executor_job = AsyncMock(side_effect=lambda fn: fn())

        await lock.async_keep_unlocked(duration_seconds=600)
        mock_coord.engine.keep_unlocked.assert_called_with("lock_1", duration_seconds=600)

    def test_clean_telemetry_no_fake_fallbacks(self):
        """Sensors and lock attributes report None instead of fake -70 dBm or STRONG_ACTIVE_GATT."""
        from custom_components.geek_door.sensor import GeekDoorSignalSensor, GeekDoorBLESignalStateSensor
        from custom_components.geek_door.lock import GeekDoorLock

        mock_coord = MagicMock()
        mock_coord.data = {"lock_empty": {}}
        mock_coord.last_update_success = True

        sig_sensor = GeekDoorSignalSensor(mock_coord, "lock_empty")
        ble_sensor = GeekDoorBLESignalStateSensor(mock_coord, "lock_empty")
        lock = GeekDoorLock(mock_coord, "lock_empty")

        self.assertIsNone(sig_sensor.native_value)
        self.assertIsNone(ble_sensor.native_value)
        self.assertIsNone(lock.extra_state_attributes.get("ble_signal_state"))

    async def test_async_unload_entry_teardown(self):
        """async_unload_entry cleanly invokes coordinator.async_shutdown and clears runtime_data."""
        from custom_components.geek_door import async_unload_entry

        mock_hass = MagicMock()
        mock_entry = MagicMock()
        mock_entry.data = {}
        mock_coordinator = MagicMock()
        mock_coordinator.async_shutdown = AsyncMock()
        mock_entry.runtime_data = mock_coordinator

        mock_hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)

        res = await async_unload_entry(mock_hass, mock_entry)
        self.assertTrue(res)
        mock_coordinator.async_shutdown.assert_awaited_once()
        self.assertIsNone(mock_entry.runtime_data)


if __name__ == "__main__":
    unittest.main()
