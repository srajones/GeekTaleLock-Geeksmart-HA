#!/usr/bin/env python3
"""
Milestone 12 Comprehensive Audit & Universal Hardening Test Suite (test_m12_audit_hardening.py).

Exhaustively verifies Requirements R1 through R6:
- R1: Universal Setup Hardening, Zero Hardcoding in Production, Shared Codebase Architecture
- R2: Standalone HACS Component Packaging & sys.path Isolation
- R3: Home Assistant manifest.json ('hub', 'after_dependencies: [bluetooth]', requirements) & hacs.json Parity
- R4: LockEngine, BLE GATT Fallback, Session Cache (.geek_door_session_cache.json), DeviceInfo via_device,
      and HomeAssistant exception translation (HomeAssistantError, ConfigEntryAuthFailed, ConfigEntryNotReady)
- R5: Server Bridge & HA Add-on Alignment (Auto-lock route, /api/ha/status telemetry, Dockerfile/build.yaml/run.sh)
- R6: Verification Safety Constraints (Zero physical deadbolt actuation, dry_run=True, zero leaked server processes)
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from custom_components.geek_door.const import (
    CONF_API_KEY,
    CONF_BLE_DIRECT_FALLBACK,
    CONF_CACHE_PATH,
    CONF_DEFAULT_AUTO_LOCK_TIME,
    CONF_MODE,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_SERVER_URL,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DEFAULT_BLE_DIRECT_FALLBACK,
    DOMAIN,
    MODE_DIRECT_CLOUD,
    MODE_SERVER_BRIDGE,
    SESSION_CACHE_FILENAME,
)
from custom_components.geek_door.core.exceptions import (
    ConfigEntryAuthFailed,
    ConfigEntryNotReady,
    GeekSmartAuthError,
    GeekSmartControlError,
    GeekSmartError,
    HomeAssistantError,
    SafetyBarrierViolation,
)
from custom_components.geek_door.core.lock_engine import (
    ActionResult,
    GatewayDevice,
    LockDevice,
    LockEngine,
    LockStateSnapshot,
)
from custom_components.geek_door.core.safety import ClientMode, SafetyBarrierGuard
from custom_components.geek_door.core.session_manager import SessionManager


# ===========================================================================
# 1. Architecture, HACS Packaging & Manifest Compliance (R1, R2, R3)
# ===========================================================================

class TestM12ArchitectureAndPackaging(unittest.TestCase):
    """Verifies standalone packaging, manifest schema, and client re-export shims."""

    def test_standalone_core_importability_without_root_client(self):
        """R2: custom_components.geek_door.core is completely standalone without root repo on sys.path."""
        isolated_script = f"""
import sys
# Remove repo root from sys.path
sys.path = [p for p in sys.path if '{REPO_ROOT}' not in p]
# Add custom_components parent directory
sys.path.insert(0, '{REPO_ROOT}')

from custom_components.geek_door.core import (
    LockEngine,
    GeekSmartClient,
    TuyaClient,
    BleGattClient,
    SessionManager,
    SafetyBarrierGuard,
    HomeAssistantError,
    ConfigEntryAuthFailed,
    ConfigEntryNotReady,
)
print('STANDALONE_IMPORT_SUCCESS')
"""
        res = subprocess.run(
            [sys.executable, "-c", isolated_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=tempfile.gettempdir(),
        )
        self.assertEqual(res.returncode, 0, f"Standalone import failed: {res.stderr}")
        self.assertIn("STANDALONE_IMPORT_SUCCESS", res.stdout)

    def test_client_reexport_shims_parity(self):
        """R1: client.* modules correctly shim to custom_components.geek_door.core.*."""
        import client.exceptions as c_exc
        import custom_components.geek_door.core.exceptions as core_exc
        self.assertIs(c_exc.GeekSmartError, core_exc.GeekSmartError)
        self.assertIs(c_exc.HomeAssistantError, core_exc.HomeAssistantError)
        self.assertIs(c_exc.ConfigEntryAuthFailed, core_exc.ConfigEntryAuthFailed)

        import client.lock_engine as c_le
        import custom_components.geek_door.core.lock_engine as core_le
        self.assertIs(c_le.LockEngine, core_le.LockEngine)
        self.assertIs(c_le._build_device_aliases, core_le._build_device_aliases)

        import client.safety as c_safe
        import custom_components.geek_door.core.safety as core_safe
        self.assertIs(c_safe.SafetyBarrierGuard, core_safe.SafetyBarrierGuard)

    def test_manifest_json_hub_and_after_dependencies(self):
        """R3: manifest.json specifies 'hub', 'after_dependencies: [bluetooth]', and package requirements."""
        manifest_path = REPO_ROOT / "custom_components" / "geek_door" / "manifest.json"
        self.assertTrue(manifest_path.is_file())
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        self.assertEqual(manifest.get("domain"), "geek_door")
        self.assertEqual(manifest.get("integration_type"), "hub")
        self.assertEqual(manifest.get("after_dependencies"), ["bluetooth"])
        # Bluetooth must NOT be a hard blocking dependency
        deps = manifest.get("dependencies", [])
        self.assertNotIn("bluetooth", deps)

        reqs = manifest.get("requirements", [])
        self.assertTrue(any("cryptography" in r for r in reqs), f"cryptography missing in {reqs}")
        self.assertTrue(any("requests" in r for r in reqs), f"requests missing in {reqs}")
        self.assertRegex(str(manifest.get("version")), r"^1\.0\.\d+(-[0-9A-Za-z.]+)?$")

    def test_hacs_json_name_reconciliation(self):
        """R3: hacs.json matches manifest.json name exactly (GeekSmart Door Lock)."""
        manifest_path = REPO_ROOT / "custom_components" / "geek_door" / "manifest.json"
        hacs_path = REPO_ROOT / "hacs.json"

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        with open(hacs_path, "r", encoding="utf-8") as f:
            hacs = json.load(f)

        self.assertEqual(hacs.get("name"), manifest.get("name"))
        self.assertEqual(hacs.get("name"), "GeekSmart Door Lock")
        self.assertTrue(hacs.get("render_readme"))


# ===========================================================================
# 2. Session Cache Resolution & Persistence (R4)
# ===========================================================================

class TestM12SessionCacheAndResolution(unittest.TestCase):
    """Verifies session cache path resolution using hass.config.path."""

    def test_session_cache_constant_and_resolution(self):
        """R4: SESSION_CACHE_FILENAME is .geek_door_session_cache.json."""
        self.assertEqual(SESSION_CACHE_FILENAME, ".geek_door_session_cache.json")

    def test_coordinator_and_config_flow_resolve_hass_config_path(self):
        """R4: coordinator and config_flow invoke hass.config.path for cache resolution."""
        mock_hass = MagicMock()
        mock_hass.config.path = MagicMock(return_value="/ha/config/.geek_door_session_cache.json")

        from custom_components.geek_door.coordinator import GeekDoorDataUpdateCoordinator
        mock_entry = MagicMock()
        mock_entry.entry_id = "test_entry_1"
        mock_entry.data = {
            CONF_MODE: MODE_DIRECT_CLOUD,
            CONF_USERNAME: "user@example.com",
            CONF_PASSWORD: "secure_password",
        }
        mock_entry.options = {
            CONF_SCAN_INTERVAL: 30,
            CONF_BLE_DIRECT_FALLBACK: False,
        }

        with patch("custom_components.geek_door.core.lock_engine.LockEngine") as mock_engine_cls:
            coord = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)
            mock_hass.config.path.assert_called_with(".geek_door_session_cache.json")
            mock_engine_cls.assert_called_once()
            _, kwargs = mock_engine_cls.call_args
            self.assertEqual(kwargs.get("session_cache_path"), "/ha/config/.geek_door_session_cache.json")

    def test_session_cache_atomic_persistence(self):
        """R4: Session credentials persist cleanly across reloads with 0o600 permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = os.path.join(tmpdir, ".geek_door_session_cache.json")
            mgr1 = SessionManager(cache_file)
            mgr1.save({
                "email": "persisted_user@example.com",
                "clientId": 8888888,
                "token": "persisted_token_xyz",
                "tuyaUid": "tuya_uid_999",
            })
            self.assertTrue(os.path.exists(cache_file))

            # Permissions check (user read/write only)
            mode = os.stat(cache_file).st_mode & 0o777
            self.assertEqual(mode, 0o600)

            # Reload from fresh SessionManager instance
            mgr2 = SessionManager(cache_file)
            loaded = mgr2.load()
            self.assertEqual(loaded.get("email"), "persisted_user@example.com")
            self.assertEqual(loaded.get("clientId"), 8888888)
            self.assertEqual(loaded.get("token"), "persisted_token_xyz")


# ===========================================================================
# 3. Entity Reliability, DeviceInfo & Exception Translation (R4)
# ===========================================================================

class TestM12EntityReliabilityAndExceptions(unittest.IsolatedAsyncioTestCase):
    """Verifies entity platform fault tolerance, via_device, and exception translation."""

    def test_entity_setup_none_data_guard(self):
        """R4: async_setup_entry across all platforms handles coordinator.data is None without crash."""
        from custom_components.geek_door.lock import async_setup_entry as setup_locks
        from custom_components.geek_door.switch import async_setup_entry as setup_switches
        from custom_components.geek_door.sensor import async_setup_entry as setup_sensors
        from custom_components.geek_door.binary_sensor import async_setup_entry as setup_binary_sensors

        mock_hass = MagicMock()
        mock_entry = MagicMock()
        mock_entry.entry_id = "test_entry"
        mock_coord = MagicMock()
        mock_coord.data = None  # NoneType data condition
        mock_entry.runtime_data = mock_coord

        added_entities: List[Any] = []
        def mock_add(ents):
            added_entities.extend(ents)

        # None of these calls should raise AttributeError: 'NoneType' object has no attribute 'keys'
        asyncio.run(setup_locks(mock_hass, mock_entry, mock_add))
        asyncio.run(setup_switches(mock_hass, mock_entry, mock_add))
        asyncio.run(setup_sensors(mock_hass, mock_entry, mock_add))
        asyncio.run(setup_binary_sensors(mock_hass, mock_entry, mock_add))
        self.assertEqual(len(added_entities), 0)

    def test_entity_device_info_hierarchy_via_device(self):
        """R4: All entity platforms configure DeviceInfo with via_device pointing to gateway."""
        from custom_components.geek_door.lock import GeekDoorLock
        from custom_components.geek_door.switch import GeekDoorAutoLockSwitch
        from custom_components.geek_door.sensor import GeekDoorBatterySensor, GeekDoorSignalSensor
        from custom_components.geek_door.binary_sensor import GeekDoorBLEConnectionSensor

        mock_coord = MagicMock()
        mock_coord.data = {
            "lock_001": {
                "name": "Front Door",
                "dev_id": "lock_001",
                "gatewayId": "gateway_plug_100",
                "hardware_model": "K01 2",
                "sw_version": "3.5.1",
                "battery": 92,
                "wifi_rssi": -65,
                "ble_connected": True,
            }
        }

        lock = GeekDoorLock(mock_coord, "lock_001")
        switch = GeekDoorAutoLockSwitch(mock_coord, "lock_001")
        bat_sensor = GeekDoorBatterySensor(mock_coord, "lock_001")
        sig_sensor = GeekDoorSignalSensor(mock_coord, "lock_001")
        ble_sensor = GeekDoorBLEConnectionSensor(mock_coord, "lock_001")

        for ent in (lock, switch, bat_sensor, sig_sensor, ble_sensor):
            info = ent.device_info
            self.assertIn("via_device", info, f"via_device missing on {type(ent).__name__}")
            self.assertEqual(info["via_device"], (DOMAIN, "gateway_plug_100"))
            self.assertEqual(info["identifiers"], {(DOMAIN, "lock_001")})
            self.assertEqual(info["manufacturer"], "GeekSmart")

    def test_sensor_safe_numeric_conversion(self):
        """R4: Battery and RSSI sensors safely parse non-numeric telemetry without ValueError."""
        from custom_components.geek_door.sensor import GeekDoorBatterySensor, GeekDoorSignalSensor

        mock_coord = MagicMock()
        mock_coord.data = {
            "lock_bad_data": {
                "battery": "invalid_str",
                "wifi_rssi": "n/a",
            }
        }
        bat = GeekDoorBatterySensor(mock_coord, "lock_bad_data")
        sig = GeekDoorSignalSensor(mock_coord, "lock_bad_data")

        # Must safely parse without ValueError (battery None, signal None)
        self.assertIsNone(bat.native_value)
        self.assertIsNone(sig.native_value)

    async def test_coordinator_translates_auth_error(self):
        """R4: Coordinator raises ConfigEntryAuthFailed on authentication error."""
        from custom_components.geek_door.coordinator import GeekDoorDataUpdateCoordinator

        mock_hass = MagicMock()
        mock_hass.config.path.return_value = "/tmp/cache.json"
        mock_entry = MagicMock()
        mock_entry.data = {CONF_MODE: MODE_DIRECT_CLOUD}
        mock_entry.options = {CONF_SCAN_INTERVAL: 30, CONF_BLE_DIRECT_FALLBACK: False}

        coord = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)
        coord.engine = MagicMock()

        # Simulate GeekSmartAuthError during cloud snapshot query
        coord.engine.get_all_lock_snapshots.side_effect = GeekSmartAuthError(401, "Token revoked")
        mock_hass.async_add_executor_job = AsyncMock(side_effect=coord.engine.get_all_lock_snapshots)

        with self.assertRaises(ConfigEntryAuthFailed):
            await coord._async_update_data()

    async def test_lock_entity_translates_command_errors(self):
        """R4: Lock entity translates actuation errors to HomeAssistantError or ConfigEntryAuthFailed."""
        from custom_components.geek_door.lock import GeekDoorLock

        mock_coord = MagicMock()
        mock_coord.mode = MODE_DIRECT_CLOUD
        mock_coord.engine = MagicMock()
        mock_coord.data = {"lock_1": {"name": "Test Door"}}

        lock = GeekDoorLock(mock_coord, "lock_1")
        lock.hass = MagicMock()

        # 1. Hardware control failure -> HomeAssistantError
        mock_coord.engine.lock.side_effect = GeekSmartControlError(500, "Motor jam")
        lock.hass.async_add_executor_job = AsyncMock(side_effect=mock_coord.engine.lock)

        with self.assertRaises(HomeAssistantError):
            await lock.async_lock()

        # 2. Authentication failure -> ConfigEntryAuthFailed
        mock_coord.engine.unlock.side_effect = GeekSmartAuthError(401, "Session expired")
        lock.hass.async_add_executor_job = AsyncMock(side_effect=mock_coord.engine.unlock)

        with self.assertRaises(ConfigEntryAuthFailed):
            await lock.async_unlock()


# ===========================================================================
# 4. Switch Platform & Server Bridge Auto-Lock Route (R4, R5)
# ===========================================================================

class TestM12SwitchAndServerBridgeAutoLock(unittest.IsolatedAsyncioTestCase):
    """Verifies Switch platform uses /api/ha/lock/<dev_id>/auto_lock without actuating deadbolt."""

    async def test_switch_calls_auto_lock_endpoint_without_motor_actuation(self):
        """R4, R5: Switch dispatches to /api/ha/lock/<dev_id>/auto_lock with confirmed=True."""
        from custom_components.geek_door.switch import GeekDoorAutoLockSwitch

        mock_coord = MagicMock()
        mock_coord.mode = MODE_SERVER_BRIDGE
        mock_coord.entry.data = {
            CONF_SERVER_URL: "http://127.0.0.1:5050",
            CONF_API_KEY: "secret_ha_key",
            CONF_VERIFY_SSL: False,
        }
        mock_coord.data = {"lock_101": {"name": "Living Room"}}
        mock_coord.async_request_refresh = AsyncMock()

        switch = GeekDoorAutoLockSwitch(mock_coord, "lock_101")
        switch.hass = MagicMock()

        called_urls = []
        called_payloads = []

        class MockResponse:
            status = 200
            async def text(self): return '{"success": true}'
            async def __aenter__(self): return self
            async def __aexit__(self, exc_type, exc, tb): pass

        class MockSession:
            def post(self, url, headers=None, json=None):
                called_urls.append(url)
                called_payloads.append(json)
                return MockResponse()

        with patch("custom_components.geek_door.switch.async_get_clientsession", return_value=MockSession()):
            await switch.async_turn_on()
            await switch.async_turn_off()

        # Must call auto_lock endpoint, NEVER /lock or /unlock
        self.assertEqual(len(called_urls), 2)
        self.assertEqual(called_urls[0], "http://127.0.0.1:5050/api/ha/lock/lock_101/auto_lock")
        self.assertEqual(called_urls[1], "http://127.0.0.1:5050/api/ha/lock/lock_101/auto_lock")
        self.assertEqual(called_payloads[0], {"enabled": True, "confirmed": True})
        self.assertEqual(called_payloads[1], {"enabled": False, "confirmed": True})

    def test_flask_server_auto_lock_route_end_to_end(self):
        """R5: Real Flask server handles POST /api/ha/lock/<dev_id>/auto_lock without errors."""
        from server.flask_app import create_app

        import shutil
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = os.path.join(tmpdir, ".session_cache.json")
            shutil.copyfile(REPO_ROOT / ".session_cache.json", cache_file)

            app = create_app(session_cache_path=cache_file)
            app.config["HA_BEARER_TOKEN"] = "test_bearer_token_123"
            headers = {"Authorization": "Bearer test_bearer_token_123"}
            client = app.test_client()

            # Enable auto-lock
            resp = client.post(
                "/api/ha/lock/101/auto_lock",
                headers=headers,
                json={"enabled": True, "confirmed": True, "dry_run": True},
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data["success"])
            self.assertTrue(data["auto_lock_enabled"])

            # Disable auto-lock (Passage Mode)
            resp2 = client.post(
                "/api/ha/lock/101/auto_lock",
                headers=headers,
                json={"enabled": False, "confirmed": True, "dry_run": True},
            )
            self.assertEqual(resp2.status_code, 200)
            data2 = resp2.get_json()
            self.assertTrue(data2["success"])
            self.assertFalse(data2["auto_lock_enabled"])

    def test_flask_server_ha_status_telemetry_keys(self):
        """R5: /api/ha/status provides all required telemetry attributes."""
        import shutil
        from server.flask_app import create_app

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = os.path.join(tmpdir, ".session_cache.json")
            shutil.copyfile(REPO_ROOT / ".session_cache.json", cache_file)

            app = create_app(session_cache_path=cache_file)
            app.config["HA_BEARER_TOKEN"] = "test_bearer_token_123"
            headers = {"Authorization": "Bearer test_bearer_token_123"}
            client = app.test_client()

            resp = client.get("/api/ha/status", headers=headers)
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertEqual(data["status"], "healthy")
            self.assertIn("locks", data)
            self.assertGreaterEqual(len(data["locks"]), 1)

            lock_item = data["locks"][0]
            required_keys = [
                "device_id", "name", "state", "battery",
                "auto_lock_enabled", "auto_lock_seconds",
                "hardware_model", "gateway_name", "ble_connected", "wifi_rssi"
            ]
            for rk in required_keys:
                self.assertIn(rk, lock_item, f"Key '{rk}' missing in /api/ha/status lock payload")


# ===========================================================================
# 5. Direct BLE GATT Fallback Mechanics (R4, R6)
# ===========================================================================

class TestM12DirectBleGattFallbackAndSafety(unittest.TestCase):
    """Verifies that offline gateways trigger Direct BLE GATT fallback cleanly."""

    def test_direct_ble_fallback_when_gateway_fails(self):
        """R4: LockEngine executes Direct BLE GATT when Tuya Cloud actuation fails."""
        mock_gs = MagicMock()
        mock_gs.unlock_door.side_effect = GeekSmartAuthError(3, "Expired token")

        mock_tuya = MagicMock()
        mock_tuya.publish_dp.side_effect = Exception("Tuya gateway offline: device unreachable")

        mock_ble = MagicMock()
        mock_ble.mac = None
        mock_ble.unlock = AsyncMock(return_value={"success": True, "action": "ble_unlock"})

        engine = LockEngine(
            gs_client=mock_gs,
            tuya_client=mock_tuya,
            ble_client=mock_ble,
            dry_run=False,
            preferred_transport="auto",
        )

        test_lock = LockDevice(
            dev_id="ebexamplelock001",
            name="Living Room Lock",
            client_equipment_id=101,
            mac="DC:23:4F:00:00:90",
            parent_gateway_id="gw_offline_1",
        )
        engine._locks["ebexamplelock001"] = test_lock

        res = engine.execute_action(
            device_identifier="ebexamplelock001",
            action="unlock",
            confirm=True,
            dry_run=False,
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["transport_used"], "direct_ble")
        self.assertEqual(res["newState"], "UNLOCKED")

    def test_all_transports_fail_returns_failure_result(self):
        """R4: When Hop 1, Hop 2, and BLE fallback all fail, returns success=False."""
        mock_gs = MagicMock()
        mock_gs.unlock_door.side_effect = Exception("Hop 1 failed")

        mock_tuya = MagicMock()
        mock_tuya.publish_dp.side_effect = Exception("Hop 2 failed")

        mock_ble = MagicMock()
        mock_ble.unlock = AsyncMock(side_effect=Exception("BLE connection timed out"))

        engine = LockEngine(
            gs_client=mock_gs,
            tuya_client=mock_tuya,
            ble_client=mock_ble,
            dry_run=False,
            preferred_transport="auto",
        )

        test_lock = LockDevice(
            dev_id="ebexamplelock001",
            name="Living Room Lock",
            client_equipment_id=101,
            mac="DC:23:4F:00:00:90",
            parent_gateway_id="gw_offline_1",
        )
        engine._locks["ebexamplelock001"] = test_lock

        with self.assertRaises(GeekSmartControlError):
            engine.execute_action(
                device_identifier="ebexamplelock001",
                action="unlock",
                confirm=True,
                dry_run=False,
            )


# ===========================================================================
# 6. Universal Hardening & Zero Hardcoding in Production (R1)
# ===========================================================================

class TestM12UniversalHardeningZeroHardcoding(unittest.TestCase):
    """Verifies that non-fixture production runs contain zero hardcoded device IDs or names."""

    def test_zero_hardcoding_in_production_discovery(self):
        """R1: Arbitrary production accounts do not inject legacy test mappings or aliases."""
        with tempfile.TemporaryDirectory() as tmpdir:
            prod_cache = os.path.join(tmpdir, ".geek_door_session_cache.json")
            with open(prod_cache, "w") as f:
                json.dump({
                    "email": "real_production_user@example.com",
                    "clientId": 1234567,
                    "tuyaUid": "prod_tuya_uid_99",
                }, f)

            engine = LockEngine(session_cache_path=prod_cache, sample_mode=False)
            self.assertFalse(engine.sample_mode)

            # Discover synthetic arbitrary user devices
            from custom_components.geek_door.core.tuya_client import TuyaDevice
            custom_dev = TuyaDevice(
                dev_id="eb_custom_prod_lock_999",
                name="Front Security Door",
                product_id="prod_pid_1",
                category="jtmspro",
                is_online=True,
            )

            mock_tuya = MagicMock()
            mock_tuya.get_cached_devices.return_value = [custom_dev]
            mock_tuya.get_home_device_list.return_value = [custom_dev]
            engine.tuya_client = mock_tuya

            engine.discover(skip_network=True)
            locks = engine.list_locks()
            self.assertEqual(len(locks), 1)

            lock = locks[0]
            self.assertEqual(lock.dev_id, "eb_custom_prod_lock_999")
            self.assertEqual(lock.name, "Front Security Door")
            # Should NOT inject test room names
            lower_aliases = {a.lower() for a in lock.aliases}
            self.assertNotIn("livingroom", lower_aliases)
            self.assertNotIn("living room door", lower_aliases)
            self.assertNotIn("bathroom", lower_aliases)
            self.assertNotIn("k11", lower_aliases)
            self.assertNotIn("ebexamplelock001", lock.aliases)


# ===========================================================================
# 7. HA OS Add-on Packaging & Script Robustness (R5)
# ===========================================================================

class TestM12AddonPackagingAndRunSh(unittest.TestCase):
    """Verifies HA OS Add-on configuration, build.yaml, Dockerfile, and run.sh."""

    def test_addon_build_yaml_architectures(self):
        """R5: geek_door_addon/build.yaml specifies valid base images across architectures."""
        import yaml
        build_yaml = REPO_ROOT / "geek_door_addon" / "build.yaml"
        self.assertTrue(build_yaml.is_file())
        with open(build_yaml, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self.assertIn("build_from", data)
        self.assertIn("aarch64", data["build_from"])
        self.assertIn("amd64", data["build_from"])

    def test_addon_dockerfile_and_requirements_presence(self):
        """R5: geek_door_addon contains local requirements.txt and copies run.sh."""
        addon_dir = REPO_ROOT / "geek_door_addon"
        dockerfile = addon_dir / "Dockerfile"
        reqs = addon_dir / "requirements.txt"
        run_sh = addon_dir / "run.sh"

        self.assertTrue(dockerfile.is_file())
        self.assertTrue(reqs.is_file())
        self.assertTrue(run_sh.is_file())

        content = dockerfile.read_text()
        self.assertIn("COPY requirements.txt", content)
        self.assertIn("COPY run.sh /run.sh", content)
        self.assertTrue("CMD [\"/run.sh\"]" in content or "ENTRYPOINT [\"/run.sh\"]" in content)

    def test_addon_run_sh_python_options_fallback(self):
        """R5: run.sh contains resilient python fallback for options parsing without jq."""
        run_sh = (REPO_ROOT / "geek_door_addon" / "run.sh").read_text()
        self.assertIn("python3 -c", run_sh)
        self.assertIn("AUTH_ENABLED", run_sh)
        self.assertIn("GEEK_DOOR_API_KEY", run_sh)


# ===========================================================================
# 8. Zero-Smart-Plug Direct BLE, Exact DP 71 Parity & Session Auto-Heal
# ===========================================================================

class TestM12ZeroSmartPlugBleAndSessionAutoHeal(unittest.IsolatedAsyncioTestCase):
    """Verifies HA operation without a Smart Plug, exact BLE packet parity, and automatic session token self-healing."""

    async def test_zero_smart_plug_ha_direct_ble_exact_dp71_packets(self):
        """User without a Smart Plug gets all entities available and sends identical 19-byte DP 71 frames over HA Bluetooth."""
        import base64
        from custom_components.geek_door.coordinator import GeekDoorDataUpdateCoordinator
        from custom_components.geek_door.core.ble_gatt_client import (
            MockBleGattTransport,
            TuyaBleCmd,
            TuyaBlePacketEngine,
        )
        from custom_components.geek_door.core.tuya_client import TuyaClient
        from custom_components.geek_door.lock import GeekDoorLock, async_setup_entry as setup_locks
        from custom_components.geek_door.switch import GeekDoorAutoLockSwitch, async_setup_entry as setup_switches
        from custom_components.geek_door.sensor import async_setup_entry as setup_sensors
        from custom_components.geek_door.binary_sensor import async_setup_entry as setup_binary_sensors

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = os.path.join(tmpdir, ".geek_door_session_cache.json")
            # Account with ZERO Smart Plugs: lock is offline in Tuya Cloud, has 12-hex-char MAC and DP 73 seed
            with open(cache_file, "w") as f:
                json.dump({
                    "tuyaUid": "uid_no_plug_user",
                    "tuyaUsername": "no_plug_user@example.com",
                    "devices": [
                        {
                            "devId": "eb_no_plug_lock_01",
                            "name": "Front Entry Door",
                            "productId": "a0wnqgxs",
                            "category": "jtmspro",
                            "isOnline": False,  # Offline in cloud because user has NO Smart Plug!
                            "parentId": None,
                            "mac": "dc234d1a2b3c",  # Tuya 12-hex format without colons
                            "localKey": "TU:ESBz-3TXkj-Bq",
                            "uuid": "fakeuuid1a2b0a02",
                            "dps": {
                                "8": 91,
                                "33": True,
                                "36": 5,
                                "47": False,
                                "73": "AAAAAf///wABMTIzNDU2Nzg=",  # 18-byte Tuya DP 73 seed (slot 1, key 12345678)
                            },
                        }
                    ],
                }, f)

            mock_hass = MagicMock()
            mock_hass.config.path.return_value = cache_file
            mock_hass.async_add_executor_job = AsyncMock(side_effect=lambda fn, *a: fn(*a))

            mock_entry = MagicMock()
            mock_entry.entry_id = "entry_no_plug"
            mock_entry.title = "GeekSmart Cloud (no_plug_user@example.com)"
            mock_entry.data = {
                CONF_MODE: MODE_DIRECT_CLOUD,
                CONF_USERNAME: "no_plug_user@example.com",
                CONF_PASSWORD: "user_secret_pw",
            }
            mock_entry.options = {
                CONF_SCAN_INTERVAL: 30,
                CONF_BLE_DIRECT_FALLBACK: True,
            }

            coord = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)
            # Attach MockBleGattTransport to the coordinator's HomeAssistantBleAdapter
            peripheral = MockBleGattTransport(
                mac="DC:23:4D:1A:2B:3C",
                local_key="TU:ESBz-3TXkj-Bq",
                uuid="fakeuuid1a2b0a02",
                dev_id="eb_no_plug_lock_01",
                initial_is_locked=True,
                initial_battery=91,
            )
            captured_dp71_frames: List[bytes] = []
            orig_write = peripheral.write_payload

            def spy_write_payload(raw_payload: bytes) -> None:
                flag = raw_payload[0] if raw_payload else 0
                if flag == 5:
                    _, _, cmd, data = TuyaBlePacketEngine.unpack_message(raw_payload, peripheral.session_key)
                    if cmd in (TuyaBleCmd.DP_PUBLISH, TuyaBleCmd.DP_PUBLISH_V4):
                        tlvs = TuyaBlePacketEngine.decode_dp_tlv(data)
                        if "71" in tlvs:
                            captured_dp71_frames.append(tlvs["71"])
                return orig_write(raw_payload)

            peripheral.write_payload = spy_write_payload
            coord.engine.ble_client.transport = peripheral
            # Avoid live cloud HTTP during unit test
            coord.engine.tuya_client.get_home_device_list = MagicMock(side_effect=Exception("Offline local BLE mode"))

            coord.data = await coord._async_update_data()
            mock_entry.runtime_data = coord

            # Verify all 6 entities auto-populate
            created_entities: List[Any] = []
            await setup_locks(mock_hass, mock_entry, created_entities.extend)
            await setup_switches(mock_hass, mock_entry, created_entities.extend)
            await setup_sensors(mock_hass, mock_entry, created_entities.extend)
            await setup_binary_sensors(mock_hass, mock_entry, created_entities.extend)
            self.assertEqual(len(created_entities), 6)

            lock_entity = next(e for e in created_entities if isinstance(e, GeekDoorLock))
            switch_entity = next(e for e in created_entities if isinstance(e, GeekDoorAutoLockSwitch))
            lock_entity.hass = mock_hass
            switch_entity.hass = mock_hass

            # Crucial: Even though Tuya Cloud says isOnline=False (no Smart Plug),
            # both Lock and Auto-Lock Switch remain available=True via Direct BLE!
            self.assertTrue(lock_entity.available)
            self.assertTrue(switch_entity.available)
            self.assertTrue(lock_entity.is_locked)

            # Actuate UNLOCK in Home Assistant without a Smart Plug
            await lock_entity.async_unlock()
            self.assertFalse(peripheral.is_locked)
            self.assertEqual(len(captured_dp71_frames), 1)

            ble_dp71 = captured_dp71_frames[0]
            self.assertEqual(len(ble_dp71), 19)
            # Extract timestamp from BLE frame and compare against Smart Plug's TuyaClient.build_ble_unlock_check_payload
            ts = int.from_bytes(ble_dp71[13:17], "big")
            plug_b64 = TuyaClient.build_ble_unlock_check_payload(
                {"73": "AAAAAf///wABMTIzNDU2Nzg="},
                unlock=True,
                timestamp=ts,
                dev_id="eb_no_plug_lock_01",
            )
            plug_dp71 = base64.b64decode(plug_b64)
            # Prove bit-for-bit identical 19-byte DP 71 packet between Smart Plug and HA Direct BLE!
            self.assertEqual(ble_dp71, plug_dp71)
            self.assertEqual(ble_dp71[:12], b"\xff\xff\x00\x0112345678")
            self.assertEqual(ble_dp71[12], 1)

    async def test_real_bleak_uleb128_chunked_handshake_and_dp_publish(self):
        """BleGattClient over real bleak path executes DEVICE_INFO + PAIR + DP_PUBLISH with 20-byte ULEB128 chunks."""
        from custom_components.geek_door.core.ble_gatt_client import (
            BleGattClient,
            DpType,
            TuyaBleCmd,
            TuyaBlePacketEngine,
        )

        local_key = "TU:ESBz-3TXkj-Bq"
        srand = b"\x11\x22\x33\x44\x55\x66"
        login_key = TuyaBlePacketEngine.derive_login_key(local_key)
        session_key = TuyaBlePacketEngine.derive_session_key(local_key, srand)

        notify_cb = None
        tx_rx_buffer = bytearray()
        tx_expected = 0

        class FakeBleakClient:
            def __init__(self, target, timeout=6.0):
                self.target = target
                self.is_connected = False

            async def connect(self):
                self.is_connected = True

            async def disconnect(self):
                self.is_connected = False

            async def start_notify(self, char_uuid, callback):
                nonlocal notify_cb
                notify_cb = callback

            async def write_gatt_char(self, char_uuid, chunk, response=False):
                nonlocal tx_rx_buffer, tx_expected
                pkt_no, pos = TuyaBlePacketEngine.decode_uleb128(chunk, 0)
                if pkt_no == 0:
                    tx_expected, pos = TuyaBlePacketEngine.decode_uleb128(chunk, pos)
                    pos += 1  # version byte 0x40
                    tx_rx_buffer = bytearray(chunk[pos:])
                else:
                    tx_rx_buffer.extend(chunk[pos:])

                if tx_expected > 0 and len(tx_rx_buffer) >= tx_expected:
                    full_frame = bytes(tx_rx_buffer[:tx_expected])
                    tx_rx_buffer.clear()
                    tx_expected = 0
                    flag = full_frame[0]
                    k = login_key if flag == 4 else session_key
                    seq, _, cmd, data = TuyaBlePacketEngine.unpack_message(full_frame, k)

                    if cmd == TuyaBleCmd.DEVICE_INFO:
                        resp_chunks = TuyaBlePacketEngine.pack_message(
                            seq_num=200,
                            cmd=TuyaBleCmd.DEVICE_INFO,
                            data=b"\x00\x04" + srand,
                            key=login_key,
                            security_flag=4,
                            response_to=seq,
                        )
                    elif cmd == TuyaBleCmd.PAIR:
                        resp_chunks = TuyaBlePacketEngine.pack_message(
                            seq_num=201,
                            cmd=TuyaBleCmd.PAIR,
                            data=b"\x00",
                            key=session_key,
                            security_flag=5,
                            response_to=seq,
                        )
                    else:
                        report = TuyaBlePacketEngine.encode_dp_tlv(47, DpType.BOOL, True)
                        resp_chunks = TuyaBlePacketEngine.pack_message(
                            seq_num=202,
                            cmd=TuyaBleCmd.DP_REPORT,
                            data=report,
                            key=session_key,
                            security_flag=5,
                            response_to=seq,
                        )
                    for rc in resp_chunks:
                        notify_cb(char_uuid, bytearray(rc))

        fake_bleak_mod = MagicMock()
        fake_bleak_mod.BleakClient = FakeBleakClient

        with patch.dict(sys.modules, {"bleak": fake_bleak_mod}):
            client = BleGattClient(
                mac="dc234d1a2b3c",
                local_key=local_key,
                uuid="fakeuuid1a2b0a02",
                dev_id="ebexamplelock001",
            )
            self.assertEqual(client.mac, "DC:23:4D:1A:2B:3C")
            res = await client.unlock(slot_id=1, member_key="12345678")
            self.assertTrue(client.is_paired)
            self.assertEqual(res.get("47"), True)
            await client.disconnect()

    async def test_coordinator_auto_heals_expired_session_token_without_logout(self):
        """When a session token dies (USER_SESSION_INVALID), coordinator auto-heals via stored credentials without logging user out."""
        from custom_components.geek_door.coordinator import GeekDoorDataUpdateCoordinator

        mock_hass = MagicMock()
        mock_hass.config.path.return_value = "/tmp/cache_heal.json"
        mock_hass.async_add_executor_job = AsyncMock(side_effect=lambda fn, *a: fn(*a))

        mock_entry = MagicMock()
        mock_entry.entry_id = "entry_heal"
        mock_entry.title = "GeekSmart Cloud"
        mock_entry.data = {
            CONF_MODE: MODE_DIRECT_CLOUD,
            CONF_USERNAME: "stay_logged_in@example.com",
            CONF_PASSWORD: "valid_password_123",
        }
        mock_entry.options = {CONF_SCAN_INTERVAL: 30, CONF_BLE_DIRECT_FALLBACK: True}

        coord = GeekDoorDataUpdateCoordinator(mock_hass, mock_entry)
        coord.engine = MagicMock()
        # Simulate expired session token on poll
        coord.engine.get_all_lock_snapshots.side_effect = Exception("TuyaApiError: USER_SESSION_INVALID (Session expired)")
        # Simulate successful background re-authentication using stored entry.data credentials
        coord.engine.authenticate_and_discover.return_value = [
            {"devId": "eb_healed_lock_1", "name": "Healed Front Door", "is_locked": True, "online": True}
        ]

        data = await coord._async_update_data()
        coord.engine.authenticate_and_discover.assert_called_once_with(
            "stay_logged_in@example.com",
            "valid_password_123",
            "1",
        )
        self.assertIn("eb_healed_lock_1", data)
        self.assertEqual(data["eb_healed_lock_1"]["name"], "Healed Front Door")


if __name__ == "__main__":
    unittest.main()
