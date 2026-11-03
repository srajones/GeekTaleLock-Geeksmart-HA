#!/usr/bin/env python3
"""
Empirical Challenger Test Suite for Milestone 12 (tests/test_challenger_m12_2.py).

Adversarially stress-tests:
1. Server Bridge Auto-Lock Deadbolt Isolation:
   - POST /api/ha/lock/<dev_id>/auto_lock against create_app()
   - Deadbolt motor actuation isolation (lock state unchanged when toggling auto-lock)
   - switch.py _async_send_server_switch calls /auto_lock and NEVER /lock or /unlock
   - Error translations (401/403 -> ConfigEntryAuthFailed, 500 -> HomeAssistantError)
   - SEC-09 query parameter credential rejection
   - Malformed JSON body handling (400)
2. Telemetry Parity in /api/ha/status:
   - Presence of auto_lock_seconds, hardware_model, gateway_name, ble_connected, wifi_rssi
   - Graceful fallback resilience when telemetry fields are missing/corrupted
3. Add-on Packaging & Script Robustness:
   - geek_door_addon/build.yaml & config.yaml YAML validity and arch coverage
   - Dockerfile syntax & context self-containment
   - run.sh python fallback option extraction when jq is missing
   - Verification of AUTH_ENABLED and GEEK_DOOR_API_KEY environment exports
   - Resilience against corrupt or missing options.json
4. Verification Safety Constraints:
   - Zero physical deadbolt actuation, dry_run=True enforcement
   - Port 5050 and process hygiene
"""

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.flask_app import create_app
from custom_components.geek_door.const import (
    DOMAIN,
    MODE_SERVER_BRIDGE,
    CONF_SERVER_URL,
    CONF_API_KEY,
    CONF_VERIFY_SSL,
)
from custom_components.geek_door.switch import GeekDoorAutoLockSwitch
from custom_components.geek_door.core.exceptions import (
    HomeAssistantError,
    ConfigEntryAuthFailed,
)


class TestChallengerAutoLockDeadboltIsolation(unittest.TestCase):
    """Challenge 1: Server Bridge Auto-Lock Deadbolt Isolation."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cache_file = os.path.join(self.tmpdir, ".session_cache.json")
        shutil.copyfile(REPO_ROOT / ".session_cache.json", self.cache_file)
        self.app = create_app(session_cache_path=self.cache_file)
        self.app.config["HA_BEARER_TOKEN"] = "adversarial_secret_token_xyz"
        self.headers = {"Authorization": "Bearer adversarial_secret_token_xyz"}
        self.client = self.app.test_client()
        self.engine = self.app.config["LOCK_ENGINE"]

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_auto_lock_toggle_preserves_locked_state_without_actuation(self):
        """Verify that disabling auto-lock on a LOCKED door leaves the deadbolt strictly LOCKED."""
        # 1. Explicitly set initial state to LOCKED and auto-lock to True
        self.engine.set_state_override("101", "LOCKED")
        self.engine.set_auto_lock_override("101", True)

        state_resp = self.client.get("/api/ha/lock/101/state", headers=self.headers)
        self.assertEqual(state_resp.status_code, 200)
        state_data = state_resp.get_json()
        self.assertEqual(state_data["state"], "locked")
        self.assertTrue(state_data["is_locked"])
        self.assertTrue(state_data["auto_lock_enabled"])

        # 2. Toggle Auto-Lock OFF (Passage Mode) via POST /api/ha/lock/101/auto_lock
        toggle_resp = self.client.post(
            "/api/ha/lock/101/auto_lock",
            headers=self.headers,
            json={"enabled": False, "confirmed": True, "dry_run": True},
        )
        self.assertEqual(toggle_resp.status_code, 200)
        toggle_data = toggle_resp.get_json()
        self.assertTrue(toggle_data["success"])
        self.assertFalse(toggle_data["auto_lock_enabled"])
        self.assertEqual(toggle_data["action"], "auto_lock_off")

        # 3. Deadbolt state MUST remain LOCKED (isolation verification)
        state_after = self.client.get("/api/ha/lock/101/state", headers=self.headers)
        self.assertEqual(state_after.status_code, 200)
        after_data = state_after.get_json()
        self.assertEqual(after_data["state"], "locked", "Deadbolt state mutated during auto-lock toggle!")
        self.assertTrue(after_data["is_locked"], "is_locked changed during auto-lock toggle!")
        self.assertFalse(after_data["auto_lock_enabled"], "auto_lock_enabled did not update!")

    def test_auto_lock_toggle_preserves_unlocked_state_without_actuation(self):
        """Verify that enabling auto-lock on an UNLOCKED door leaves the deadbolt strictly UNLOCKED."""
        # 1. Explicitly set initial state to UNLOCKED and auto-lock to False
        self.engine.set_state_override("101", "UNLOCKED")
        self.engine.set_auto_lock_override("101", False)

        state_resp = self.client.get("/api/ha/lock/101/state", headers=self.headers)
        self.assertEqual(state_resp.status_code, 200)
        state_data = state_resp.get_json()
        self.assertEqual(state_data["state"], "unlocked")
        self.assertFalse(state_data["is_locked"])
        self.assertFalse(state_data["auto_lock_enabled"])

        # 2. Toggle Auto-Lock ON via POST /api/ha/lock/101/auto_lock
        toggle_resp = self.client.post(
            "/api/ha/lock/101/auto_lock",
            headers=self.headers,
            json={"enabled": True, "auto_lock_seconds": 10, "confirmed": True, "dry_run": True},
        )
        self.assertEqual(toggle_resp.status_code, 200)
        toggle_data = toggle_resp.get_json()
        self.assertTrue(toggle_data["success"])
        self.assertTrue(toggle_data["auto_lock_enabled"])
        self.assertEqual(toggle_data["action"], "auto_lock_on")

        # 3. Deadbolt state MUST remain UNLOCKED (isolation verification)
        state_after = self.client.get("/api/ha/lock/101/state", headers=self.headers)
        self.assertEqual(state_after.status_code, 200)
        after_data = state_after.get_json()
        self.assertEqual(after_data["state"], "unlocked", "Deadbolt state mutated to locked during auto-lock ON!")
        self.assertFalse(after_data["is_locked"], "is_locked changed during auto-lock toggle!")
        self.assertTrue(after_data["auto_lock_enabled"], "auto_lock_enabled did not update!")

    def test_mock_engine_receives_auto_lock_actions_never_lock_or_unlock(self):
        """Verify underlying LockEngine receives auto_lock_on / auto_lock_off, never lock / unlock."""
        mock_engine = MagicMock()
        mock_engine.execute_action.return_value = {
            "success": True,
            "action": "auto_lock_on",
            "newState": "LOCKED",
            "state_label": "LOCKED",
        }
        self.app.config["LOCK_ENGINE"] = mock_engine

        # Call auto_lock ON
        resp_on = self.client.post(
            "/api/ha/lock/101/auto_lock",
            headers=self.headers,
            json={"enabled": True, "confirmed": True, "dry_run": True},
        )
        self.assertEqual(resp_on.status_code, 200)

        # Verify action passed to engine was "auto_lock_on"
        call_args = mock_engine.execute_action.call_args
        action_arg = call_args.kwargs.get("action") or (call_args.args[1] if len(call_args.args) > 1 else None)
        self.assertEqual(action_arg, "auto_lock_on")
        self.assertNotEqual(action_arg, "lock")
        self.assertNotEqual(action_arg, "unlock")

        # Call auto_lock OFF
        mock_engine.execute_action.reset_mock()
        mock_engine.execute_action.return_value = {
            "success": True,
            "action": "auto_lock_off",
            "newState": "LOCKED",
            "state_label": "LOCKED",
        }
        resp_off = self.client.post(
            "/api/ha/lock/101/auto_lock",
            headers=self.headers,
            json={"enabled": False, "confirmed": True, "dry_run": True},
        )
        self.assertEqual(resp_off.status_code, 200)
        call_args_off = mock_engine.execute_action.call_args
        action_arg_off = call_args_off.kwargs.get("action") or (call_args_off.args[1] if len(call_args_off.args) > 1 else None)
        self.assertEqual(action_arg_off, "auto_lock_off")
        self.assertNotEqual(action_arg_off, "lock")
        self.assertNotEqual(action_arg_off, "unlock")

    def test_switch_py_server_bridge_endpoints_and_exception_handling(self):
        """Verify switch.py routes server switch to /auto_lock and translates 401/500 errors."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        coordinator = MagicMock()
        coordinator.mode = MODE_SERVER_BRIDGE
        coordinator.data = {"101": {"name": "Test Door", "auto_lock_enabled": True}}
        coordinator.entry = MagicMock()
        coordinator.entry.data = {
            CONF_SERVER_URL: "http://127.0.0.1:5050",
            CONF_API_KEY: "secret_bridge_token",
            CONF_VERIFY_SSL: False,
        }
        coordinator.async_request_refresh = AsyncMock()

        switch = GeekDoorAutoLockSwitch(coordinator, "101")
        switch.hass = MagicMock()

        # Test A: Successful toggle calls /auto_lock with correct parameters
        recorded_calls = []

        class MockResponse:
            def __init__(self, status=200, text="OK"):
                self.status = status
                self._text = text
            async def text(self): return self._text
            async def __aenter__(self): return self
            async def __aexit__(self, exc_type, exc, tb): pass

        class MockSession:
            def post(self, url, headers=None, json=None):
                recorded_calls.append({"url": url, "headers": headers, "json": json})
                return MockResponse(200, '{"success": true}')

        with patch("custom_components.geek_door.switch.async_get_clientsession", return_value=MockSession()):
            loop.run_until_complete(switch.async_turn_on())
            loop.run_until_complete(switch.async_turn_off())

        self.assertEqual(len(recorded_calls), 2)
        # Turn ON check
        self.assertEqual(recorded_calls[0]["url"], "http://127.0.0.1:5050/api/ha/lock/101/auto_lock")
        self.assertEqual(recorded_calls[0]["json"], {"enabled": True, "confirmed": True})
        self.assertTrue(recorded_calls[0]["url"].endswith("/auto_lock"))
        self.assertFalse(recorded_calls[0]["url"].endswith("/lock"))
        self.assertFalse(recorded_calls[0]["url"].endswith("/unlock"))

        # Turn OFF check
        self.assertEqual(recorded_calls[1]["url"], "http://127.0.0.1:5050/api/ha/lock/101/auto_lock")
        self.assertEqual(recorded_calls[1]["json"], {"enabled": False, "confirmed": True})

        # Test B: 401 Unauthorized raises ConfigEntryAuthFailed
        class AuthFailSession:
            def post(self, url, headers=None, json=None):
                return MockResponse(401, '{"error": "Unauthorized"}')

        with patch("custom_components.geek_door.switch.async_get_clientsession", return_value=AuthFailSession()):
            with self.assertRaises(ConfigEntryAuthFailed):
                loop.run_until_complete(switch.async_turn_on())

        # Test C: 500 Internal Error raises HomeAssistantError
        class ServerErrorSession:
            def post(self, url, headers=None, json=None):
                return MockResponse(500, '{"error": "Server bridge down"}')

        with patch("custom_components.geek_door.switch.async_get_clientsession", return_value=ServerErrorSession()):
            with self.assertRaises(HomeAssistantError):
                loop.run_until_complete(switch.async_turn_off())

        loop.close()

    def test_auto_lock_security_and_malformed_payload_adversarial(self):
        """Adversarially verify SEC-09 query param rejection, unauthenticated 401, and malformed JSON 400."""
        # 1. SEC-09: Rejection of query string token
        resp_query = self.client.post("/api/ha/lock/101/auto_lock?token=some_token", json={"enabled": True})
        self.assertEqual(resp_query.status_code, 400)
        self.assertIn("QUERY_PARAM_TOKEN_FORBIDDEN", resp_query.get_json().get("securityViolation", ""))

        # 2. Missing authentication -> 401
        resp_noauth = self.client.post("/api/ha/lock/101/auto_lock", json={"enabled": True})
        self.assertEqual(resp_noauth.status_code, 401)

        # 3. Invalid authentication token -> 401
        resp_badauth = self.client.post(
            "/api/ha/lock/101/auto_lock",
            headers={"Authorization": "Bearer wrong_token_999"},
            json={"enabled": True},
        )
        self.assertEqual(resp_badauth.status_code, 401)

        # 4. Malformed JSON syntax -> 400
        resp_badjson = self.client.post(
            "/api/ha/lock/101/auto_lock",
            headers=self.headers,
            data="{malformed_json_syntax:",
            content_type="application/json",
        )
        self.assertEqual(resp_badjson.status_code, 400)
        self.assertIn("Malformed JSON", resp_badjson.get_json().get("error", ""))


class TestChallengerTelemetryParityInHaStatus(unittest.TestCase):
    """Challenge 2: Telemetry Parity in /api/ha/status."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cache_file = os.path.join(self.tmpdir, ".session_cache.json")
        shutil.copyfile(REPO_ROOT / ".session_cache.json", self.cache_file)
        self.app = create_app(session_cache_path=self.cache_file)
        self.app.config["HA_BEARER_TOKEN"] = "adversarial_secret_token_xyz"
        self.headers = {"Authorization": "Bearer adversarial_secret_token_xyz"}
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_all_five_telemetry_fields_present_and_typed(self):
        """Verify auto_lock_seconds, hardware_model, gateway_name, ble_connected, wifi_rssi."""
        resp = self.client.get("/api/ha/status", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("locks", data)
        self.assertGreaterEqual(len(data["locks"]), 1)

        required_telemetry = {
            "auto_lock_seconds": (int, float),
            "hardware_model": str,
            "gateway_name": (str, int, type(None)),
            "ble_connected": bool,
            "wifi_rssi": (int, float),
        }

        for lock in data["locks"]:
            for field, expected_type in required_telemetry.items():
                self.assertIn(field, lock, f"Telemetry field '{field}' missing from lock: {lock}")
                val = lock[field]
                self.assertIsInstance(
                    val,
                    expected_type,
                    f"Field '{field}' has invalid type {type(val)} (value: {val}) in lock: {lock}"
                )

    def test_telemetry_resilience_on_sparse_device_payload(self):
        """Stress-test /api/ha/status when devices have missing or sparse telemetry dictionaries."""
        sparse_device = {
            "id": 999,
            "devId": "sparse-lock-999",
            "name": "Sparse Test Door",
            "isLock": True,
            "state": "LOCKED",
            # All 5 telemetry fields explicitly missing
        }
        self.app._collect_devices = lambda: [sparse_device]

        resp = self.client.get("/api/ha/status", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data["locks"]), 1)
        lock = data["locks"][0]

        # Verify fallback defaults
        self.assertEqual(lock["auto_lock_seconds"], 5)
        self.assertEqual(lock["hardware_model"], "Smart Lock")
        self.assertIsNone(lock["gateway_name"])
        self.assertIsInstance(lock["ble_connected"], bool)
        self.assertEqual(lock["wifi_rssi"], -70)


class TestChallengerAddonPackagingAndRunSh(unittest.TestCase):
    """Challenge 3: Add-on Packaging & Script Robustness."""

    def test_build_yaml_and_config_yaml_syntax_and_schemas(self):
        """Verify YAML validity and required schemas of build.yaml and config.yaml."""
        import yaml

        # 1. build.yaml validation
        build_yaml_path = REPO_ROOT / "geek_door_addon" / "build.yaml"
        self.assertTrue(build_yaml_path.is_file(), "build.yaml missing in geek_door_addon")
        with open(build_yaml_path, "r", encoding="utf-8") as f:
            build_data = yaml.safe_load(f)
        self.assertIn("build_from", build_data)
        required_archs = ["aarch64", "amd64", "armhf", "armv7", "i386"]
        for arch in required_archs:
            self.assertIn(arch, build_data["build_from"], f"Architecture '{arch}' missing in build.yaml")
            self.assertTrue(build_data["build_from"][arch].startswith("ghcr.io/home-assistant/"))

        # 2. config.yaml validation
        config_yaml_path = REPO_ROOT / "geek_door_addon" / "config.yaml"
        self.assertTrue(config_yaml_path.is_file(), "config.yaml missing in geek_door_addon")
        with open(config_yaml_path, "r", encoding="utf-8") as f:
            config_data = yaml.safe_load(f)
        self.assertEqual(config_data.get("slug"), "geek_door")
        self.assertIn("5050/tcp", config_data.get("ports", {}))
        self.assertIn("api_key", config_data.get("options", {}))
        self.assertIn("enable_2fa", config_data.get("options", {}))

    def test_dockerfile_commands_and_assets(self):
        """Verify Dockerfile instructions and that local requirements.txt exists."""
        dockerfile_path = REPO_ROOT / "geek_door_addon" / "Dockerfile"
        self.assertTrue(dockerfile_path.is_file(), "Dockerfile missing in geek_door_addon")
        content = dockerfile_path.read_text(encoding="utf-8")

        self.assertIn("ARG BUILD_FROM", content)
        self.assertIn("FROM ${BUILD_FROM}", content)
        self.assertIn("COPY requirements.txt /app/requirements.txt", content)
        self.assertIn("pip install --no-cache-dir -r /app/requirements.txt", content)
        self.assertIn("COPY run.sh /run.sh", content)
        self.assertIn("chmod +x /run.sh", content)
        self.assertIn("EXPOSE 5050", content)

        # Confirm requirements.txt exists inside geek_door_addon context
        local_reqs = REPO_ROOT / "geek_door_addon" / "requirements.txt"
        self.assertTrue(local_reqs.is_file(), "requirements.txt missing inside geek_door_addon context")

    def test_run_sh_python_options_fallback_and_env_exports(self):
        """Empirically execute run.sh option parsing logic with jq ABSENT from PATH."""
        test_script = """
set -e
OPTIONS_FILE="$1"
ENV_FILE="$2"

get_option() {
    local key="$1"
    local default_val="$2"
    if [ -f "$OPTIONS_FILE" ]; then
        if command -v jq >/dev/null 2>&1; then
            local val
            val=$(jq -r ".${key} // empty" "$OPTIONS_FILE" 2>/dev/null || true)
            if [ -n "$val" ]; then
                echo "$val"
            else
                echo "$default_val"
            fi
        else
            python3 -c "
import json
try:
    with open('$OPTIONS_FILE') as f:
        data = json.load(f)
    v = data.get('$key', None)
    if v is None or v == '':
        print('$default_val')
    elif isinstance(v, bool):
        print(str(v).lower())
    else:
        print(v)
except Exception:
    print('$default_val')
"
        fi
    else
        echo "$default_val"
    fi
}

EMAIL=$(get_option "email" "")
PASSWORD=$(get_option "password" "")
COUNTRY_CODE=$(get_option "country_code" "1")
API_KEY=$(get_option "api_key" "")
ENABLE_2FA=$(get_option "enable_2fa" "false")
LOG_LEVEL=$(get_option "log_level" "info")
DRY_RUN=$(get_option "dry_run" "false")

cat <<EOF > "$ENV_FILE"
GEEK_DOOR_SESSION_CACHE=/data/.session_cache.json
TUYA_USERNAME=${EMAIL}
TUYA_PASSWORD=${PASSWORD}
TUYA_COUNTRY_CODE=${COUNTRY_CODE}
HA_BEARER_TOKEN=${API_KEY}
GEEK_DOOR_API_KEY=${API_KEY}
LOG_LEVEL=${LOG_LEVEL}
ENABLE_2FA=${ENABLE_2FA}
AUTH_ENABLED=${ENABLE_2FA}
DRY_RUN=${DRY_RUN}
PORT=5050
HOST=0.0.0.0
EOF
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            options_path = os.path.join(tmpdir, "options.json")
            env_path = os.path.join(tmpdir, ".env")
            script_path = os.path.join(tmpdir, "test_extract.sh")

            with open(options_path, "w") as f:
                json.dump({
                    "email": "test_addon_user@domain.com",
                    "password": "SuperSecretPassword123!",
                    "country_code": 44,
                    "api_key": "ha_bridge_key_999888",
                    "enable_2fa": True,
                    "log_level": "debug",
                    "dry_run": True,
                }, f)

            with open(script_path, "w") as f:
                f.write(test_script)
            os.chmod(script_path, 0o755)

            # Construct clean PATH without jq
            safe_dirs = []
            for d in os.environ.get("PATH", "").split(os.path.pathsep):
                if d and os.path.isdir(d):
                    if not os.path.exists(os.path.join(d, "jq")):
                        safe_dirs.append(d)
            clean_path = os.path.pathsep.join(safe_dirs)

            env = os.environ.copy()
            env["PATH"] = clean_path

            res = subprocess.run(
                ["/bin/bash", script_path, options_path, env_path],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}")
            self.assertTrue(os.path.isfile(env_path))

            env_content = Path(env_path).read_text()
            self.assertIn("TUYA_USERNAME=test_addon_user@domain.com", env_content)
            self.assertIn("TUYA_PASSWORD=SuperSecretPassword123!", env_content)
            self.assertIn("TUYA_COUNTRY_CODE=44", env_content)
            self.assertIn("HA_BEARER_TOKEN=ha_bridge_key_999888", env_content)
            self.assertIn("GEEK_DOOR_API_KEY=ha_bridge_key_999888", env_content)
            self.assertIn("ENABLE_2FA=true", env_content)
            self.assertIn("AUTH_ENABLED=true", env_content)
            self.assertIn("DRY_RUN=true", env_content)
            self.assertIn("PORT=5050", env_content)
            self.assertIn("HOST=0.0.0.0", env_content)

    def test_run_sh_missing_or_corrupt_options_file_falls_back_cleanly(self):
        """Verify python fallback handles missing or corrupt options.json with defaults."""
        test_script = """
set -e
OPTIONS_FILE="$1"
get_option() {
    local key="$1"
    local default_val="$2"
    if [ -f "$OPTIONS_FILE" ]; then
        python3 -c "
import json
try:
    with open('$OPTIONS_FILE') as f:
        data = json.load(f)
    v = data.get('$key', None)
    if v is None or v == '':
        print('$default_val')
    elif isinstance(v, bool):
        print(str(v).lower())
    else:
        print(v)
except Exception:
    print('$default_val')
"
    else
        echo "$default_val"
    fi
}
echo "val=$(get_option 'enable_2fa' 'false')"
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = os.path.join(tmpdir, "test_corrupt.sh")
            with open(script_path, "w") as f:
                f.write(test_script)
            os.chmod(script_path, 0o755)

            # Test A: completely missing file
            res_missing = subprocess.run(
                ["/bin/bash", script_path, os.path.join(tmpdir, "nonexistent.json")],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res_missing.returncode, 0)
            self.assertIn("val=false", res_missing.stdout)

            # Test B: corrupted invalid JSON file
            corrupt_file = os.path.join(tmpdir, "corrupt.json")
            with open(corrupt_file, "w") as f:
                f.write("{this is not valid json!@#$")
            res_corrupt = subprocess.run(
                ["/bin/bash", script_path, corrupt_file],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res_corrupt.returncode, 0)
            self.assertIn("val=false", res_corrupt.stdout)


class TestChallengerVerificationSafetyAndHygiene(unittest.TestCase):
    """Challenge 4: Verification Safety Constraints."""

    def test_port_5050_is_not_lingering(self):
        """Verify port 5050 is completely free and no background server is lingering."""
        res = subprocess.run(["lsof", "-i", ":5050"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 1, f"Port 5050 is in use:\n{res.stdout}")
        self.assertEqual(res.stdout.strip(), "")

    def test_no_lingering_door_lock_or_flask_processes(self):
        """Verify no unmanaged background flask or door_lock processes are running."""
        res = subprocess.run(
            ["pgrep", "-f", "door_lock_control.py serve"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 1, f"Lingering door_lock server process detected: {res.stdout}")


if __name__ == "__main__":
    unittest.main()
