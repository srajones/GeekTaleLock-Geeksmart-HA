"""Unit and E2E Tests for door_lock_control.py standalone user CLI.

Verifies:
- Command line parsing for --list, --status, --unlock, --lock, --serve, --capabilities.
- Formatted table and JSON output.
- ZERO AUTOMATED PHYSICAL ACTUATION safety barriers:
  - Non-interactive / automated calls without --confirm are hard-blocked.
  - Interactive prompts require verbatim 'YES'.
- ZERO NETWORK LOGIN RATE-LIMIT RULE:
  - Loads credentials exclusively from .session_cache.json with zero cloud login calls.
- Positional command alias handling.
"""

from __future__ import annotations

import io
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import door_lock_control
from door_lock_control import (
    discover_unified_devices,
    load_clients,
    build_parser,
    main,
)
from client.session_manager import SessionManager


class TestDoorLockControlCLI(unittest.TestCase):
    """Test suite for door_lock_control.py CLI tool."""

    def setUp(self):
        self.cache_path = os.path.join(REPO_ROOT, ".session_cache.json")
        self.assertTrue(os.path.exists(self.cache_path), "Session cache must exist")

    def test_T5_01_load_clients_from_session_cache(self):
        """T5.01: load_clients initializes GeekSmartClient and TuyaClient from cache with zero loginByPassword calls."""
        gs_client, tuya_client, mgr = load_clients(cache_path=self.cache_path)
        self.assertFalse(gs_client.allow_network_login, "allow_network_login must be False to prevent rate-limiting")
        self.assertEqual(gs_client.client_id, 9999999)
        self.assertEqual(tuya_client.username, "testuser@example.com")

    def test_T5_02_discover_unified_devices(self):
        """T5.02: discover_unified_devices returns hardware topology with Smart Plug Gateway and Locks."""
        gs_client, tuya_client, mgr = load_clients(cache_path=self.cache_path)
        devices, topology = discover_unified_devices(gs_client, tuya_client, mgr, skip_network=True)

        self.assertEqual(topology["clientId"], 9999999)
        self.assertEqual(topology["accountEmail"], "testuser@example.com")
        self.assertEqual(topology["tuyaUid"], "tuya_mock_uid_1099")
        self.assertEqual(topology["ttlockUid"], "10000001")

        self.assertGreaterEqual(len(devices), 3)
        # Verify Smart Plug Gateway is present
        gw = next((d for d in devices if d.get("deviceType") == "GATEWAY"), None)
        self.assertIsNotNone(gw, "Smart Plug BLE Gateway must be present")
        self.assertIn(gw["id"], (701, "ebexamplegw1a2b3c4d5e6"))
        self.assertEqual(gw["state"], "ONLINE")

        # Verify Lock is present
        locks = [d for d in devices if d.get("deviceType") == "SMART_LOCK"]
        self.assertGreaterEqual(len(locks), 2)
        for lk in locks:
            self.assertIn("Smart Plug BLE Gateway", lk["connectionPath"])
            self.assertIn(lk["state"], ("LOCKED", "UNLOCKED"))

    def test_T5_03_parser_supports_all_commands_and_flags(self):
        """T5.03: build_parser defines all required options, commands, and safety flags."""
        parser = build_parser()
        args = parser.parse_args(["list"])
        self.assertEqual(args.command, "list")

        args = parser.parse_args(["--list"])
        self.assertTrue(args.list_flag)

        args = parser.parse_args(["--status", "101"])
        self.assertEqual(args.status_flag, "101")

        args = parser.parse_args(["--unlock", "101", "--dry-run"])
        self.assertEqual(args.unlock_flag, "101")
        self.assertTrue(args.dry_run)

        args = parser.parse_args(["--lock", "101", "--confirm"])
        self.assertEqual(args.lock_flag, "101")
        self.assertTrue(args.confirm)

        args = parser.parse_args(["--serve", "--port", "5050"])
        self.assertTrue(args.serve_flag)
        self.assertEqual(args.port, 5050)

    def test_T5_04_cli_help(self):
        """T5.04: --help outputs comprehensive usage instructions and exits 0."""
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            with self.assertRaises(SystemExit) as cm:
                main(["--help"])
            self.assertEqual(cm.exception.code, 0)
            output = fake_out.getvalue()
            self.assertIn("--list", output)
            self.assertIn("--status", output)
            self.assertIn("--unlock", output)
            self.assertIn("--lock", output)
            self.assertIn("--serve", output)
            self.assertIn("--confirm", output)
            self.assertIn("--dry-run", output)

    def test_T5_05_cli_list_table_output(self):
        """T5.05: --list outputs formatted table with account summary and device topology."""
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = main(["--list"])
            self.assertEqual(exit_code, 0)
            output = fake_out.getvalue()
            self.assertIn("GEEKSMART & TUYA MULTI-HOP DEVICE INVENTORY", output)
            self.assertIn("testuser@example.com", output)
            self.assertIn("tuya_mock_uid_1099", output)
            self.assertIn("10000001", output)
            self.assertIn("Smart Plug BLE Gateway", output)
            self.assertIn("Living Room Door", output)
            self.assertIn("Bathroom Door", output)

    def test_T5_06_cli_list_json_output(self):
        """T5.06: --list --json outputs valid JSON payload with account and devices array."""
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = main(["--list", "--json"])
            self.assertEqual(exit_code, 0)
            output = fake_out.getvalue()
            data = json.loads(output)
            self.assertTrue(data["success"])
            self.assertEqual(data["command"], "list")
            self.assertEqual(data["topology"]["clientId"], 9999999)
            self.assertGreaterEqual(data["count"], 3)

    def test_T5_07_cli_status_dry_run(self):
        """T5.07: --status 101 --dry-run simulates status inquiry with zero network I/O."""
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = main(["--status", "101", "--dry-run"])
            self.assertEqual(exit_code, 0)
            output = fake_out.getvalue()
            self.assertIn("DEVICE STATUS, TOPOLOGY & DATA POINTS (DRY-RUN)", output)
            self.assertIn("Living Room Door", output)
            self.assertIn("UNLOCKED", output)
            self.assertIn("residual_electricity", output)

    def test_T5_08_cli_status_json_dry_run(self):
        """T5.08: --status 101 --dry-run --json outputs machine-readable JSON status."""
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = main(["--status", "101", "--dry-run", "--json"])
            self.assertEqual(exit_code, 0)
            data = json.loads(fake_out.getvalue())
            self.assertTrue(data["success"])
            self.assertEqual(data["command"], "status")
            self.assertTrue(data["dryRun"])
            self.assertIn("Living Room Door", data["devices"][0]["name"])

    def test_T5_09_cli_unlock_dry_run(self):
        """T5.09: --unlock 101 --dry-run validates safety and encrypts without actuation."""
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = main(["--unlock", "101", "--dry-run"])
            self.assertEqual(exit_code, 0)
            output = fake_out.getvalue()
            self.assertIn("REMOTE DOOR LOCK CONTROL — UNLOCK (DRY-RUN SIMULATION)", output)
            self.assertIn("PASSED_SAFE_CONTROL", output)
            self.assertIn("/app/home/ttlockGatewayUnlock", output)
            self.assertIn("thing.m.device.dp.publish", output)
            self.assertIn("ZERO network I/O", output)

    def test_T5_10_cli_lock_dry_run(self):
        """T5.10: --lock 101 --dry-run validates safety and encrypts without actuation."""
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = main(["--lock", "101", "--dry-run"])
            self.assertEqual(exit_code, 0)
            output = fake_out.getvalue()
            self.assertIn("REMOTE DOOR LOCK CONTROL — LOCK (DRY-RUN SIMULATION)", output)
            self.assertIn("PASSED_SAFE_CONTROL", output)
            self.assertIn("/app/home/ttlockGatewayLock", output)
            self.assertIn("thing.m.device.dp.publish", output)
            self.assertIn("ZERO network I/O", output)

    def test_T5_11_zero_automated_actuation_blocked_without_confirm(self):
        """T5.11: Non-interactive automated execution without --confirm is hard-blocked."""
        with patch("sys.stdin.isatty", return_value=False):
            with patch("sys.stderr", new=io.StringIO()) as fake_err:
                exit_code = main(["--unlock", "101"])
                self.assertEqual(exit_code, 1)
                self.assertIn("Refusing unattended live", fake_err.getvalue())

    def test_T5_12_interactive_confirmation_abort_on_non_yes(self):
        """T5.12: Interactive prompt aborts actuation if user inputs anything other than 'YES'."""
        with patch("sys.stdin.isatty", return_value=True):
            with patch("builtins.input", return_value="NO"):
                with patch("sys.stdout", new=io.StringIO()) as fake_out:
                    exit_code = main(["--unlock", "101"])
                    self.assertEqual(exit_code, 1)
                    self.assertIn("[ABORTED]", fake_out.getvalue())

    def test_T5_13_interactive_confirmation_yes_executes(self):
        """T5.13: Interactive prompt proceeds when user enters verbatim 'YES'."""
        mock_result = MagicMock()
        mock_result.__bool__.return_value = True
        mock_result.get.side_effect = lambda k, default=None: "Unlocked successfully" if k == "message" else default

        with patch("sys.stdin.isatty", return_value=True):
            with patch("builtins.input", return_value="YES"):
                with patch("client.geeksmart_client.GeekSmartClient.unlock_door", return_value=mock_result):
                    with patch("sys.stdout", new=io.StringIO()) as fake_out:
                        exit_code = main(["--unlock", "101"])
                        self.assertEqual(exit_code, 0)
                        self.assertIn("[SUCCESS]", fake_out.getvalue())

    def test_T5_14_confirm_flag_executes_without_prompt(self):
        """T5.14: Passing --confirm flag bypasses interactive prompt safely."""
        mock_result = MagicMock()
        mock_result.__bool__.return_value = True
        mock_result.get.side_effect = lambda k, default=None: "Locked successfully" if k == "message" else default

        with patch("client.geeksmart_client.GeekSmartClient.lock_door", return_value=mock_result):
            with patch("sys.stdout", new=io.StringIO()) as fake_out:
                exit_code = main(["--lock", "101", "--confirm"])
                self.assertEqual(exit_code, 0)

    def test_T5_15_positional_command_aliases(self):
        """T5.15: Positional subcommands ('list', 'status', 'unlock', 'lock') work identically."""
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = main(["list", "--json"])
            self.assertEqual(exit_code, 0)
            data = json.loads(fake_out.getvalue())
            self.assertEqual(data["command"], "list")

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = main(["status", "101", "--dry-run", "--json"])
            self.assertEqual(exit_code, 0)
            data = json.loads(fake_out.getvalue())
            self.assertTrue(data["dryRun"])

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = main(["unlock", "101", "--dry-run", "--json"])
            self.assertEqual(exit_code, 0)
            data = json.loads(fake_out.getvalue())
            self.assertTrue(data["dryRun"])
            self.assertTrue(data["success"])

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = main(["lock", "101", "--dry-run", "--json"])
            self.assertEqual(exit_code, 0)
            data = json.loads(fake_out.getvalue())
            self.assertTrue(data["dryRun"])
            self.assertTrue(data["success"])

    def test_T5_16_capabilities_matrix(self):
        """T5.16: capabilities command outputs read-only, safe-control, and 45 blocked endpoints."""
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = main(["capabilities"])
            self.assertEqual(exit_code, 0)
            output = fake_out.getvalue()
            self.assertIn("DEVICE CAPABILITIES & SAFETY BARRIER ENFORCEMENT MATRIX", output)
            self.assertIn("GLOBAL READ-ONLY ALLOWLIST", output)
            self.assertIn("GLOBAL SAFE CONTROL ALLOWLIST", output)
            self.assertIn("PERMANENTLY BLOCKED DESTRUCTIVE OPERATIONS IN SAFETY.PY (45 Endpoints)", output)
            self.assertIn("/clearallfingerprints", output)
            self.assertIn("/resetfactory", output)

    def test_T5_17_live_hop1_token_expiry_auto_heals_via_tuya_hop2(self):
        """T5.17: When Hop 1 raises GeekSmartAuthError(3) during --unlock 101 --confirm, CLI auto-heals via Tuya Hop 2 DP 71."""
        from client.exceptions import GeekSmartAuthError

        mock_hop2 = {
            "dry_run": False,
            "action": "thing.m.device.dp.publish",
            "payload": {"71": "mocked_dp71"},
            "response": {"status": "ok", "result": True},
        }
        with patch(
            "client.geeksmart_client.GeekSmartClient.unlock_door",
            side_effect=GeekSmartAuthError(3, "Token expired, please login again"),
        ):
            with patch(
                "client.tuya_client.TuyaClient.publish_dp",
                return_value=mock_hop2,
            ) as mock_pub:
                with patch("sys.stdout", new=io.StringIO()) as fake_out:
                    exit_code = main(["--unlock", "101", "--confirm", "--json"])
                    self.assertEqual(exit_code, 0)
                    data = json.loads(fake_out.getvalue())
                    self.assertTrue(data["success"])
                    self.assertEqual(data["command"], "unlock")
                    self.assertIsNotNone(data["hop2Result"])
                    mock_pub.assert_called_once()
                    call_kwargs = mock_pub.call_args.kwargs
                    self.assertEqual(call_kwargs["dev_id"], "ebexamplelock001")
                    self.assertIn("71", call_kwargs["dps"])
                    self.assertFalse(call_kwargs["dry_run"])

    def test_T5_18_live_status_refreshes_from_tuya_hop2_without_hop1_error(self):
        """T5.18: Live --status 101 refreshes state from Tuya Hop 2 without emitting Hop 1 code 3 errors."""
        from client.tuya_client import TuyaDevice

        live_dev = TuyaDevice.from_dict({
            "devId": "ebexamplelock001",
            "name": "livingroom",
            "category": "jtmspro",
            "productId": "rlyxv73w",
            "isOnline": True,
            "dps": {"8": 60, "47": True},
            "dpCodes": {"residual_electricity": 60, "lock_motor_state": True},
        })
        with patch("client.tuya_client.TuyaClient.login", return_value={"uid": "tuya_mock_uid_1099"}):
            with patch("client.tuya_client.TuyaClient.get_home_device_list", return_value=[live_dev]):
                with patch("sys.stdout", new=io.StringIO()) as fake_out:
                    exit_code = main(["--status", "101"])
                    self.assertEqual(exit_code, 0)
                    output = fake_out.getvalue()
                    self.assertNotIn("Auth failed (code 3)", output)
                    self.assertIn("Bridged via Hop 2 Tuya Cloud", output)
                    self.assertIn("UNLOCKED", output)

    def test_T5_19_geeksmart_client_http_transient_retry(self):
        """T5.19: GeekSmartClient.execute_request retries transient ConnectionError in live HTTP mode."""
        import requests
        from client.geeksmart_client import GeekSmartClient

        client = GeekSmartClient(mock_transport=None, allow_network_login=False, auto_relogin=False)
        client.token = "TEST_TOKEN"
        client.client_id = 9999999

        encrypted_resp = GeekSmartClient.encrypt_payload({"equipmentList": []})
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.raise_for_status.return_value = None
        ok_resp.json.return_value = {"code": 0, "msg": "OK", "data": encrypted_resp}

        with patch("time.sleep"):
            with patch.object(
                client.session,
                "get",
                side_effect=[requests.ConnectionError("Transient reset"), ok_resp],
            ) as mock_get:
                code, msg, data = client.execute_request(
                    "/app/home/getClientEquipmentListMap",
                    {"clientId": 9999999},
                )
                self.assertEqual(code, 0)
                self.assertEqual(data, {"equipmentList": []})
                self.assertEqual(mock_get.call_count, 2)

    def test_T5_20_wifi_ble_signal_telemetry_and_weak_signal_warning(self):
        """T5.20: CLI displays Wi-Fi/BLE signal levels, resolves alternate devIds, and warns on weak BLE link."""
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = main(["--list", "--dry-run"])
            self.assertEqual(exit_code, 0)
            out_list = fake_out.getvalue()
            self.assertIn("Wi-Fi -70 dBm", out_list)
            self.assertIn("BLE Connected (Strong)", out_list)
            self.assertIn("BLE Weak Signal (Standby)", out_list)
            self.assertIn("BLE Offline (Out of Range)", out_list)

        for alt_id in ("ebexamplelock002", "ebexamplelock012", "ebexamplelock003", "ebexamplelock013"):
            with patch("sys.stdout", new=io.StringIO()) as fake_out:
                exit_code = main(["--status", alt_id, "--dry-run", "--json"])
                self.assertEqual(exit_code, 0)
                data = json.loads(fake_out.getvalue())
                self.assertEqual(len(data["devices"]), 1)

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = main(["--unlock", "ebexamplelock012", "--dry-run", "--json"])
            self.assertEqual(exit_code, 0)
            ctrl_data = json.loads(fake_out.getvalue())
            self.assertEqual(ctrl_data["battery"], 100)
            self.assertEqual(ctrl_data["gatewayWifiSignal"], "Wi-Fi -70 dBm")
            self.assertIn("BLE Weak Signal", ctrl_data["signal"])
            self.assertIsNotNone(ctrl_data["signalWarning"])
            self.assertTrue(ctrl_data["gatewayWakeQueued"])


if __name__ == "__main__":
    unittest.main()
