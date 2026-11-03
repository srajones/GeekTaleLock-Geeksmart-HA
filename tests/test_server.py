"""Unit and Route Tests for the Local Flask Mobile Dashboard Server (Milestone 4).

Tests:
1. GET / renders dark-mode mobile dashboard with Hop 1 GeekSmart UserBean,
   Hop 2 Tuya (tuya_mock_uid_1099) & TTLock (10000001) accounts, 5-layer
   Safety Barrier status, and device cards.
2. GET /api/status (and /api/info) returns session cache health, multi-hop
   account details, and 5-layer safety barrier metadata.
3. GET /api/devices returns combined device inventory from TuyaClient,
   GeekSmartClient, and cached topology fallback.
4. GET /api/devices/<dev_id> returns detailed device inspection including
   live Data Points (dps/dpCodes), DP schema, gateway topology, and safe actions.
5. POST /api/devices/<dev_id>/action with dry_run=True validates safety barriers
   and returns encrypted/signed payloads for lock and unlock without network I/O.
6. POST /api/devices/<dev_id>/action hard-blocks destructive actions (403).
7. Both server.flask_app and server.app module aliases are importable and
   default to 0.0.0.0:5050.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from client.geeksmart_client import GeekSmartClient
from client.safety import ClientMode
from client.session_manager import SessionManager
from client.tuya_client import TuyaClient
from server.app import app as alias_app
from server.flask_app import DEFAULT_HOST, DEFAULT_PORT, create_app, detect_lan_ip


class TestFlaskMobileDashboard(unittest.TestCase):
    """Route and safety verification suite for the Flask mobile dashboard."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cache_path = os.path.join(self.temp_dir.name, ".session_cache.json")
        self.session_mgr = SessionManager(self.cache_path)
        self.session_mgr.save({
            "id": 9999999,
            "email": "testuser@example.com",
            "token": "sI63dWOkMdh5xylabxUCVw==",
            "tuyaUsername": "testuser@example.com",
            "tuyaPassword": "a1b2c3d4",
            "tuyaUid": "tuya_mock_uid_1099",
            "tuyaCountryCode": 1,
            "ttlockUid": "10000001",
            "ttlockUsername": "geekaihome_9999999",
        })

        self.app = create_app(session_cache_path=self.cache_path, redact_status=False)
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_T1_01_server_defaults_and_module_aliases(self):
        """T1.01: Verifies default binding 0.0.0.0:5050 and server.app alias."""
        self.assertEqual(DEFAULT_HOST, "0.0.0.0")
        self.assertEqual(DEFAULT_PORT, 5050)
        self.assertIsNotNone(alias_app)
        lan_ip = detect_lan_ip()
        self.assertTrue(isinstance(lan_ip, str) and len(lan_ip) >= 7)

    def test_T1_02_get_index_dashboard_renders_all_sections(self):
        """T1.02: GET / renders mobile dashboard with Hop 1 & Hop 2 accounts, 5-layer Safety Barrier, and devices."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        # Hop 1 GeekSmart UserBean & Hop 2 Tuya / TTLock accounts
        self.assertIn("testuser@example.com", html)
        self.assertIn("9999999", html)
        self.assertIn("tuya_mock_uid_1099", html)
        self.assertIn("10000001", html)
        self.assertIn("geekaihome_9999999", html)

        # 5-Layer Safety Barrier confirmation
        self.assertIn("5-Layer Safety Barrier", html)
        self.assertIn("Device Deletion Blocked", html)
        self.assertIn("Unbinding Blocked", html)
        self.assertIn("Factory Reset Blocked", html)
        self.assertIn("Fingerprint Changes Blocked", html)

        # Hardware inventory & controls
        self.assertIn("Smart Plug BLE Gateway", html)
        self.assertIn("Living Room Door", html)
        self.assertIn("Bathroom Door", html)
        self.assertIn("Dry-Run", html)

    def test_T1_03_get_api_status_returns_session_and_safety_summary(self):
        """T1.03: GET /api/status returns complete session health, multi-hop accounts, and 5-layer safety status."""
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["clientId"], 9999999)
        self.assertEqual(data["email"], "testuser@example.com")
        self.assertEqual(data["tuyaUid"], "tuya_mock_uid_1099")
        self.assertEqual(data["ttlockUid"], "10000001")
        self.assertTrue(data["session"]["cacheExists"])
        self.assertTrue(data["session"]["networkLoginSuppressed"])
        self.assertEqual(len(data["safetyBarrier"]["layers"]), 5)
        self.assertEqual(data["safetyBarrier"]["mode"], "SAFE_CONTROL")

    def test_T1_04_get_api_devices_returns_inventory_and_dps(self):
        """T1.04: GET /api/devices returns Smart Plug BLE Gateway and Bluetooth Door Locks with DPs and topology."""
        resp = self.client.get("/api/devices")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        self.assertTrue(data["success"])
        self.assertGreaterEqual(data["count"], 3)
        devices = data["devices"]

        gw = next((d for d in devices if d["isGateway"]), None)
        self.assertIsNotNone(gw)
        self.assertEqual(gw["category"], "cz")
        self.assertIn("1", gw["dps"])

        locks = [d for d in devices if d["isLock"]]
        self.assertGreaterEqual(len(locks), 2)
        for lk in locks:
            self.assertEqual(lk["category"], "ms")
            self.assertEqual(lk["parentId"], "gw-201")
            self.assertIsNotNone(lk["battery"])
            self.assertIn("1", lk["dps"])
            self.assertIn("unlock", lk["availableActions"])
            self.assertIn("lock", lk["availableActions"])

    def test_T1_05_get_api_devices_combines_live_tuya_mock_inventory(self):
        """T1.05: GET /api/devices integrates TuyaClient devices when Tuya session is active."""
        self.session_mgr.update_tuya_session(
            sid="ACTIVE_TUYA_SID_123",
            expires_in=86400,
            uid="tuya_mock_uid_1099",
            home_id=998877,
        )

        def mock_tuya_transport(action, version, params, post_str):
            if action == "m.life.my.group.device.list":
                return {
                    "success": True,
                    "result": {
                        "devices": [
                            {
                                "devId": "tuya_gw_plug",
                                "name": "Tuya Smart Plug Gateway",
                                "productId": "pid_plug",
                                "isOnline": True,
                                "category": "cz",
                                "dps": {"1": True, "9": 0},
                                "dpCodes": {"switch_1": True},
                            },
                            {
                                "devId": "tuya_lock_01",
                                "name": "Tuya Front Deadbolt",
                                "productId": "pid_lock",
                                "isOnline": True,
                                "category": "ms",
                                "parentId": "tuya_gw_plug",
                                "dps": {"1": True, "8": 91},
                                "dpCodes": {"door_state": True, "residual_electricity": 91},
                            },
                        ]
                    },
                }
            return {"success": True, "result": []}

        tc = TuyaClient(session_cache_path=self.cache_path, mock_transport=mock_tuya_transport)
        app = create_app(session_cache_path=self.cache_path, tuya_client=tc)
        client = app.test_client()

        resp = client.get("/api/devices")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        dev_ids = [d["devId"] for d in data["devices"]]
        self.assertIn("tuya_gw_plug", dev_ids)
        self.assertIn("tuya_lock_01", dev_ids)

    def test_T1_06_get_single_device_detail_and_404_handling(self):
        """T1.06: GET /api/devices/<dev_id> returns DP schema, capabilities, and gateway topology; unknown returns 404."""
        resp = self.client.get("/api/devices/lock-101")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        self.assertTrue(data["success"])
        self.assertEqual(data["devId"], "lock-101")
        self.assertEqual(data["clientEquipmentId"], 101)
        self.assertEqual(data["parentId"], "gw-201")
        self.assertIn("1", data["dps"])
        self.assertTrue(isinstance(data["dpSchema"], list) and len(data["dpSchema"]) >= 3)
        self.assertIn("supportedEndpoints", data["capabilities"])

        # Numeric ID lookup also resolves
        resp_num = self.client.get("/api/devices/101")
        self.assertEqual(resp_num.status_code, 200)

        # Non-existent device returns 404
        resp_404 = self.client.get("/api/devices/nonexistent-device-999")
        self.assertEqual(resp_404.status_code, 404)

    def test_T1_07_post_device_action_dry_run_unlock_and_lock(self):
        """T1.07: POST /api/devices/<id>/action with dry_run=True simulates unlock and lock with zero network I/O."""
        # Dry-run unlock
        resp_unlock = self.client.post(
            "/api/devices/lock-101/action",
            json={"action": "unlock", "dry_run": True},
        )
        self.assertEqual(resp_unlock.status_code, 200)
        unlock_data = resp_unlock.get_json()

        self.assertTrue(unlock_data["success"])
        self.assertEqual(unlock_data["action"], "unlock")
        self.assertTrue(unlock_data["dry_run"])
        self.assertTrue(unlock_data["dryRun"])
        self.assertEqual(unlock_data["safetyStatus"], "PASSED_SAFE_CONTROL")
        self.assertTrue(unlock_data["geeksmartResult"]["dryRun"])
        self.assertIn("encryptedPayload", unlock_data["geeksmartResult"]["data"])
        self.assertTrue(unlock_data["tuyaResult"]["dry_run"])

        # Dry-run lock
        resp_lock = self.client.post(
            "/api/devices/102/action",
            json={"action": "lock", "dry_run": True},
        )
        self.assertEqual(resp_lock.status_code, 200)
        lock_data = resp_lock.get_json()

        self.assertTrue(lock_data["success"])
        self.assertEqual(lock_data["action"], "lock")
        self.assertTrue(lock_data["dry_run"])
        self.assertTrue(lock_data["geeksmartResult"]["dryRun"])
        self.assertTrue(lock_data["tuyaResult"]["dry_run"])

    def test_T1_08_post_device_action_blocks_destructive_requests(self):
        """T1.08: POST /api/devices/<id>/action hard-blocks destructive actions with HTTP 403."""
        for forbidden_action in ("delete", "reset", "unbind", "clear_fingerprints", "factory_reset"):
            resp = self.client.post(
                "/api/devices/lock-101/action",
                json={"action": forbidden_action, "dry_run": True},
            )
            self.assertEqual(resp.status_code, 403)
            data = resp.get_json()
            self.assertFalse(data["success"])
            self.assertTrue(data.get("safetyViolation"))

    def test_T1_09_deterministic_ids_legacy_aliases_and_signal_telemetry(self):
        """T1.09: Verifies deterministic equip_id (201, 101, 102, 103), legacy aliases, Wi-Fi RSSI (-70 dBm), and BLE signal diagnostics."""
        self.session_mgr.update_tuya_session(
            sid="ACTIVE_TUYA_SID_123",
            expires_in=86400,
            uid="tuya_mock_uid_1099",
            home_id=999999999,
            devices=[
                {
                    "devId": "ebexamplelock003",
                    "name": "K11",
                    "productId": "czybdhba",
                    "isOnline": False,
                    "category": "jtmspro",
                    "parentId": "ebexamplegw1a2b3c4d5e6",
                    "dps": {"8": 66, "47": True, "73": "AAP//zg3NjU0MzIxAQABAA=="},
                    "battery": 66,
                },
                {
                    "devId": "ebexamplegw1a2b3c4d5e6",
                    "name": "Dyson",
                    "productId": "qvk3ovko8ht800a4",
                    "isOnline": True,
                    "category": "cz",
                    "dps": {"1": True, "9": 0},
                },
                {
                    "devId": "ebexamplelock002",
                    "name": "bathroom",
                    "productId": "a0wnqgxs",
                    "isOnline": False,
                    "category": "jtmspro",
                    "parentId": "ebexamplegw1a2b3c4d5e6",
                    "dps": {"8": 100, "33": True, "36": 8, "47": False, "73": "AAL//zEyMzQ1Njc4AQABAA=="},
                    "battery": 100,
                },
                {
                    "devId": "ebexamplelock001",
                    "name": "livingroom",
                    "productId": "a0wnqgxs",
                    "isOnline": True,
                    "category": "jtmspro",
                    "parentId": "ebexamplegw1a2b3c4d5e6",
                    "dps": {"8": 100, "47": True, "73": "AAH//zEyMzQ1Njc4AQABAA=="},
                    "battery": 100,
                },
            ],
        )

        app = create_app(session_cache_path=self.cache_path)
        client = app.test_client()

        resp = client.get("/api/devices")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("no-store", resp.headers.get("Cache-Control", ""))
        self.assertEqual(resp.headers.get("Pragma"), "no-cache")

        devs = resp.get_json()["devices"]
        self.assertEqual([d["clientEquipmentId"] for d in devs], [201, 101, 102, 103])
        self.assertEqual(devs[0]["hardwareModel"], "SK517-WBG(NEW)")
        self.assertEqual(devs[0]["wifiRssi"], -70)
        self.assertEqual(devs[1]["hardwareModel"], "K01 2")
        self.assertEqual(devs[1]["bleConnectionStatus"], 2)
        self.assertIn("Strong BLE Link", devs[1]["bleSignalLabel"])
        self.assertEqual(devs[2]["hardwareModel"], "K01")
        self.assertEqual(devs[2]["bleConnectionStatus"], 0)
        self.assertIn("Weak BLE Signal", devs[2]["bleSignalLabel"])
        self.assertIn("ENABLED (8s)", devs[2]["signalDiagnostic"])
        self.assertEqual(devs[3]["hardwareModel"], "K11")
        self.assertEqual(devs[3]["battery"], 66)

        # Verify all legacy and alternative aliases resolve accurately
        for alias, expected_equip_id in (
            ("101", 101),
            ("lock-101", 101),
            ("livingroom", 101),
            ("ebexamplelock001", 101),
            ("102", 102),
            ("lock-102", 102),
            ("bathroom", 102),
            ("ebexamplelock002", 102),
            ("ebexamplelock012", 102),
            ("103", 103),
            ("lock-103", 103),
            ("k11", 103),
            ("ebexamplelock003", 103),
            ("ebexamplelock013", 103),
            ("201", 201),
            ("701", 201),
            ("gw-201", 201),
            ("dyson", 201),
        ):
            r = client.get(f"/api/devices/{alias}")
            self.assertEqual(r.status_code, 200, f"Alias '{alias}' must resolve to 200")
            self.assertEqual(r.get_json()["clientEquipmentId"], expected_equip_id)

    def test_T1_10_hop1_code3_error_auto_heals_via_hop2_tuya(self):
        """T1.10: Verifies Hop-1 code 3 expired token error is auto-healed via Hop-2 Tuya DP publish."""
        def failing_geeksmart_transport(method, endpoint, params, headers):
            return {"code": "3", "message": "Token expired, please login again"}

        def succeeding_tuya_transport(action, version, params, post_str):
            return {"success": True, "result": True}

        gsc = GeekSmartClient(
            mode=ClientMode.SAFE_CONTROL,
            session_cache_path=self.cache_path,
            mock_transport=failing_geeksmart_transport,
            allow_network_login=False,
        )
        gsc.token = "EXPIRED_HOP1_TOKEN"

        tc = TuyaClient(
            session_cache_path=self.cache_path,
            mock_transport=succeeding_tuya_transport,
        )
        tc.sid = "ACTIVE_TUYA_SID_123"

        app = create_app(
            session_cache_path=self.cache_path,
            tuya_client=tc,
            geeksmart_client=gsc,
        )
        client = app.test_client()

        resp = client.post(
            "/api/devices/101/action",
            json={"action": "unlock", "dry_run": True},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["geeksmartResult"].get("autoHealed"))
        self.assertEqual(data["geeksmartResult"].get("hop"), 2)

    def test_T1_11_keep_unlocked_and_auto_lock_toggle(self):
        """T1.11: Verifies Keep Unlocked (Passage Mode / DP 33=False) and Auto-Lock ON (DP 33=True) endpoints."""
        published_calls = []

        def mock_tuya_transport(action, version, params, post_str):
            published_calls.append((action, version, post_str))
            return {"success": True, "result": True}

        tc = TuyaClient(
            session_cache_path=self.cache_path,
            mock_transport=mock_tuya_transport,
        )
        tc.sid = "ACTIVE_TUYA_SID_123"

        app = create_app(
            session_cache_path=self.cache_path,
            tuya_client=tc,
            csrf_enabled=False,
        )
        client = app.test_client()

        # 1. Keep Unlocked (Auto-Lock OFF, DP 33 = False)
        resp = client.post(
            "/api/devices/101/keep_unlocked",
            json={"confirmed": True},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["newState"], "UNLOCKED")
        self.assertFalse(data["autoLockEnabled"])
        self.assertIn("OFF", data["autoLockLabel"])

        # 2. Re-enable Auto-Lock (DP 33 = True)
        resp2 = client.post(
            "/api/devices/101/auto_lock",
            json={"enabled": True, "confirmed": True},
        )
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.get_json()
        self.assertTrue(data2["success"])
        self.assertTrue(data2["autoLockEnabled"])
        self.assertIn("ON", data2["autoLockLabel"])


if __name__ == "__main__":
    unittest.main()
