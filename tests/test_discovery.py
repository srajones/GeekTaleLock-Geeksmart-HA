"""Tier 1 and Tier 2 tests for Account and Device Discovery."""

import unittest
from tests.conftest import (
    MOCK_EQUIPMENT_LIST_MAP,
    MOCK_USER_BEAN,
    GeekSmartAuthError,
    GeekSmartControlError,
    GeekSmartProtocolError,
    get_client_class,
)


class TestDeviceDiscovery(unittest.TestCase):
    """Test suite covering GeekSmart account inspection, device discovery, and metadata parsing."""

    def setUp(self):
        self.client_cls = get_client_class()
        self.client = self.client_cls()
        # Pre-authenticate
        self.client.login("testuser@example.com", "MockPassword123!")

    # --- Tier 1: Feature Coverage (Device Discovery) ---

    def test_T1_16_discovery_parses_equipment_list(self):
        """T1.16: Calling discover_devices fetches getClientEquipmentListMap and returns equipment list."""
        devices = self.client.discover_devices()
        self.assertIsInstance(devices, list)
        self.assertEqual(len(devices), 3)

    def test_T1_17_discovery_extracts_device_attributes(self):
        """T1.17: Discovered devices contain ID, model number, model name, note, and room."""
        devices = self.client.discover_devices()
        deadbolt = next(d for d in devices if d["clientEquipmentId"] == 101)
        self.assertEqual(deadbolt["equipmentModelNo"], "L-B400")
        self.assertEqual(deadbolt["equipmentModelName"], "GeekSmart Smart Deadbolt")
        self.assertEqual(deadbolt["equipmentNote"], "Living Room Door")
        self.assertEqual(deadbolt["roomName"], "Living Room")

    def test_T1_18_discovery_extracts_battery_percentage(self):
        """T1.18: Device battery percentage is extracted from thirdpartyJson.electricQuantity."""
        devices = self.client.discover_devices()
        living_room = next(d for d in devices if d["clientEquipmentId"] == 101)
        bathroom = next(d for d in devices if d["clientEquipmentId"] == 102)

        self.assertEqual(living_room["thirdpartyJson"]["electricQuantity"], 85)
        self.assertEqual(bathroom["thirdpartyJson"]["electricQuantity"], 72)

    def test_T1_19_discovery_identifies_smart_plug_gateway(self):
        """T1.19: Device discovery identifies the smart plug BLE gateway bridge equipment."""
        devices = self.client.discover_devices()
        gateway = next((d for d in devices if d.get("isGateway") or "Gateway" in d.get("equipmentModelName", "")), None)
        self.assertIsNotNone(gateway, "Smart plug BLE gateway bridge must be identified")
        self.assertEqual(gateway["clientEquipmentId"], 201)
        self.assertEqual(gateway["equipmentModelNo"], "GW-PLUG-01")

    def test_T1_20_discovery_classifies_all_home_devices(self):
        """T1.20: Verify complete multi-device setup (2 deadbolts + 1 smart plug gateway)."""
        devices = self.client.discover_devices()
        deadbolts = [d for d in devices if d["equipmentModelNo"] == "L-B400"]
        gateways = [d for d in devices if d["equipmentModelNo"] == "GW-PLUG-01"]

        self.assertEqual(len(deadbolts), 2, "Should discover 2 deadbolts")
        self.assertEqual(len(gateways), 1, "Should discover 1 smart plug gateway bridge")

    # --- Tier 2: Boundary & Corner Cases (Device Discovery) ---

    def test_T2_12_boundary_empty_equipment_list_handling(self):
        """T2.12: Account with 0 registered devices returns empty list [] without error."""
        def empty_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            return {"code": 0, "msg": "OK", "data": {"equipmentList": []}}

        client = self.client_cls(mock_transport=empty_transport)
        client.login("testuser@example.com", "MockPassword123!")
        devices = client.discover_devices()
        self.assertEqual(devices, [])

    def test_T2_13_boundary_missing_battery_info_in_thirdparty_json(self):
        """T2.13: Device record lacking thirdpartyJson or electricQuantity is parsed gracefully."""
        device_no_battery = {
            "equipmentList": [
                {
                    "clientEquipmentId": 301,
                    "equipmentModelNo": "L-B400",
                    "equipmentModelName": "GeekSmart Smart Deadbolt",
                    "thirdpartyJson": {}  # Missing electricQuantity
                }
            ]
        }

        def no_battery_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            return {"code": 0, "msg": "OK", "data": device_no_battery}

        client = self.client_cls(mock_transport=no_battery_transport)
        client.login("testuser@example.com", "MockPassword123!")
        devices = client.discover_devices()
        self.assertEqual(len(devices), 1)
        self.assertNotIn("electricQuantity", devices[0]["thirdpartyJson"])

    def test_T2_05_boundary_non_json_decrypted_payload(self):
        """T2.05: Malformed decrypted plaintext that is not valid JSON raises GeekSmartProtocolError."""
        def malformed_json_transport(endpoint, full_params, method):
            if "loginByPassword" in endpoint:
                return {"code": 0, "msg": "OK", "data": MOCK_USER_BEAN}
            # Return encrypted text that is NOT json
            ct = self.client_cls.encrypt_payload({"dummy": 1})
            # Intentionally replace with encrypted non-JSON string
            from cryptography.hazmat.primitives import padding
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            import base64
            from tests.conftest import GEEKSMART_AES_KEY, GEEKSMART_AES_IV
            raw = b"THIS IS NOT VALID JSON AT ALL"
            padder = padding.PKCS7(128).padder()
            padded = padder.update(raw) + padder.finalize()
            cipher = Cipher(algorithms.AES(GEEKSMART_AES_KEY), modes.CBC(GEEKSMART_AES_IV))
            encrypted = base64.b64encode(cipher.encryptor().update(padded) + cipher.encryptor().finalize()).decode("ascii")
            return {"code": 0, "msg": "OK", "data": encrypted}

        client = self.client_cls(mock_transport=malformed_json_transport)
        client.login("testuser@example.com", "MockPassword123!")
        with self.assertRaises(GeekSmartProtocolError):
            client.discover_devices()


if __name__ == "__main__":
    unittest.main()
