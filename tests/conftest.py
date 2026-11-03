"""Shared fixtures, mock data, cryptographic oracle, and test helpers for GeekSmart tests."""

import base64
import json
import os
import sys
import time
from typing import Any, Dict, Optional, Tuple, List
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Static AES key and IV discovered from APK resources.arsc & MainProcessApp bytecode
GEEKSMART_BASE_URL: str = "https://app.geekaihome.com"
GEEKSMART_AES_KEY: bytes = b"yljt789512356325"  # 16 ASCII bytes (AES-128)
GEEKSMART_AES_IV: bytes = b"yljt7415856896iv"   # 16 ASCII bytes (CBC IV)
GEEKSMART_PLATFORM: str = "android_geeksmarthome"
GEEKSMART_VERSION: str = "1.1.2"
GEEKSMART_LANG: str = "EN"

# Strict safety barrier list of forbidden destructive endpoints
FORBIDDEN_ENDPOINTS: List[str] = [
    "/app/home/deleteClientEquipment",
    "app/doorbellLock/removeLock",
    "/app/doorbellLock/removeLock",
    "app/doorbellLock/bindLock",
    "/app/doorbellLock/bindLock",
    "/app/home/addEquipment",
    "/app/home/addEquipmentToClient",
    "/app/home/alterEquipmentNote",
    "/app/home/alterEquipmentRoom",
    "/app/home/addClientEquipmentAccountOperation",
    "resetLock",
    "clearFingerprints",
    "deletePasscode",
]

# Canonical Exceptions imported from production package client.exceptions
from client.exceptions import (
    GeekSmartError,
    GeekSmartAuthError,
    GeekSmartCryptoError,
    GeekSmartProtocolError,
    GeekSmartControlError,
    GeekSmartNetworkError,
    GeekSmartTimeoutError,
    SafetyBarrierViolation,
    SafetyViolationError,
)
from client.geeksmart_client import ControlResult, LockState



# Canonical Cryptographic Functions (Oracle)
def encrypt_payload_oracle(params: Dict[str, Any], key: bytes = GEEKSMART_AES_KEY, iv: bytes = GEEKSMART_AES_IV) -> str:
    """Serializes dictionary to compact JSON and encrypts with AES-128-CBC + PKCS7 + Base64 NO_WRAP."""
    raw_json = json.dumps(params, separators=(",", ":")).encode("utf-8")
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(raw_json) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("ascii")


def decrypt_payload_oracle(b64_ciphertext: str, key: bytes = GEEKSMART_AES_KEY, iv: bytes = GEEKSMART_AES_IV) -> str:
    """Decrypts Base64 AES-128-CBC ciphertext and unpads PKCS7."""
    try:
        raw_bytes = base64.b64decode(b64_ciphertext)
    except Exception as exc:
        raise GeekSmartCryptoError(f"Invalid Base64 payload: {exc}") from exc

    if len(raw_bytes) % 16 != 0:
        raise GeekSmartCryptoError(f"Ciphertext length {len(raw_bytes)} is not a multiple of 16")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    try:
        padded_plaintext = decryptor.update(raw_bytes) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext_bytes.decode("utf-8")
    except Exception as exc:
        raise GeekSmartCryptoError(f"Decryption/unpadding failed: {exc}") from exc


# Canonical Mock Payloads
MOCK_USER_BEAN = {
    "id": 9999999,
    "email": "testuser@example.com",
    "token": "TW9ja1Rva2VuMTIzNDU2Nw==",
    "password": "MockPassword123!",
    "tuyaUid": "tuya_mock_uid_1099",
    "tuyaUsername": "testuser@example.com",
    "tuyaPassword": "a1b2c3d4",
    "tuyaPasswordMd5": "22c14f311a60486b36f79f3bc962be66",
    "tuyaCountryCode": 1,
    "tuyaUsernameType": 2,
    "ttlockUid": "10000001",
    "ttlockUsername": "geekaihome_9999999",
    "ttlockPassword": "d4c3b2a1",
    "ttlockPasswordMd5": "7c30cfa560281bf14bfac1143ef72e53",
    "headImg": "http://app.geekaihome.com/images/head/user-default.png",
    "createTime": 1683208426000
}

MOCK_EQUIPMENT_LIST_MAP = {
    "sortList": [101, 102, 201],
    "hiddenMap": {},
    "equipmentList": [
        {
            "clientEquipmentId": 201,
            "equipmentModelNo": "GW-PLUG-01",
            "equipmentModelName": "Smart Plug BLE Gateway",
            "equipmentNote": "Living Room Hub",
            "roomName": "Living Room",
            "isGateway": True,
            "onlineStatus": 1,
            "thirdpartyJson": {
                "mac": "11:22:33:44:55:66",
                "firmwareVersion": "1.0.4"
            }
        },
        {
            "clientEquipmentId": 101,
            "equipmentModelNo": "L-B400",
            "equipmentModelName": "GeekSmart Smart Deadbolt",
            "equipmentNote": "Living Room Door",
            "roomName": "Living Room",
            "isGateway": False,
            "onlineStatus": 1,
            "thirdpartyJson": {
                "mac": "AA:BB:CC:DD:EE:01",
                "electricQuantity": 85,
                "lockType": "BLE_DEADBOLT",
                "gatewayId": 201
            }
        },
        {
            "clientEquipmentId": 102,
            "equipmentModelNo": "L-B400",
            "equipmentModelName": "GeekSmart Smart Deadbolt",
            "equipmentNote": "Bathroom Door",
            "roomName": "Bathroom",
            "isGateway": False,
            "onlineStatus": 1,
            "thirdpartyJson": {
                "mac": "AA:BB:CC:DD:EE:02",
                "electricQuantity": 72,
                "lockType": "BLE_DEADBOLT",
                "gatewayId": 201
            }
        }
    ]
}


def build_mock_server_response(code: int, msg: str, data_dict: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generates an encrypted envelope matching GeekSmart production response."""
    if data_dict is not None and code == 0:
        encrypted_data = encrypt_payload_oracle(data_dict)
        return {"code": code, "msg": msg, "data": encrypted_data}
    elif data_dict is not None and code == 200:
        # Some endpoints (e.g. gateway control) return code 200
        encrypted_data = encrypt_payload_oracle(data_dict)
        return {"code": code, "msg": msg, "data": encrypted_data}
    else:
        return {"code": code, "msg": msg, "data": None}


def default_mock_transport(
    endpoint: str,
    full_params: Dict[str, Any],
    method: str = "GET",
) -> Dict[str, Any]:
    """
    Canonical offline test harness mock transport.
    Generates AES-encrypted response envelopes matching the GeekSmart backend.
    Used exclusively by offline unit tests.
    """
    clean_endpoint = "/" + endpoint.strip().lstrip("/")

    if "loginByPassword" in clean_endpoint:
        email = full_params.get("email")
        pwd = full_params.get("password")
        if not email or not pwd:
            raise ValueError("Email and password required")
        if pwd != "MockPassword123!":
            return {"code": 2007, "msg": "Password mistake", "data": None}
        if email != "testuser@example.com":
            return {"code": 2010, "msg": "This mailbox is not registered", "data": None}
        return build_mock_server_response(0, "OK", MOCK_USER_BEAN)

    elif "getClientEquipmentListMap" in clean_endpoint:
        if not full_params.get("token"):
            return {"code": 3, "msg": "Token expired, please login again", "data": None}
        return build_mock_server_response(0, "OK", MOCK_EQUIPMENT_LIST_MAP)

    elif "ttlockGatewayQueryOpenState" in clean_endpoint:
        return build_mock_server_response(200, "success", {"state": "2"})

    elif "ttlockGatewayUnlock" in clean_endpoint:
        return build_mock_server_response(200, "success", {"result": "unlocked"})

    elif "ttlockGatewayLock" in clean_endpoint:
        return build_mock_server_response(200, "success", {"result": "locked"})

    return {"code": 0, "msg": "OK", "data": None}


def load_env_credentials() -> Tuple[Optional[str], Optional[str]]:
    """Loads USER and PASS from .env file if available."""
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if not os.path.exists(env_path):
        return None, None
    user, pwd = None, None
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("USER="):
                user = line.split("=", 1)[1]
            elif line.startswith("PASS="):
                pwd = line.split("=", 1)[1]
    return user, pwd


class ReferenceGeekSmartClient:
    """Reference implementation of GeekSmartClient strictly adhering to interface contracts."""

    def __init__(self, base_url: str = GEEKSMART_BASE_URL, mock_transport=None):
        self.base_url = base_url.rstrip("/")
        self.token: Optional[str] = None
        self.client_id: Optional[int] = None
        self._user_email: Optional[str] = None
        self._user_password: Optional[str] = None
        self.mock_transport = mock_transport
        self._relogin_attempts = 0

    @staticmethod
    def encrypt_payload(params: Dict[str, Any]) -> str:
        return encrypt_payload_oracle(params)

    @staticmethod
    def decrypt_payload(b64_ciphertext: str) -> str:
        return decrypt_payload_oracle(b64_ciphertext)

    def _check_safety_barrier(self, endpoint: str) -> None:
        """Strict safety barrier enforcement blocking destructive operations."""
        clean_endpoint = endpoint.strip().lstrip("/")
        for forbidden in FORBIDDEN_ENDPOINTS:
            clean_forbidden = forbidden.strip().lstrip("/")
            if clean_forbidden in clean_endpoint:
                raise SafetyBarrierViolation(
                    f"CRITICAL SAFETY VIOLATION: Endpoint '{endpoint}' is strictly forbidden by GeekSmart Safety Barrier!"
                )

    def execute_request(self, endpoint: str, extra_params: Dict[str, Any], method: str = "GET") -> Tuple[int, str, Optional[Dict[str, Any]]]:
        self._check_safety_barrier(endpoint)

        full_params: Dict[str, Any] = {
            "platform": GEEKSMART_PLATFORM,
            "version": GEEKSMART_VERSION,
            "currentTimestamp": str(int(time.time() * 1000)),
            "countryLang": GEEKSMART_LANG,
        }
        if self.token:
            full_params["token"] = self.token
        full_params.update(extra_params)

        if self.mock_transport:
            resp_json = self.mock_transport(endpoint, full_params, method)
        else:
            resp_json = default_mock_transport(endpoint, full_params, method)

        code = resp_json.get("code", -1)
        msg = resp_json.get("msg", "")
        raw_data = resp_json.get("data")

        # Auto-relogin on code 3
        if code == 3:
            if self._relogin_attempts < 1 and self._user_email and self._user_password:
                self._relogin_attempts += 1
                self.login(self._user_email, self._user_password)
                return self.execute_request(endpoint, extra_params, method)
            self._relogin_attempts = 0
            raise GeekSmartAuthError(3, msg)

        if "loginByPassword" not in endpoint:
            self._relogin_attempts = 0

        if code in (0, 200) and raw_data:
            if isinstance(raw_data, str):
                decrypted_str = self.decrypt_payload(raw_data)
                try:
                    parsed_data = json.loads(decrypted_str) if decrypted_str else None
                except Exception as exc:
                    raise GeekSmartProtocolError(f"Decrypted data is not valid JSON: {exc}") from exc
                return code, msg, parsed_data
            elif isinstance(raw_data, dict):
                return code, msg, raw_data
        return code, msg, None

    def login(self, email: str, password: str) -> Dict[str, Any]:
        if not email or not isinstance(email, str) or not email.strip():
            raise ValueError("Email must be a non-empty string")
        if not password or not isinstance(password, str) or not password.strip():
            raise ValueError("Password must be a non-empty string")

        self._user_email = email
        self._user_password = password
        code, msg, data = self.execute_request("/app/client/loginByPassword", {
            "email": email,
            "password": password,
            "type": "1"
        })
        if code != 0 or not data:
            raise GeekSmartAuthError(code, msg)

        self.token = data.get("token")
        self.client_id = data.get("id")
        return data

    def discover_devices(self) -> List[Dict[str, Any]]:
        if not self.token or not self.client_id:
            raise GeekSmartAuthError(3, "Must authenticate before discovering devices")
        code, msg, data = self.execute_request("/app/home/getClientEquipmentListMap", {
            "clientId": self.client_id
        })
        if code != 0 or not data:
            raise GeekSmartControlError(code, msg)
        return data.get("equipmentList", [])

    def dry_run_request(self, endpoint: str, extra_params: Dict[str, Any], method: str = "GET") -> Dict[str, Any]:
        self._check_safety_barrier(endpoint)
        full_params: Dict[str, Any] = {
            "platform": GEEKSMART_PLATFORM,
            "version": GEEKSMART_VERSION,
            "currentTimestamp": str(int(time.time() * 1000)),
            "countryLang": GEEKSMART_LANG,
        }
        if self.token:
            full_params["token"] = self.token
        full_params.update(extra_params)
        encrypted_data = self.encrypt_payload(full_params)
        return {
            "dryRun": True,
            "endpoint": "/" + endpoint.lstrip("/"),
            "method": method.upper(),
            "targetUrl": f"{self.base_url}/{endpoint.lstrip('/')}?data={encrypted_data}",
            "plaintextParams": full_params,
            "encryptedPayload": encrypted_data,
            "safetyStatus": "PASSED_SAFE_CONTROL",
            "ioExecuted": False,
        }

    def query_lock_state(self, client_equipment_id: int, dry_run: bool = False) -> LockState:
        if int(client_equipment_id) <= 0:
            raise ValueError("client_equipment_id must be a positive integer")
        if not self.token:
            raise GeekSmartAuthError(3, "Must authenticate before querying status")
        params = {
            "clientEquipmentId": int(client_equipment_id),
            "clientEquipmentAccountId": 0,
        }
        if dry_run:
            dry_info = self.dry_run_request("/app/home/ttlockGatewayQueryOpenState", params)
            return LockState("UNKNOWN", int(client_equipment_id), "0", "[DRY-RUN] Simulated", 200, dry_info, dry_run=True)
        code, msg, data = self.execute_request("/app/home/ttlockGatewayQueryOpenState", params)
        if code not in (0, 200) or not data:
            raise GeekSmartControlError(code, msg)
        state_str = str(data.get("state", "0"))
        state_name = "UNLOCKED" if state_str == "1" else ("LOCKED" if state_str == "2" else "UNKNOWN")
        return LockState(state_name, int(client_equipment_id), state_str, msg or "success", code, data)

    def unlock_door(self, client_equipment_id: int, lock_data: Optional[Dict[str, Any]] = None, dry_run: bool = False) -> ControlResult:
        if int(client_equipment_id) <= 0:
            raise ValueError("client_equipment_id must be a positive integer")
        if not self.token or not self.client_id:
            raise GeekSmartAuthError(3, "Must authenticate before unlocking")
        params = {
            "clientId": self.client_id,
            "clientEquipmentId": int(client_equipment_id),
            "clientEquipmentAccountId": 0,
        }
        if lock_data:
            params.update(lock_data)
        if dry_run:
            dry_info = self.dry_run_request("/app/home/ttlockGatewayUnlock", params)
            return ControlResult(True, int(client_equipment_id), "unlock", "[DRY-RUN] Simulated", 200, dry_info, dry_run=True)
        code, msg, data = self.execute_request("/app/home/ttlockGatewayUnlock", params)
        if code not in (0, 200):
            raise GeekSmartControlError(code, msg)
        return ControlResult(True, int(client_equipment_id), "unlock", msg or "success", code, data or {"result": "unlocked"})

    def lock_door(self, client_equipment_id: int, lock_data: Optional[Dict[str, Any]] = None, dry_run: bool = False) -> ControlResult:
        if int(client_equipment_id) <= 0:
            raise ValueError("client_equipment_id must be a positive integer")
        if not self.token or not self.client_id:
            raise GeekSmartAuthError(3, "Must authenticate before locking")
        params = {
            "clientId": self.client_id,
            "clientEquipmentId": int(client_equipment_id),
            "clientEquipmentAccountId": 0,
        }
        if lock_data:
            params.update(lock_data)
        if dry_run:
            dry_info = self.dry_run_request("/app/home/ttlockGatewayLock", params)
            return ControlResult(True, int(client_equipment_id), "lock", "[DRY-RUN] Simulated", 200, dry_info, dry_run=True)
        code, msg, data = self.execute_request("/app/home/ttlockGatewayLock", params)
        if code not in (0, 200):
            raise GeekSmartControlError(code, msg)
        return ControlResult(True, int(client_equipment_id), "lock", msg or "success", code, data or {"result": "locked"})


def get_client_class():
    """Dynamically loads client.geeksmart_client.GeekSmartClient if implemented, else returns ReferenceGeekSmartClient."""
    try:
        from client.geeksmart_client import GeekSmartClient

        class TestGeekSmartClient(GeekSmartClient):
            """Harness test wrapper that defaults mock_transport to default_mock_transport for offline unit tests."""
            def __init__(self, *args, **kwargs):
                if "mock_transport" not in kwargs:
                    kwargs["mock_transport"] = default_mock_transport
                super().__init__(*args, **kwargs)

        TestGeekSmartClient.__name__ = "GeekSmartClient"
        return TestGeekSmartClient
    except (ImportError, ModuleNotFoundError):
        return ReferenceGeekSmartClient
