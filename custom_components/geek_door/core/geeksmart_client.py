"""
GeekSmart Cloud Protocol Client SDK.

Provides standalone native Python communication with the GeekSmart IoT cloud
(https://app.geekaihome.com) via verified AES-128-CBC encryption, envelope serialization,
automatic token lifecycle management, and read-only device discovery with strict safety barriers.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sys
import threading
import time
import urllib.parse
import warnings
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .exceptions import (
    GeekSmartError,
    GeekSmartAuthError,
    GeekSmartCryptoError,
    GeekSmartProtocolError,
    GeekSmartControlError,
    GeekSmartNetworkError,
    GeekSmartTimeoutError,
    SafetyBarrierViolation,
)
from .safety import ClientMode, SafetyBarrierGuard
from .session_manager import SessionManager

logger = logging.getLogger("geeksmart_client")

# ============================================================================
# Protocol Constants
# ============================================================================
DEFAULT_BASE_URL: str = "https://app.geekaihome.com"
DEFAULT_AES_KEY: bytes = b"yljt789512356325"  # 16-byte ASCII key (AES-128)
DEFAULT_AES_IV: bytes = b"yljt7415856896iv"   # 16-byte ASCII IV (CBC mode)
DEFAULT_PLATFORM: str = "android_geeksmarthome"
DEFAULT_VERSION: str = "1.1.2"
DEFAULT_LANG: str = "EN"
DEFAULT_USER_AGENT: str = "okhttp/4.9.1"
DEFAULT_TIMEOUT: float = 15.0


# ============================================================================
# Data Models (DTOs)
# ============================================================================
class UserInfo(dict):
    """
    GeekSmart user account and multi-ecosystem bridge credentials.
    Subclasses dict so it satisfies isinstance(user, dict) while providing typed attributes.
    """
    def __init__(self, data: Dict[str, Any]):
        super().__init__(data)
        self.client_id = int(data.get("id") or data.get("clientId") or 0)
        self.email = str(data.get("email") or "")
        self.token = str(data.get("token") or "")
        self.tuya_uid = data.get("tuyaUid")
        self.tuya_username = data.get("tuyaUsername")
        self.tuya_password = data.get("tuyaPassword")
        self.tuya_country_code = data.get("tuyaCountryCode")
        self.ttlock_uid = data.get("ttlockUid")
        self.ttlock_username = data.get("ttlockUsername")
        self.ttlock_password = data.get("ttlockPassword")
        self.raw = data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> UserInfo:
        return cls(data)


@dataclass
class DeviceRecord:
    """Individual hardware device or door lock registered under client account."""
    client_equipment_id: int
    equipment_did: str
    equipment_model_no: Union[int, str]
    equipment_model_name: str
    equipment_note: str
    equipment_type_no: int
    equipment_type_name: str
    room_id: int
    thirdparty_data: Dict[str, Any] = field(default_factory=dict)
    battery: Optional[int] = None
    mac: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DeviceRecord:
        thirdparty_raw = data.get("thirdpartyJson")
        thirdparty: Dict[str, Any] = {}
        if isinstance(thirdparty_raw, str) and thirdparty_raw.strip():
            try:
                thirdparty = json.loads(thirdparty_raw)
            except Exception:
                thirdparty = {"raw_string": thirdparty_raw}
        elif isinstance(thirdparty_raw, dict):
            thirdparty = thirdparty_raw

        battery: Optional[int] = None
        if "electricQuantity" in thirdparty:
            try:
                battery = int(thirdparty["electricQuantity"])
            except (ValueError, TypeError):
                pass

        mac = thirdparty.get("mac") or thirdparty.get("lockMac") or data.get("mac") or data.get("equipmentMac")

        return cls(
            client_equipment_id=int(data.get("clientEquipmentId") or 0),
            equipment_did=str(data.get("equipmentDid") or ""),
            equipment_model_no=data.get("equipmentModelNo", 0),
            equipment_model_name=str(data.get("equipmentModelName") or ""),
            equipment_note=str(data.get("equipmentNote") or ""),
            equipment_type_no=int(data.get("equipmentTypeNo") or 0),
            equipment_type_name=str(data.get("equipmentTypeName") or ""),
            room_id=int(data.get("roomId") or 0),
            thirdparty_data=thirdparty,
            battery=battery,
            mac=mac,
            raw=data,
        )


@dataclass
class EquipmentGroup:
    """Group of equipment categorized by device type."""
    equipment_type_no: int
    equipment_type_name: str
    equipment_type_icon_url: Optional[str]
    devices: List[DeviceRecord] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EquipmentGroup:
        devices = [
            DeviceRecord.from_dict(d)
            for d in data.get("equipmentList", [])
            if isinstance(d, dict)
        ]
        return cls(
            equipment_type_no=int(data.get("equipmentTypeNo") or 0),
            equipment_type_name=str(data.get("equipmentTypeName") or ""),
            equipment_type_icon_url=data.get("equipmentTypeIconUrl"),
            devices=devices,
        )


class EquipmentListMapResult(dict):
    """Parsed result structure for getClientEquipmentListMap."""
    def __init__(self, data: Dict[str, Any]):
        super().__init__(data)
        self.sort_list = data.get("sortList")
        self.hidden_map = data.get("hiddenMap") if isinstance(data.get("hiddenMap"), dict) else None
        self.raw = data
        self.equipment_groups: List[EquipmentGroup] = [
            EquipmentGroup.from_dict(g)
            for g in data.get("equipmentList", [])
            if isinstance(g, dict) and "equipmentList" in g
        ]

    @property
    def all_devices(self) -> List[DeviceRecord]:
        devices: List[DeviceRecord] = []
        for grp in self.equipment_groups:
            devices.extend(grp.devices)
        return devices

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EquipmentListMapResult:
        return cls(data)


@dataclass
class DoorbellLockRecord:
    """Doorbell / camera lock record from app/doorbellLock/getLockList."""
    client_id: Optional[int]
    lock_id: Optional[str]
    lock_type: Optional[str]
    tuya_did: Optional[str]
    tuya_pid: Optional[str]
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DoorbellLockRecord:
        cid = data.get("clientId")
        return cls(
            client_id=int(cid) if cid is not None else None,
            lock_id=data.get("lockId"),
            lock_type=data.get("lockType"),
            tuya_did=data.get("tuyaDid"),
            tuya_pid=data.get("tuyaPid"),
            raw=data,
        )


# ============================================================================
# Control & State Result Data Models (Subclassing dict for Dual Compatibility)
# ============================================================================
class ControlResult(dict):
    """
    Result of a lock or unlock control operation against the GeekSmart cloud.

    Subclasses dict to provide full dictionary indexing and JSON serialization
    while evaluating to True in boolean contexts (and matching True/False in equality)
    to preserve 100% backward compatibility with existing tests.
    """
    def __init__(
        self,
        success: bool,
        client_equipment_id: int,
        action: str,  # "unlock" or "lock"
        message: str = "success",
        code: int = 200,
        raw_data: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
    ) -> None:
        payload: Dict[str, Any] = {
            "success": success,
            "clientEquipmentId": client_equipment_id,
            "action": action,
            "message": message,
            "code": code,
            "dryRun": dry_run,
        }
        if raw_data:
            payload["data"] = raw_data
            for k, v in raw_data.items():
                if k not in payload:
                    payload[k] = v
        super().__init__(payload)
        self.success = success
        self.client_equipment_id = client_equipment_id
        self.action = action
        self.message = message
        self.code = code
        self.raw_data = raw_data or {}
        self.dry_run = dry_run

    def __bool__(self) -> bool:
        return self.success

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, bool):
            return self.success == other
        return super().__eq__(other)

    def __ne__(self, other: Any) -> bool:
        eq = self.__eq__(other)
        if eq is NotImplemented:
            return NotImplemented
        return not eq

    def __str__(self) -> str:
        prefix = "[DRY-RUN] " if self.dry_run else ""
        return f"{prefix}{self.action.upper()} {'SUCCESS' if self.success else 'FAILED'}: {self.message}"

    def __repr__(self) -> str:
        return (
            f"ControlResult(success={self.success}, "
            f"clientEquipmentId={self.client_equipment_id}, "
            f"action={self.action!r}, code={self.code}, dryRun={self.dry_run})"
        )


class LockState(dict):
    """
    Representation of physical lock state inquiry returned by query_lock_state.

    Subclasses dict to provide dictionary indexing and JSON serialization while
    behaving as equal to strings "LOCKED", "UNLOCKED", or "UNKNOWN" to preserve
    100% backward compatibility with existing unit tests.
    """
    def __init__(
        self,
        state: str,  # "LOCKED", "UNLOCKED", "UNKNOWN"
        client_equipment_id: int,
        raw_state_code: str = "0",
        message: str = "success",
        code: int = 200,
        raw_data: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
    ) -> None:
        payload: Dict[str, Any] = {
            "state": state,
            "clientEquipmentId": client_equipment_id,
            "rawStateCode": raw_state_code,
            "message": message,
            "code": code,
            "dryRun": dry_run,
        }
        if raw_data:
            payload["data"] = raw_data
            for k, v in raw_data.items():
                if k not in payload:
                    payload[k] = v
        super().__init__(payload)
        self.state = state
        self.client_equipment_id = client_equipment_id
        self.raw_state_code = raw_state_code
        self.message = message
        self.code = code
        self.raw_data = raw_data or {}
        self.dry_run = dry_run

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            return self.state == other
        return super().__eq__(other)

    def __ne__(self, other: Any) -> bool:
        eq = self.__eq__(other)
        if eq is NotImplemented:
            return NotImplemented
        return not eq

    def __hash__(self) -> int:
        return hash(self.state)

    def __str__(self) -> str:
        return self.state

    def __repr__(self) -> str:
        return (
            f"LockState(state={self.state!r}, "
            f"clientEquipmentId={self.client_equipment_id}, "
            f"rawStateCode={self.raw_state_code!r}, dryRun={self.dry_run})"
        )


# ============================================================================
# Core GeekSmartClient Implementation
# ============================================================================
class GeekSmartClient:
    """
    Core client for communicating with GeekSmart IoT cloud service.

    Implements:
    - Byte-level AES-128-CBC encryption and decryption.
    - Envelope serialization and URL encoding.
    - Session management and connection pooling.
    - Automatic token caching and re-login on code == 3.
    - Device discovery and lock inspection.
    - Strict 5-layer safety barrier guarding against destructive actions.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        aes_key: bytes = DEFAULT_AES_KEY,
        aes_iv: bytes = DEFAULT_AES_IV,
        timeout: float = DEFAULT_TIMEOUT,
        session: Optional[requests.Session] = None,
        auto_relogin: bool = True,
        mode: ClientMode = ClientMode.SAFE_CONTROL,
        mock_transport: Optional[Callable[[str, Dict[str, Any], str], Dict[str, Any]]] = None,
        session_cache_path: Optional[str] = None,
        allow_network_login: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.aes_key = aes_key
        self.aes_iv = aes_iv
        self.timeout = timeout
        self.session = session or requests.Session()
        if session is None and hasattr(self.session, "mount"):
            adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10)
            self.session.mount("https://", adapter)
            self.session.mount("http://", adapter)
        self.auto_relogin = auto_relogin
        self.mode = mode
        self.mock_transport = mock_transport
        self.session_cache_path = session_cache_path
        self.allow_network_login = allow_network_login

        # Active session state
        self.token: Optional[str] = None
        self.client_id: Optional[int] = None
        self.user_info: Optional[UserInfo] = None
        self._user_email: Optional[str] = None
        self._user_password: Optional[str] = None
        self._relogin_attempts: int = 0
        self._relogin_lock: threading.Lock = threading.Lock()

        # Standard headers matching Android app (OkHttp)
        self.session.headers.update({
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "application/json",
        })

    # ------------------------------------------------------------------------
    # Cryptographic Primitives (Static / Class Callable)
    # ------------------------------------------------------------------------
    @staticmethod
    def encrypt_payload(
        params: Dict[str, Any],
        key: bytes = DEFAULT_AES_KEY,
        iv: bytes = DEFAULT_AES_IV,
    ) -> str:
        """
        Serializes parameter dictionary to compact JSON and encrypts with AES-128-CBC.

        Returns:
            Base64 encoded ciphertext string (NO_WRAP, no newlines).
        """
        try:
            raw_json = json.dumps(params, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(raw_json) + padder.finalize()

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return base64.b64encode(ciphertext).decode("ascii")
        except Exception as e:
            raise GeekSmartCryptoError(f"Encryption failed: {e}") from e

    @staticmethod
    def decrypt_payload(
        b64_ciphertext: str,
        key: bytes = DEFAULT_AES_KEY,
        iv: bytes = DEFAULT_AES_IV,
    ) -> str:
        """
        Decrypts Base64 AES-128-CBC ciphertext and removes PKCS7 padding.

        Returns:
            Decrypted UTF-8 plaintext string.
        """
        if not b64_ciphertext or not isinstance(b64_ciphertext, str):
            raise GeekSmartCryptoError("Ciphertext must be a non-empty string")

        try:
            raw_bytes = base64.b64decode(b64_ciphertext, validate=True)
        except Exception as e:
            raise GeekSmartCryptoError(f"Base64 decoding failed: {e}") from e

        if len(raw_bytes) == 0 or len(raw_bytes) % 16 != 0:
            raise GeekSmartCryptoError(f"Ciphertext length {len(raw_bytes)} is not a valid 16-byte multiple")

        try:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(raw_bytes) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            return plaintext.decode("utf-8")
        except Exception as e:
            raise GeekSmartCryptoError(f"AES decryption/unpadding failed: {e}") from e

    # ------------------------------------------------------------------------
    # HTTP Transport & Request Envelope
    # ------------------------------------------------------------------------
    def execute_request(
        self,
        endpoint: str,
        extra_params: Optional[Dict[str, Any]] = None,
        method: str = "GET",
        _is_retry: bool = False,
    ) -> Tuple[int, str, Optional[Any]]:
        """
        Executes a single API request with pre-flight safety verification,
        parameter encryption, response decryption, and auto-relogin.

        Returns:
            Tuple of (code, msg, parsed_data)
        """
        extra_params = extra_params or {}

        # 1. MANDATORY SAFETY BARRIER PRE-FLIGHT GUARD (Zero-I/O Guarantee)
        SafetyBarrierGuard.validate_request(endpoint, extra_params, self.mode)

        # Assemble full parameters payload
        full_params: Dict[str, Any] = {
            "platform": DEFAULT_PLATFORM,
            "version": DEFAULT_VERSION,
            "currentTimestamp": str(int(time.time() * 1000)),
            "countryLang": DEFAULT_LANG,
        }
        if self.token:
            full_params["token"] = self.token
        full_params.update(extra_params)
        request_token = full_params.get("token")

        # 2. Check Mock Transport (Injected exclusively by tests)
        if self.mock_transport is not None:
            try:
                resp_json = self.mock_transport(endpoint, full_params, method)
            except requests.Timeout as e:
                norm_endpoint = "/" + endpoint.lstrip("/")
                raise GeekSmartTimeoutError(f"Request timed out for {norm_endpoint}: {e}") from e
            except requests.RequestException as e:
                norm_endpoint = "/" + endpoint.lstrip("/")
                raise GeekSmartNetworkError(0, f"Network request failed for {norm_endpoint}: {e}") from e
            code = resp_json.get("code", -1)
            msg = resp_json.get("msg", "")
            raw_data = resp_json.get("data")
        else:
            # 3. Real HTTP execution via requests.Session with transient retry backoff
            norm_endpoint = "/" + endpoint.lstrip("/")
            encrypted_data = self.encrypt_payload(full_params, self.aes_key, self.aes_iv)
            url = f"{self.base_url}{norm_endpoint}"

            max_retries = 2
            backoffs = (0.3, 0.6)
            resp_json: Dict[str, Any] = {}

            for attempt in range(max_retries + 1):
                try:
                    if method.upper() == "GET":
                        req_url = f"{url}?data={urllib.parse.quote(encrypted_data)}"
                        response = self.session.get(req_url, timeout=self.timeout)
                    elif method.upper() == "POST":
                        body = {"data": encrypted_data}
                        response = self.session.post(
                            url,
                            data=body,
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            timeout=self.timeout,
                        )
                    else:
                        raise ValueError(f"Unsupported HTTP method: {method}")

                    status_code_attr = getattr(response, "status_code", None)
                    if (
                        isinstance(status_code_attr, int)
                        and status_code_attr in (502, 503, 504)
                        and attempt < max_retries
                    ):
                        delay = backoffs[attempt] if attempt < len(backoffs) else backoffs[-1]
                        logger.warning(
                            "Transient HTTP %d for %s (attempt %d/%d), retrying in %.1fs...",
                            status_code_attr,
                            norm_endpoint,
                            attempt + 1,
                            max_retries + 1,
                            delay,
                        )
                        time.sleep(delay)
                        continue

                    response.raise_for_status()
                    resp_json = response.json()
                    break
                except requests.Timeout as e:
                    raise GeekSmartTimeoutError(f"Request timed out for {norm_endpoint}: {e}") from e
                except requests.ConnectionError as e:
                    if attempt < max_retries:
                        delay = backoffs[attempt] if attempt < len(backoffs) else backoffs[-1]
                        logger.warning(
                            "Transient ConnectionError for %s (attempt %d/%d), retrying in %.1fs: %s",
                            norm_endpoint,
                            attempt + 1,
                            max_retries + 1,
                            delay,
                            e,
                        )
                        time.sleep(delay)
                        continue
                    raise GeekSmartNetworkError(0, f"Network request failed for {norm_endpoint}: {e}") from e
                except requests.HTTPError as e:
                    status_code = e.response.status_code if e.response is not None else 500
                    if status_code in (502, 503, 504) and attempt < max_retries:
                        delay = backoffs[attempt] if attempt < len(backoffs) else backoffs[-1]
                        time.sleep(delay)
                        continue
                    raise GeekSmartNetworkError(status_code, f"HTTP error {status_code}: {e}") from e
                except requests.RequestException as e:
                    raise GeekSmartNetworkError(0, f"Network request failed for {norm_endpoint}: {e}") from e
                except json.JSONDecodeError as e:
                    raise GeekSmartNetworkError(0, f"Invalid JSON returned by server: {e}") from e

            code = resp_json.get("code", -1)
            msg = resp_json.get("msg", "")
            raw_data = resp_json.get("data")

        # 4. Handle Token Expiration (code 3) with Auto-Relogin & Concurrency Guard
        if code == 3:
            if _is_retry or "loginByPassword" in endpoint:
                self._relogin_attempts = 0
                raise GeekSmartAuthError(3, msg)

            with self._relogin_lock:
                # Double-checked locking: If another concurrent thread already renewed the token
                # while this thread was waiting for the lock, skip login and retry immediately.
                if not (request_token and self.token != request_token):
                    if (
                        self.auto_relogin
                        and self._user_email
                        and self._user_password
                        and self._relogin_attempts < 1
                        and (self.allow_network_login or self.mock_transport is not None)
                    ):
                        self._relogin_attempts += 1
                        try:
                            logger.warning("Session token expired (code 3). Executing automatic re-login...")
                            self.login(self._user_email, self._user_password)
                        finally:
                            self._relogin_attempts = 0
                    else:
                        self._relogin_attempts = 0
                        raise GeekSmartAuthError(3, msg)

            # Re-execute original request once outside the lock with renewed token
            return self.execute_request(endpoint, extra_params, method, _is_retry=True)

        if "loginByPassword" not in endpoint:
            self._relogin_attempts = 0

        # 5. Parse and decrypt data payload on success
        parsed_data = None
        if code in (0, 200) and raw_data:
            if isinstance(raw_data, str):
                decrypted_str = self.decrypt_payload(raw_data, self.aes_key, self.aes_iv)
                try:
                    parsed_data = json.loads(decrypted_str) if decrypted_str else None
                except Exception as exc:
                    raise GeekSmartProtocolError(f"Decrypted data is not valid JSON: {exc}") from exc
            elif isinstance(raw_data, dict):
                parsed_data = raw_data

        return code, msg, parsed_data

    def request(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        method: str = "GET",
    ) -> Any:
        """
        High-level authenticated request helper that unpacks data and raises on API errors.
        """
        code, msg, data = self.execute_request(endpoint, params, method)
        if code not in (0, 200):
            if code in (2007, 2010, 1003, 3):
                raise GeekSmartAuthError(code, msg)
            raise GeekSmartControlError(code, msg)
        return data

    # ------------------------------------------------------------------------
    # Public Authentication APIs
    # ------------------------------------------------------------------------
    def login(
        self,
        email: Optional[str] = None,
        password: Optional[str] = None,
        use_cache: bool = True,
    ) -> UserInfo:
        """
        Authenticates against GeekSmart cloud with email and password or loads from session cache.
        When use_cache=True and a valid cache exists, completely suppresses network
        requests to /app/client/loginByPassword to prevent rate-limiting.

        Returns:
            UserInfo containing client ID, email, token, and bridge credentials.
        """
        # 1. If credentials were provided, validate non-empty string types
        if email is not None or password is not None:
            if not email or not isinstance(email, str) or not email.strip():
                raise ValueError("Email must be a non-empty string")
            if not password or not isinstance(password, str) or not password.strip():
                raise ValueError("Password must be a non-empty string")

        # 2. In mock mode (e.g., unit tests), execute mock transport directly when credentials provided
        if self.mock_transport is not None and email and password:
            self._user_email = email
            self._user_password = password

            code, msg, data = self.execute_request("/app/client/loginByPassword", {
                "email": email,
                "password": password,
                "type": "1",
            }, method="GET")

            if code != 0 or not data:
                if code in (2007, 2010):
                    raise GeekSmartAuthError(code, msg)
                raise GeekSmartAuthError(code, f"Login failed: {msg}")

            user = UserInfo.from_dict(data)
            self.token = user.token
            self.client_id = user.client_id
            self.user_info = user
            logger.info(f"Successfully authenticated client {self.client_id} ({user.email}) via mock transport")
            return user

        # 3. Check local session cache (.session_cache.json)
        if use_cache:
            cache_mgr = SessionManager(self.session_cache_path)
            cached_data = cache_mgr.load()
            if cached_data:
                cached_token = cached_data.get("token") or cached_data.get("geeksmart", {}).get("token")
                cached_id = (
                    cached_data.get("id")
                    or cached_data.get("clientId")
                    or cached_data.get("geeksmart", {}).get("client_id")
                )
                cached_email = cached_data.get("email") or cached_data.get("geeksmart", {}).get("email")
                # If email was provided, ensure it matches cached email
                email_matches = (
                    email is None
                    or not cached_email
                    or email.strip().lower() == str(cached_email).strip().lower()
                )
                if cached_token and cached_id and email_matches:
                    user = UserInfo.from_dict(cached_data)
                    self.token = str(cached_token)
                    self.client_id = int(cached_id)
                    self.user_info = user
                    self._user_email = user.email or email
                    self._user_password = cached_data.get("password") or password
                    logger.info(
                        "Loaded valid session for client %s from %s (zero network calls)",
                        self.client_id,
                        cache_mgr.cache_path,
                    )
                    return user

        # 4. If cache missing or disabled, verify credentials and network permission
        if not self.allow_network_login and self.mock_transport is None:
            raise GeekSmartAuthError(
                3,
                "Network login to /app/client/loginByPassword is strictly disabled to prevent "
                "cloud rate-limiting. Please provide a valid .session_cache.json.",
            )

        if not email or not isinstance(email, str) or not email.strip():
            raise ValueError("Email must be a non-empty string")
        if not password or not isinstance(password, str) or not password.strip():
            raise ValueError("Password must be a non-empty string")

        self._user_email = email
        self._user_password = password

        code, msg, data = self.execute_request("/app/client/loginByPassword", {
            "email": email,
            "password": password,
            "type": "1",
        }, method="GET")

        if code != 0 or not data:
            if code in (2007, 2010):
                raise GeekSmartAuthError(code, msg)
            raise GeekSmartAuthError(code, f"Login failed: {msg}")

        user = UserInfo.from_dict(data)
        self.token = user.token
        self.client_id = user.client_id
        self.user_info = user

        # Persist to disk
        try:
            SessionManager(self.session_cache_path).save(data, merge=True)
        except Exception as e:
            logger.warning("Could not persist session cache: %s", e)

        logger.info(f"Successfully authenticated client {self.client_id} ({user.email})")
        return user

    def get_client_info(self) -> UserInfo:
        """
        Fetches current client user profile from /app/client/getClientInfo.
        """
        if not self.token or not self.client_id:
            raise GeekSmartAuthError(3, "Must authenticate before requesting user profile")
        data = self.request("/app/client/getClientInfo", {"id": self.client_id})
        self.user_info = UserInfo.from_dict(data or {})
        return self.user_info

    # ------------------------------------------------------------------------
    # Public Device Discovery APIs (Milestone 1)
    # ------------------------------------------------------------------------
    def get_equipment_list_map(self) -> EquipmentListMapResult:
        """
        Discovers registered equipment map via /app/home/getClientEquipmentListMap.
        """
        if not self.token or not self.client_id:
            raise GeekSmartAuthError(3, "Must authenticate before querying equipment map")
        data = self.request("/app/home/getClientEquipmentListMap", {"clientId": self.client_id})
        return EquipmentListMapResult.from_dict(data or {})

    def get_equipment_list(self) -> List[EquipmentGroup]:
        """
        Discovers registered equipment list via /app/home/getClientEquipmentList.
        """
        if not self.token or not self.client_id:
            raise GeekSmartAuthError(3, "Must authenticate before querying equipment list")
        data = self.request("/app/home/getClientEquipmentList", {"clientId": self.client_id})
        if isinstance(data, list):
            return [EquipmentGroup.from_dict(item) for item in data if isinstance(item, dict)]
        return []

    def get_lock_list(self) -> List[DoorbellLockRecord]:
        """
        Discovers registered doorbell/camera door locks via app/doorbellLock/getLockList.
        """
        data = self.request("app/doorbellLock/getLockList")
        if isinstance(data, list):
            return [DoorbellLockRecord.from_dict(item) for item in data if isinstance(item, dict)]
        return []

    def get_lock(self, tuya_did: str) -> Optional[DoorbellLockRecord]:
        """
        Fetches a specific lock record by its Tuya Device ID via app/doorbellLock/getLock.
        """
        data = self.request("app/doorbellLock/getLock", {"tuyaDid": tuya_did})
        if isinstance(data, dict):
            return DoorbellLockRecord.from_dict(data)
        return None

    def discover_devices(self) -> List[Dict[str, Any]]:
        """
        Discovers all devices on account, returning a flattened list of device dictionaries.
        Supports both flat device list (test fixtures) and nested category groups (APK format).
        """
        if not self.token or not self.client_id:
            raise GeekSmartAuthError(3, "Must authenticate before discovering devices")

        code, msg, data = self.execute_request("/app/home/getClientEquipmentListMap", {
            "clientId": self.client_id
        })
        if code != 0 or not data:
            raise GeekSmartControlError(code, msg)

        raw_list = data.get("equipmentList", [])
        devices: List[Dict[str, Any]] = []

        for item in raw_list:
            if isinstance(item, dict):
                if "equipmentList" in item and isinstance(item["equipmentList"], list):
                    # Category container format (APK)
                    for sub_item in item["equipmentList"]:
                        if isinstance(sub_item, dict):
                            devices.append(sub_item)
                else:
                    # Flat device format (test fixtures with clientEquipmentId or id)
                    devices.append(item)

        return devices

    # ------------------------------------------------------------------------
    # Public Device Control APIs (Milestone 2 - Gated by Mode)
    # ------------------------------------------------------------------------
    def dry_run_request(
        self,
        endpoint: str,
        extra_params: Optional[Dict[str, Any]] = None,
        method: str = "GET",
    ) -> Dict[str, Any]:
        """
        Simulates an API request with full pre-flight safety validation, parameter assembly,
        and AES-128-CBC encryption, with a 100% guarantee of ZERO network I/O.

        Args:
            endpoint: Target API route (e.g. "/app/home/ttlockGatewayUnlock").
            extra_params: Optional dictionary of query or body parameters.
            method: HTTP method ("GET" or "POST").

        Returns:
            Dictionary containing target endpoint, HTTP method, assembled plaintext parameters,
            Base64 AES ciphertext, complete target URL, and safety validation audit result.
        """
        extra_params = extra_params or {}
        SafetyBarrierGuard.validate_request(endpoint, extra_params, self.mode)

        full_params: Dict[str, Any] = {
            "platform": DEFAULT_PLATFORM,
            "version": DEFAULT_VERSION,
            "currentTimestamp": str(int(time.time() * 1000)),
            "countryLang": DEFAULT_LANG,
        }
        if self.token:
            full_params["token"] = self.token
        full_params.update(extra_params)

        encrypted_data = self.encrypt_payload(full_params, self.aes_key, self.aes_iv)
        norm_endpoint = "/" + endpoint.lstrip("/")
        base_url = self.base_url

        if method.upper() == "GET":
            target_url = f"{base_url}{norm_endpoint}?data={urllib.parse.quote(encrypted_data)}"
        else:
            target_url = f"{base_url}{norm_endpoint}"

        return {
            "dryRun": True,
            "endpoint": norm_endpoint,
            "method": method.upper(),
            "targetUrl": target_url,
            "plaintextParams": full_params,
            "encryptedPayload": encrypted_data,
            "safetyStatus": "PASSED_SAFE_CONTROL",
            "ioExecuted": False,
        }

    def query_lock_state(
        self,
        client_equipment_id: int,
        dry_run: bool = False,
    ) -> LockState:
        """
        Queries physical lock status (LOCKED / UNLOCKED / UNKNOWN) via smart plug BLE gateway bridge.
        Issues GET /app/home/ttlockGatewayQueryOpenState.

        Args:
            client_equipment_id: The unique integer ID of the registered lock equipment.
            dry_run: If True, validates safety barriers and generates encrypted payload without network I/O.

        Returns:
            LockState: Dual-compatible dictionary result object evaluating to string states.
        """
        if isinstance(client_equipment_id, bool) or not isinstance(client_equipment_id, (int, str)):
            raise ValueError(f"client_equipment_id must be a positive integer, got: {client_equipment_id!r}")
        try:
            equipment_id = int(client_equipment_id)
            if equipment_id <= 0:
                raise ValueError
        except (ValueError, TypeError, OverflowError):
            raise ValueError(f"client_equipment_id must be a positive integer, got: {client_equipment_id!r}")

        if not self.token:
            raise GeekSmartAuthError(3, "Must authenticate before querying status")

        params: Dict[str, Any] = {
            "clientEquipmentId": equipment_id,
            "clientEquipmentAccountId": 0,
        }

        if dry_run:
            dry_run_info = self.dry_run_request("/app/home/ttlockGatewayQueryOpenState", params, method="GET")
            return LockState(
                state="UNKNOWN",
                client_equipment_id=equipment_id,
                raw_state_code="0",
                message="[DRY-RUN] Status query simulated without network I/O.",
                code=200,
                raw_data=dry_run_info,
                dry_run=True,
            )

        code, msg, data = self.execute_request("/app/home/ttlockGatewayQueryOpenState", params, method="GET")
        if code not in (0, 200) or not data:
            raise GeekSmartControlError(code, msg)

        state_code = str(data.get("state", "0"))
        if state_code == "1":
            state_str = "UNLOCKED"
        elif state_code == "2":
            state_str = "LOCKED"
        else:
            state_str = "UNKNOWN"

        return LockState(
            state=state_str,
            client_equipment_id=equipment_id,
            raw_state_code=state_code,
            message=msg or "success",
            code=code,
            raw_data=data,
            dry_run=False,
        )

    def unlock_door(
        self,
        client_equipment_id: int,
        lock_data: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
    ) -> ControlResult:
        """
        Sends safe remote unlock command via smart plug BLE gateway bridge.
        Issues GET /app/home/ttlockGatewayUnlock.

        Args:
            client_equipment_id: Unique integer ID of registered lock equipment.
            lock_data: Optional dictionary containing supplementary lock parameters. Defaults to owner account (0).
            dry_run: If True, validates safety barriers and encrypts payload without network I/O.

        Returns:
            ControlResult: Dual-compatible dictionary result object evaluating to True in boolean contexts.
        """
        if isinstance(client_equipment_id, bool) or not isinstance(client_equipment_id, (int, str)):
            raise ValueError(f"client_equipment_id must be a positive integer, got: {client_equipment_id!r}")
        try:
            equipment_id = int(client_equipment_id)
            if equipment_id <= 0:
                raise ValueError
        except (ValueError, TypeError, OverflowError):
            raise ValueError(f"client_equipment_id must be a positive integer, got: {client_equipment_id!r}")

        if lock_data is not None and not isinstance(lock_data, dict):
            raise TypeError(f"lock_data must be a dict or None, got: {type(lock_data).__name__}")

        if not self.token or not self.client_id:
            raise GeekSmartAuthError(3, "Must authenticate before unlocking")

        params: Dict[str, Any] = {
            "clientId": self.client_id,
            "clientEquipmentId": equipment_id,
            "clientEquipmentAccountId": 0,
        }
        if lock_data:
            if "clientEquipmentAccountId" in lock_data:
                params["clientEquipmentAccountId"] = lock_data["clientEquipmentAccountId"]
            for k, v in lock_data.items():
                if k not in params:
                    params[k] = v

        if dry_run:
            dry_run_info = self.dry_run_request("/app/home/ttlockGatewayUnlock", params, method="GET")
            return ControlResult(
                success=True,
                client_equipment_id=equipment_id,
                action="unlock",
                message="[DRY-RUN] Unlock command validated and encrypted without transmission.",
                code=200,
                raw_data=dry_run_info,
                dry_run=True,
            )

        code, msg, data = self.execute_request("/app/home/ttlockGatewayUnlock", params, method="GET")
        if code not in (0, 200):
            raise GeekSmartControlError(code, msg)

        raw_result = data if isinstance(data, dict) else {"result": "unlocked"}
        return ControlResult(
            success=True,
            client_equipment_id=equipment_id,
            action="unlock",
            message=msg or "Unlocked successfully",
            code=code,
            raw_data=raw_result,
            dry_run=False,
        )

    def lock_door(
        self,
        client_equipment_id: int,
        lock_data: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
    ) -> ControlResult:
        """
        Sends safe remote lock command via smart plug BLE gateway bridge.
        Issues GET /app/home/ttlockGatewayLock.

        Args:
            client_equipment_id: Unique integer ID of registered lock equipment.
            lock_data: Optional dictionary containing supplementary lock parameters. Defaults to owner account (0).
            dry_run: If True, validates safety barriers and encrypts payload without network I/O.

        Returns:
            ControlResult: Dual-compatible dictionary result object evaluating to True in boolean contexts.
        """
        if isinstance(client_equipment_id, bool) or not isinstance(client_equipment_id, (int, str)):
            raise ValueError(f"client_equipment_id must be a positive integer, got: {client_equipment_id!r}")
        try:
            equipment_id = int(client_equipment_id)
            if equipment_id <= 0:
                raise ValueError
        except (ValueError, TypeError, OverflowError):
            raise ValueError(f"client_equipment_id must be a positive integer, got: {client_equipment_id!r}")

        if lock_data is not None and not isinstance(lock_data, dict):
            raise TypeError(f"lock_data must be a dict or None, got: {type(lock_data).__name__}")

        if not self.token or not self.client_id:
            raise GeekSmartAuthError(3, "Must authenticate before locking")

        params: Dict[str, Any] = {
            "clientId": self.client_id,
            "clientEquipmentId": equipment_id,
            "clientEquipmentAccountId": 0,
        }
        if lock_data:
            if "clientEquipmentAccountId" in lock_data:
                params["clientEquipmentAccountId"] = lock_data["clientEquipmentAccountId"]
            for k, v in lock_data.items():
                if k not in params:
                    params[k] = v

        if dry_run:
            dry_run_info = self.dry_run_request("/app/home/ttlockGatewayLock", params, method="GET")
            return ControlResult(
                success=True,
                client_equipment_id=equipment_id,
                action="lock",
                message="[DRY-RUN] Lock command validated and encrypted without transmission.",
                code=200,
                raw_data=dry_run_info,
                dry_run=True,
            )

        code, msg, data = self.execute_request("/app/home/ttlockGatewayLock", params, method="GET")
        if code not in (0, 200):
            raise GeekSmartControlError(code, msg)

        raw_result = data if isinstance(data, dict) else {"result": "locked"}
        return ControlResult(
            success=True,
            client_equipment_id=equipment_id,
            action="lock",
            message=msg or "Locked successfully",
            code=code,
            raw_data=raw_result,
            dry_run=False,
        )
