"""Tuya/ThingSmart OEM Mobile API Client for GeekSmart / MyDoor.

Replaces GeekSmart cloud API for hardware discovery and communicates directly
with the Tuya Mobile Gateway (https://a1.tuyaus.com/api.json) using reversed
cryptographic signatures, 4-quarter MD5 permutation, composite BMP+Cert+Secret
HMAC-SHA256 signing, channel key (chKey) derivation, dynamic RSA PKCS#1 v1.5
key exchange, and session caching.

Completely native Python implementation with zero Android emulation, Waydroid,
or Frida runtime dependencies.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple

import requests
import requests.adapters

from .exceptions import (
    GeekSmartCryptoError,
    SafetyBarrierViolation,
    TuyaApiError,
)
from .session_manager import SessionManager

logger = logging.getLogger("geeksmart.tuya")


# ============================================================================
# Protocol Constants & Configuration (Reverse-Engineered from GeekSmart APK)
# ============================================================================
DEFAULT_TUYA_GATEWAY_URL: str = "https://a1.tuyaus.com/api.json"
DEFAULT_TUYA_PACKAGE_NAME: str = "com.geektechnology.geeksmarthome"
DEFAULT_TUYA_CERT_SHA256: str = (
    "2A:A1:C4:9E:E7:65:70:B3:8C:D9:D7:B8:D7:23:4A:DC:"
    "A8:7F:0B:24:90:73:C2:02:87:AB:7A:5B:A1:9B:46:04"
)
# Extracted from assets/t_s.bmp via LSB steganography + Shamir's Secret Sharing
# Lagrange interpolation at x=0 + libthing_security.so transform()
DEFAULT_TUYA_BMP_KEY: str = "9cyampyappggykh8ey3gqf3t7pkjcray"
DEFAULT_TUYA_APP_KEY: str = "nw547nqyxsfh9sjynk85"
DEFAULT_TUYA_APP_SECRET: str = "fhr5jckeawrdgqpetfvp8ydsgsypj3vx"
DEFAULT_TUYA_SIGN_KEY: str = (
    f"{DEFAULT_TUYA_PACKAGE_NAME}_{DEFAULT_TUYA_CERT_SHA256}_"
    f"{DEFAULT_TUYA_BMP_KEY}_{DEFAULT_TUYA_APP_SECRET}"
)
# Derived via libthing_security.so getChKey:
# HMAC-SHA256(key=appKey, msg=f"{pkg}_{cert}").hexdigest()[8:16]
DEFAULT_TUYA_CH_KEY: str = "a9e4bfc3"
DEFAULT_TUYA_TTID: str = "216200@geek_android_1.2.9"
DEFAULT_TUYA_APP_VERSION: str = "1.2.9"
DEFAULT_TUYA_APP_RN_VERSION: str = "5.14"
DEFAULT_TUYA_SDK_VERSION: str = "5.14.0"
DEFAULT_TUYA_DEVICE_ID: str = (
    "e39553349bf4bfd7dc8db12113676c80543c1a16d459a0a163034603da1a6c16"
)
DEFAULT_TUYA_OS: str = "Android"
DEFAULT_TUYA_LANG: str = "en"
DEFAULT_TUYA_TIMEOUT: float = 15.0
DEFAULT_TUYA_RETRY_BACKOFF: Tuple[float, ...] = (0.4, 0.8, 1.5)
TUYA_SESSION_EXPIRED_CODES: FrozenSet[str] = frozenset({
    "USER_SESSION_LOSS",
    "USER_SESSION_INVALID",
    "SESSION_EXPIRED",
    "TOKEN_EXPIRED",
    "SYS_TOKEN_EXPIRED",
    "1010",
})

# Static Allowed Keys Whitelist (from ThingApiSignManager / libthing_security.so)
TUYA_SIGN_WHITELIST: List[str] = [
    "a",
    "v",
    "lat",
    "lon",
    "lang",
    "deviceId",
    "appVersion",
    "ttid",
    "isH5",
    "h5Token",
    "os",
    "clientId",
    "postData",
    "time",
    "requestId",
    "et",
    "n4h5",
    "sid",
    "chKey",
    "sp",
]


# ============================================================================
# Device Data Model
# ============================================================================
# Smart Plug BLE Gateway outlet relay. Tuya category "cz" plugs expose the mains outlet
# as a plain boolean on DP 1 (dp code "switch_1"). On jtmspro locks DP 1 means
# unlock_method_create (raw) and boolean lock intent is remapped to DP 71, so plug
# outlet control has its own guarded path (TuyaClient.publish_plug_switch).
PLUG_SWITCH_CATEGORIES: FrozenSet[str] = frozenset({"cz"})
PLUG_OUTLET_DP: str = "1"
PLUG_OUTLET_CODE: str = "switch_1"
# DPs that only exist on door locks; their presence makes a device ineligible for plug control.
LOCK_ONLY_DPS: FrozenSet[str] = frozenset({"21", "47", "70", "71", "73"})


@dataclass
class TuyaDevice:
    """Represents a physical Tuya device (Smart Plug BLE Gateway, Lock, or Sub-device)."""

    dev_id: str
    name: str
    product_id: str
    is_online: bool
    category: str
    parent_id: Optional[str] = None
    mac: Optional[str] = None
    ip: Optional[str] = None
    local_key: Optional[str] = None
    sec_key: Optional[str] = None
    uuid: Optional[str] = None
    node_id: Optional[str] = None
    category_code: Optional[str] = None
    dps: Dict[str, Any] = field(default_factory=dict)
    dp_codes: Dict[str, Any] = field(default_factory=dict)
    battery: Optional[int] = None
    connection_status: int = 1
    ble_signal_state: str = "DIRECT_WIFI"
    wifi_rssi: Optional[int] = None
    wifi_ssid: Optional[str] = None
    hardware_model: Optional[str] = None
    last_seen_ms: Optional[int] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_lock(self) -> bool:
        """Determines if device is a door lock based on category or DP signatures."""
        return (
            self.category in ("ms", "jtmspro", "jtmsbh", "gyms", "videolock", "ms_category")
            or self.category.startswith("jtms")
            or "door_state" in self.dp_codes
            or "lock_motor_state" in self.dp_codes
            or "21" in self.dps
            or "70" in self.dps
            or (
                "1" in self.dps
                and isinstance(self.dps.get("1"), bool)
                and self.category != "cz"
            )
        )

    @property
    def is_gateway(self) -> bool:
        """Determines if device is a Smart Plug BLE Gateway."""
        return (
            self.category in ("cz", "wg2", "bh")
            or "plug" in self.name.lower()
            or "gateway" in self.name.lower()
            or bool(self.raw.get("gatewayVerCAD"))
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TuyaDevice:
        """Constructs TuyaDevice from Tuya API DeviceBean dictionary (v1.0, v2.1, v2.2, or merged)."""
        raw_dps = (
            data.get("dps")
            or (data.get("dataPointInfo") or {}).get("dps")
            or {}
        )
        dps: Dict[str, Any] = dict(raw_dps) if isinstance(raw_dps, dict) else {}
        raw_dp_codes = data.get("dpCodes") or {}
        dp_codes: Dict[str, Any] = dict(raw_dp_codes) if isinstance(raw_dp_codes, dict) else {}

        dev_id = str(data.get("devId") or data.get("id") or "")

        # Online status resolution across v1.0 (moduleMap), v2.1/v2.2 (cloudOnline), and normalized (isOnline)
        if "isOnline" in data and data["isOnline"] is not None:
            is_online = bool(data["isOnline"])
        elif "cloudOnline" in data and data["cloudOnline"] is not None:
            is_online = bool(data["cloudOnline"])
        else:
            mod_map = data.get("moduleMap") or {}
            is_online = any(
                isinstance(m, dict) and bool(m.get("isOnline"))
                for m in mod_map.values()
            )

        # Parent gateway / mesh node resolution across v1.0 and v2.1/v2.2
        topo = data.get("deviceTopo") or {}
        comm = data.get("communication") or {}
        comm_node = comm.get("communicationNode")
        mesh_id = data.get("meshId")
        parent_id = (
            data.get("parentId")
            or data.get("parentDevId")
            or topo.get("parentDevId")
            or (comm_node if comm_node and comm_node != dev_id else None)
            or (
                mesh_id
                if mesh_id
                and mesh_id != dev_id
                and (data.get("topoType") == 1 or data.get("category") in ("jtmspro", "ms"))
                else None
            )
        )

        # Category resolution
        category = str(data.get("category") or "")
        category_code = data.get("categoryCode")
        if not category:
            if data.get("gatewayVerCAD") or (
                (data.get("otaInfo") or {}).get("otaModuleMap") or {}
            ).get("wifi"):
                category = "cz"
            elif (
                ((data.get("otaInfo") or {}).get("otaModuleMap") or {}).get("bluetooth")
                or "70" in dps
                or "21" in dps
            ):
                category = "jtmspro"

        # Battery extraction from standard Tuya lock DPs: DP 8 (residual_electricity) or DP 14
        battery: Optional[int] = data.get("battery")
        if battery is None:
            for dp_key in ("8", "14", "residual_electricity", "battery_percentage"):
                val = dps.get(dp_key) if dp_key in dps else dp_codes.get(dp_key)
                if val is not None and not isinstance(val, bool):
                    try:
                        battery = int(val)
                        break
                    except (ValueError, TypeError):
                        pass

        # Enrich standard dp_codes for jtmspro / ms locks and cz smart plug gateways
        is_lock_cat = (
            category in ("ms", "jtmspro", "jtmsbh", "gyms", "videolock")
            or category.startswith("jtms")
            or "70" in dps
            or "21" in dps
        )
        if is_lock_cat:
            if "47" in dps and "lock_motor_state" not in dp_codes:
                dp_codes["lock_motor_state"] = dps["47"]
            if "8" in dps and "residual_electricity" not in dp_codes:
                dp_codes["residual_electricity"] = dps["8"]
            if "21" in dps and "alarm_lock" not in dp_codes:
                dp_codes["alarm_lock"] = dps["21"]
            if "31" in dps and "beep_volume" not in dp_codes:
                dp_codes["beep_volume"] = dps["31"]
            if "33" in dps and "automatic_lock" not in dp_codes:
                dp_codes["automatic_lock"] = dps["33"]
            if "36" in dps and "auto_lock_time" not in dp_codes:
                dp_codes["auto_lock_time"] = dps["36"]
            if "46" in dps and "manual_lock" not in dp_codes:
                dp_codes["manual_lock"] = dps["46"]
            if "70" in dps and "remote_no_dp_key" not in dp_codes:
                dp_codes["remote_no_dp_key"] = dps["70"]
            if "71" in dps and "ble_unlock_check" not in dp_codes:
                dp_codes["ble_unlock_check"] = dps["71"]
            if "73" in dps and "remote_pd_setkey_check" not in dp_codes:
                dp_codes["remote_pd_setkey_check"] = dps["73"]
        elif category == "cz":
            if "1" in dps and "switch_1" not in dp_codes:
                dp_codes["switch_1"] = dps["1"]
            if "9" in dps and "countdown_1" not in dp_codes:
                dp_codes["countdown_1"] = dps["9"]
            if "38" in dps and "relay_status" not in dp_codes:
                dp_codes["relay_status"] = dps["38"]
            if "40" in dps and "light_mode" not in dp_codes:
                dp_codes["light_mode"] = dps["40"]
            if "41" in dps and "child_lock" not in dp_codes:
                dp_codes["child_lock"] = dps["41"]

        node_id = data.get("nodeId") or topo.get("nodeId")
        dp_info = data.get("dataPointInfo") or {}

        last_seen_raw = (
            data.get("lastSeenMs")
            or data.get("last_seen_ms")
            or data.get("cloudConnectLastUpdateTime")
            or dp_info.get("dpMaxTime")
            or data.get("dpMaxTime")
        )
        last_seen_ms: Optional[int] = None
        if last_seen_raw is not None:
            try:
                last_seen_ms = int(last_seen_raw)
            except (ValueError, TypeError):
                pass

        if isinstance(comm, dict) and comm.get("connectionStatus") is not None:
            connection_status = int(comm["connectionStatus"])
        elif "connectionStatus" in data and data["connectionStatus"] is not None:
            connection_status = int(data["connectionStatus"])
        elif "connection_status" in data and data["connection_status"] is not None:
            connection_status = int(data["connection_status"])
        elif is_lock_cat:
            connection_status = 2 if is_online else 0
        else:
            connection_status = 1 if is_online else 0

        ble_signal_state = str(data.get("bleSignalState") or data.get("ble_signal_state") or "")
        if not ble_signal_state:
            if not is_lock_cat and category in ("cz", "wg2", "bh"):
                ble_signal_state = "DIRECT_WIFI" if is_online else "OFFLINE"
            elif connection_status == 2 or is_online:
                ble_signal_state = "STRONG_ACTIVE_GATT"
            elif (last_seen_ms and last_seen_ms >= 1790000000000):
                ble_signal_state = "WEAK_SIGNAL_STANDBY"
            else:
                ble_signal_state = "OUT_OF_RANGE_SLEEP"

        known_models = {
            "ebexamplegw1a2b3c4d5e6": "SK517-WBG(NEW)",
            "ebexamplelock001": "K01 2",
            "ebexamplelock002": "K01",
            "ebexamplelock003": "K11",
        }
        hardware_model = (
            data.get("hardwareModel")
            or data.get("hardware_model")
            or data.get("productModel")
            or known_models.get(dev_id)
        )

        wifi_rssi_raw = data.get("wifiRssi") if "wifiRssi" in data else data.get("wifi_rssi")
        wifi_rssi: Optional[int] = None
        if wifi_rssi_raw is not None:
            try:
                wifi_rssi = int(wifi_rssi_raw)
            except (ValueError, TypeError):
                pass

        wifi_ssid = data.get("wifiSsid") or data.get("wifi_ssid") or data.get("ssid")

        raw_nested = data.get("raw") if isinstance(data.get("raw"), dict) else {}
        return cls(
            dev_id=dev_id,
            name=str(data.get("name") or ""),
            product_id=str(data.get("productId") or data.get("product_id") or ""),
            is_online=is_online,
            category=category,
            parent_id=parent_id,
            mac=data.get("mac") or raw_nested.get("mac"),
            ip=data.get("ip") or raw_nested.get("ip"),
            local_key=data.get("localKey") or data.get("local_key") or raw_nested.get("localKey"),
            sec_key=data.get("secKey") or data.get("sec_key") or raw_nested.get("secKey"),
            uuid=data.get("uuid") or raw_nested.get("uuid"),
            node_id=node_id,
            category_code=category_code,
            dps=dps,
            dp_codes=dp_codes,
            battery=battery,
            connection_status=connection_status,
            ble_signal_state=ble_signal_state,
            wifi_rssi=wifi_rssi,
            wifi_ssid=wifi_ssid,
            hardware_model=hardware_model,
            last_seen_ms=last_seen_ms,
            raw=data,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes device to dictionary format."""
        return {
            "devId": self.dev_id,
            "name": self.name,
            "productId": self.product_id,
            "isOnline": self.is_online,
            "category": self.category,
            "categoryCode": self.category_code,
            "parentId": self.parent_id,
            "mac": self.mac,
            "ip": self.ip,
            "localKey": self.local_key,
            "secKey": self.sec_key,
            "uuid": self.uuid,
            "nodeId": self.node_id,
            "dps": self.dps,
            "dpCodes": self.dp_codes,
            "battery": self.battery,
            "connectionStatus": self.connection_status,
            "connection_status": self.connection_status,
            "bleSignalState": self.ble_signal_state,
            "ble_signal_state": self.ble_signal_state,
            "wifiRssi": self.wifi_rssi,
            "wifi_rssi": self.wifi_rssi,
            "wifiSsid": self.wifi_ssid,
            "wifi_ssid": self.wifi_ssid,
            "hardwareModel": self.hardware_model,
            "hardware_model": self.hardware_model,
            "lastSeenMs": self.last_seen_ms,
            "last_seen_ms": self.last_seen_ms,
            "isLock": self.is_lock,
            "isGateway": self.is_gateway,
        }


# ============================================================================
# TuyaClient Implementation
# ============================================================================
class TuyaClient:
    """Native Python client for Tuya/ThingSmart OEM Mobile API (a1.tuyaus.com).

    Reverse-engineered from GeekSmart Android APK DEX bytecode and native libraries
    (libthing_security.so, libthing_security_algorithm.so, assets/t_s.bmp).
    Provides:
    - 4-quarter swapped MD5 hashing of postData (B + A + D + C).
    - Alphabetical whitelist parameter sorting and '||' delimiter joining.
    - Composite HMAC-SHA256 request signing:
      f"{pkg_name}_{cert_sha256}_{bmp_key}_{app_secret}"
    - Channel key (chKey) derivation:
      HMAC-SHA256(key=app_key, msg=f"{pkg_name}_{cert_sha256}").hexdigest()[8:16]
    - RSA PKCS#1 v1.5 password encryption over password MD5.
    - Session caching and reuse to prevent repetitive authentication.
    - Home and device enumeration for Smart Plug BLE Gateway and Locks.
    """

    def __init__(
        self,
        session_cache_path: Optional[str] = None,
        base_url: str = DEFAULT_TUYA_GATEWAY_URL,
        app_key: str = DEFAULT_TUYA_APP_KEY,
        app_secret: str = DEFAULT_TUYA_APP_SECRET,
        app_version: str = DEFAULT_TUYA_APP_VERSION,
        os_name: str = DEFAULT_TUYA_OS,
        lang: str = DEFAULT_TUYA_LANG,
        timeout: float = DEFAULT_TUYA_TIMEOUT,
        session: Optional[requests.Session] = None,
        mock_transport: Optional[
            Callable[[str, str, Dict[str, Any], Optional[str]], Dict[str, Any]]
        ] = None,
        package_name: str = DEFAULT_TUYA_PACKAGE_NAME,
        cert_sha256: str = DEFAULT_TUYA_CERT_SHA256,
        bmp_key: str = DEFAULT_TUYA_BMP_KEY,
        sign_key: Optional[str] = None,
        ttid: str = DEFAULT_TUYA_TTID,
        device_id: str = DEFAULT_TUYA_DEVICE_ID,
        load_cache: bool = True,
    ) -> None:
        self.session_cache_path = session_cache_path
        self.base_url = base_url
        self.app_key = app_key
        self.app_secret = app_secret
        self.app_version = app_version
        self.os_name = os_name
        self.lang = lang
        self.timeout = timeout
        if session is not None:
            self.session = session
        else:
            self.session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10)
            self.session.mount("https://", adapter)
            self.session.mount("http://", adapter)
        self.mock_transport = mock_transport
        self._auth_lock = threading.RLock()
        self.max_retries: int = 3
        self.retry_backoff_delays: Tuple[float, ...] = DEFAULT_TUYA_RETRY_BACKOFF

        self.package_name = package_name
        self.cert_sha256 = cert_sha256
        self.bmp_key = bmp_key
        self.ttid = ttid
        self.device_id = device_id
        self.ch_key = self.derive_ch_key(self.app_key, self.package_name, self.cert_sha256)

        if sign_key is not None:
            self.sign_key = sign_key
        elif app_secret == DEFAULT_TUYA_APP_SECRET:
            self.sign_key = self.derive_composite_sign_key(
                self.package_name,
                self.cert_sha256,
                self.bmp_key,
                self.app_secret,
            )
        else:
            self.sign_key = app_secret

        # State credentials
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.password_md5: Optional[str] = None
        self.country_code: str = "1"
        self.uid: Optional[str] = None
        self.sid: Optional[str] = None
        self.ecode: Optional[str] = None
        self.home_id: Optional[int] = None
        self.home_name: Optional[str] = None
        self._cache_loaded: bool = False

        # Pre-load credentials from session cache if enabled
        if load_cache:
            self._load_from_cache()

    def _load_from_cache(self) -> None:
        """Loads cached Tuya credentials and session from session manager."""
        self._cache_loaded = True
        mgr = SessionManager(self.session_cache_path)
        tuya_sec = mgr.get_tuya_session()
        if tuya_sec:
            self.username = tuya_sec.get("username") or self.username
            self.password = tuya_sec.get("password") or self.password
            self.password_md5 = tuya_sec.get("password_md5") or self.password_md5
            self.country_code = str(tuya_sec.get("country_code") or self.country_code or "1")
            self.uid = tuya_sec.get("uid") or self.uid
            self.sid = tuya_sec.get("sid") or self.sid
            self.ecode = tuya_sec.get("ecode") or self.ecode
            if tuya_sec.get("home_id") is not None:
                self.home_id = tuya_sec.get("home_id")
            self.home_name = tuya_sec.get("home_name") or self.home_name

    # ------------------------------------------------------------------------
    # Cryptographic Primitives & Request Signing
    # ------------------------------------------------------------------------
    @staticmethod
    def derive_composite_sign_key(
        package_name: str = DEFAULT_TUYA_PACKAGE_NAME,
        cert_sha256: str = DEFAULT_TUYA_CERT_SHA256,
        bmp_key: str = DEFAULT_TUYA_BMP_KEY,
        app_secret: str = DEFAULT_TUYA_APP_SECRET,
    ) -> str:
        """Constructs composite HMAC signing key as in libthing_security.so genKey."""
        return f"{package_name}_{cert_sha256}_{bmp_key}_{app_secret}"

    @staticmethod
    def derive_ch_key(
        app_key: str = DEFAULT_TUYA_APP_KEY,
        package_name: str = DEFAULT_TUYA_PACKAGE_NAME,
        cert_sha256: str = DEFAULT_TUYA_CERT_SHA256,
    ) -> str:
        """Computes 8-char channel key (chKey) as in libthing_security.so getChKey (0x6fcc).

        Computes HMAC-SHA256(key=appKey, msg=f"{packageName}_{certSha256}")
        and returns characters [8:16] of the lowercase hex digest.
        """
        msg = f"{package_name}_{cert_sha256}".encode("utf-8")
        digest = hmac.new(app_key.encode("utf-8"), msg, hashlib.sha256).hexdigest().lower()
        return digest[8:16]

    @staticmethod
    def swap_sign_string(md5_hex: str) -> str:
        """Permutes 32-character lowercase hex MD5 into 4 quarters: B + A + D + C.

        Bytecode reproduction of ThingApiSignManager.swapSignString at offset 0x23f2f4:
          Chunk A = s[0:8]
          Chunk B = s[8:16]
          Chunk C = s[16:24]
          Chunk D = s[24:32]
          Result = B + A + D + C -> s[8:16] + s[0:8] + s[24:32] + s[16:24]
        """
        if not isinstance(md5_hex, str) or len(md5_hex) != 32:
            raise GeekSmartCryptoError(
                f"swap_sign_string requires a 32-character hex string, got {len(md5_hex) if isinstance(md5_hex, str) else type(md5_hex)}"
            )
        return (
            md5_hex[8:16] + md5_hex[0:8] + md5_hex[24:32] + md5_hex[16:24]
        )

    @classmethod
    def post_data_md5_hex(cls, post_data: str) -> str:
        """Computes MD5 hash of JSON post data and permutes with 4-quarter swap."""
        raw_md5 = hashlib.md5(post_data.encode("utf-8")).hexdigest().lower()
        return cls.swap_sign_string(raw_md5)

    def generate_signature(
        self,
        params: Dict[str, Any],
        use_hmac: bool = True,
        sign_key: Optional[str] = None,
    ) -> str:
        """Computes Tuya request signature over sorted whitelisted parameters.

        Filters parameters against TUYA_SIGN_WHITELIST, pre-hashes postData,
        sorts keys alphabetically, joins with '||', and computes HMAC-SHA256
        using the composite sign key (or custom app_secret in unit tests).
        """
        sign_map: Dict[str, str] = {}
        for k in TUYA_SIGN_WHITELIST:
            val = params.get(k)
            if val is not None and str(val) != "":
                if k == "postData":
                    sign_map[k] = self.post_data_md5_hex(str(val))
                else:
                    sign_map[k] = str(val)

        sorted_keys = sorted(sign_map.keys())
        string_to_sign = "||".join(f"{k}={sign_map[k]}" for k in sorted_keys)
        effective_key = sign_key if sign_key is not None else self.sign_key

        if use_hmac:
            return hmac.new(
                effective_key.encode("utf-8"),
                string_to_sign.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest().lower()
        else:
            return hashlib.md5(
                (effective_key + string_to_sign).encode("utf-8")
            ).hexdigest().lower()

    @staticmethod
    def rsa_encrypt_pkcs1(
        modulus_str: str,
        exponent_str: str,
        plaintext: bytes,
    ) -> str:
        """Pure-Python RSA encryption with PKCS#1 v1.5 padding.

        Matches Tuya Android RSAUtil.encrypt(String, PublicKey, byte[]).
        Padding format: 00 || 02 || PS || 00 || M
        where PS is non-zero pseudorandom bytes.
        """
        try:
            n = int(modulus_str)
            e = int(exponent_str)
        except (ValueError, TypeError) as exc:
            raise GeekSmartCryptoError(f"Invalid RSA modulus or exponent: {exc}") from exc

        k = (n.bit_length() + 7) // 8
        ps_len = k - len(plaintext) - 3
        if ps_len < 8:
            raise GeekSmartCryptoError("Plaintext too long for RSA key modulus")

        # Generate non-zero random padding bytes
        ps = bytearray()
        while len(ps) < ps_len:
            rand_byte = os.urandom(1)[0]
            if rand_byte != 0:
                ps.append(rand_byte)

        # Construct padded block
        eb = b"\x00\x02" + bytes(ps) + b"\x00" + plaintext
        m = int.from_bytes(eb, byteorder="big")
        c = pow(m, e, n)
        return c.to_bytes(k, byteorder="big").hex().lower()

    # ------------------------------------------------------------------------
    # Network Envelope & Gateway Dispatch
    # ------------------------------------------------------------------------
    @staticmethod
    def _normalize_wire_endpoint(action: str, version: str) -> tuple[str, str]:
        """Normalizes SDK action/version to live Tuya US gateway wire format."""
        if action == "m.life.group.location.list":
            return "smartlife.m.location.list", "2.1"
        if action in (
            "thing.m.user.email.password.login",
            "smartlife.m.user.email.password.login",
        ):
            return "smartlife.m.user.email.password.login", "1.0"
        if action.startswith("thing."):
            return "smartlife." + action[6:], version
        return action, version

    def _auto_heal_session(
        self,
        failed_sid: Optional[str],
        action: str,
        err_code: str,
    ) -> bool:
        """Thread-safely re-authenticates Tuya session after session expiration/loss."""
        with self._auth_lock:
            logger.warning(
                "Tuya session rejected (%s) during '%s'; initiating automatic session self-heal...",
                err_code,
                action,
            )
            # If another thread sharing this client already refreshed sid while waiting on lock
            if self.sid and failed_sid and self.sid != failed_sid:
                logger.info("Reusing newly refreshed in-memory Tuya sid")
                return True

            # Check if another process updated .session_cache.json with a newer sid
            try:
                mgr = SessionManager(self.session_cache_path)
                cached_tuya = mgr.get_tuya_session()
                disk_sid = cached_tuya.get("sid")
                if disk_sid and failed_sid and disk_sid != failed_sid:
                    self._load_from_cache()
                    logger.info("Reusing newly refreshed on-disk Tuya sid")
                    return True
            except Exception:
                pass

            if not self.username or not (self.password or self.password_md5):
                self._load_from_cache()

            if not self.username or not (self.password or self.password_md5):
                logger.error("Cannot auto-heal Tuya session: missing username/password credentials")
                return False

            # Rate-limit live re-logins so we never hammer Tuya auth or fight the phone app
            if self.mock_transport is None:
                now_ts = time.time()
                last_login_ts = getattr(self.__class__, "_LAST_LIVE_LOGIN_TS", 0.0)
                min_interval = getattr(self.__class__, "MIN_LIVE_LOGIN_INTERVAL_SEC", 45.0)
                if (now_ts - last_login_ts) < min_interval:
                    logger.warning(
                        "Skipping live Tuya re-login due to %.0fs rate-limit cooldown (%.1fs elapsed)",
                        min_interval,
                        now_ts - last_login_ts,
                    )
                    return False
                self.__class__._LAST_LIVE_LOGIN_TS = now_ts

            try:
                self.login(use_cache=False)
                return bool(self.sid)
            except Exception as exc:
                logger.error("Automatic Tuya session re-authentication failed: %s", exc)
                return False

    def request(
        self,
        action: str,
        version: str,
        post_data: Optional[Dict[str, Any]] = None,
        requires_session: bool = False,
        extra_params: Optional[Dict[str, Any]] = None,
        _is_retry: bool = False,
        allow_session_heal: bool = True,
    ) -> Any:
        """Dispatches signed request envelope to Tuya mobile gateway.

        Features:
        - Automatic session loading/re-authentication if sid is missing or expired.
        - Automatic exponential-backoff retry (0.4s, 0.8s, 1.5s) on transient timeouts,
          connection errors, and HTTP 502/503/504 responses.
        """
        post_str = (
            json.dumps(post_data, separators=(",", ":"))
            if post_data
            else ""
        )

        if requires_session and not self.sid:
            with self._auth_lock:
                self._load_from_cache()
                if not self.sid and self.username and (self.password or self.password_md5):
                    try:
                        self.login(use_cache=True)
                        if not self.sid:
                            self.login(use_cache=False)
                    except Exception as auth_exc:
                        logger.warning(
                            "Auto-login for missing sid on '%s' failed: %s",
                            action,
                            auth_exc,
                        )
            if not self.sid:
                raise TuyaApiError(
                    "USER_SESSION_INVALID",
                    f"Action '{action}' requires an active session, but client is not authenticated.",
                )

        backoff_schedule = self.retry_backoff_delays[: self.max_retries]
        max_attempts = len(backoff_schedule) + 1
        active_sid = self.sid

        # Mock transport execution for offline unit tests (with timeout retry & session self-heal)
        if self.mock_transport is not None:
            res: Optional[Dict[str, Any]] = None
            for attempt in range(max_attempts):
                timestamp = str(int(time.time()))
                query_params: Dict[str, str] = {
                    "a": action,
                    "v": version,
                    "clientId": self.app_key,
                    "appVersion": self.app_version,
                    "os": self.os_name,
                    "lang": self.lang,
                    "time": timestamp,
                }
                if post_str:
                    query_params["postData"] = post_str
                if requires_session and self.sid:
                    query_params["sid"] = self.sid
                if extra_params:
                    for k, v in extra_params.items():
                        if v is not None:
                            query_params[k] = str(v)
                query_params["sign"] = self.generate_signature(query_params, use_hmac=True)

                try:
                    res = self.mock_transport(action, version, query_params, post_str or None)
                    break
                except requests.Timeout as exc:
                    if attempt < len(backoff_schedule):
                        continue
                    raise TuyaApiError("TIMEOUT", f"Tuya gateway request timed out: {exc}") from exc
                except requests.ConnectionError as exc:
                    if attempt < len(backoff_schedule):
                        continue
                    raise TuyaApiError("NETWORK_ERROR", f"Tuya gateway connection failed: {exc}") from exc
                except requests.RequestException as exc:
                    raise TuyaApiError("NETWORK_ERROR", f"Tuya gateway request failed: {exc}") from exc

            if not res or not res.get("success", False):
                err_code = str((res or {}).get("errorCode", "UNKNOWN_ERROR"))
                err_msg = str((res or {}).get("errorMsg", "Tuya request failed in mock transport"))
                if (
                    requires_session
                    and allow_session_heal
                    and not _is_retry
                    and err_code in TUYA_SESSION_EXPIRED_CODES
                ):
                    if self._auto_heal_session(failed_sid=active_sid, action=action, err_code=err_code):
                        return self.request(
                            action=action,
                            version=version,
                            post_data=post_data,
                            requires_session=requires_session,
                            extra_params=extra_params,
                            _is_retry=True,
                            allow_session_heal=False,
                        )
                raise TuyaApiError(err_code, err_msg)
            return res.get("result")

        # Live network execution against https://a1.tuyaus.com/api.json
        wire_action, wire_version = self._normalize_wire_endpoint(action, version)
        headers = {
            "User-Agent": "okhttp/3.14.9",
            "Accept": "application/json",
        }
        resp = None
        resp_json: Optional[Dict[str, Any]] = None

        for attempt in range(max_attempts):
            timestamp = str(int(time.time()))
            wire_params: Dict[str, str] = {
                "a": wire_action,
                "v": wire_version,
                "os": self.os_name,
                "lang": self.lang,
                "clientId": self.app_key,
                "appVersion": self.app_version,
                "ttid": self.ttid,
                "et": "0.0.1",
                "chKey": self.ch_key,
                "time": timestamp,
                "requestId": str(uuid.uuid4()),
                "deviceId": self.device_id,
                "appRnVersion": DEFAULT_TUYA_APP_RN_VERSION,
                "o": "true",
                "sdkVersion": DEFAULT_TUYA_SDK_VERSION,
                "timeZoneId": "America/New_York",
            }

            if post_str:
                wire_params["postData"] = post_str
            if requires_session and self.sid:
                wire_params["sid"] = self.sid
            if extra_params:
                for k, v in extra_params.items():
                    if v is not None:
                        wire_params[k] = str(v)

            sig = self.generate_signature(wire_params, use_hmac=True)
            url_query_params = {
                k: v for k, v in wire_params.items() if k not in ("postData", "time", "sign")
            }
            form_body = {**wire_params, "sign": sig}

            try:
                resp = self.session.post(
                    self.base_url,
                    params=url_query_params,
                    data=form_body,
                    headers=headers,
                    timeout=self.timeout,
                )
            except requests.Timeout as exc:
                if attempt < len(backoff_schedule):
                    delay = backoff_schedule[attempt]
                    logger.warning(
                        "Tuya gateway timeout on '%s' (attempt %d/%d); retrying in %.1fs...",
                        action,
                        attempt + 1,
                        max_attempts,
                        delay,
                    )
                    time.sleep(delay)
                    continue
                raise TuyaApiError("TIMEOUT", f"Tuya gateway request timed out: {exc}") from exc
            except requests.ConnectionError as exc:
                if attempt < len(backoff_schedule):
                    delay = backoff_schedule[attempt]
                    logger.warning(
                        "Tuya gateway connection error on '%s' (attempt %d/%d); retrying in %.1fs...",
                        action,
                        attempt + 1,
                        max_attempts,
                        delay,
                    )
                    time.sleep(delay)
                    continue
                raise TuyaApiError("NETWORK_ERROR", f"Tuya gateway request failed: {exc}") from exc
            except requests.RequestException as exc:
                raise TuyaApiError("NETWORK_ERROR", f"Tuya gateway request failed: {exc}") from exc

            status_code = getattr(resp, "status_code", 200)
            if isinstance(status_code, int) and status_code in (502, 503, 504):
                if attempt < len(backoff_schedule):
                    delay = backoff_schedule[attempt]
                    logger.warning(
                        "Tuya gateway returned HTTP %d on '%s' (attempt %d/%d); retrying in %.1fs...",
                        status_code,
                        action,
                        attempt + 1,
                        max_attempts,
                        delay,
                    )
                    time.sleep(delay)
                    continue
                raise TuyaApiError(
                    "NETWORK_ERROR",
                    f"Tuya gateway returned HTTP {status_code} after {max_attempts} attempts",
                )

            try:
                resp_json = resp.json()
            except (json.JSONDecodeError, ValueError) as exc:
                raise TuyaApiError("INVALID_JSON", f"Invalid JSON received from Tuya gateway: {exc}") from exc
            break

        if not resp_json or not resp_json.get("success", False):
            err_code = str((resp_json or {}).get("errorCode", "ERROR"))
            err_msg = str((resp_json or {}).get("errorMsg", "Unknown Tuya error"))
            if (
                requires_session
                and allow_session_heal
                and not _is_retry
                and err_code in TUYA_SESSION_EXPIRED_CODES
            ):
                if self._auto_heal_session(failed_sid=active_sid, action=action, err_code=err_code):
                    return self.request(
                        action=action,
                        version=version,
                        post_data=post_data,
                        requires_session=requires_session,
                        extra_params=extra_params,
                        _is_retry=True,
                        allow_session_heal=False,
                    )
            raise TuyaApiError(err_code, err_msg)

        return resp_json.get("result")

    # ------------------------------------------------------------------------
    # Authentication APIs
    # ------------------------------------------------------------------------
    def get_token(
        self,
        username: Optional[str] = None,
        country_code: Optional[str] = None,
    ) -> Dict[str, str]:
        """Fetches TokenBean with dynamic RSA modulus and exponent from Tuya.

        Action: thing.m.user.username.token.get (v2.0) -> smartlife.m.user.username.token.get
        """
        if not self._cache_loaded and not username and not self.username:
            with self._auth_lock:
                if not self._cache_loaded:
                    self._load_from_cache()

        target_username = username or self.username
        target_country = str(country_code or self.country_code or "1")

        if not target_username:
            raise ValueError("Username required for Tuya token acquisition")

        post_data = {
            "countryCode": target_country,
            "username": target_username,
            "isUid": False,
        }
        res = self.request(
            action="thing.m.user.username.token.get",
            version="2.0",
            post_data=post_data,
            requires_session=False,
        )

        return {
            "token": res.get("token", ""),
            "publicKey": res.get("publicKey", ""),
            "exponent": str(res.get("exponent", "65537")),
        }

    def login(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        country_code: Optional[str] = None,
        use_cache: bool = True,
    ) -> Dict[str, Any]:
        """Authenticates against Tuya Mobile Gateway using email and password.

        If use_cache=True and a valid cached session exists with active sid,
        reuses cached session without network login.
        Otherwise executes dynamic RSA PKCS#1 v1.5 password encryption and
        calls thing.m.user.email.password.login.
        """
        with self._auth_lock:
            # If cache loading was deferred during __init__, load cached credentials lazily
            if not self._cache_loaded and (use_cache or not (username or self.username)):
                self._load_from_cache()

            target_username = username or self.username
            target_password = password or self.password
            target_country = str(country_code or self.country_code or "1")

            # Check session cache first
            if use_cache:
                mgr = SessionManager(self.session_cache_path)
                cached_tuya = mgr.get_tuya_session()
                cached_sid = cached_tuya.get("sid")
                cached_expires = cached_tuya.get("expires_at", 0)
                now = int(time.time())

                # If active valid session is cached and not expired
                if cached_sid and (cached_expires == 0 or cached_expires > now + 60):
                    self.sid = cached_sid
                    self.ecode = cached_tuya.get("ecode") or self.ecode
                    self.uid = cached_tuya.get("uid") or self.uid
                    self.home_id = cached_tuya.get("home_id") or self.home_id
                    self.home_name = cached_tuya.get("home_name") or self.home_name
                    logger.info("Loaded active Tuya session from cache (zero network calls)")
                    return {
                        "sid": self.sid,
                        "ecode": self.ecode,
                        "uid": self.uid,
                        "cached": True,
                    }

            if not target_username:
                raise ValueError("Tuya username/email required for login")
            if not target_password and not self.password_md5:
                raise ValueError("Tuya password required for login")

            # Step 1: Acquire ephemeral RSA public key token
            token_bean = self.get_token(target_username, target_country)

            # Step 2: Compute lowercase MD5 of plaintext password (or use cached MD5)
            if target_password:
                pw_md5 = (
                    hashlib.md5(target_password.encode("utf-8"))
                    .hexdigest()
                    .lower()
                    .encode("utf-8")
                )
            else:
                pw_md5 = str(self.password_md5).strip().lower().encode("utf-8")

            # Step 3: Encrypt password MD5 with RSA PKCS#1 v1.5
            encrypted_pw = self.rsa_encrypt_pkcs1(
                token_bean["publicKey"],
                token_bean["exponent"],
                pw_md5,
            )

            # Step 4: Submit email password login
            post_data = {
                "countryCode": target_country,
                "email": target_username,
                "passwd": encrypted_pw,
                "token": token_bean["token"],
                "ifencrypt": 1,
                "options": '{"group": 1}',
            }

            res = self.request(
                action="thing.m.user.email.password.login",
                version="3.0",
                post_data=post_data,
                requires_session=False,
            )

            self.sid = res.get("sid")
            self.ecode = res.get("ecode")
            self.uid = res.get("uid")
            self.username = target_username
            if target_password:
                self.password = target_password
            self.country_code = target_country

            # Step 5: Persist Tuya session to session cache
            try:
                mgr = SessionManager(self.session_cache_path)
                mgr.update_tuya_session(
                    sid=self.sid,
                    expires_in=res.get("expiresIn") or 2592000,
                    uid=self.uid,
                    ecode=self.ecode,
                )
                logger.info("Tuya session credentials persisted to cache")
            except Exception as exc:
                logger.warning("Could not persist Tuya session cache: %s", exc)

            return res

    # ------------------------------------------------------------------------
    # Home & Device Discovery APIs
    # ------------------------------------------------------------------------
    def query_home_list(self) -> List[Dict[str, Any]]:
        """Queries registered Tuya homes for the user.

        Action: m.life.group.location.list (normalized to smartlife.m.location.list v2.1)
        """
        res = self.request(
            action="m.life.group.location.list",
            version="7.0",
            post_data={},
            requires_session=True,
        )

        homes: List[Dict[str, Any]] = []
        if isinstance(res, list):
            homes = res
        elif isinstance(res, dict):
            homes = res.get("homeList") or res.get("homes") or []

        if homes:
            first_home = homes[0]
            self.home_id = (
                first_home.get("homeId")
                or first_home.get("groupId")
                or first_home.get("gid")
            )
            self.home_name = first_home.get("name")
            try:
                mgr = SessionManager(self.session_cache_path)
                mgr.update_tuya_session(
                    sid=self.sid or "",
                    uid=self.uid,
                    ecode=self.ecode,
                    home_id=self.home_id,
                    home_name=self.home_name,
                )
            except Exception:
                pass

        return homes

    def list_homes(self) -> List[Dict[str, Any]]:
        """Canonical alias for query_home_list."""
        return self.query_home_list()

    def get_home_device_list(
        self,
        home_id: Optional[int] = None,
        enrich_metadata: bool = False,
        allow_session_heal: bool = True,
    ) -> List[TuyaDevice]:
        """Retrieves list of devices registered under target Tuya home.

        Uses a single lightweight call (m.life.my.group.device.list v2.2 -> smartlife.m.my.group.device.list v2.1)
        by default and merges cached category/RSSI metadata from .session_cache.json to avoid hitting
        Tuya with 4-5 requests per refresh. Optional deep enrichment (v1.0 + ext.prop + RSSI) runs only
        when enrich_metadata=True.
        """
        homes_list: List[Dict[str, Any]] = []
        target_home_id = home_id or self.home_id
        if target_home_id is None:
            homes_list = self.query_home_list()
            if homes_list:
                target_home_id = self.home_id
            else:
                target_home_id = 0

        post_data = {"gid": int(target_home_id)}
        res = self.request(
            action="m.life.my.group.device.list",
            version="2.2",
            post_data=post_data,
            requires_session=True,
            allow_session_heal=allow_session_heal,
        )

        raw_devices: List[Dict[str, Any]] = []
        if isinstance(res, list):
            raw_devices = res
        elif isinstance(res, dict):
            raw_devices = (
                res.get("devices")
                or res.get("deviceRespBeen")
                or res.get("deviceList")
                or []
            )

        # If the user has multiple homes and the primary home was empty, scan remaining homes
        if not raw_devices and home_id is None and len(homes_list) > 1:
            for extra_home in homes_list[1:]:
                extra_gid = (
                    extra_home.get("homeId")
                    or extra_home.get("groupId")
                    or extra_home.get("gid")
                )
                if not extra_gid:
                    continue
                try:
                    extra_res = self.request(
                        action="m.life.my.group.device.list",
                        version="2.2",
                        post_data={"gid": int(extra_gid)},
                        requires_session=True,
                        allow_session_heal=allow_session_heal,
                    )
                    extra_devs = (
                        extra_res
                        if isinstance(extra_res, list)
                        else (
                            extra_res.get("devices")
                            or extra_res.get("deviceRespBeen")
                            or extra_res.get("deviceList")
                            or []
                        )
                        if isinstance(extra_res, dict)
                        else []
                    )
                    if extra_devs:
                        raw_devices.extend(extra_devs)
                        target_home_id = int(extra_gid)
                        self.home_id = int(extra_gid)
                        self.home_name = extra_home.get("name") or self.home_name
                        post_data = {"gid": int(target_home_id)}
                except Exception:
                    pass

        # Merge cached static metadata (category, categoryCode, mac, localKey, uuid, wifiRssi, etc.)
        # from .session_cache.json with zero extra network calls
        if self.mock_transport is None and raw_devices:
            try:
                mgr = SessionManager(self.session_cache_path)
                cached_devs = mgr.get_tuya_session().get("devices") or []
                cached_by_id = {
                    str(cd.get("devId")): cd
                    for cd in cached_devs
                    if isinstance(cd, dict) and cd.get("devId")
                }
                for d in raw_devices:
                    if not isinstance(d, dict):
                        continue
                    did = str(d.get("devId") or "")
                    cd = cached_by_id.get(did)
                    if isinstance(cd, dict):
                        for preserve_key in (
                            "category",
                            "categoryCode",
                            "mac",
                            "localKey",
                            "secKey",
                            "uuid",
                            "nodeId",
                            "parentId",
                            "wifiRssi",
                            "wifiSsid",
                            "hardwareModel",
                            "lastSeenMs",
                        ):
                            if d.get(preserve_key) is None and cd.get(preserve_key) is not None:
                                d[preserve_key] = cd[preserve_key]
            except Exception:
                pass

        needs_v1_enrichment = enrich_metadata or any(
            isinstance(d, dict) and (not d.get("category") or not d.get("mac") or not d.get("localKey"))
            for d in raw_devices
        )

        # Deep metadata enrichment (when enrich_metadata=True or when BLE keys/MAC/category are missing)
        if self.mock_transport is None and raw_devices and needs_v1_enrichment:
            try:
                v1_res = self.request(
                    action="thing.m.my.group.device.list",
                    version="1.0",
                    post_data=post_data,
                    requires_session=True,
                    extra_params={"gid": int(target_home_id)},
                )
                if isinstance(v1_res, list):
                    v1_by_id = {
                        str(d.get("devId")): d
                        for d in v1_res
                        if isinstance(d, dict) and d.get("devId")
                    }
                    merged_devices: List[Dict[str, Any]] = []
                    for d in raw_devices:
                        if not isinstance(d, dict):
                            continue
                        did = str(d.get("devId") or "")
                        v1_d = v1_by_id.get(did, {})
                        merged = dict(v1_d)
                        merged.update(d)
                        merged_devices.append(merged)
                    raw_devices = merged_devices
            except Exception as exc:
                logger.debug("Optional v1.0 device enrichment skipped: %s", exc)

        if self.mock_transport is None and raw_devices and enrich_metadata:

            try:
                dev_id_list = [
                    str(d.get("devId"))
                    for d in raw_devices
                    if isinstance(d, dict) and d.get("devId")
                ]
                if dev_id_list:
                    ext_props = self.request(
                        action="thing.m.device.ext.prop.batch.get",
                        version="1.1",
                        post_data={
                            "devIds": json.dumps(dev_id_list, separators=(",", ":")),
                            "keys": '["cloudConnectLastUpdateTime"]',
                        },
                        requires_session=True,
                    )
                    if isinstance(ext_props, dict):
                        for d in raw_devices:
                            if not isinstance(d, dict):
                                continue
                            did = str(d.get("devId") or "")
                            ep = ext_props.get(did)
                            if isinstance(ep, dict) and ep.get("cloudConnectLastUpdateTime"):
                                d["cloudConnectLastUpdateTime"] = ep["cloudConnectLastUpdateTime"]
            except Exception as exc:
                logger.debug("Optional ext.prop.batch.get enrichment skipped: %s", exc)

            for d in raw_devices:
                if not isinstance(d, dict):
                    continue
                did = str(d.get("devId") or "")
                cat = str(d.get("category") or "")
                if cat in ("cz", "wg2", "bh") or did == "ebexamplegw1a2b3c4d5e6":
                    try:
                        rssi_info = self.query_device_rssi(did, rssi_type=1)
                        if isinstance(rssi_info, dict) and rssi_info.get("value") is not None:
                            d["wifiRssi"] = int(rssi_info["value"])
                    except Exception as exc:
                        logger.debug("Optional gateway RSSI query skipped for %s: %s", did, exc)

        devices = [TuyaDevice.from_dict(d) for d in raw_devices if isinstance(d, dict)]

        # Persist discovered devices to session cache when running against live gateway
        if self.mock_transport is None and devices:
            try:
                mgr = SessionManager(self.session_cache_path)
                mgr.update_tuya_session(
                    sid=self.sid or "",
                    uid=self.uid,
                    ecode=self.ecode,
                    home_id=int(target_home_id) if target_home_id else self.home_id,
                    home_name=self.home_name,
                    devices=[d.to_dict() for d in devices],
                )
            except Exception as exc:
                logger.debug("Could not cache discovered Tuya devices: %s", exc)

        return devices

    def query_device_rssi(
        self,
        dev_id: str,
        rssi_type: int = 1,
    ) -> Dict[str, Any]:
        """Queries live Wi-Fi / network RSSI signal strength (dBm) for a Tuya device.

        Action: thing.m.device.rssi.info.query (v1.0) -> smartlife.m.device.rssi.info.query
        rssi_type=1 queries NETWORK RSSI (e.g. -70 dBm on Dyson Smart Plug BLE Gateway);
        rssi_type=0 queries OTA RSSI.
        """
        res = self.request(
            action="thing.m.device.rssi.info.query",
            version="1.0",
            post_data={"devId": dev_id, "type": int(rssi_type)},
            requires_session=True,
        )
        return dict(res) if isinstance(res, dict) else {"value": res}

    def list_devices(
        self,
        home_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Returns raw device dictionaries for target home."""
        devices = self.get_home_device_list(home_id)
        return [d.to_dict() for d in devices]

    def get_device_dps(
        self,
        dev_id: str,
        home_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Retrieves current DP state map for specific device ID."""
        devices = self.get_home_device_list(home_id)
        for dev in devices:
            if dev.dev_id == dev_id:
                return dict(dev.dps)
        raise TuyaApiError("DEVICE_NOT_FOUND", f"Device ID '{dev_id}' not found in home")

    @staticmethod
    def build_ble_unlock_check_payload(
        dps: Dict[str, Any],
        unlock: bool = True,
        timestamp: Optional[int] = None,
        dev_id: Optional[str] = None,
    ) -> str:
        """Constructs the 19-byte base64 DP 71 (ble_unlock_check) frame for jtmspro BLE locks.

        Frame layout (verified from live device DPs 70, 71, 73 on livingroom, bathroom, and K11):
          - Bytes 0..11 (12B):
              - On K01 2 (livingroom ebexamplelock001): 0xFFFF + 0x0001 + 8-byte ASCII key ("12345678")
                (matching live capture //8AATEyMzQ1Njc4AWrmKtsAAA==)
              - Or if DP 71 already holds a 19-byte frame, reuses its exact 12-byte header prefix
              - Otherwise extracts key/slot from DP 70 / DP 73
          - Byte 12 (1B)     : 0x01 for UNLOCK, 0x00 for LOCK
          - Bytes 13..16 (4B): Big-endian uint32 Unix timestamp in seconds
          - Bytes 17..18 (2B): 0x0000 trailer
        """
        import base64

        prefix = b"\xff\xff\x00\x0112345678"
        if dev_id == "ebexamplelock002":
            prefix = b"\x00\x02\xff\xff12345678"
        elif dev_id == "ebexamplelock003":
            prefix = b"\x00\x03\xff\xff87654321"

        dp71_b64 = dps.get("71")
        parsed_prefix: Optional[bytes] = None
        if isinstance(dp71_b64, str) and len(dp71_b64) >= 20:
            try:
                raw_71 = base64.b64decode(dp71_b64)
                if len(raw_71) >= 12 and raw_71[4:12] != b"\x00" * 8:
                    parsed_prefix = raw_71[:12]
            except Exception:
                pass

        if parsed_prefix is None:
            for seed_key in ("73", "70"):
                seed_val = dps.get(seed_key)
                if not isinstance(seed_val, str) or not seed_val:
                    continue
                try:
                    raw_seed: Optional[bytes] = None
                    val_clean = seed_val.strip()
                    if len(val_clean) >= 24 and all(c in "0123456789abcdefABCDEF" for c in val_clean):
                        try:
                            raw_seed = bytes.fromhex(val_clean)
                        except Exception:
                            raw_seed = None
                    if raw_seed is None:
                        raw_seed = base64.b64decode(val_clean)

                    if raw_seed and len(raw_seed) >= 17 and raw_seed[5:7] == b"\xff\xff" and raw_seed[9:17] != b"\x00" * 8:
                        # Standard 17-byte Tuya DP 73 (e.g. AAAAAf///wABMTIzNDU2Nzg= -> bytes 5..17 is \xff\xff + slot + 8B key)
                        parsed_prefix = raw_seed[5:17]
                        break
                    elif raw_seed and len(raw_seed) >= 18 and raw_seed[6:8] == b"\xff\xff" and raw_seed[10:18] != b"\x00" * 8:
                        parsed_prefix = raw_seed[6:18]
                        break
                    elif raw_seed and len(raw_seed) >= 12 and raw_seed[4:12] != b"\x00" * 8:
                        if dev_id == "ebexamplelock001" or (len(raw_seed) >= 15 and raw_seed[13:15] == b"\xff\xff"):
                            parsed_prefix = raw_seed[2:4] + raw_seed[0:2] + raw_seed[4:12]
                        else:
                            parsed_prefix = raw_seed[:12]
                        break
                except Exception:
                    pass

        if parsed_prefix is not None:
            prefix = parsed_prefix

        ts = int(timestamp if timestamp is not None else time.time())
        op_byte = b"\x01" if unlock else b"\x00"
        frame = prefix + op_byte + ts.to_bytes(4, byteorder="big") + b"\x00\x00"
        return base64.b64encode(frame).decode("ascii")

    def set_auto_lock(
        self,
        dev_id: str,
        auto_lock: bool,
        auto_lock_time: Optional[int] = None,
        gw_id: Optional[str] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Controls the 'Auto Lock' / 'Keep Unlocked (Passage Mode)' setting (DP 33 & DP 36).

        Verified from live capture on livingroom (ebexamplelock001):
          - auto_lock=False (DP 33 = False): Disables Auto-Lock and puts the lock into
            'Keep Unlocked / Passage Mode' (within ~230ms DP 47 lock_motor_state becomes True / UNLOCKED
            and stays unlocked indefinitely without 5s auto-relock).
          - auto_lock=True (DP 33 = True): Enables Auto-Lock (re-locks automatically after DP 36 seconds,
            default 5s on livingroom / 8s on bathroom) so Unlock acts as a momentary unlock.
        """
        dps_payload: Dict[str, Any] = {"33": bool(auto_lock)}
        if auto_lock_time is not None and int(auto_lock_time) > 0:
            dps_payload["36"] = int(auto_lock_time)
        return self.publish_dp(
            dev_id=dev_id,
            dps=dps_payload,
            gw_id=gw_id,
            dry_run=dry_run,
        )

    def publish_dp(
        self,
        dev_id: str,
        dps: Dict[str, Any],
        gw_id: Optional[str] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Publishes DP command to target device.

        STRICT SAFETY ENFORCEMENT:
        - Blocks destructive/credential mutation DPs (DP 2 unlock_method_delete,
          DP 3 unlock_method_modify, DP 51 temporary_password_creat, or raw DP 1
          unlock_method_create) on jtmspro locks.
        - If dry_run=True, simulates payload without network dispatch.
        """
        FORBIDDEN_JTMSPRO_DPS = {"2", "3", "51"}
        for bad_dp in FORBIDDEN_JTMSPRO_DPS.intersection(dps.keys()):
            raise SafetyBarrierViolation(
                f"DP {bad_dp} modifies or deletes lock credentials/methods and is permanently blocked.",
                endpoint=f"thing.m.device.dp.publish(dp={bad_dp})",
                category="CREDENTIAL_MUTATION",
            )
        if "1" in dps and isinstance(dps["1"], str):
            raise SafetyBarrierViolation(
                "Raw DP 1 (unlock_method_create) is permanently blocked on jtmspro locks.",
                endpoint="thing.m.device.dp.publish(dp=1:raw)",
                category="CREDENTIAL_MUTATION",
            )

        effective_dps = dict(dps)
        cached_dev_dps: Dict[str, Any] = {}
        conn_status: int = 2
        ble_signal_state: str = "STRONG_ACTIVE_GATT"
        cached_is_plug: bool = False
        try:
            mgr = SessionManager(self.session_cache_path)
            tuya_sec = mgr.get_tuya_session()
            for cd in tuya_sec.get("devices") or []:
                if isinstance(cd, dict) and cd.get("devId") == dev_id:
                    cached_dev_dps = cd.get("dps") or {}
                    if not gw_id and cd.get("parentId"):
                        gw_id = str(cd["parentId"])
                    tdev_cached = TuyaDevice.from_dict(cd)
                    cached_is_plug = bool(
                        tdev_cached.category in PLUG_SWITCH_CATEGORIES
                        and tdev_cached.is_gateway
                        and not tdev_cached.is_lock
                    )
                    conn_status = tdev_cached.connection_status
                    ble_signal_state = tdev_cached.ble_signal_state
                    break
        except Exception:
            pass

        # For real jtmspro BLE locks (e.g. ebexamplelock001, ebexamplelock002, ebexamplelock003),
        # translate generic boolean {"1": False/True} lock/unlock intent to DP 71 (ble_unlock_check)
        # so DP 1 (unlock_method_create) is never written on jtmspro hardware.
        # Smart plugs / BLE gateways (Tuya category "cz") use DP 1 as the plain boolean
        # outlet relay (switch_1) and must NEVER be rewritten into a lock DP 71 frame.
        if (
            "1" in effective_dps
            and isinstance(effective_dps["1"], bool)
            and dev_id.startswith("eb")
            and dev_id != "ebexamplegw1a2b3c4d5e6"
            and not cached_is_plug
        ):
            want_unlock = not effective_dps.pop("1")
            effective_dps["71"] = self.build_ble_unlock_check_payload(
                cached_dev_dps, unlock=want_unlock, dev_id=dev_id
            )
            # When locking a jtmspro lock that had Auto-Lock (DP 33) turned OFF (Keep Unlocked mode),
            # also set DP 33 = True so the clutch closes and locks.
            if not want_unlock and "33" not in effective_dps:
                effective_dps["33"] = True

        payload: Dict[str, Any] = {
            "devId": dev_id,
            "dps": json.dumps(effective_dps, separators=(",", ":")),
        }
        if gw_id:
            payload["gwId"] = gw_id

        if dry_run:
            logger.info("Dry-run DP publish suppressed live transmission: %s", payload)
            return {
                "dry_run": True,
                "action": "thing.m.device.dp.publish",
                "payload": payload,
                "dps": effective_dps,
                "connectionStatus": conn_status,
                "bleSignalState": ble_signal_state,
                "success": True,
            }

        if not self.sid:
            with self._auth_lock:
                self._load_from_cache()
                if not self.sid and self.username and (self.password or self.password_md5):
                    try:
                        self.login(use_cache=True)
                        if not self.sid:
                            self.login(use_cache=False)
                    except Exception as auth_exc:
                        logger.warning("Auto-login before publish_dp failed: %s", auth_exc)

        res_v1 = self.request(
            action="thing.m.device.dp.publish",
            version="1.0",
            post_data=payload,
            requires_session=True,
        )

        # When BLE lock has connectionStatus == 0 (weak BLE signal / standby like bathroom or K11),
        # also dispatch DPCacheBusiness thing.m.device.dp.publish v2.0 so Dyson Smart Plug BLE Gateway
        # caches the command for the next BLE advertisement wake-up.
        dp_cache_queued = False
        if (
            conn_status == 0
            and dev_id.startswith("eb")
            and gw_id
            and dev_id != gw_id
        ):
            cache_payload = {
                "gwId": gw_id,
                "devId": dev_id,
                "dps": payload["dps"],
                "dpCacheType": 0,
                "validity": 300,
                "reason": "offline_device",
            }
            try:
                self.request(
                    action="thing.m.device.dp.publish",
                    version="2.0",
                    post_data=cache_payload,
                    requires_session=True,
                )
                dp_cache_queued = True
            except Exception as cache_exc:
                logger.debug(
                    "Optional v2.0 DPCacheBusiness queue for %s returned: %s",
                    dev_id,
                    cache_exc,
                )

        if isinstance(res_v1, dict):
            out = dict(res_v1)
            out.setdefault("success", True)
            out.setdefault("action", "thing.m.device.dp.publish")
            out.setdefault("devId", dev_id)
            out.setdefault("gwId", gw_id)
            out.setdefault("connectionStatus", conn_status)
            out.setdefault("bleSignalState", ble_signal_state)
            out.setdefault("dpCacheQueued", dp_cache_queued)
            return out

        return {
            "success": bool(res_v1) if res_v1 is not None else True,
            "result": res_v1,
            "action": "thing.m.device.dp.publish",
            "devId": dev_id,
            "gwId": gw_id,
            "dps": effective_dps,
            "connectionStatus": conn_status,
            "bleSignalState": ble_signal_state,
            "dpCacheQueued": dp_cache_queued,
        }

    # ------------------------------------------------------------------------
    # Smart Plug BLE Gateway outlet relay (Tuya category "cz", DP 1 / switch_1)
    # ------------------------------------------------------------------------
    def _find_cached_device_record(self, dev_id: str) -> Optional[Dict[str, Any]]:
        """Returns the cached Tuya device dict for dev_id from the session cache, if any."""
        try:
            mgr = SessionManager(self.session_cache_path)
            tuya_sec = mgr.get_tuya_session() or {}
            for cd in tuya_sec.get("devices") or []:
                if isinstance(cd, dict) and str(cd.get("devId") or cd.get("id") or "") == dev_id:
                    return cd
        except Exception:
            pass
        return None

    @staticmethod
    def assert_plug_outlet_target(meta: Optional[Dict[str, Any]], dev_id: str) -> TuyaDevice:
        """Hard guard: raises SafetyBarrierViolation unless meta describes a cz smart plug.

        A device is accepted ONLY if ALL hold:
          - metadata exists and its devId matches the requested dev_id
          - Tuya category is in PLUG_SWITCH_CATEGORIES ("cz")
          - TuyaDevice.is_gateway is True and TuyaDevice.is_lock is False
          - it has no parent gateway (a plug is a top-level Wi-Fi device, locks hang off it)
          - none of the lock-only DPs (21, 47, 70, 71, 73) are present
          - DP 1 (switch_1) is a boolean
        """
        endpoint = f"thing.m.device.dp.publish(plug_outlet:{dev_id})"
        if not isinstance(meta, dict) or not meta:
            raise SafetyBarrierViolation(
                f"Refusing plug outlet publish: device '{dev_id}' is not in the discovered device cache.",
                endpoint=endpoint,
                category="PLUG_GUARD",
            )
        tdev = TuyaDevice.from_dict(meta)
        if str(tdev.dev_id) != str(dev_id):
            raise SafetyBarrierViolation(
                f"Refusing plug outlet publish: metadata devId mismatch for '{dev_id}'.",
                endpoint=endpoint,
                category="PLUG_GUARD",
            )
        lock_dps = LOCK_ONLY_DPS.intersection(str(k) for k in (tdev.dps or {}).keys())
        if tdev.is_lock or lock_dps:
            raise SafetyBarrierViolation(
                f"Refusing plug outlet publish: '{dev_id}' is a door lock (category={tdev.category!r}). "
                "Plug outlet control never actuates locks.",
                endpoint=endpoint,
                category="LOCK_ACTUATION_BLOCKED",
            )
        if tdev.category not in PLUG_SWITCH_CATEGORIES or not tdev.is_gateway:
            raise SafetyBarrierViolation(
                f"Refusing plug outlet publish: '{dev_id}' category {tdev.category!r} is not a smart plug gateway.",
                endpoint=endpoint,
                category="PLUG_GUARD",
            )
        if tdev.parent_id:
            raise SafetyBarrierViolation(
                f"Refusing plug outlet publish: '{dev_id}' is a sub-device of gateway {tdev.parent_id}.",
                endpoint=endpoint,
                category="PLUG_GUARD",
            )
        dp1 = (tdev.dps or {}).get(PLUG_OUTLET_DP)
        if dp1 is None:
            dp1 = (tdev.dp_codes or {}).get(PLUG_OUTLET_CODE)
        if not isinstance(dp1, bool):
            raise SafetyBarrierViolation(
                f"Refusing plug outlet publish: '{dev_id}' has no boolean DP 1 / switch_1.",
                endpoint=endpoint,
                category="PLUG_GUARD",
            )
        return tdev

    def publish_plug_switch(
        self,
        dev_id: str,
        on: bool,
        device_meta: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Turns a smart plug's outlet relay on/off by publishing ONLY {"1": <bool>}.

        Differences from the lock path in publish_dp():
          - Never rewrites DP 1 into a DP 71 ble_unlock_check frame (that is lock-only).
          - Never adds DP 33 / auto-lock side effects.
          - Never sends gwId (the plug IS the gateway) and never queues the v2.0
            DPCacheBusiness offline-subdevice command.
          - Refuses (SafetyBarrierViolation, zero network I/O) unless the target is a
            verified cz smart plug; door locks are always refused.
        """
        if not isinstance(on, bool):
            raise SafetyBarrierViolation(
                "Plug outlet state must be a boolean.",
                endpoint="thing.m.device.dp.publish(plug_outlet)",
                category="PLUG_GUARD",
            )
        dev_id = str(dev_id or "").strip()
        cached = self._find_cached_device_record(dev_id)
        # Cache is authoritative when present; fall back to caller-provided metadata.
        meta = cached if cached is not None else device_meta
        self.assert_plug_outlet_target(meta, dev_id)
        if cached is not None and device_meta is not None:
            # Defense in depth: both views must agree this is a plug.
            self.assert_plug_outlet_target(device_meta, dev_id)

        dps_out: Dict[str, Any] = {PLUG_OUTLET_DP: bool(on)}
        payload: Dict[str, Any] = {
            "devId": dev_id,
            "dps": json.dumps(dps_out, separators=(",", ":")),
        }
        if dry_run:
            logger.info("Dry-run plug outlet publish suppressed: %s", payload)
            return {
                "dry_run": True,
                "success": True,
                "action": "thing.m.device.dp.publish",
                "payload": payload,
                "dps": dps_out,
                "devId": dev_id,
            }

        if not self.sid:
            with self._auth_lock:
                self._load_from_cache()
                if not self.sid and self.username and (self.password or self.password_md5):
                    try:
                        self.login(use_cache=True)
                        if not self.sid:
                            self.login(use_cache=False)
                    except Exception as auth_exc:
                        logger.warning("Auto-login before plug outlet publish failed: %s", auth_exc)

        logger.info("Publishing plug outlet DP 1=%s to %s", bool(on), dev_id)
        res = self.request(
            action="thing.m.device.dp.publish",
            version="1.0",
            post_data=payload,
            requires_session=True,
        )
        out: Dict[str, Any] = dict(res) if isinstance(res, dict) else {"result": res}
        out.setdefault("success", bool(res) if res is not None else True)
        out["action"] = "thing.m.device.dp.publish"
        out["devId"] = dev_id
        out["dps"] = dps_out
        return out


# Canonical alias for compatibility
TuyaMobileClient = TuyaClient
