"""Session Cache Manager for GeekSmart and Tuya credentials.

Provides atomic read/write for .session_cache.json with 0o600 permissions,
preventing cloud rate limiting and securing credential persistence across
both GeekSmart and Tuya ecosystems.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger("geeksmart.session")

_SESSION_FILE_LOCK = threading.RLock()

_CURR = os.path.dirname(os.path.abspath(__file__))
if os.path.basename(_CURR) == "core":
    _PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(_CURR)))
else:
    _PROJECT_ROOT = os.path.dirname(_CURR)
DEFAULT_CACHE_PATH = os.environ.get(
    "GEEK_DOOR_SESSION_CACHE",
    os.environ.get(
        "SESSION_CACHE_PATH",
        os.path.join(_PROJECT_ROOT, ".session_cache.json"),
    ),
)

DEFAULT_HARDWARE_DEVICES: List[Dict[str, Any]] = [
    {
        "devId": "ebexamplegw1a2b3c4d5e6",
        "name": "Dyson",
        "productId": "k6i993927610903a",
        "category": "cz",
        "iconUrl": "https://images.tuyaus.com/smart/icon/ay1541645512259wH31g/0371fb6ba80ed1f6ca9a5eb42dcffce3.png",
        "isOnline": True,
        "dps": {
            "1": True,
            "9": 0,
            "38": "memory",
            "41": False,
            "42": "",
            "43": "",
            "45": 0,
        },
        "dpCodes": {
            "switch_1": True,
            "countdown_1": 0,
            "relay_status": "memory",
            "light_mode": "relay",
            "child_lock": False,
            "cycle_time": "",
            "random_time": "",
            "fault": 0,
        },
        "parentId": None,
        "devAttribute": 515,
        "mac": "000000000000",
        "uuid": "fakeuuid1a2b0a01",
        "meshId": None,
        "nodeId": None,
        "raw": {
            "ability": 0,
            "bleMeshVersion": 0,
            "bv": "40.00",
            "cadv": "1.0.2",
            "devAttribute": 515,
            "devId": "ebexamplegw1a2b3c4d5e6",
            "gwType": "s",
            "ip": "0.0.0.0",
            "lat": "0.0000",
            "lon": "0.0000",
            "mac": "000000000000",
            "name": "Dyson",
            "online": True,
            "productId": "k6i993927610903a",
            "pv": "2.2",
            "runtimeEnv": "prod",
            "sv": "1.1.7",
            "timeZone": "-05:00",
            "uuid": "fakeuuid1a2b0a01",
            "verSw": "1.1.7",
            "wifiEnable": True,
        },
    },
    {
        "devId": "ebexamplelock001",
        "name": "livingroom",
        "productId": "a0wnqgxs",
        "category": "jtmspro",
        "iconUrl": "https://images.tuyaus.com/smart/icon/bay1617864004789265P/1ed8bc3f57cd0fb7b8d56d8c5286bf7e.png",
        "isOnline": True,
        "dps": {
            "8": 100,
            "9": "normal",
            "12": 1,
            "19": 1,
            "21": 2,
            "31": "high",
            "33": False,
            "36": 5,
            "44": 0,
            "46": False,
            "47": True,
            "54": "AQA=",
            "62": 0,
            "63": 1,
            "69": "BAAA",
            "70": "AQH//wAB",
            "71": "//8AATEyMzQ1Njc4AAAAAAAAAFI=",
            "73": "AAAAAf///wABMTIzNDU2Nzg=",
        },
        "dpCodes": {
            "residual_electricity": 100,
            "battery_state": "normal",
            "unlock_fingerprint": 1,
            "unlock_ble": 1,
            "alarm_lock": 2,
            "beep_volume": "high",
            "automatic_lock": False,
            "auto_lock_time": 5,
            "rtc_lock": 0,
            "manual_lock": False,
            "lock_motor_state": True,
            "synch_method": "AQA=",
            "unlock_phone_remote": 0,
            "unlock_voice_remote": 1,
            "record": "BAAA",
            "check_code_set": "AQH//wAB",
            "ble_unlock_check": "//8AATEyMzQ1Njc4AAAAAAAAAFI=",
            "remote_pd_setkey_check": "AAAAAf///wABMTIzNDU2Nzg=",
        },
        "parentId": "ebexamplegw1a2b3c4d5e6",
        "devAttribute": 0,
        "mac": "000000000001",
        "uuid": "fakeuuid1a2b0a02",
        "meshId": "ebexamplegw1a2b3c4d5e6",
        "nodeId": "0215",
        "raw": {
            "ability": 5,
            "devAttribute": 0,
            "devId": "ebexamplelock001",
            "gwType": "b",
            "mac": "000000000001",
            "meshId": "ebexamplegw1a2b3c4d5e6",
            "name": "livingroom",
            "nodeId": "0215",
            "online": True,
            "parentId": "ebexamplegw1a2b3c4d5e6",
            "productId": "a0wnqgxs",
            "pv": "2.2",
            "runtimeEnv": "prod",
            "sv": "1.0.2",
            "timeZone": "-05:00",
            "uuid": "fakeuuid1a2b0a02",
            "verSw": "1.0.2",
        },
    },
    {
        "devId": "ebexamplelock002",
        "name": "bathroom",
        "productId": "a0wnqgxs",
        "category": "jtmspro",
        "iconUrl": "https://images.tuyaus.com/smart/icon/bay1617864004789265P/1ed8bc3f57cd0fb7b8d56d8c5286bf7e.png",
        "isOnline": False,
        "dps": {
            "8": 100,
            "12": 10,
            "19": 2,
            "31": "high",
            "33": True,
            "36": 8,
            "44": 0,
            "46": False,
            "47": False,
            "54": "AQA=",
            "69": "BAAA",
            "70": "AQH//wAC",
            "71": "//8AAjEyMzQ1Njc4AAAAAAAAAFI=",
            "73": "AAAAAf///wACMTIzNDU2Nzg=",
        },
        "dpCodes": {
            "residual_electricity": 100,
            "unlock_fingerprint": 10,
            "unlock_ble": 2,
            "beep_volume": "high",
            "automatic_lock": True,
            "auto_lock_time": 8,
            "rtc_lock": 0,
            "manual_lock": False,
            "lock_motor_state": False,
            "synch_method": "AQA=",
            "record": "BAAA",
            "check_code_set": "AQH//wAC",
            "ble_unlock_check": "//8AAjEyMzQ1Njc4AAAAAAAAAFI=",
            "remote_pd_setkey_check": "AAAAAf///wACMTIzNDU2Nzg=",
        },
        "parentId": "ebexamplegw1a2b3c4d5e6",
        "devAttribute": 0,
        "mac": "000000000002",
        "uuid": "fakeuuid1a2b0a03",
        "meshId": "ebexamplegw1a2b3c4d5e6",
        "nodeId": "0214",
        "raw": {
            "ability": 5,
            "devAttribute": 0,
            "devId": "ebexamplelock002",
            "gwType": "b",
            "mac": "000000000002",
            "meshId": "ebexamplegw1a2b3c4d5e6",
            "name": "bathroom",
            "nodeId": "0214",
            "online": False,
            "parentId": "ebexamplegw1a2b3c4d5e6",
            "productId": "a0wnqgxs",
            "pv": "2.2",
            "runtimeEnv": "prod",
            "sv": "1.0.2",
            "timeZone": "-05:00",
            "uuid": "fakeuuid1a2b0a03",
            "verSw": "1.0.2",
        },
    },
    {
        "devId": "ebexamplelock003",
        "name": "K11",
        "productId": "0g4ae04s",
        "category": "jtmspro",
        "iconUrl": "https://images.tuyaus.com/smart/icon/bay1617864004789265P/c4cf3a0be118bd8be5d3540a978fb2bf.png",
        "isOnline": False,
        "dps": {
            "8": 80,
            "12": 2,
            "19": 2,
            "21": 2,
            "31": "high",
            "33": False,
            "36": 5,
            "44": 1,
            "47": False,
            "54": "AQA=",
            "69": "BAAA",
            "70": "AQH//wAD",
            "71": "A123456780000000000R",
            "73": "AAAAAf///wADODc2NTQzMjE=",
        },
        "dpCodes": {
            "residual_electricity": 80,
            "unlock_fingerprint": 2,
            "unlock_ble": 2,
            "alarm_lock": 2,
            "beep_volume": "high",
            "automatic_lock": False,
            "auto_lock_time": 5,
            "rtc_lock": 1,
            "lock_motor_state": False,
            "synch_method": "AQA=",
            "record": "BAAA",
            "check_code_set": "AQH//wAD",
            "ble_unlock_check": "A123456780000000000R",
            "remote_pd_setkey_check": "AAAAAf///wADODc2NTQzMjE=",
        },
        "parentId": "ebexamplegw1a2b3c4d5e6",
        "devAttribute": 0,
        "mac": "000000000003",
        "uuid": "fakeuuid1a2b0a04",
        "meshId": None,
        "nodeId": None,
        "raw": {
            "ability": 5,
            "devAttribute": 0,
            "devId": "ebexamplelock003",
            "gwType": "b",
            "mac": "000000000003",
            "name": "K11",
            "online": False,
            "productId": "0g4ae04s",
            "pv": "2.2",
            "runtimeEnv": "prod",
            "sv": "1.0.8",
            "timeZone": "-04:00",
            "uuid": "fakeuuid1a2b0a04",
            "verSw": "1.0.8",
        },
    },
]

# Alias for sample device testing isolation
DEFAULT_TUYA_DEVICES_SAMPLE: List[Dict[str, Any]] = DEFAULT_HARDWARE_DEVICES


class SessionManager:
    """Thread-safe and process-safe manager for session cache file."""

    def __init__(self, cache_path: Optional[str] = None) -> None:
        self.cache_path = os.path.abspath(cache_path or DEFAULT_CACHE_PATH)

    def exists(self) -> bool:
        """Checks if session cache file exists and is non-empty."""
        try:
            return os.path.exists(self.cache_path) and os.path.getsize(self.cache_path) > 0
        except OSError:
            return False

    def load(self) -> Optional[Dict[str, Any]]:
        """Loads and parses session cache JSON. Returns None if file is missing or invalid."""
        with _SESSION_FILE_LOCK:
            if not self.exists():
                return None
            try:
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
                return None
            except Exception as e:
                logger.warning("Failed to read session cache from %s: %s", self.cache_path, e)
                return None

    def save(self, data: Dict[str, Any], merge: bool = True) -> None:
        """Atomically saves data to session cache file with 0o600 permissions.

        Uses write-to-temp-file + os.replace pattern to prevent race conditions
        and corruptions.
        """
        with _SESSION_FILE_LOCK:
            payload: Dict[str, Any] = {}
            if merge and self.exists():
                existing = self.load()
                if existing:
                    payload.update(existing)

            # Merge nested sections if both exist
            for section in ("geeksmart", "tuya", "ttlock"):
                if section in data and isinstance(data[section], dict):
                    existing_section = payload.get(section, {})
                    if isinstance(existing_section, dict):
                        merged_sec = dict(existing_section)
                        merged_sec.update(data[section])
                        payload[section] = merged_sec
                    else:
                        payload[section] = data[section]

            # Update remaining top-level keys
            for k, v in data.items():
                if k not in ("geeksmart", "tuya", "ttlock"):
                    payload[k] = v

            payload["cached_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            cache_dir = os.path.dirname(self.cache_path)
            if cache_dir and not os.path.exists(cache_dir):
                os.makedirs(cache_dir, exist_ok=True)

            temp_path = (
                f"{self.cache_path}.tmp.{os.getpid()}_"
                f"{threading.get_ident()}_{uuid.uuid4().hex[:8]}"
            )
            try:
                # Write with restricted permissions
                fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)

                # Ensure file permissions are explicitly 0o600
                try:
                    os.chmod(temp_path, 0o600)
                except OSError:
                    pass

                os.replace(temp_path, self.cache_path)
                logger.debug("Session cache atomically saved to %s", self.cache_path)
            except Exception as e:
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except OSError:
                        pass
                if isinstance(e, PermissionError) or getattr(e, "errno", None) == 13:
                    raise PermissionError(
                        f"Cannot write session cache to '{self.cache_path}': Permission denied. "
                        f"If running inside Docker, ensure host directory '{cache_dir}' is owned by "
                        f"container user (UID 10001 geekdoor): run 'chown -R 10001:10001 ./data'"
                    ) from e
                raise IOError(f"Failed to atomically persist session cache: {e}") from e

    def get_geeksmart_token(self) -> Optional[str]:
        """Retrieves active GeekSmart session token."""
        cache = self.load()
        if not cache:
            return None
        return cache.get("token") or cache.get("geeksmart", {}).get("token")

    def get_geeksmart_client_id(self) -> Optional[int]:
        """Retrieves GeekSmart client ID as integer."""
        cache = self.load()
        if not cache:
            return None
        cid = (
            cache.get("id")
            or cache.get("clientId")
            or cache.get("geeksmart", {}).get("client_id")
        )
        return int(cid) if cid is not None else None

    def get_geeksmart_credentials(self) -> Dict[str, Any]:
        """Retrieves GeekSmart credentials and session state."""
        cache = self.load() or {}
        gs_sec = cache.get("geeksmart") or {}
        return {
            "token": cache.get("token") or gs_sec.get("token"),
            "client_id": self.get_geeksmart_client_id(),
            "email": cache.get("email") or gs_sec.get("email"),
            "password": cache.get("password") or gs_sec.get("password"),
            "password_md5": cache.get("passwordMd5") or gs_sec.get("password_md5"),
        }

    def get_tuya_session(self) -> Dict[str, Any]:
        """Retrieves Tuya credentials, session ID, and home context."""
        cache = self.load() or {}
        tuya_sec = cache.get("tuya") or {}
        return {
            "username": (
                tuya_sec.get("tuya_username")
                or cache.get("tuyaUsername")
                or cache.get("email")
            ),
            "password": tuya_sec.get("tuya_password") or cache.get("tuyaPassword"),
            "password_md5": (
                tuya_sec.get("tuya_password_md5") or cache.get("tuyaPasswordMd5")
            ),
            "uid": tuya_sec.get("tuya_uid") or cache.get("tuyaUid"),
            "country_code": str(
                tuya_sec.get("tuya_country_code")
                or cache.get("tuyaCountryCode")
                or "1"
            ),
            "username_type": int(
                tuya_sec.get("tuya_username_type")
                or cache.get("tuyaUsernameType")
                or 2
            ),
            "sid": tuya_sec.get("sid") or cache.get("tuyaSid"),
            "ecode": tuya_sec.get("ecode") or cache.get("tuyaEcode"),
            "expires_at": int(tuya_sec.get("expires_at") or 0),
            "home_id": tuya_sec.get("home_id") or cache.get("tuyaHomeId"),
            "home_name": tuya_sec.get("home_name") or cache.get("tuyaHomeName"),
            "devices": (
                tuya_sec.get("devices")
                or cache.get("tuya_devices")
                or cache.get("devices")
                or []
            ),
        }

    def update_tuya_session(
        self,
        sid: str,
        expires_in: int = 2592000,
        uid: Optional[str] = None,
        home_id: Optional[int] = None,
        home_name: Optional[str] = None,
        ecode: Optional[str] = None,
        devices: Optional[Any] = None,
    ) -> None:
        """Updates and persists Tuya session token, expiration, and home context."""
        now = int(time.time())
        tuya_data: Dict[str, Any] = {
            "sid": sid,
            "expires_in": expires_in,
            "expires_at": now + expires_in,
            "cached_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if uid:
            tuya_data["tuya_uid"] = uid
        if ecode:
            tuya_data["ecode"] = ecode
        if home_id is not None:
            tuya_data["home_id"] = home_id
        if home_name:
            tuya_data["home_name"] = home_name
        if devices is not None:
            tuya_data["devices"] = devices

        payload: Dict[str, Any] = {
            "tuya": tuya_data,
            "tuyaSid": sid,
        }
        if uid:
            payload["tuyaUid"] = uid
        if ecode:
            payload["tuyaEcode"] = ecode
        if home_id is not None:
            payload["tuyaHomeId"] = home_id
        if home_name:
            payload["tuyaHomeName"] = home_name
        if devices is not None:
            payload["tuya_devices"] = devices
            payload["devices"] = devices

        self.save(payload, merge=True)

    def verify_permissions(self) -> bool:
        """Checks if cache file permissions are restricted to owner (0o600 or 0o400)."""
        if not os.path.exists(self.cache_path):
            return True
        mode = stat.S_IMODE(os.stat(self.cache_path).st_mode)
        # Check that group and other have no permissions (mode & 0o077 == 0)
        return (mode & 0o077) == 0

    def bootstrap_from_env(self) -> bool:
        """Initializes .session_cache.json from environment variables (or .env file) if missing.

        Useful for first-boot Ubuntu VPS Docker Compose deployments where .session_cache.json
        has not been created yet and credentials are provided via environment variables.
        """
        with _SESSION_FILE_LOCK:
            if self.exists():
                return False

            # Also check for a local .env file if env vars are not yet populated
            env_map: Dict[str, str] = dict(os.environ)
            dotenv_path = os.path.join(_PROJECT_ROOT, ".env")
            if os.path.exists(dotenv_path):
                try:
                    with open(dotenv_path, "r", encoding="utf-8") as f:
                        for raw_line in f:
                            line = raw_line.strip()
                            if not line or line.startswith("#") or "=" not in line:
                                continue
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip().strip('"').strip("'")
                            if k and k not in env_map:
                                env_map[k] = v
                except Exception:
                    pass

            email = (
                env_map.get("GEEKSMART_EMAIL")
                or env_map.get("TUYA_USERNAME")
                or ""
            ).strip()
            password = (
                env_map.get("GEEKSMART_PASSWORD")
                or env_map.get("TUYA_PASSWORD")
                or ""
            ).strip()
            tuya_sid = (env_map.get("TUYA_SID") or "").strip()
            gs_token = (env_map.get("GEEKSMART_TOKEN") or "").strip()

            if not (email or password or tuya_sid or gs_token):
                return False

            email_val = email or ""
            pwd_md5 = (
                env_map.get("GEEKSMART_PASSWORD_MD5")
                or (hashlib.md5(password.encode("utf-8")).hexdigest() if password else "")
            )
            client_id = int(env_map.get("GEEKSMART_CLIENT_ID") or 0)
            tuya_uid = env_map.get("TUYA_UID") or ""
            tuya_ecode = env_map.get("TUYA_ECODE") or ""
            home_id = int(env_map.get("TUYA_HOME_ID") or 0)
            country_code = str(env_map.get("TUYA_COUNTRY_CODE") or "1")
            ttlock_uid = int(env_map.get("TTLOCK_UID") or 0)
            ttlock_user = env_map.get("TTLOCK_USERNAME") or (f"geekaihome_{client_id}" if client_id else "")
            now = int(time.time())

            bootstrap_payload: Dict[str, Any] = {
                "token": gs_token,
                "id": client_id,
                "clientId": client_id,
                "email": email_val,
                "passwordMd5": pwd_md5,
                "tuyaUid": tuya_uid,
                "tuyaUsername": email_val,
                "tuyaPasswordMd5": pwd_md5,
                "tuyaCountryCode": country_code,
                "tuyaUsernameType": 2,
                "tuyaSid": tuya_sid,
                "tuyaEcode": tuya_ecode,
                "tuyaHomeId": home_id,
                "tuyaHomeName": "My Home",
                "ttlockUid": ttlock_uid,
                "ttlockUsername": ttlock_user,
                "geeksmart": {
                    "token": gs_token,
                    "client_id": client_id,
                    "email": email_val,
                    "password_md5": pwd_md5,
                },
                "tuya": {
                    "tuya_uid": tuya_uid,
                    "tuya_username": email_val,
                    "tuya_password_md5": pwd_md5,
                    "tuya_country_code": country_code,
                    "tuya_username_type": 2,
                    "sid": tuya_sid,
                    "ecode": tuya_ecode,
                    "expires_in": 2592000 if tuya_sid else 0,
                    "expires_at": (now + 2592000) if tuya_sid else 0,
                    "home_id": home_id,
                    "home_name": "My Home",
                    "devices": list(DEFAULT_HARDWARE_DEVICES),
                },
                "ttlock": {
                    "ttlock_uid": ttlock_uid,
                    "ttlock_username": ttlock_user,
                },
                "tuya_devices": list(DEFAULT_HARDWARE_DEVICES),
                "devices": list(DEFAULT_HARDWARE_DEVICES),
            }
            self.save(bootstrap_payload, merge=False)
            return True
