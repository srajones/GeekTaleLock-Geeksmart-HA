"""DataUpdateCoordinator for GeekSmart Door Lock integration."""
from __future__ import annotations

from datetime import timedelta
import inspect
import logging
from typing import Any, Dict, Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

try:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.exceptions import ConfigEntryAuthFailed
    from homeassistant.helpers.aiohttp_client import async_get_clientsession
    from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
except ImportError:
    # Lightweight mock classes for standalone testing
    class ConfigEntry:  # type: ignore[no-redef]
        def __init__(self, data: Optional[Dict[str, Any]] = None, options: Optional[Dict[str, Any]] = None) -> None:
            self.data = data or {}
            self.options = options or {}
            self.title = "GeekSmart Lock"
            self.entry_id = "test_entry"

    class HomeAssistant:  # type: ignore[no-redef]
        def __init__(self) -> None:
            self.data: Dict[str, Any] = {}

        async def async_add_executor_job(self, target: Any, *args: Any) -> Any:
            return target(*args)

    class DataUpdateCoordinator:  # type: ignore[no-redef]
        def __class_getitem__(cls, item: Any) -> Any:
            return cls

        def __init__(self, hass: Any, logger: Any, name: str, update_interval: Any) -> None:
            self.hass = hass
            self.logger = logger
            self.name = name
            self.update_interval = update_interval
            self.data: Optional[Dict[str, Any]] = None
            self.last_update_success: bool = True

        def async_set_updated_data(self, data: Any) -> None:
            self.data = data

    class UpdateFailed(Exception):  # type: ignore[no-redef]
        pass

    try:
        from .core.exceptions import ConfigEntryAuthFailed, HomeAssistantError, ConfigEntryNotReady
    except ImportError:
        class ConfigEntryAuthFailed(Exception):  # type: ignore[no-redef]
            pass

    def async_get_clientsession(hass: Any, verify_ssl: bool = True) -> Any:  # type: ignore[no-redef]
        return None

from .const import (
    DOMAIN,
    CONF_MODE,
    MODE_DIRECT_CLOUD,
    MODE_SERVER_BRIDGE,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_COUNTRY_CODE,
    DEFAULT_COUNTRY_CODE,
    CONF_SERVER_URL,
    CONF_API_KEY,
    CONF_VERIFY_SSL,
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    CONF_PREFER_DIRECT_BLE,
    DEFAULT_PREFER_DIRECT_BLE,
    CONF_BLE_DIRECT_FALLBACK,
    DEFAULT_BLE_DIRECT_FALLBACK,
    SESSION_CACHE_FILENAME,
)

_LOGGER = logging.getLogger(__name__)


class GeekDoorDataUpdateCoordinator(DataUpdateCoordinator[Dict[str, Any]]):
    """Class to manage fetching GeekSmart lock data."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.entry = entry
        scan_interval = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
        super().__init__(
            hass,
            _LOGGER,
            name=f"GeekSmart Lock ({entry.title})",
            update_interval=timedelta(seconds=scan_interval),
        )
        self.mode = entry.data.get(CONF_MODE, MODE_DIRECT_CLOUD)
        self.engine: Any = None
        self._last_heal_error: Optional[Exception] = None
        # Smart plug BLE gateways (cz) keyed by devId. Kept separate from self.data so
        # lock/sensor/binary_sensor platforms never create lock entities for plugs.
        self.gateway_data: Dict[str, Any] = {}
        if self.mode == MODE_DIRECT_CLOUD:
            try:
                from .core.lock_engine import LockEngine
                from .core.ble_gatt_client import HomeAssistantBleAdapter
            except ImportError:
                from client.lock_engine import LockEngine
                from client.ble_gatt_client import HomeAssistantBleAdapter

            cache_path = (
                self.hass.config.path(SESSION_CACHE_FILENAME)
                if hasattr(self.hass, "config") and hasattr(self.hass.config, "path")
                else None
            )
            ble_client = HomeAssistantBleAdapter(hass=self.hass)
            loop = getattr(self.hass, "loop", None) if self.hass else None

            self.engine = LockEngine(
                credentials=entry.data,
                session_cache_path=cache_path,
                ble_client=ble_client,
                dry_run=bool(entry.data.get("dry_run", False)),
                sample_mode=False,
                use_sample_devices=False,
                prefer_direct_ble=self.prefer_direct_ble,
                loop=loop,
            )

    @property
    def prefer_direct_ble(self) -> bool:
        """True if HA native Bluetooth stack is preferred over Tuya Cloud / Smart Plug."""
        return bool(
            self.entry.options.get(
                CONF_PREFER_DIRECT_BLE,
                self.entry.options.get(CONF_BLE_DIRECT_FALLBACK, DEFAULT_PREFER_DIRECT_BLE),
            )
        )

    async def _async_update_data(self) -> Dict[str, Any]:
        """Fetch data from lock engine or server bridge."""
        if self.mode == MODE_DIRECT_CLOUD:
            return await self._async_update_direct_cloud()
        return await self._async_update_server_bridge()

    async def async_try_heal_session(self) -> Optional[list]:
        """Attempts to re-authenticate with stored ConfigEntry credentials if a session token died."""
        self._last_heal_error = None
        username = str(self.entry.data.get(CONF_USERNAME) or "").strip()
        password = str(self.entry.data.get(CONF_PASSWORD) or "").strip()
        country_code = str(self.entry.data.get(CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE)).strip()
        if not username or not password or not self.engine:
            self._last_heal_error = ValueError("Missing credentials in config entry")
            return None
        if not hasattr(self.engine, "authenticate_and_discover"):
            return None
        try:
            _LOGGER.info("Session token expired; auto-healing Tuya/GeekSmart session for %s", username)
            if hasattr(self.hass, "async_add_executor_job"):
                healed = await self.hass.async_add_executor_job(
                    self.engine.authenticate_and_discover,
                    username,
                    password,
                    country_code,
                )
            else:
                healed = self.engine.authenticate_and_discover(username, password, country_code)
            if isinstance(healed, list):
                return healed
        except Exception as heal_exc:
            _LOGGER.warning("Automatic session re-authentication failed: %s", heal_exc)
            self._last_heal_error = heal_exc
        return None

    async def _async_refresh_gateway_data(self) -> None:
        """Refresh smart plug gateway snapshots from the engine (no extra network I/O)."""
        getter = getattr(self.engine, "get_all_gateway_snapshots", None)
        if not callable(getter):
            return
        try:
            if hasattr(self.hass, "async_add_executor_job"):
                gws = await self.hass.async_add_executor_job(getter)
            else:
                gws = getter()
        except Exception as exc:
            _LOGGER.debug("Gateway snapshot refresh failed: %s", exc)
            return
        if not isinstance(gws, list):
            return
        self.gateway_data = {
            str(g.get("devId")): g
            for g in gws
            if isinstance(g, dict) and g.get("devId")
        }
        _LOGGER.debug(
            "Gateway snapshots: %s",
            [
                (gid, g.get("category"), g.get("outletOn"), g.get("plugOutletControllable"))
                for gid, g in self.gateway_data.items()
            ],
        )

    async def _async_update_direct_cloud(self) -> Dict[str, Any]:
        ble_fallback = self.prefer_direct_ble
        try:
            devices = await self.hass.async_add_executor_job(
                self.engine.get_all_lock_snapshots, ble_fallback
            )
            await self._async_refresh_gateway_data()
            return {
                str(dev.get("devId") or dev.get("dev_id") or dev.get("id")): dev
                for dev in devices
                if isinstance(dev, dict) and (dev.get("devId") or dev.get("dev_id") or dev.get("id"))
            }
        except Exception as exc:
            err_str = str(exc)
            is_fatal_cred_error = (
                "USER_PASSWD_WRONG" in err_str
                or "USERNAME_NOT_EXIST" in err_str
                or "Invalid credentials" in err_str
            )
            is_session_or_auth_error = (
                "Auth failed" in err_str
                or "USER_SESSION_INVALID" in err_str
                or "USER_SESSION_LOSS" in err_str
                or "SESSION_EXPIRED" in err_str
                or "TOKEN_EXPIRED" in err_str
                or "unauthorized" in err_str.lower()
                or "401" in err_str
                or "403" in err_str
            )
            if is_session_or_auth_error and not is_fatal_cred_error:
                healed_devices = await self.async_try_heal_session()
                if isinstance(healed_devices, list) and healed_devices:
                    await self._async_refresh_gateway_data()
                    return {
                        str(dev.get("devId") or dev.get("dev_id") or dev.get("id")): dev
                        for dev in healed_devices
                        if isinstance(dev, dict) and (dev.get("devId") or dev.get("dev_id") or dev.get("id"))
                    }
                # Check if re-authentication failed due to permanent bad credentials
                heal_err_str = str(self._last_heal_error) if self._last_heal_error else ""
                heal_is_fatal = (
                    "USER_PASSWD_WRONG" in heal_err_str
                    or "USERNAME_NOT_EXIST" in heal_err_str
                    or "Invalid credentials" in heal_err_str
                    or "Missing credentials" in heal_err_str
                )
                if heal_is_fatal:
                    raise ConfigEntryAuthFailed(
                        f"Authentication failed permanently during session heal: {self._last_heal_error}"
                    ) from (self._last_heal_error or exc)

                # Transient network failure during heal attempt
                raise UpdateFailed(
                    f"Session expired and automatic re-authentication encountered network error: {self._last_heal_error or exc}"
                ) from (self._last_heal_error or exc)

            if is_fatal_cred_error:
                raise ConfigEntryAuthFailed(f"Authentication failed: {exc}") from exc
            raise UpdateFailed(f"Direct cloud update failed: {exc}") from exc

    async def _async_update_server_bridge(self) -> Dict[str, Any]:
        server_url = self.entry.data.get(CONF_SERVER_URL, "")
        api_key = self.entry.data.get(CONF_API_KEY, "")
        verify_ssl = self.entry.data.get(CONF_VERIFY_SSL, True)
        session = async_get_clientsession(self.hass, verify_ssl=verify_ssl)
        if not session:
            raise UpdateFailed("aiohttp ClientSession not available")

        headers = {"Authorization": f"Bearer {api_key}"}
        get_timeout = (
            aiohttp.ClientTimeout(total=10.0, connect=4.0)
            if aiohttp and hasattr(aiohttp, "ClientTimeout")
            else 8.0
        )
        try:
            async with session.get(f"{server_url}/api/ha/status", headers=headers, timeout=get_timeout) as resp:
                if resp.status in (401, 403):
                    raise ConfigEntryAuthFailed(f"Authentication rejected by server bridge (HTTP {resp.status})")
                if resp.status != 200:
                    raise UpdateFailed(f"Server returned HTTP {resp.status}")
                payload = await resp.json()
                if not isinstance(payload, dict):
                    raise UpdateFailed(f"Unexpected server response format: {type(payload)}")
                locks = payload.get("locks", [])
                if not isinstance(locks, list):
                    locks = []
                return {
                    lock["device_id"]: lock
                    for lock in locks
                    if isinstance(lock, dict) and "device_id" in lock
                }
        except (ConfigEntryAuthFailed, UpdateFailed):
            raise
        except Exception as exc:
            raise UpdateFailed(f"Server bridge connection error: {exc}") from exc

    def async_handle_push_data(self, payload: Any) -> None:
        """Receive instant push update from incoming webhook."""
        if not isinstance(payload, dict):
            _LOGGER.warning("Discarding invalid push payload of type %s", type(payload))
            return

        dev_id = str(
            payload.get("device_id")
            or payload.get("devId")
            or payload.get("id")
            or ""
        ).strip()
        if not dev_id:
            return
        if self.data is None:
            self.data = {}

        val = self.data.get(dev_id)
        if hasattr(val, "to_dashboard_dict"):
            current_record = dict(val.to_dashboard_dict())
        elif isinstance(val, dict):
            current_record = dict(val)
        elif val is not None:
            current_record = dict(getattr(val, "__dict__", {}))
        else:
            current_record = {}

        new_state = str(payload.get("new_state") or "").strip().lower()
        if new_state:
            current_record["state"] = new_state
            current_record["is_locked"] = (new_state == "locked")
        if "battery" in payload:
            current_record["battery"] = payload["battery"]
        if "auto_lock_enabled" in payload:
            current_record["auto_lock_enabled"] = payload["auto_lock_enabled"]

        self.data[dev_id] = current_record
        if hasattr(self, "async_set_updated_data"):
            self.async_set_updated_data(self.data)

    async def async_shutdown(self) -> None:
        """Teardown coordinator background tasks, listeners, and BLE connections."""
        if hasattr(super(), "async_shutdown"):
            try:
                res = super().async_shutdown()
                if inspect.isawaitable(res):
                    await res
            except Exception as exc:
                _LOGGER.debug("Base coordinator async_shutdown exception: %s", exc)
        elif hasattr(self, "_async_unsub_refresh") and getattr(self, "_async_unsub_refresh", None):
            unsub = getattr(self, "_async_unsub_refresh")
            if callable(unsub):
                unsub()
                self._async_unsub_refresh = None

        if self.engine and hasattr(self.engine, "ble_client") and self.engine.ble_client:
            ble_client = self.engine.ble_client
            if hasattr(ble_client, "async_disconnect_all"):
                try:
                    await ble_client.async_disconnect_all()
                except Exception as exc:
                    _LOGGER.debug("Error disconnecting BLE adapter during coordinator shutdown: %s", exc)
            elif hasattr(ble_client, "_clients") and isinstance(ble_client._clients, dict):
                for client in list(ble_client._clients.values()):
                    try:
                        if hasattr(client, "disconnect"):
                            res = client.disconnect()
                            if inspect.isawaitable(res):
                                await res
                    except Exception as exc:
                        _LOGGER.debug("Error disconnecting BLE client during teardown: %s", exc)
                ble_client._clients.clear()
