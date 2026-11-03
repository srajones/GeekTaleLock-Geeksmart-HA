"""Lock platform for GeekSmart Door Lock."""
from __future__ import annotations

import inspect
import logging
from functools import partial
from typing import Any, Dict, Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

try:
    from homeassistant.components.lock import LockEntity
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
    from homeassistant.helpers.entity import DeviceInfo
    from homeassistant.helpers.entity_platform import AddEntitiesCallback
    from homeassistant.helpers.update_coordinator import CoordinatorEntity
    from homeassistant.helpers.aiohttp_client import async_get_clientsession
except ImportError:
    class LockEntity:  # type: ignore[no-redef]
        pass
    class CoordinatorEntity:  # type: ignore[no-redef]
        def __init__(self, coordinator: Any) -> None:
            self.coordinator = coordinator
        def async_write_ha_state(self) -> None:
            pass
    class DeviceInfo(dict):  # type: ignore[no-redef]
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(kwargs)
    try:
        from .core.exceptions import HomeAssistantError, ConfigEntryAuthFailed, ConfigEntryNotReady
    except ImportError:
        class HomeAssistantError(Exception):  # type: ignore[no-redef]
            pass
        class ConfigEntryAuthFailed(HomeAssistantError):  # type: ignore[no-redef]
            pass
        class ConfigEntryNotReady(HomeAssistantError):  # type: ignore[no-redef]
            pass
    ConfigEntry = Any  # type: ignore[assignment,misc]
    HomeAssistant = Any  # type: ignore[assignment,misc]
    AddEntitiesCallback = Any  # type: ignore[assignment,misc]
    async_get_clientsession = None  # type: ignore[assignment]

from .const import (
    DOMAIN,
    CONF_MODE,
    MODE_DIRECT_CLOUD,
    CONF_SERVER_URL,
    CONF_API_KEY,
    CONF_VERIFY_SSL,
    CONF_BLE_DIRECT_FALLBACK,
    DEFAULT_BLE_DIRECT_FALLBACK,
    ATTR_BATTERY,
    ATTR_AUTO_LOCK_TIME,
)
from .coordinator import GeekDoorDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up GeekSmart lock entities from a config entry."""
    coordinator: GeekDoorDataUpdateCoordinator = (
        entry.runtime_data if hasattr(entry, "runtime_data") else hass.data[DOMAIN][entry.entry_id]
    )

    dev_ids = list(coordinator.data.keys()) if coordinator.data else []
    entities = [
        GeekDoorLock(coordinator, dev_id)
        for dev_id in dev_ids
    ]
    async_add_entities(entities)


class GeekDoorLock(CoordinatorEntity, LockEntity):
    """Representation of a GeekSmart Door Lock."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: GeekDoorDataUpdateCoordinator, dev_id: str) -> None:
        super().__init__(coordinator)
        self.dev_id = str(dev_id)
        self._attr_unique_id = f"geek_door_lock_{dev_id}"
        self._is_locking = False
        self._is_unlocking = False

    @property
    def lock_data(self) -> Dict[str, Any]:
        if self.coordinator and self.coordinator.data:
            dev = self.coordinator.data.get(self.dev_id)
            if hasattr(dev, "to_dashboard_dict"):
                return dev.to_dashboard_dict()
            elif isinstance(dev, dict):
                return dev
            elif dev is not None:
                return getattr(dev, "__dict__", {})
        return {}

    @property
    def name(self) -> str:
        return str(self.lock_data.get("name") or f"GeekSmart Lock {self.dev_id}")

    @property
    def is_locked(self) -> bool:
        return bool(self.lock_data.get("is_locked", True) if "is_locked" in self.lock_data else (self.lock_data.get("state") == "LOCKED"))

    @property
    def is_locking(self) -> bool:
        return self._is_locking

    @property
    def is_unlocking(self) -> bool:
        return self._is_unlocking

    @property
    def available(self) -> bool:
        if self.coordinator is None or not getattr(self.coordinator, "last_update_success", True):
            return False
        data = self.lock_data
        if bool(data.get("online", data.get("isOnline", True))):
            return True
        entry = getattr(self.coordinator, "entry", None)
        options = getattr(entry, "options", {}) if entry and getattr(entry, "options", None) else {}
        ble_enabled = options.get(CONF_BLE_DIRECT_FALLBACK, DEFAULT_BLE_DIRECT_FALLBACK)
        has_ble = bool(
            data.get("ble_fallback_available")
            or data.get("mac")
            or data.get("localKey")
            or data.get("local_key")
            or (data.get("capabilities") or {}).get("direct_ble")
        )
        return bool(ble_enabled and has_ble)

    @property
    def is_online(self) -> bool:
        return self.available

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return {
            ATTR_BATTERY: self.lock_data.get("battery"),
            "auto_lock_enabled": self.lock_data.get("auto_lock_enabled", self.lock_data.get("autoLockEnabled", True)),
            ATTR_AUTO_LOCK_TIME: self.lock_data.get("auto_lock_seconds", self.lock_data.get("autoLockSeconds", 5)),
            "ble_connected": self.lock_data.get("connection_status") == 2 or self.lock_data.get("connectionStatus") == 2,
            "ble_signal_state": self.lock_data.get("ble_signal_state") or self.lock_data.get("bleSignalState"),
            "wifi_rssi": self.lock_data.get("wifi_rssi", self.lock_data.get("wifiRssi")),
            "gateway_name": self.lock_data.get("gateway_name") or self.lock_data.get("gatewayId"),
            "hardware_model": self.lock_data.get("hardware_model") or self.lock_data.get("hardwareModel", "K01 2"),
        }

    @property
    def device_info(self) -> DeviceInfo:
        info = DeviceInfo(
            identifiers={(DOMAIN, self.dev_id)},
            name=self.name,
            manufacturer="GeekSmart",
            model=self.lock_data.get("hardware_model", self.lock_data.get("hardwareModel", "Smart Lock")),
            sw_version=str(self.lock_data.get("sw_version") or self.lock_data.get("verSw") or "2.11.0"),
        )
        gw_id = self.lock_data.get("gatewayId") or self.lock_data.get("parentId")
        if gw_id:
            info["via_device"] = (DOMAIN, str(gw_id))
        return info

    async def async_lock(self, **kwargs: Any) -> None:
        """Lock the door."""
        self._is_locking = True
        self.async_write_ha_state()
        try:
            if self.coordinator.mode == MODE_DIRECT_CLOUD:
                if hasattr(self, "hass") and hasattr(self.hass, "async_add_executor_job"):
                    res = await self.hass.async_add_executor_job(
                        self.coordinator.engine.lock, self.dev_id
                    )
                else:
                    res = self.coordinator.engine.lock(self.dev_id)
                if res and hasattr(res, "get") and not res.get("success"):
                    raise HomeAssistantError(res.get("message", "Lock command failed"))
            else:
                await self._async_send_server_command("lock")
            if hasattr(self.coordinator, "async_request_refresh"):
                res = self.coordinator.async_request_refresh()
                if inspect.isawaitable(res):
                    await res
        except (HomeAssistantError, ConfigEntryAuthFailed):
            raise
        except Exception as exc:
            err_str = str(exc)
            if "Auth failed" in err_str or "401" in err_str or "403" in err_str:
                raise ConfigEntryAuthFailed(f"Authentication failed: {exc}") from exc
            raise HomeAssistantError(f"Failed to lock door {self.dev_id}: {exc}") from exc
        finally:
            self._is_locking = False
            self.async_write_ha_state()

    async def async_unlock(self, **kwargs: Any) -> None:
        """Unlock the door."""
        self._is_unlocking = True
        self.async_write_ha_state()
        try:
            if self.coordinator.mode == MODE_DIRECT_CLOUD:
                if hasattr(self, "hass") and hasattr(self.hass, "async_add_executor_job"):
                    res = await self.hass.async_add_executor_job(
                        self.coordinator.engine.unlock, self.dev_id
                    )
                else:
                    res = self.coordinator.engine.unlock(self.dev_id)
                if res and hasattr(res, "get") and not res.get("success"):
                    raise HomeAssistantError(res.get("message", "Unlock command failed"))
            else:
                await self._async_send_server_command("unlock")
            if hasattr(self.coordinator, "async_request_refresh"):
                res = self.coordinator.async_request_refresh()
                if inspect.isawaitable(res):
                    await res
        except (HomeAssistantError, ConfigEntryAuthFailed):
            raise
        except Exception as exc:
            err_str = str(exc)
            if "Auth failed" in err_str or "401" in err_str or "403" in err_str:
                raise ConfigEntryAuthFailed(f"Authentication failed: {exc}") from exc
            raise HomeAssistantError(f"Failed to unlock door {self.dev_id}: {exc}") from exc
        finally:
            self._is_unlocking = False
            self.async_write_ha_state()

    async def async_open(self, **kwargs: Any) -> None:
        """Open / unlock the door."""
        await self.async_unlock(**kwargs)

    async def async_keep_unlocked(self, duration_seconds: Optional[int] = None) -> None:
        """Enable Passage Mode (Keep Unlocked indefinitely or for a duration)."""
        try:
            if self.coordinator.mode == MODE_DIRECT_CLOUD:
                engine = self.coordinator.engine
                pass_duration = False
                try:
                    sig = inspect.signature(engine.keep_unlocked)
                    if (
                        "duration_seconds" in sig.parameters
                        or "seconds" in sig.parameters
                        or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
                    ):
                        pass_duration = True
                except Exception:
                    pass_duration = False

                kwargs: Dict[str, Any] = {}
                if pass_duration and duration_seconds is not None:
                    kwargs["duration_seconds"] = duration_seconds

                if hasattr(self, "hass") and hasattr(self.hass, "async_add_executor_job"):
                    call_fn = partial(engine.keep_unlocked, self.dev_id, **kwargs) if kwargs else partial(engine.keep_unlocked, self.dev_id)
                    res = await self.hass.async_add_executor_job(call_fn)
                else:
                    res = engine.keep_unlocked(self.dev_id, **kwargs)
                if res and hasattr(res, "get") and not res.get("success"):
                    raise HomeAssistantError(res.get("message", "Keep unlocked command failed"))
            else:
                extra = {"duration": duration_seconds, "duration_seconds": duration_seconds} if duration_seconds is not None else {}
                await self._async_send_server_command("keep_unlocked", extra_payload=extra)
            if hasattr(self.coordinator, "async_request_refresh"):
                res = self.coordinator.async_request_refresh()
                if inspect.isawaitable(res):
                    await res
        except (HomeAssistantError, ConfigEntryAuthFailed):
            raise
        except Exception as exc:
            err_str = str(exc)
            if "Auth failed" in err_str or "401" in err_str or "403" in err_str:
                raise ConfigEntryAuthFailed(f"Authentication failed: {exc}") from exc
            raise HomeAssistantError(f"Failed to set keep unlocked on door {self.dev_id}: {exc}") from exc

    async def _async_send_server_command(self, action: str, extra_payload: Optional[Dict[str, Any]] = None) -> None:
        entry = self.coordinator.entry
        server_url = entry.data.get(CONF_SERVER_URL, "")
        api_key = entry.data.get(CONF_API_KEY, "")
        verify_ssl = entry.data.get(CONF_VERIFY_SSL, True)

        if async_get_clientsession and hasattr(self, "hass") and self.hass:
            session = async_get_clientsession(self.hass, verify_ssl=verify_ssl)
            headers = {"Authorization": f"Bearer {api_key}"}
            url = f"{server_url}/api/ha/lock/{self.dev_id}/{action}"
            post_timeout = (
                aiohttp.ClientTimeout(total=10.0, connect=4.0)
                if aiohttp and hasattr(aiohttp, "ClientTimeout")
                else 10.0
            )
            payload: Dict[str, Any] = {"confirmed": True}
            if extra_payload:
                payload.update(extra_payload)
            post_kwargs: Dict[str, Any] = {
                "headers": headers,
                "json": payload,
                "timeout": post_timeout,
            }
            try:
                sig = inspect.signature(session.post)
                if "timeout" not in sig.parameters and not any(
                    p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
                ):
                    post_kwargs.pop("timeout", None)
            except Exception:
                pass
            try:
                async with session.post(url, **post_kwargs) as resp:
                    if resp.status in (401, 403):
                        raise ConfigEntryAuthFailed(f"Authentication failed for server bridge (HTTP {resp.status})")
                    elif resp.status != 200:
                        text = await resp.text()
                        _LOGGER.error("Failed to execute %s on %s: HTTP %s (%s)", action, self.dev_id, resp.status, text)
                        raise HomeAssistantError(f"Server bridge error (HTTP {resp.status}): {text}")
            except (HomeAssistantError, ConfigEntryAuthFailed):
                raise
            except Exception as exc:
                _LOGGER.error("Network error executing %s on %s: %s", action, self.dev_id, exc)
                raise HomeAssistantError(f"Failed to communicate with server bridge: {exc}") from exc
