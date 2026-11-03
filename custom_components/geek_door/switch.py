"""Switch platform: GeekSmart lock Auto-Lock / Passage Mode toggle and Smart Plug outlet relay."""
from __future__ import annotations

import inspect
import logging
from typing import Any, Dict, Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

try:
    from homeassistant.components.switch import SwitchEntity
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.const import EntityCategory
    from homeassistant.core import HomeAssistant
    from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
    from homeassistant.helpers.entity import DeviceInfo
    from homeassistant.helpers.entity_platform import AddEntitiesCallback
    from homeassistant.helpers.update_coordinator import CoordinatorEntity
    from homeassistant.helpers.aiohttp_client import async_get_clientsession
except ImportError:
    class SwitchEntity:  # type: ignore[no-redef]
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
    class _MockCat:
        CONFIG = "config"
        DIAGNOSTIC = "diagnostic"
    EntityCategory = _MockCat()  # type: ignore[assignment,misc]
    ConfigEntry = Any  # type: ignore[assignment,misc]
    HomeAssistant = Any  # type: ignore[assignment,misc]
    AddEntitiesCallback = Any  # type: ignore[assignment,misc]
    async_get_clientsession = None  # type: ignore[assignment]

from .const import (
    DOMAIN,
    MODE_DIRECT_CLOUD,
    CONF_SERVER_URL,
    CONF_API_KEY,
    CONF_VERIFY_SSL,
    CONF_BLE_DIRECT_FALLBACK,
    DEFAULT_BLE_DIRECT_FALLBACK,
)
from .coordinator import GeekDoorDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: GeekDoorDataUpdateCoordinator = (
        entry.runtime_data if hasattr(entry, "runtime_data") else hass.data[DOMAIN][entry.entry_id]
    )

    dev_ids = list(coordinator.data.keys()) if coordinator.data else []
    entities: list = [
        GeekDoorAutoLockSwitch(coordinator, dev_id)
        for dev_id in dev_ids
    ]
    if getattr(coordinator, "mode", None) == MODE_DIRECT_CLOUD:
        lock_ids = set(dev_ids)
        for gw_id, gw in (getattr(coordinator, "gateway_data", None) or {}).items():
            if str(gw_id) in lock_ids:
                continue
            if isinstance(gw, dict) and gw.get("plugOutletControllable"):
                entities.append(GeekDoorPlugOutletSwitch(coordinator, str(gw_id)))
    async_add_entities(entities)


class GeekDoorPlugOutletSwitch(CoordinatorEntity, SwitchEntity):
    """Mains outlet relay of a GeekSmart Smart Plug BLE Gateway (Tuya cz, DP 1 / switch_1).

    Turning this off cuts mains power to whatever is plugged into the outlet. The plug's
    own Wi-Fi/BLE bridge electronics stay powered. It never actuates any lock.
    """

    _attr_has_entity_name = True
    _attr_icon = "mdi:power-socket-us"
    _attr_device_class = "outlet"

    def __init__(self, coordinator: GeekDoorDataUpdateCoordinator, dev_id: str) -> None:
        super().__init__(coordinator)
        self.dev_id = str(dev_id)
        self._attr_unique_id = f"geek_door_plug_outlet_{dev_id}"

    @property
    def gateway_data(self) -> Dict[str, Any]:
        gws = getattr(self.coordinator, "gateway_data", None) or {}
        gw = gws.get(self.dev_id)
        return dict(gw) if isinstance(gw, dict) else {}

    @property
    def name(self) -> str:
        return "Outlet"

    @property
    def available(self) -> bool:
        if self.coordinator is None or not getattr(self.coordinator, "last_update_success", True):
            return False
        data = self.gateway_data
        if not data or not data.get("plugOutletControllable"):
            return False
        return bool(data.get("isOnline", True))

    @property
    def is_on(self) -> Optional[bool]:
        data = self.gateway_data
        val = data.get("outletOn")
        if not isinstance(val, bool):
            val = (data.get("dps") or {}).get("1")
        if not isinstance(val, bool):
            val = (data.get("dpCodes") or {}).get("switch_1")
        return val if isinstance(val, bool) else None

    @property
    def device_info(self) -> DeviceInfo:
        data = self.gateway_data
        return DeviceInfo(
            identifiers={(DOMAIN, self.dev_id)},
            name=data.get("name") or f"GeekSmart Plug {self.dev_id[-6:]}",
            manufacturer="GeekSmart",
            model=data.get("hardwareModel") or data.get("model") or "Smart Plug BLE Gateway",
        )

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        data = self.gateway_data
        return {
            "device_id": self.dev_id,
            "category": data.get("category"),
            "product_id": data.get("productId"),
            "bridged_locks": data.get("bridgedLocks") or [],
            "pending_cloud_confirmation": bool(data.get("outletPending")),
        }

    def _guard_target(self) -> None:
        """Entity-level guard: never allow this entity to address a lock."""
        lock_ids = set((self.coordinator.data or {}).keys()) if self.coordinator else set()
        data = self.gateway_data
        if (
            self.dev_id in lock_ids
            or data.get("isLock")
            or not data.get("isGateway")
            or data.get("category") != "cz"
        ):
            raise HomeAssistantError(
                f"Refusing outlet control: {self.dev_id} is not a GeekSmart smart plug"
            )
        if getattr(self.coordinator, "mode", None) != MODE_DIRECT_CLOUD:
            raise HomeAssistantError("Plug outlet control requires Direct Cloud mode")

    async def _async_set(self, on: bool) -> None:
        self._guard_target()
        engine = self.coordinator.engine
        try:
            if hasattr(self, "hass") and hasattr(self.hass, "async_add_executor_job"):
                res = await self.hass.async_add_executor_job(engine.set_plug_outlet, self.dev_id, on)
            else:
                res = engine.set_plug_outlet(self.dev_id, on)
        except (HomeAssistantError, ConfigEntryAuthFailed):
            raise
        except Exception as exc:
            err_str = str(exc)
            if "Auth failed" in err_str or "401" in err_str or "403" in err_str:
                raise ConfigEntryAuthFailed(f"Authentication failed: {exc}") from exc
            raise HomeAssistantError(
                f"Failed to turn {'on' if on else 'off'} outlet {self.dev_id}: {exc}"
            ) from exc
        if res is not None and hasattr(res, "get") and not res.get("success", True):
            raise HomeAssistantError(res.get("message", "Plug outlet command failed"))
        # Optimistic local update; next poll confirms the real DP 1 from the cloud.
        gws = getattr(self.coordinator, "gateway_data", None)
        if isinstance(gws, dict) and isinstance(gws.get(self.dev_id), dict):
            gws[self.dev_id]["outletOn"] = on
        self.async_write_ha_state()
        if hasattr(self.coordinator, "async_request_refresh"):
            r = self.coordinator.async_request_refresh()
            if inspect.isawaitable(r):
                await r

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._async_set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._async_set(False)


class GeekDoorAutoLockSwitch(CoordinatorEntity, SwitchEntity):
    """Switch controlling DP 33 (automatic_lock) / Passage Mode."""

    _attr_has_entity_name = True
    _attr_name = "Auto Lock"
    _attr_icon = "mdi:lock-clock"
    _attr_entity_category = getattr(EntityCategory, "CONFIG", "config")

    def __init__(self, coordinator: GeekDoorDataUpdateCoordinator, dev_id: str) -> None:
        super().__init__(coordinator)
        self.dev_id = str(dev_id)
        self._attr_unique_id = f"geek_door_autolock_{dev_id}"

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
        base = self.lock_data.get("name")
        return f"{base} Auto-Lock" if base else "Auto Lock"

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
    def is_on(self) -> bool:
        """True if Auto-Lock is enabled; False if in Keep Unlocked / Passage Mode."""
        data = self.lock_data
        if "auto_lock_enabled" in data:
            return bool(data["auto_lock_enabled"])
        if "autoLockEnabled" in data:
            return bool(data["autoLockEnabled"])
        return True

    @property
    def device_info(self) -> DeviceInfo:
        info = DeviceInfo(
            identifiers={(DOMAIN, self.dev_id)},
            name=self.lock_data.get("name") or f"GeekSmart Lock {self.dev_id}",
            manufacturer="GeekSmart",
            model=self.lock_data.get("hardware_model", self.lock_data.get("hardwareModel", "Smart Lock")),
            sw_version=str(self.lock_data.get("sw_version") or self.lock_data.get("verSw") or "2.11.0"),
        )
        gw_id = self.lock_data.get("gatewayId") or self.lock_data.get("parentId")
        if gw_id:
            info["via_device"] = (DOMAIN, str(gw_id))
        return info

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Enable auto-lock (DP 33 = True)."""
        try:
            if self.coordinator.mode == MODE_DIRECT_CLOUD:
                if hasattr(self, "hass") and hasattr(self.hass, "async_add_executor_job"):
                    res = await self.hass.async_add_executor_job(
                        self.coordinator.engine.auto_lock_on, self.dev_id
                    )
                else:
                    res = self.coordinator.engine.auto_lock_on(self.dev_id)
                if res and hasattr(res, "get") and not res.get("success"):
                    raise HomeAssistantError(res.get("message", "Auto-lock enable failed"))
            else:
                await self._async_send_server_switch(True)
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
            raise HomeAssistantError(f"Failed to turn on auto-lock for {self.dev_id}: {exc}") from exc

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Disable auto-lock / Enable Passage Mode (DP 33 = False)."""
        try:
            if self.coordinator.mode == MODE_DIRECT_CLOUD:
                if hasattr(self, "hass") and hasattr(self.hass, "async_add_executor_job"):
                    res = await self.hass.async_add_executor_job(
                        self.coordinator.engine.auto_lock_off, self.dev_id
                    )
                else:
                    res = self.coordinator.engine.auto_lock_off(self.dev_id)
                if res and hasattr(res, "get") and not res.get("success"):
                    raise HomeAssistantError(res.get("message", "Auto-lock disable failed"))
            else:
                await self._async_send_server_switch(False)
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
            raise HomeAssistantError(f"Failed to turn off auto-lock for {self.dev_id}: {exc}") from exc

    async def _async_send_server_switch(self, enable: bool) -> None:
        entry = self.coordinator.entry
        server_url = entry.data.get(CONF_SERVER_URL, "")
        api_key = entry.data.get(CONF_API_KEY, "")
        verify_ssl = entry.data.get(CONF_VERIFY_SSL, True)

        if async_get_clientsession and hasattr(self, "hass") and self.hass:
            session = async_get_clientsession(self.hass, verify_ssl=verify_ssl)
            url = f"{server_url}/api/ha/lock/{self.dev_id}/auto_lock"
            headers = {"Authorization": f"Bearer {api_key}"}
            post_timeout = (
                aiohttp.ClientTimeout(total=10.0, connect=4.0)
                if aiohttp and hasattr(aiohttp, "ClientTimeout")
                else 10.0
            )
            post_kwargs: Dict[str, Any] = {
                "headers": headers,
                "json": {"enabled": enable, "confirmed": True},
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
                        _LOGGER.error("Server switch error for %s: HTTP %s (%s)", self.dev_id, resp.status, text)
                        raise HomeAssistantError(f"Server switch error (HTTP {resp.status}): {text}")
            except (HomeAssistantError, ConfigEntryAuthFailed):
                raise
            except Exception as exc:
                _LOGGER.error("Network error executing auto_lock on %s: %s", self.dev_id, exc)
                raise HomeAssistantError(f"Failed to communicate with server bridge: {exc}") from exc
