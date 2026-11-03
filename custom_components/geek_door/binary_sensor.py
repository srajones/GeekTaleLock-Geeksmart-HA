"""Binary sensor platform for GeekSmart Door Lock connectivity."""
from __future__ import annotations

import logging
from typing import Any, Dict

try:
    from homeassistant.components.binary_sensor import (
        BinarySensorDeviceClass,
        BinarySensorEntity,
    )
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.const import EntityCategory
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity import DeviceInfo
    from homeassistant.helpers.entity_platform import AddEntitiesCallback
    from homeassistant.helpers.update_coordinator import CoordinatorEntity
except ImportError:
    class BinarySensorEntity:  # type: ignore[no-redef]
        pass
    class CoordinatorEntity:  # type: ignore[no-redef]
        def __init__(self, coordinator: Any) -> None:
            self.coordinator = coordinator
    class DeviceInfo(dict):  # type: ignore[no-redef]
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(kwargs)
    class _MockBinClass:
        CONNECTIVITY = "connectivity"
    class _MockCat:
        DIAGNOSTIC = "diagnostic"
    BinarySensorDeviceClass = _MockBinClass()  # type: ignore[assignment,misc]
    EntityCategory = _MockCat()  # type: ignore[assignment,misc]
    ConfigEntry = Any  # type: ignore[assignment,misc]
    HomeAssistant = Any  # type: ignore[assignment,misc]
    AddEntitiesCallback = Any  # type: ignore[assignment,misc]

from .const import DOMAIN
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
    entities = [
        GeekDoorBLEConnectionSensor(coordinator, dev_id)
        for dev_id in dev_ids
    ]
    async_add_entities(entities)


class GeekDoorBLEConnectionSensor(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor for BLE link status (connectionStatus == 2)."""

    _attr_has_entity_name = True
    _attr_name = "BLE Gateway Connected"
    _attr_device_class = getattr(BinarySensorDeviceClass, "CONNECTIVITY", "connectivity")
    _attr_entity_category = getattr(EntityCategory, "DIAGNOSTIC", "diagnostic")

    def __init__(self, coordinator: GeekDoorDataUpdateCoordinator, dev_id: str) -> None:
        super().__init__(coordinator)
        self.dev_id = str(dev_id)
        self._attr_unique_id = f"geek_door_ble_connected_{dev_id}"

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
    def is_on(self) -> bool:
        data = self.lock_data
        status = data.get("connection_status")
        if status is None:
            status = data.get("connectionStatus")
        return bool(status == 2 or data.get("ble_connected") or data.get("bleConnected"))

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
