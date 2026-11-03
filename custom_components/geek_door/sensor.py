"""Sensor platform for GeekSmart Door Lock telemetry."""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

try:
    from homeassistant.components.sensor import (
        SensorDeviceClass,
        SensorEntity,
        SensorStateClass,
    )
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.const import PERCENTAGE, SIGNAL_STRENGTH_DECIBELS_MILLIWATT, EntityCategory
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity import DeviceInfo
    from homeassistant.helpers.entity_platform import AddEntitiesCallback
    from homeassistant.helpers.update_coordinator import CoordinatorEntity
except ImportError:
    class SensorEntity:  # type: ignore[no-redef]
        @property
        def native_unit_of_measurement(self) -> Optional[str]:
            return getattr(self, "_attr_native_unit_of_measurement", None)

    class CoordinatorEntity:  # type: ignore[no-redef]
        def __init__(self, coordinator: Any) -> None:
            self.coordinator = coordinator
    class DeviceInfo(dict):  # type: ignore[no-redef]
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(kwargs)
    class _MockDevClass:
        BATTERY = "battery"
        SIGNAL_STRENGTH = "signal_strength"
    class _MockStateClass:
        MEASUREMENT = "measurement"
    class _MockCat:
        DIAGNOSTIC = "diagnostic"
    SensorDeviceClass = _MockDevClass()  # type: ignore[assignment,misc]
    SensorStateClass = _MockStateClass()  # type: ignore[assignment,misc]
    EntityCategory = _MockCat()  # type: ignore[assignment,misc]
    PERCENTAGE = "%"
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT = "dBm"
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
    entities: list[Any] = []
    for dev_id in dev_ids:
        entities.append(GeekDoorBatterySensor(coordinator, dev_id))
        entities.append(GeekDoorSignalSensor(coordinator, dev_id))
        entities.append(GeekDoorBLESignalStateSensor(coordinator, dev_id))

    async_add_entities(entities)


def _extract_lock_data(coordinator: Any, dev_id: str) -> Dict[str, Any]:
    if coordinator and coordinator.data:
        val = coordinator.data.get(dev_id)
        if hasattr(val, "to_dashboard_dict"):
            return val.to_dashboard_dict()
        elif isinstance(val, dict):
            return val
        elif val is not None:
            return getattr(val, "__dict__", {})
    return {}


def _build_sensor_device_info(lock_data: Dict[str, Any], dev_id: str) -> DeviceInfo:
    info = DeviceInfo(
        identifiers={(DOMAIN, dev_id)},
        name=lock_data.get("name") or f"GeekSmart Lock {dev_id}",
        manufacturer="GeekSmart",
        model=lock_data.get("hardware_model", lock_data.get("hardwareModel", "Smart Lock")),
        sw_version=str(lock_data.get("sw_version") or lock_data.get("verSw") or "2.11.0"),
    )
    gw_id = lock_data.get("gatewayId") or lock_data.get("parentId")
    if gw_id:
        info["via_device"] = (DOMAIN, str(gw_id))
    return info


class GeekDoorBatterySensor(CoordinatorEntity, SensorEntity):
    """Battery percentage sensor (DP 8)."""

    _attr_has_entity_name = True
    _attr_name = "Battery"
    _attr_device_class = getattr(SensorDeviceClass, "BATTERY", "battery")
    _attr_state_class = getattr(SensorStateClass, "MEASUREMENT", "measurement")
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_entity_category = getattr(EntityCategory, "DIAGNOSTIC", "diagnostic")

    def __init__(self, coordinator: GeekDoorDataUpdateCoordinator, dev_id: str) -> None:
        super().__init__(coordinator)
        self.dev_id = str(dev_id)
        self._attr_unique_id = f"geek_door_battery_{dev_id}"

    @property
    def lock_data(self) -> Dict[str, Any]:
        return _extract_lock_data(self.coordinator, self.dev_id)

    @property
    def native_value(self) -> Optional[int]:
        val = self.lock_data.get("battery")
        if val is None:
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            return None

    @property
    def device_info(self) -> DeviceInfo:
        return _build_sensor_device_info(self.lock_data, self.dev_id)


class GeekDoorSignalSensor(CoordinatorEntity, SensorEntity):
    """Signal strength sensor (Smart Plug Wi-Fi RSSI in dBm)."""

    _attr_has_entity_name = True
    _attr_name = "Signal Strength"
    _attr_device_class = getattr(SensorDeviceClass, "SIGNAL_STRENGTH", "signal_strength")
    _attr_state_class = getattr(SensorStateClass, "MEASUREMENT", "measurement")
    _attr_native_unit_of_measurement = SIGNAL_STRENGTH_DECIBELS_MILLIWATT
    _attr_entity_category = getattr(EntityCategory, "DIAGNOSTIC", "diagnostic")

    def __init__(self, coordinator: GeekDoorDataUpdateCoordinator, dev_id: str) -> None:
        super().__init__(coordinator)
        self.dev_id = str(dev_id)
        self._attr_unique_id = f"geek_door_signal_{dev_id}"

    @property
    def lock_data(self) -> Dict[str, Any]:
        return _extract_lock_data(self.coordinator, self.dev_id)

    @property
    def native_value(self) -> Optional[int]:
        data = self.lock_data
        rssi = data.get("wifiRssi") if "wifiRssi" in data else (data.get("wifi_rssi") or data.get("rssi_dbm"))
        if rssi is None:
            return None
        try:
            return int(rssi)
        except (ValueError, TypeError):
            return None

    @property
    def device_info(self) -> DeviceInfo:
        return _build_sensor_device_info(self.lock_data, self.dev_id)


class GeekDoorBLESignalStateSensor(CoordinatorEntity, SensorEntity):
    """BLE Link state sensor (e.g. STRONG_ACTIVE_GATT, STANDBY)."""

    _attr_has_entity_name = True
    _attr_name = "BLE Signal State"
    _attr_icon = "mdi:bluetooth-audio"
    _attr_entity_category = getattr(EntityCategory, "DIAGNOSTIC", "diagnostic")

    def __init__(self, coordinator: GeekDoorDataUpdateCoordinator, dev_id: str) -> None:
        super().__init__(coordinator)
        self.dev_id = str(dev_id)
        self._attr_unique_id = f"geek_door_ble_state_{dev_id}"

    @property
    def lock_data(self) -> Dict[str, Any]:
        return _extract_lock_data(self.coordinator, self.dev_id)

    @property
    def native_value(self) -> Optional[str]:
        data = self.lock_data
        val = data.get("ble_signal_state") or data.get("bleSignalState")
        return str(val) if val else None

    @property
    def device_info(self) -> DeviceInfo:
        return _build_sensor_device_info(self.lock_data, self.dev_id)
