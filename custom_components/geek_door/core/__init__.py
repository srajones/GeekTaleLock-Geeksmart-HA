"""GeekSmart and Tuya Core Client Engine for Home Assistant."""
from .exceptions import (
    GeekSmartError,
    GeekSmartAuthError,
    GeekSmartCryptoError,
    GeekSmartProtocolError,
    GeekSmartControlError,
    GeekSmartNetworkError,
    GeekSmartTimeoutError,
    SafetyBarrierViolation,
    SafetyViolationError,
    TuyaApiError,
    HomeAssistantError,
    ConfigEntryAuthFailed,
    ConfigEntryNotReady,
)
from .safety import ClientMode, SafetyBarrierGuard
from .session_manager import SessionManager, DEFAULT_CACHE_PATH
from .geeksmart_client import GeekSmartClient, ControlResult, LockState, UserInfo
from .tuya_client import TuyaClient, TuyaMobileClient, TuyaDevice
from .ble_gatt_client import BleGattClient, HomeAssistantBleAdapter
from .device_extractor import DiscoveredDevice, extract_all_devices
from .lock_engine import LockEngine, LockDevice, GatewayDevice, LockStateSnapshot, ActionResult

__all__ = [
    "GeekSmartError",
    "GeekSmartAuthError",
    "GeekSmartCryptoError",
    "GeekSmartProtocolError",
    "GeekSmartControlError",
    "GeekSmartNetworkError",
    "GeekSmartTimeoutError",
    "SafetyBarrierViolation",
    "SafetyViolationError",
    "TuyaApiError",
    "HomeAssistantError",
    "ConfigEntryAuthFailed",
    "ConfigEntryNotReady",
    "ClientMode",
    "SafetyBarrierGuard",
    "SessionManager",
    "DEFAULT_CACHE_PATH",
    "GeekSmartClient",
    "ControlResult",
    "LockState",
    "UserInfo",
    "TuyaClient",
    "TuyaMobileClient",
    "TuyaDevice",
    "BleGattClient",
    "HomeAssistantBleAdapter",
    "DiscoveredDevice",
    "extract_all_devices",
    "LockEngine",
    "LockDevice",
    "GatewayDevice",
    "LockStateSnapshot",
    "ActionResult",
]
