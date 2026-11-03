"""Constants for the GeekSmart Door Lock integration."""
from __future__ import annotations

from typing import Any, Final

DOMAIN: Final = "geek_door"

# Integration Modes
CONF_MODE: Final = "mode"
CONF_CONNECTION_MODE: Final = "connection_mode"
MODE_DIRECT_CLOUD: Final = "direct_cloud"
MODE_SERVER_BRIDGE: Final = "server_bridge"

# Direct Cloud Credentials
CONF_USERNAME: Final = "username"
CONF_PASSWORD: Final = "password"
CONF_COUNTRY_CODE: Final = "country_code"
DEFAULT_COUNTRY_CODE: Final = "1"
CONF_CACHE_PATH: Final = "cache_path"
SESSION_CACHE_FILENAME: Final = ".geek_door_session_cache.json"
CONF_DEFAULT_GW: Final = "default_gateway"

# Server Bridge Credentials
CONF_SERVER_URL: Final = "server_url"
CONF_HOST: Final = "host"
CONF_PORT: Final = "port"
CONF_API_KEY: Final = "api_key"
CONF_VERIFY_SSL: Final = "verify_ssl"
DEFAULT_SERVER_URL: Final = "http://localhost:5050"


# Common Options & Intervals
CONF_SCAN_INTERVAL: Final = "scan_interval"
DEFAULT_SCAN_INTERVAL: Final = 30
MIN_SCAN_INTERVAL: Final = 5
MAX_SCAN_INTERVAL: Final = 300

CONF_PREFER_DIRECT_BLE: Final = "prefer_direct_ble"
DEFAULT_PREFER_DIRECT_BLE: Final = True

CONF_BLE_DIRECT_FALLBACK: Final = "ble_direct_fallback"
DEFAULT_BLE_DIRECT_FALLBACK: Final = True

CONF_DEFAULT_AUTO_LOCK_TIME: Final = "default_auto_lock_time"
DEFAULT_AUTO_LOCK_TIME: Final = 5

CONF_WEBHOOK_ID: Final = "webhook_id"

# Platform definitions
try:
    from homeassistant.const import Platform
    PLATFORMS: Final[list[Any]] = [
        Platform.LOCK,
        Platform.SWITCH,
        Platform.SENSOR,
        Platform.BINARY_SENSOR,
    ]
except ImportError:
    PLATFORMS: Final[list[str]] = [
        "lock",
        "switch",
        "sensor",
        "binary_sensor",
    ]

# Custom Services & Attributes
SERVICE_KEEP_UNLOCKED: Final = "keep_unlocked"
ATTR_DURATION: Final = "duration"
ATTR_AUTO_LOCK_TIME: Final = "auto_lock_time"
ATTR_BATTERY: Final = "battery"
ATTR_BLE_CONNECTED: Final = "ble_connected"
ATTR_BLE_SIGNAL_STATE: Final = "ble_signal_state"
ATTR_RSSI: Final = "rssi"
ATTR_GATEWAY_NAME: Final = "gateway_name"
ATTR_HARDWARE_MODEL: Final = "hardware_model"
ATTR_LAST_SEEN: Final = "last_seen"
