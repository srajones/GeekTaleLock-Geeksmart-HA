"""
GeekSmart Device Extraction and Model Normalization Pipeline.

Transforms raw GeekSmart API payloads (EquipmentListMap -> DeviceListBean -> DeviceBean -> thirdpartyJson)
into standardized, strongly-typed DiscoveredDevice records with battery level, MAC, and capabilities.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Union

logger = logging.getLogger("geeksmart.extractor")

# Disassembled hardware model capability sets from classes23.dex
LOCK_MODEL_NUMBERS: Set[int] = {4, 5, 6, 7, 8, 9, 17, 19, 21, 23, 33, 51}
GATEWAY_MODEL_NUMBERS: Set[int] = {701}


@dataclass
class DiscoveredDevice:
    """Standardized representation of a discovered GeekSmart / Tuya device."""
    client_equipment_id: int
    name: str
    room_id: int
    room_name: str
    note: str
    model_no: Union[int, str]
    model_name: str
    device_type: str                  # "SMART_LOCK", "GATEWAY", "CAMERA", "UNKNOWN"
    mac_address: Optional[str]
    lock_id: Optional[int]
    electric_quantity: Optional[int]  # 0 to 100%
    is_online: bool
    open_state: str                   # "LOCKED", "UNLOCKED", "UNKNOWN"
    raw_thirdparty: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes device to JSON-serializable dictionary."""
        return {
            "client_equipment_id": self.client_equipment_id,
            "name": self.name,
            "room_id": self.room_id,
            "room_name": self.room_name,
            "note": self.note,
            "model_no": self.model_no,
            "model_name": self.model_name,
            "device_type": self.device_type,
            "mac_address": self.mac_address,
            "lock_id": self.lock_id,
            "electric_quantity": self.electric_quantity,
            "is_online": self.is_online,
            "open_state": self.open_state,
            "raw_thirdparty": self.raw_thirdparty,
        }


def parse_thirdparty_json(raw: Any) -> Dict[str, Any]:
    """
    Safely extracts dictionary from thirdpartyJson, handling nested strings,
    double-escaped JSON strings, nulls, and dict types.
    """
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        cleaned = raw.strip()
        if not cleaned or cleaned == "null":
            return {}
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, dict):
                return parsed
            if isinstance(parsed, str):  # Handle double-escaped JSON string
                nested = json.loads(parsed)
                return nested if isinstance(nested, dict) else {}
        except Exception as e:
            logger.warning("Failed to parse thirdpartyJson string '%s': %s", raw, e)
    return {}


def extract_device_from_bean(
    bean: Dict[str, Any],
    type_no: int = 0,
    type_name: str = "",
) -> DiscoveredDevice:
    """
    Transforms a raw DeviceBean dictionary into a strongly-typed DiscoveredDevice.
    """
    client_id = int(bean.get("clientEquipmentId") or 0)
    model_no = bean.get("equipmentModelNo", 0)
    model_name = str(bean.get("equipmentModelName") or f"Model-{model_no}")
    note = str(bean.get("equipmentNote") or "")
    room_id = int(bean.get("roomId") or 0)
    room_name = str(bean.get("roomName") or (f"Room {room_id}" if room_id else "Default Room"))

    # Parse thirdpartyJson
    tp = parse_thirdparty_json(bean.get("thirdpartyJson"))

    # Extract MAC address from diverse known keys
    mac = (
        tp.get("lockMac")
        or tp.get("mac")
        or bean.get("mac")
        or bean.get("equipmentMac")
        or bean.get("equipmentDid")
    )
    if mac and not isinstance(mac, str):
        mac = str(mac)

    # Extract lock ID
    lock_id = tp.get("lockId")
    if lock_id is not None:
        try:
            lock_id = int(lock_id)
        except (ValueError, TypeError):
            pass

    # Extract battery percentage (electricQuantity: 0 to 100%)
    battery = tp.get("electricQuantity")
    if battery is not None:
        try:
            battery = int(battery)
        except (ValueError, TypeError):
            battery = None

    # Determine numeric model for categorization
    numeric_model = 0
    try:
        numeric_model = int(model_no)
    except (ValueError, TypeError):
        pass

    # Device type classification
    m_name_lower = model_name.lower()
    is_gateway_flag = bool(bean.get("isGateway"))
    if type_no == 2 or numeric_model in LOCK_MODEL_NUMBERS or "deadbolt" in m_name_lower or "lock" in m_name_lower:
        dev_type = "SMART_LOCK"
    elif type_no in (10, 14) or numeric_model in GATEWAY_MODEL_NUMBERS or is_gateway_flag or "gateway" in m_name_lower or "hub" in m_name_lower:
        dev_type = "GATEWAY"
    elif type_no == 1 or "camera" in m_name_lower or "doorbell" in m_name_lower:
        dev_type = "CAMERA"
    else:
        dev_type = "UNKNOWN"

    # Human-readable name
    name = note if note else (tp.get("lockAlias") or tp.get("lockName") or model_name)

    # Online status
    online_status = bean.get("onlineStatus", 1)
    is_online = bool(online_status != 0)

    return DiscoveredDevice(
        client_equipment_id=client_id,
        name=name,
        room_id=room_id,
        room_name=room_name,
        note=note,
        model_no=model_no,
        model_name=model_name,
        device_type=dev_type,
        mac_address=mac,
        lock_id=lock_id,
        electric_quantity=battery,
        is_online=is_online,
        open_state="UNKNOWN",
        raw_thirdparty=tp,
    )


def extract_all_devices(
    equipment_list_map: Union[Dict[str, Any], Any],
) -> List[DiscoveredDevice]:
    """
    Extracts all DiscoveredDevice objects from an EquipmentListMap response.
    Gracefully handles both nested category lists (APK format) and flat equipment lists (test mocks).
    """
    devices: List[DiscoveredDevice] = []
    if not equipment_list_map:
        return devices

    if isinstance(equipment_list_map, dict):
        category_or_device_list = equipment_list_map.get("equipmentList") or []
    elif hasattr(equipment_list_map, "get"):
        category_or_device_list = equipment_list_map.get("equipmentList") or []
    else:
        return devices

    if not isinstance(category_or_device_list, list):
        return devices

    for item in category_or_device_list:
        if not isinstance(item, dict):
            continue

        # Case 1: item is a flat DeviceBean (Mock test format)
        if "clientEquipmentId" in item:
            dev = extract_device_from_bean(item, type_no=item.get("equipmentTypeNo", 0), type_name=item.get("equipmentTypeName", ""))
            devices.append(dev)

        # Case 2: item is a DeviceListBean (Category group format from APK)
        elif "equipmentList" in item and isinstance(item["equipmentList"], list):
            type_no = item.get("equipmentTypeNo", 0)
            type_name = item.get("equipmentTypeName", "")
            for dev_bean in item["equipmentList"]:
                if isinstance(dev_bean, dict):
                    dev = extract_device_from_bean(dev_bean, type_no=type_no, type_name=type_name)
                    devices.append(dev)

    return devices
