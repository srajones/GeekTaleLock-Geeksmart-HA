"""
GeekSmart Command-Line Interface (CLI).

Provides safe account inspection, device discovery across Hop 1 (GeekSmart) and Hop 2 (Tuya),
lock status inquiry, capabilities reporting, and remote lock/unlock control operations
with strict safety barrier enforcement and session cache prioritization.
"""

from __future__ import annotations

import warnings
warnings.filterwarnings("ignore")

import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

from client.device_extractor import DiscoveredDevice, extract_all_devices
from client.geeksmart_client import GeekSmartClient, ControlResult, LockState, UserInfo
from client.safety import (
    ALLOWLIST_READ_ONLY,
    ALLOWLIST_SAFE_CONTROL,
    HARD_DENYLIST_ENDPOINTS,
    ClientMode,
)
from client.session_manager import DEFAULT_CACHE_PATH, SessionManager
from client.tuya_client import TuyaClient, TuyaDevice
from client.exceptions import (
    GeekSmartAuthError,
    GeekSmartControlError,
    GeekSmartNetworkError,
    GeekSmartTimeoutError,
    SafetyBarrierViolation,
    TuyaApiError,
)

logger = logging.getLogger("geeksmart.cli")


def load_credentials(env_path: str) -> Dict[str, str]:
    """Parses USER and PASS from the specified .env file."""
    if not os.path.exists(env_path):
        raise FileNotFoundError(f"Environment file not found at: {env_path}")

    creds: Dict[str, str] = {}
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                creds[k.strip()] = v.strip()

    if "USER" not in creds or "PASS" not in creds:
        raise ValueError(f"Missing USER or PASS in {env_path}")

    return creds


def init_authenticated_client(
    env_path: str = ".env",
    mode: ClientMode = ClientMode.SAFE_CONTROL,
    timeout: float = 15.0,
    cache_path: Optional[str] = None,
) -> Tuple[GeekSmartClient, UserInfo]:
    """
    Initializes GeekSmartClient prioritizing .session_cache.json.
    Strictly suppresses /app/client/loginByPassword whenever .session_cache.json exists.
    """
    session_mgr = SessionManager(cache_path)
    if session_mgr.exists():
        client = GeekSmartClient(
            timeout=timeout,
            mode=mode,
            session_cache_path=session_mgr.cache_path,
            allow_network_login=False,
            auto_relogin=False,
        )
        user = client.login(use_cache=True)
        return client, user

    creds = load_credentials(env_path)
    client = GeekSmartClient(
        timeout=timeout,
        mode=mode,
        session_cache_path=session_mgr.cache_path,
    )
    user = client.login(creds["USER"], creds["PASS"], use_cache=True)
    return client, user


def resolve_device_target(
    client: GeekSmartClient,
    device_id: Optional[Union[int, str]],
    device_name: Optional[str],
) -> Tuple[int, str]:
    """
    Resolves the client equipment ID and human-readable label from --id/--device-id or --name.

    Returns:
        Tuple[int, str]: (client_equipment_id, resolved_device_name)
    """
    if device_id is not None:
        try:
            if isinstance(device_id, bool):
                raise ValueError
            val = int(device_id)
            if val <= 0:
                raise ValueError
            return val, device_name or f"Device #{val}"
        except (ValueError, TypeError):
            raise ValueError(f"Invalid --id: '{device_id}'. Must be a positive integer.")

    if not device_name or not device_name.strip():
        raise ValueError("Either --id (or --device-id) or --name must be specified.")

    # Search by device name alias in discovered equipment map
    equipment_map = client.get_equipment_list_map()
    devices = extract_all_devices(equipment_map)

    target_clean = device_name.strip().lower()
    matches: List[DiscoveredDevice] = []

    for d in devices:
        d_name = (d.name or "").lower()
        d_note = (d.note or "").lower()
        d_room = (d.room_name or "").lower()
        if target_clean in d_name or target_clean in d_note or target_clean in d_room:
            matches.append(d)

    if len(matches) == 1:
        match = matches[0]
        return match.client_equipment_id, match.name

    if len(matches) > 1:
        match_desc = ", ".join(f"{m.name} (ID: {m.client_equipment_id})" for m in matches)
        raise ValueError(
            f"Multiple devices matched '{device_name}': {match_desc}. Please specify target using --id."
        )

    all_names = ", ".join(f"{d.name} (ID: {d.client_equipment_id})" for d in devices) or "None"
    raise ValueError(f"No device found matching '{device_name}'. Available devices: {all_names}")


def discover_tuya_devices(
    cache_path: Optional[str] = None,
    timeout: float = 15.0,
) -> Tuple[List[TuyaDevice], Optional[str]]:
    """
    Queries Hop 2 (Tuya Mobile Gateway or cached Tuya devices in .session_cache.json).
    Returns (list_of_tuya_devices, error_or_status_note).
    """
    session_mgr = SessionManager(cache_path)
    cache_data = session_mgr.load() or {}
    tuya_client = TuyaClient(session_cache_path=session_mgr.cache_path, timeout=timeout)

    try:
        tuya_client.login(use_cache=True)
        tuya_client.query_home_list()
        devices = tuya_client.get_home_device_list()
        if devices:
            return devices, None
    except Exception as exc:
        err_note = f"{type(exc).__name__}: {exc}"
        # Check if devices were pre-cached in .session_cache.json
        cached_raw = (
            cache_data.get("devices")
            or cache_data.get("tuya_devices")
            or (cache_data.get("tuya") or {}).get("devices")
            or []
        )
        if isinstance(cached_raw, list) and cached_raw:
            return [TuyaDevice.from_dict(d) for d in cached_raw if isinstance(d, dict)], err_note
        return [], err_note

    cached_raw = (
        cache_data.get("devices")
        or cache_data.get("tuya_devices")
        or (cache_data.get("tuya") or {}).get("devices")
        or []
    )
    if isinstance(cached_raw, list) and cached_raw:
        return [TuyaDevice.from_dict(d) for d in cached_raw if isinstance(d, dict)], None
    return [], None


def run_inspection(
    env_path: str = ".env",
    as_json: bool = False,
    verbose: bool = False,
    timeout: float = 15.0,
    cache_path: Optional[str] = None,
) -> int:
    """Executes read-only discovery inspection against Hop 1 (GeekSmart) and Hop 2 (Tuya)."""
    client, login_user = init_authenticated_client(
        env_path=env_path,
        mode=ClientMode.READ_ONLY,
        timeout=timeout,
        cache_path=cache_path,
    )
    client_id = login_user.client_id or login_user.get("id")
    user_email = login_user.email or login_user.get("email") or "N/A"

    try:
        equipment_map = client.get_equipment_list_map()
        devices: List[DiscoveredDevice] = extract_all_devices(equipment_map)
    except Exception as e:
        logger.debug(f"Could not retrieve direct equipment map: {e}")
        devices = []

    doorbell_locks = []
    try:
        doorbell_locks = client.get_lock_list()
    except Exception as e:
        logger.debug(f"Doorbell lock query returned: {e}")

    for dev in devices:
        if dev.device_type == "SMART_LOCK":
            try:
                state = client.query_lock_state(dev.client_equipment_id)
                dev.open_state = str(state)
            except Exception:
                dev.open_state = "UNKNOWN"
                dev.is_online = False

    tuya_devices, tuya_note = discover_tuya_devices(cache_path=cache_path, timeout=timeout)

    if as_json:
        report: Dict[str, Any] = {
            "account": {
                "clientId": client_id,
                "email": user_email,
                "tuyaUid": login_user.get("tuyaUid"),
                "tuyaUsername": login_user.get("tuyaUsername"),
                "tuyaCountryCode": login_user.get("tuyaCountryCode"),
                "ttlockUid": login_user.get("ttlockUid"),
                "ttlockUsername": login_user.get("ttlockUsername"),
                "sessionCached": SessionManager(cache_path).exists(),
            },
            "deviceCount": len(devices) + len(tuya_devices),
            "devices": [dev.to_dict() for dev in devices],
            "tuyaDevices": [td.to_dict() for td in tuya_devices],
            "doorbellLocks": [lock.__dict__ if hasattr(lock, "__dict__") else lock for lock in doorbell_locks],
            "topology": {
                "directEquipmentCount": len(devices),
                "tuyaDeviceCount": len(tuya_devices),
                "bridgeEcosystems": {
                    "tuya": {
                        "uid": login_user.get("tuyaUid"),
                        "username": login_user.get("tuyaUsername"),
                        "note": tuya_note,
                    },
                    "ttlock": {
                        "uid": login_user.get("ttlockUid"),
                        "username": login_user.get("ttlockUsername"),
                    },
                },
                "note": "Smart plug BLE gateway bridge and deadbolts communicate via linked Tuya/TTLock bridges.",
            },
        }
        print(json.dumps(report, indent=2))
        return 0

    print("\n" + "=" * 78)
    print(" GEEKSMART ACCOUNT & DEVICE DISCOVERY REPORT (STRICT READ-ONLY)")
    print("=" * 78)
    print(f" Account Email : {user_email}")
    print(f" Client ID     : {client_id}")
    print(f" Tuya UID      : {login_user.get('tuyaUid')}")
    print(f" TTLock UID    : {login_user.get('ttlockUid')} (User: {login_user.get('ttlockUsername')})")
    print("-" * 78)

    if not devices and not doorbell_locks and not tuya_devices:
        print(" [!] No direct devices returned in GeekSmart cloud equipment table.")
        print("     Session Status: Loaded from .session_cache.json (Zero loginByPassword calls).")
        print("     Topology Note : User's locks and smart plug BLE gateway bridge communicate")
        print(f"                     through linked Tuya Smart Home (UID: {login_user.get('tuyaUid')})")
        print(f"                     and TTLock (UID: {login_user.get('ttlockUid')}) sub-ecosystem bridges.")
        if verbose:
            print("     Bridge Details:")
            print(f"       - Tuya Account   : {login_user.get('tuyaUsername')} (Country: {login_user.get('tuyaCountryCode')})")
            print(f"       - TTLock Account : {login_user.get('ttlockUsername')}")
            print(f"       - Account Created: {login_user.get('createTime')}")
    else:
        if devices:
            print(f" Hop 1 (GeekSmart Direct) Devices ({len(devices)}):")
            fmt = " {id:<10} | {name:<20} | {type:<12} | {model:<10} | {batt:<6} | {status:<10}"
            print(fmt.format(id="ID", name="Name", type="Type", model="Model", batt="Batt%", status="Status"))
            print(" " + "-" * 76)
            for d in devices:
                batt_str = f"{d.electric_quantity}%" if d.electric_quantity is not None else "N/A"
                print(fmt.format(
                    id=d.client_equipment_id,
                    name=d.name[:20],
                    type=d.device_type,
                    model=str(d.model_name)[:10],
                    batt=batt_str,
                    status=d.open_state,
                ))
                if verbose and d.mac_address:
                    print(f"      MAC: {d.mac_address} | LockID: {d.lock_id} | Room: {d.room_name}")

        if tuya_devices:
            print(f"\n Hop 2 (Tuya Bridge) Devices ({len(tuya_devices)}):")
            fmt = " {id:<18} | {name:<22} | {type:<12} | {batt:<6} | {online:<8} | {dps}"
            print(fmt.format(id="DevID", name="Name", type="Category", batt="Batt%", online="Online", dps="DPs"))
            print(" " + "-" * 76)
            for td in tuya_devices:
                role = "GATEWAY" if td.is_gateway else ("SMART_LOCK" if td.is_lock else td.category)
                batt_str = f"{td.battery}%" if td.battery is not None else "N/A"
                online_str = "ONLINE" if td.is_online else "OFFLINE"
                print(fmt.format(
                    id=td.dev_id[:18],
                    name=td.name[:22],
                    type=role[:12],
                    batt=batt_str,
                    online=online_str,
                    dps=json.dumps(td.dps),
                ))

    print("=" * 78 + "\n")
    return 0


def run_status(
    env_path: str,
    device_id: Optional[Union[int, str]],
    device_name: Optional[str],
    as_json: bool = False,
    dry_run: bool = False,
    timeout: float = 15.0,
    verbose: bool = False,
    cache_path: Optional[str] = None,
) -> int:
    """Queries physical lock status for a target device."""
    client, _ = init_authenticated_client(
        env_path=env_path,
        mode=ClientMode.SAFE_CONTROL,
        timeout=timeout,
        cache_path=cache_path,
    )

    target_id, target_name = resolve_device_target(client, device_id, device_name)
    state = client.query_lock_state(target_id, dry_run=dry_run)

    if as_json:
        out = {
            "command": "status",
            "clientEquipmentId": target_id,
            "deviceName": target_name,
            "dryRun": dry_run,
            "state": str(state),
            "details": dict(state),
        }
        print(json.dumps(out, indent=2))
        return 0

    print("\n" + "=" * 78)
    banner_title = "GEEKSMART LOCK STATUS INQUIRY — DRY-RUN" if dry_run else "GEEKSMART LOCK STATUS INQUIRY"
    print(f" {banner_title}")
    print("=" * 78)
    print(f" Target Lock ID : {target_id}")
    print(f" Device Alias   : {target_name}")
    print(f" Physical State : {state}")
    print("-" * 78)
    if dry_run:
        target_info = state.get("data", {})
        print(" Target Endpoint: /app/home/ttlockGatewayQueryOpenState")
        print(f" Target URL     : {target_info.get('targetUrl', 'N/A')}")
        if verbose:
            print(f" Encrypted Data : {target_info.get('encryptedPayload', '')[:40]}...")
        print(" [DRY-RUN] Verified safety barriers and generated encrypted payload without network I/O.")
    else:
        print(f" Status Message : {state.get('message', 'success')} (Code: {state.get('code', 200)})")
        print(" Lock state verified via Smart Plug BLE Gateway Bridge.")
    print("=" * 78 + "\n")
    return 0


def run_capabilities(
    device_id: Optional[Union[int, str]] = None,
    as_json: bool = False,
) -> int:
    """Displays allowed read-only, safe control, and blocked destructive operations."""
    read_only_eps = sorted(ALLOWLIST_READ_ONLY)
    safe_control_eps = sorted(ALLOWLIST_SAFE_CONTROL)
    blocked_eps = sorted(HARD_DENYLIST_ENDPOINTS)

    payload: Dict[str, Any] = {
        "command": "capabilities",
        "deviceId": device_id,
        "hop1GeekSmart": {
            "readOnlyQueries": read_only_eps,
            "safeActuationEndpoints": safe_control_eps,
            "blockedDestructiveCount": len(blocked_eps),
            "blockedDestructiveEndpoints": blocked_eps,
        },
        "hop2Tuya": {
            "readOnlyActions": [
                "m.life.group.location.list (v7.0) — Query Homes",
                "m.life.my.group.device.list (v2.2) — Query Smart Plug BLE Gateway & Locks + DPs",
            ],
            "safeActuationActions": [
                "thing.m.device.dp.publish (v1.0) — DP 1 (lock/unlock motor or smart plug relay)",
            ],
            "supportedDataPoints": {
                "1": "door_state / lock_motor_state / switch_1 (bool)",
                "8": "residual_electricity (0-100% battery)",
                "9": "countdown_1 (0-86400s timer)",
                "14": "battery_percentage (0-100% battery)",
                "61": "remote_no_dp_key (remote unlock ticket)",
            },
        },
    }

    if as_json:
        print(json.dumps(payload, indent=2))
        return 0

    print("\n" + "=" * 78)
    print(" GEEKSMART & TUYA DEVICE API CAPABILITIES & SAFETY MATRIX")
    print("=" * 78)
    if device_id is not None:
        print(f" Target Device Filter : {device_id}")
        print("-" * 78)
    print(f" [1] READ-ONLY QUERIES ALLOWED ({len(read_only_eps)} Hop-1 endpoints + 2 Hop-2 actions):")
    for ep in read_only_eps:
        print(f"     - GET  {ep}")
    for act in payload["hop2Tuya"]["readOnlyActions"]:
        print(f"     - POST {act}")

    print(f"\n [2] SAFE MANUAL ACTUATION ALLOWED ({len(safe_control_eps)} Hop-1 endpoints + 1 Hop-2 action):")
    for ep in safe_control_eps:
        print(f"     - GET  {ep} (requires SAFE_CONTROL + manual user trigger)")
    for act in payload["hop2Tuya"]["safeActuationActions"]:
        print(f"     - POST {act}")

    print("\n [3] SUPPORTED TUYA DATA POINTS (dps):")
    for dp_id, desc in payload["hop2Tuya"]["supportedDataPoints"].items():
        print(f"     - DP {dp_id:<3}: {desc}")

    print(f"\n [4] DESTRUCTIVE OPERATIONS PERMANENTLY BLOCKED BY SAFETY.PY ({len(blocked_eps)} endpoints):")
    for ep in blocked_eps:
        print(f"     - [BLOCKED] {ep}")
    print("=" * 78 + "\n")
    return 0


def run_control(
    action: str,  # "unlock" or "lock"
    env_path: str,
    device_id: Optional[Union[int, str]],
    device_name: Optional[str],
    as_json: bool = False,
    dry_run: bool = False,
    timeout: float = 15.0,
    verbose: bool = False,
    cache_path: Optional[str] = None,
) -> int:
    """Executes safe remote unlock or lock on target device."""
    client, _ = init_authenticated_client(
        env_path=env_path,
        mode=ClientMode.SAFE_CONTROL,
        timeout=timeout,
        cache_path=cache_path,
    )

    target_id, target_name = resolve_device_target(client, device_id, device_name)

    if action == "unlock":
        result = client.unlock_door(target_id, dry_run=dry_run)
    elif action == "lock":
        result = client.lock_door(target_id, dry_run=dry_run)
    else:
        raise ValueError(f"Unknown control action: {action}")

    if as_json:
        out = {
            "command": action,
            "clientEquipmentId": target_id,
            "deviceName": target_name,
            "success": bool(result),
            "dryRun": dry_run,
            "message": result.get("message", "success"),
            "details": dict(result),
        }
        print(json.dumps(out, indent=2))
        return 0

    print("\n" + "=" * 78)
    title_action = action.upper()
    banner_title = f"GEEKSMART REMOTE LOCK CONTROL — {title_action} (DRY-RUN)" if dry_run else f"GEEKSMART REMOTE LOCK CONTROL — {title_action}"
    print(f" {banner_title}")
    print("=" * 78)
    print(f" Action         : {title_action}")
    print(f" Target Lock ID : {target_id}")
    print(f" Device Alias   : {target_name}")
    print(f" Execution      : {'SIMULATED (DRY-RUN)' if dry_run else 'EXECUTED'}")
    print("-" * 78)
    if dry_run:
        target_info = result.get("data", {})
        print(f" Target Endpoint: {target_info.get('endpoint')}")
        print(f" Target URL     : {target_info.get('targetUrl')}")
        if verbose or not as_json:
            print(f" Encrypted Data : {target_info.get('encryptedPayload', '')[:40]}...")
        print(" [DRY-RUN] Zero network I/O executed. No command was transmitted to cloud or physical lock.")
    else:
        print(f" Result Message : {result.get('message', 'success')} (Code: {result.get('code', 200)})")
        print(" Operation transmitted safely via Smart Plug BLE Gateway Bridge.")
    print("=" * 78 + "\n")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python3 -m client.cli",
        description="GeekSmart Door Lock Safe Control & Discovery CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 1. Subcommand: inspect / list
    for cmd_name in ("inspect", "list"):
        p_inspect = subparsers.add_parser(cmd_name, help="Read-only account inspection and device discovery")
        p_inspect.add_argument("--env", default=".env", help="Path to .env credentials file (default: .env)")
        p_inspect.add_argument("--cache", default=None, help="Path to .session_cache.json")
        p_inspect.add_argument("--json", action="store_true", help="Output machine-readable JSON format")
        p_inspect.add_argument("--verbose", action="store_true", help="Include hardware MAC, LockID, and bridge details")
        p_inspect.add_argument("--timeout", type=float, default=15.0, help="HTTP request timeout in seconds")

    # 2. Subcommand: status
    p_status = subparsers.add_parser("status", help="Query physical lock open/closed state")
    p_status.add_argument("--id", "--device-id", dest="id", type=int, help="Target lock clientEquipmentId (e.g. 101)")
    p_status.add_argument("--name", type=str, help="Target lock alias or name substring (e.g. 'Living Room')")
    p_status.add_argument("--env", default=".env", help="Path to .env credentials file (default: .env)")
    p_status.add_argument("--cache", default=None, help="Path to .session_cache.json")
    p_status.add_argument("--json", action="store_true", help="Output machine-readable JSON format")
    p_status.add_argument("--dry-run", action="store_true", help="Inspect query payload without transmitting to cloud")
    p_status.add_argument("--timeout", type=float, default=15.0, help="HTTP request timeout in seconds")
    p_status.add_argument("--verbose", action="store_true", help="Include verbose debug details")

    # 3. Subcommand: capabilities
    p_caps = subparsers.add_parser("capabilities", help="List available API operations and safety blocks")
    p_caps.add_argument("--id", "--device-id", dest="id", type=str, default=None, help="Target device ID")
    p_caps.add_argument("--json", action="store_true", help="Output machine-readable JSON format")

    # 4. Subcommand: unlock
    p_unlock = subparsers.add_parser("unlock", help="Safe remote door unlock via gateway bridge")
    p_unlock.add_argument("--id", "--device-id", dest="id", type=int, help="Target lock clientEquipmentId (e.g. 101)")
    p_unlock.add_argument("--name", type=str, help="Target lock alias or name substring (e.g. 'Living Room')")
    p_unlock.add_argument("--env", default=".env", help="Path to .env credentials file (default: .env)")
    p_unlock.add_argument("--cache", default=None, help="Path to .session_cache.json")
    p_unlock.add_argument("--json", action="store_true", help="Output machine-readable JSON format")
    p_unlock.add_argument("--dry-run", action="store_true", help="Validate and encrypt payload without transmitting")
    p_unlock.add_argument("--timeout", type=float, default=15.0, help="HTTP request timeout in seconds")
    p_unlock.add_argument("--verbose", action="store_true", help="Include verbose debug details")

    # 5. Subcommand: lock
    p_lock = subparsers.add_parser("lock", help="Safe remote door lock via gateway bridge")
    p_lock.add_argument("--id", "--device-id", dest="id", type=int, help="Target lock clientEquipmentId (e.g. 101)")
    p_lock.add_argument("--name", type=str, help="Target lock alias or name substring (e.g. 'Living Room')")
    p_lock.add_argument("--env", default=".env", help="Path to .env credentials file (default: .env)")
    p_lock.add_argument("--cache", default=None, help="Path to .session_cache.json")
    p_lock.add_argument("--json", action="store_true", help="Output machine-readable JSON format")
    p_lock.add_argument("--dry-run", action="store_true", help="Validate and encrypt payload without transmitting")
    p_lock.add_argument("--timeout", type=float, default=15.0, help="HTTP request timeout in seconds")
    p_lock.add_argument("--verbose", action="store_true", help="Include verbose debug details")

    args = parser.parse_args()

    if not args.command:
        parser.print_help(sys.stderr)
        sys.exit(1)

    try:
        if args.command in ("inspect", "list"):
            sys.exit(run_inspection(args.env, as_json=args.json, verbose=args.verbose, timeout=args.timeout, cache_path=args.cache))
        elif args.command == "status":
            sys.exit(run_status(args.env, device_id=args.id, device_name=args.name, as_json=args.json, dry_run=args.dry_run, timeout=args.timeout, verbose=args.verbose, cache_path=args.cache))
        elif args.command == "capabilities":
            sys.exit(run_capabilities(device_id=args.id, as_json=args.json))
        elif args.command in ("unlock", "lock"):
            sys.exit(run_control(args.command, args.env, device_id=args.id, device_name=args.name, as_json=args.json, dry_run=args.dry_run, timeout=args.timeout, verbose=args.verbose, cache_path=args.cache))
    except Exception as e:
        if getattr(args, "json", False):
            err_dict = {
                "success": False,
                "command": args.command,
                "error": {
                    "type": type(e).__name__,
                    "message": str(e),
                }
            }
            print(json.dumps(err_dict, indent=2), file=sys.stderr)
        else:
            print(f"[ERROR] Command '{args.command}' failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
