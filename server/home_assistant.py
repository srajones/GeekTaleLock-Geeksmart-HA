"""Home Assistant Integration Engine (Milestone 8 / Requirement R6).

Provides:
1. Blueprint `ha_bp = Blueprint("home_assistant", __name__, url_prefix="/api/ha")`.
2. @ha_authenticated decorator accepting Long-Lived Bearer Token and X-HA-Access header,
   with constant-time comparison (SEC-08) and admin session coexistence.
3. REST API endpoints:
   - GET  /api/ha/status
   - GET  /api/ha/lock/<dev_id>/state
   - POST /api/ha/lock/<dev_id>/lock
   - POST /api/ha/lock/<dev_id>/unlock
   - POST /api/ha/lock/<dev_id>/keep_unlocked
4. Incoming webhook handler:
   - POST /api/ha/webhook?token=<SECRET>
5. Asynchronous non-blocking outgoing webhook dispatcher (2.0s socket timeout):
   - dispatch_ha_webhook(event_payload, webhook_url)
6. Home Assistant YAML configuration snippet generator:
   - generate_ha_yaml_config(domain, bearer_token, device_id)
"""

from __future__ import annotations

import functools
import hmac
import logging
import os
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import requests
from flask import Blueprint, current_app, jsonify, request, session

from server.security import constant_time_compare

logger = logging.getLogger("mydoor.home_assistant")

ha_bp = Blueprint("home_assistant", __name__, url_prefix="/api/ha")


# ============================================================================
# Authentication Decorator
# ============================================================================

def ha_authenticated(f):
    """Enforces Long-Lived Bearer Token or active admin session authentication.

    Accepts:
    - Authorization: Bearer <TOKEN>
    - X-HA-Access: <TOKEN>
    - Active authenticated admin web session
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        # 1. Extract token candidate from headers
        auth_hdr = request.headers.get("Authorization", "").strip()
        bearer_token = (
            auth_hdr[7:].strip()
            if auth_hdr.lower().startswith("bearer ")
            else ""
        )
        x_ha_token = request.headers.get("X-HA-Access", "").strip()
        provided_token = bearer_token or x_ha_token

        # 2. Extract expected token from app config or environment
        expected_token = str(
            current_app.config.get("HA_BEARER_TOKEN")
            or os.environ.get("HA_BEARER_TOKEN", "")
            or ""
        ).strip()

        token_valid = False
        if expected_token and provided_token:
            try:
                token_valid = constant_time_compare(provided_token, expected_token)
            except Exception as e:
                logger.warning("Error comparing HA tokens: %s", e)
                token_valid = False

        if token_valid:
            setattr(request, "_api_key_valid", True)
            setattr(request, "_ha_authenticated", True)
            return f(*args, **kwargs)

        # Explicit invalid token -> reject with 401
        if provided_token and not token_valid:
            return jsonify({
                "success": False,
                "error": "Unauthorized: Invalid Home Assistant bearer token.",
            }), 401

        # Check for active admin browser session coexistence
        auth_user = session.get("auth_user")
        if auth_user:
            auth_mgr = current_app.config.get("AUTH_MANAGER")
            requires_2fa = auth_mgr.is_totp_enabled(auth_user) if auth_mgr else False
            is_2fa_verified = session.get("2fa_verified", False)
            if not requires_2fa or is_2fa_verified:
                setattr(request, "_api_key_valid", True)
                setattr(request, "_ha_authenticated", True)
                return f(*args, **kwargs)

        return jsonify({
            "success": False,
            "error": (
                "Unauthorized: Valid Bearer token (Authorization: Bearer <token>), "
                "X-HA-Access header, or active admin session required."
            ),
        }), 401

    return decorated


# ============================================================================
# Device Resolution & Webhook Notification Helpers
# ============================================================================

def _is_sample_mode() -> bool:
    """Checks whether sample/mock mode is explicitly enabled."""
    if current_app.config.get("SAMPLE_MODE") is not None:
        return bool(current_app.config.get("SAMPLE_MODE"))
    if current_app.config.get("HA_SAMPLE_MODE") is not None:
        return bool(current_app.config.get("HA_SAMPLE_MODE"))
    engine = current_app.config.get("LOCK_ENGINE")
    if engine is not None and hasattr(engine, "sample_mode"):
        return bool(engine.sample_mode)
    env_val = os.environ.get("SAMPLE_MODE") or os.environ.get("HA_SAMPLE_MODE") or os.environ.get("GEEK_DOOR_SAMPLE_MODE")
    if env_val is not None:
        return env_val.strip().lower() in ("1", "true", "yes")
    return False


def _handle_exec_exception(dev_id: str, action: str, exc: Exception) -> Tuple[Any, int]:
    """Translates backend execution errors into standardized JSON responses with proper HTTP status codes."""
    logger.error("Error executing %s on device %s: %s", action, dev_id, exc)
    exc_name = type(exc).__name__
    exc_msg = str(exc)
    if "Auth" in exc_name or "ConfigEntryAuthFailed" in exc_name:
        return jsonify({"success": False, "error": f"Authentication failure: {exc_msg}"}), 401
    elif "Safety" in exc_name or "Barrier" in exc_name:
        return jsonify({"success": False, "error": f"Safety barrier violation: {exc_msg}"}), 403
    elif "Timeout" in exc_name or isinstance(exc, (requests.exceptions.Timeout, TimeoutError)):
        return jsonify({"success": False, "error": f"Gateway timeout: {exc_msg}"}), 504
    elif "ValueError" in exc_name or isinstance(exc, ValueError):
        return jsonify({"success": False, "error": exc_msg}), 404
    return jsonify({"success": False, "error": f"Backend communication error: {exc_msg}"}), 502


def _resolve_device(dev_id: str) -> Optional[Dict[str, Any]]:
    """Resolves device dictionary via LockEngine, current_app, or fallback cached topology."""
    engine = current_app.config.get("LOCK_ENGINE")
    if engine:
        try:
            lock = engine.get_lock(dev_id)
            if lock:
                return lock.to_dashboard_dict()
        except Exception as exc:
            logger.debug("Device resolution via LockEngine error: %s", exc)

    find_fn = getattr(current_app, "_find_device", None) or current_app.config.get("FIND_DEVICE")
    if find_fn:
        try:
            dev = find_fn(dev_id)
            if dev:
                return dev
        except Exception as exc:
            logger.debug("Device resolution via _find_device error: %s", exc)

    # In production (sample_mode=False), never return fabricated mock test locks
    if not _is_sample_mode():
        return None

    # Synthetic fallback for mock testing and offline topology (ONLY when sample_mode=True)
    state_overrides = current_app.config.get("STATE_OVERRIDES", {})
    auto_overrides = current_app.config.get("AUTO_LOCK_OVERRIDES", {})
    clean_id = str(dev_id).strip().lower()
    clean_num = clean_id.replace("lock-", "").strip()

    if "101" in clean_id or clean_id in ("livingroom", "living room door"):
        st = state_overrides.get(dev_id) or state_overrides.get("lock-101") or state_overrides.get("101") or "LOCKED"
        auto = auto_overrides.get(
            dev_id,
            auto_overrides.get("lock-101", auto_overrides.get("101", False if st == "UNLOCKED" else True)),
        )
        return {
            "id": 101,
            "devId": "lock-101",
            "name": "Living Room Door",
            "isLock": True,
            "isOnline": True,
            "state": st,
            "battery": 85,
            "autoLockEnabled": bool(auto),
            "autoLockSeconds": 5,
            "hardwareModel": "K01 2",
            "source": "cached_topology",
        }
    elif "102" in clean_id or clean_id in ("bathroom", "bathroom door"):
        st = state_overrides.get(dev_id) or state_overrides.get("lock-102") or state_overrides.get("102") or "LOCKED"
        auto = auto_overrides.get(
            dev_id,
            auto_overrides.get("lock-102", auto_overrides.get("102", False if st == "UNLOCKED" else True)),
        )
        return {
            "id": 102,
            "devId": "lock-102",
            "name": "Bathroom Door",
            "isLock": True,
            "isOnline": True,
            "state": st,
            "battery": 72,
            "autoLockEnabled": bool(auto),
            "autoLockSeconds": 8,
            "hardwareModel": "K01",
            "source": "cached_topology",
        }
    return None


def _parse_json_dict() -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Safely extracts a JSON dictionary payload from the current request.

    Returns:
        (payload_dict, None) on success or empty body.
        (None, error_msg) if payload contains invalid JSON syntax or is not a JSON object (dict).
    """
    raw_data = request.get_data(cache=True)
    if not raw_data or not raw_data.strip():
        return {}, None

    raw_payload = request.get_json(silent=True)
    if raw_payload is None:
        try:
            raw_payload = request.get_json(silent=True, force=True)
        except Exception:
            raw_payload = None

    if raw_payload is None:
        return None, "Malformed JSON: Invalid JSON syntax."

    if not isinstance(raw_payload, dict):
        return None, "Malformed JSON: Expected JSON object."

    return raw_payload, None


def _parse_bool(
    payload: Dict[str, Any],
    keys: Tuple[str, ...],
    param_name: str,
    default: bool,
) -> Tuple[Optional[bool], Optional[str]]:
    """Safely extracts and validates a boolean parameter from a payload dictionary."""
    provided_key = next((k for k in keys if k in payload), None)
    if provided_key is None:
        return default, None
    raw_val = payload[provided_key]
    if isinstance(raw_val, bool):
        return raw_val, None
    if isinstance(raw_val, str):
        cleaned = raw_val.strip().lower()
        if cleaned in ("true", "1", "yes"):
            return True, None
        if cleaned in ("false", "0", "no"):
            return False, None
    return None, f"Invalid '{param_name}': boolean expected."


def _parse_positive_int(
    payload: Dict[str, Any],
    keys: Tuple[str, ...],
    param_name: str,
    default: Optional[int] = None,
) -> Tuple[Optional[int], Optional[str]]:
    """Safely extracts and validates a positive integer parameter from a payload dictionary."""
    provided_key = next((k for k in keys if k in payload), None)
    if provided_key is None:
        return default, None
    raw_val = payload[provided_key]
    if raw_val is None or isinstance(raw_val, (dict, list, tuple, bool)):
        return None, f"Invalid '{param_name}': positive integer seconds expected."
    try:
        if isinstance(raw_val, float):
            if not raw_val.is_integer():
                return None, f"Invalid '{param_name}': positive integer seconds expected."
            val = int(raw_val)
        else:
            val = int(raw_val)
        if val <= 0:
            return None, f"Invalid '{param_name}': positive integer seconds expected."
        return val, None
    except (ValueError, TypeError):
        return None, f"Invalid '{param_name}': positive integer seconds expected."


def _trigger_outgoing_webhook_if_configured(dev_id: str, new_state: str) -> None:
    """Dispatches outgoing webhook if HA_OUTGOING_WEBHOOK_URL is configured."""
    webhook_url = (
        current_app.config.get("HA_OUTGOING_WEBHOOK_URL")
        or current_app.config.get("HA_WEBHOOK_URL")
        or os.environ.get("HA_OUTGOING_WEBHOOK_URL", "")
        or os.environ.get("HA_WEBHOOK_URL", "")
    ).strip()
    if webhook_url:
        payload = {
            "event": "lock_state_changed",
            "service": "mydoor",
            "device_id": str(dev_id),
            "new_state": str(new_state).lower(),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        dispatch_ha_webhook(payload, webhook_url)


# ============================================================================
# REST Endpoints
# ============================================================================

@ha_bp.route("/status", methods=["GET"])
@ha_authenticated
def ha_status():
    """Returns Home Assistant system status and lock inventory."""
    collect_fn = getattr(current_app, "_collect_devices", None) or current_app.config.get("COLLECT_DEVICES")
    if collect_fn:
        try:
            devices = collect_fn()
        except Exception as exc:
            logger.debug("Device collection error: %s", exc)
            devices = []
    else:
        # Fallback to LockEngine inventory if mounted in app config
        engine = current_app.config.get("LOCK_ENGINE")
        if engine:
            try:
                locks_dict = getattr(engine, "locks", None) or getattr(engine, "_locks", {})
                devices = [l.to_dashboard_dict() for l in locks_dict.values()]
            except Exception as exc:
                logger.debug("Device collection via LockEngine error: %s", exc)
                devices = []
        else:
            devices = []

    # In production (sample_mode=False), never inject fabricated mock test locks
    if not devices and _is_sample_mode():
        d1 = _resolve_device("lock-101")
        d2 = _resolve_device("lock-102")
        devices = [d for d in (d1, d2) if d]

    locks = []
    for d in (devices or []):
        if not d or not isinstance(d, dict):
            continue
        if d.get("isLock", False) or d.get("deviceType") == "SMART_LOCK":
            raw_state = str(d.get("state", "LOCKED")).upper()
            is_locked = raw_state == "LOCKED"
            ha_state = "locked" if is_locked else ("unlocked" if raw_state == "UNLOCKED" else "unknown")
            dev_id_str = str(d.get("devId", d.get("id", "")))
            battery = d.get("battery")
            if battery is None:
                battery = 85
            auto_lock = d.get("autoLockEnabled")
            if auto_lock is None:
                auto_lock = True if is_locked else False

            auto_lock_seconds = d.get("autoLockSeconds", d.get("auto_lock_seconds", 5))
            hardware_model = d.get("hardwareModel", d.get("hardware_model", "Smart Lock"))
            gateway_name = d.get("gateway_name") or d.get("gatewayName") or d.get("gatewayId") or d.get("parentId")
            ble_connected = bool(
                d.get("connectionStatus") == 2
                or d.get("connection_status") == 2
                or d.get("ble_connected")
                or d.get("bleConnected")
                or d.get("isOnline", True)
            )
            wifi_rssi = d.get("wifiRssi", d.get("wifi_rssi", -70))

            locks.append({
                "device_id": dev_id_str,
                "name": str(d.get("name", dev_id_str)),
                "state": ha_state,
                "is_locked": is_locked,
                "battery": battery,
                "online": bool(d.get("isOnline", True)),
                "auto_lock_enabled": bool(auto_lock),
                "auto_lock_seconds": auto_lock_seconds,
                "hardware_model": hardware_model,
                "gateway_name": gateway_name,
                "ble_connected": ble_connected,
                "wifi_rssi": wifi_rssi,
            })

    return jsonify({
        "service": "mydoor",
        "status": "healthy",
        "version": "1.0",
        "locks": locks,
        "count": len(locks),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }), 200


@ha_bp.route("/lock/<string:dev_id>/state", methods=["GET"])
@ha_authenticated
def ha_get_lock_state(dev_id: str):
    """Returns lock state conforming to Home Assistant REST Sensor schema."""
    engine = current_app.config.get("LOCK_ENGINE")
    if engine:
        try:
            status_snap = engine.get_status(dev_id)
            if status_snap:
                raw_state = str(status_snap.state_label or "LOCKED").upper()
                is_locked = raw_state == "LOCKED"
                ha_state = "locked" if is_locked else ("unlocked" if raw_state == "UNLOCKED" else "unknown")
                battery = status_snap.battery_percent if status_snap.battery_percent is not None else 85
                auto_lock = status_snap.auto_lock_enabled
                lock_obj = engine.get_lock(dev_id)
                name = lock_obj.name if lock_obj else dev_id
                return jsonify({
                    "state": ha_state,
                    "is_locked": is_locked,
                    "battery": battery,
                    "device_id": str(dev_id),
                    "name": str(name),
                    "online": bool(lock_obj.is_online if lock_obj else True),
                    "auto_lock_enabled": bool(auto_lock),
                    "auto_lock_seconds": status_snap.auto_lock_seconds or 5,
                    "source": "lock_engine",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }), 200
        except Exception as exc:
            logger.debug("ha_get_lock_state LockEngine lookup fallback: %s", exc)

    device = _resolve_device(dev_id)
    if not device:
        return jsonify({
            "success": False,
            "error": f"Device '{dev_id}' not found",
        }), 404

    raw_state = str(device.get("state", "LOCKED")).upper()
    is_locked = raw_state == "LOCKED"
    ha_state = "locked" if is_locked else ("unlocked" if raw_state == "UNLOCKED" else "unknown")
    battery = device.get("battery")
    if battery is None:
        battery = 85

    auto_lock = device.get("autoLockEnabled")
    if auto_lock is None:
        auto_lock = False if not is_locked else True

    return jsonify({
        "state": ha_state,
        "is_locked": is_locked,
        "battery": battery,
        "device_id": str(device.get("devId", dev_id)),
        "name": str(device.get("name", dev_id)),
        "online": bool(device.get("isOnline", True)),
        "auto_lock_enabled": bool(auto_lock),
        "auto_lock_seconds": device.get("autoLockSeconds", 5),
        "source": device.get("source", "cached_topology"),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }), 200


@ha_bp.route("/lock/<string:dev_id>/lock", methods=["POST"])
@ha_authenticated
def ha_lock_device(dev_id: str):
    """Executes safe lock actuation from Home Assistant."""
    payload, err = _parse_json_dict()
    if err:
        return jsonify({"success": False, "error": err}), 400
    dry_run, dry_err = _parse_bool(payload, ("dry_run", "dryRun"), "dry_run", False)
    if dry_err:
        return jsonify({"success": False, "error": dry_err}), 400
    confirmed, conf_err = _parse_bool(payload, ("confirmed",), "confirmed", True)
    if conf_err:
        return jsonify({"success": False, "error": conf_err}), 400

    device = _resolve_device(dev_id)
    exec_fn = getattr(current_app, "_execute_device_action", None) or current_app.config.get("EXECUTE_DEVICE_ACTION")

    if not device and not exec_fn:
        return jsonify({"success": False, "error": f"Device '{dev_id}' not found"}), 404

    if exec_fn:
        try:
            res = exec_fn(dev_id, "lock", dry_run=dry_run, confirmed=confirmed)
            if isinstance(res, tuple):
                resp_obj, code = res
                if code != 200:
                    return resp_obj, code
            elif hasattr(res, "status_code") and res.status_code != 200:
                return res
        except Exception as exc:
            return _handle_exec_exception(dev_id, "lock", exc)

    now_ts = time.time()
    clean_id = str(dev_id).strip()
    clean_num = clean_id.replace("lock-", "")
    for k in (clean_id, clean_id.lower(), f"lock-{clean_num}", clean_num):
        current_app.config.setdefault("STATE_OVERRIDES", {})[k] = "LOCKED"
        current_app.config.setdefault("STATE_OVERRIDE_TIMES", {})[k] = now_ts
        current_app.config.setdefault("AUTO_LOCK_OVERRIDES", {})[k] = True
        current_app.config.setdefault("AUTO_LOCK_OVERRIDE_TIMES", {})[k] = now_ts

    _trigger_outgoing_webhook_if_configured(dev_id, "locked")

    return jsonify({
        "success": True,
        "state": "locked",
        "is_locked": True,
        "device_id": dev_id,
        "action": "lock",
        "dry_run": dry_run,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }), 200


@ha_bp.route("/lock/<string:dev_id>/unlock", methods=["POST"])
@ha_authenticated
def ha_unlock_device(dev_id: str):
    """Executes safe unlock actuation from Home Assistant."""
    payload, err = _parse_json_dict()
    if err:
        return jsonify({"success": False, "error": err}), 400
    dry_run, dry_err = _parse_bool(payload, ("dry_run", "dryRun"), "dry_run", False)
    if dry_err:
        return jsonify({"success": False, "error": dry_err}), 400
    confirmed, conf_err = _parse_bool(payload, ("confirmed",), "confirmed", True)
    if conf_err:
        return jsonify({"success": False, "error": conf_err}), 400
    seconds_keys = ("seconds", "auto_lock_seconds", "auto_lock_time", "autoLockTime", "duration")
    seconds, sec_err = _parse_positive_int(payload, seconds_keys, "seconds", default=None)
    if sec_err:
        return jsonify({"success": False, "error": sec_err}), 400

    device = _resolve_device(dev_id)
    exec_fn = getattr(current_app, "_execute_device_action", None) or current_app.config.get("EXECUTE_DEVICE_ACTION")

    if not device and not exec_fn:
        return jsonify({"success": False, "error": f"Device '{dev_id}' not found"}), 404

    if exec_fn:
        try:
            try:
                res = exec_fn(dev_id, "unlock", dry_run=dry_run, confirmed=confirmed, auto_lock_time=seconds)
            except TypeError:
                try:
                    res = exec_fn(dev_id, "unlock", dry_run=dry_run, confirmed=confirmed, seconds=seconds)
                except TypeError:
                    res = exec_fn(dev_id, "unlock", dry_run=dry_run, confirmed=confirmed)
            if isinstance(res, tuple):
                resp_obj, code = res
                if code != 200:
                    return resp_obj, code
            elif hasattr(res, "status_code") and res.status_code != 200:
                return res
        except Exception as exc:
            return _handle_exec_exception(dev_id, "unlock", exc)

    now_ts = time.time()
    clean_id = str(dev_id).strip()
    clean_num = clean_id.replace("lock-", "")
    for k in (clean_id, clean_id.lower(), f"lock-{clean_num}", clean_num):
        current_app.config.setdefault("STATE_OVERRIDES", {})[k] = "UNLOCKED"
        current_app.config.setdefault("STATE_OVERRIDE_TIMES", {})[k] = now_ts

    _trigger_outgoing_webhook_if_configured(dev_id, "unlocked")

    resp_data = {
        "success": True,
        "state": "unlocked",
        "is_locked": False,
        "device_id": dev_id,
        "action": "unlock",
        "dry_run": dry_run,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if seconds is not None:
        resp_data["seconds"] = seconds
    return jsonify(resp_data), 200


@ha_bp.route("/lock/<string:dev_id>/keep_unlocked", methods=["POST"])
@ha_authenticated
def ha_keep_unlocked_device(dev_id: str):
    """Enables Passage Mode (Auto-lock disabled) from Home Assistant."""
    payload, err = _parse_json_dict()
    if err:
        return jsonify({"success": False, "error": err}), 400
    dry_run, dry_err = _parse_bool(payload, ("dry_run", "dryRun"), "dry_run", False)
    if dry_err:
        return jsonify({"success": False, "error": dry_err}), 400
    confirmed, conf_err = _parse_bool(payload, ("confirmed",), "confirmed", True)
    if conf_err:
        return jsonify({"success": False, "error": conf_err}), 400
    duration_keys = ("duration", "duration_seconds", "seconds")
    duration_seconds, dur_err = _parse_positive_int(payload, duration_keys, "duration", default=None)
    if dur_err:
        return jsonify({"success": False, "error": dur_err}), 400

    device = _resolve_device(dev_id)
    exec_fn = getattr(current_app, "_execute_device_action", None) or current_app.config.get("EXECUTE_DEVICE_ACTION")

    if not device and not exec_fn:
        return jsonify({"success": False, "error": f"Device '{dev_id}' not found"}), 404

    if exec_fn:
        try:
            try:
                res = exec_fn(dev_id, "keep_unlocked", dry_run=dry_run, confirmed=confirmed, auto_lock_time=duration_seconds)
            except TypeError:
                try:
                    res = exec_fn(dev_id, "keep_unlocked", dry_run=dry_run, confirmed=confirmed, seconds=duration_seconds)
                except TypeError:
                    res = exec_fn(dev_id, "keep_unlocked", dry_run=dry_run, confirmed=confirmed)
            if isinstance(res, tuple):
                resp_obj, code = res
                if code != 200:
                    return resp_obj, code
            elif hasattr(res, "status_code") and res.status_code != 200:
                return res
        except Exception as exc:
            return _handle_exec_exception(dev_id, "keep_unlocked", exc)

    now_ts = time.time()
    clean_id = str(dev_id).strip()
    clean_num = clean_id.replace("lock-", "")
    for k in (clean_id, clean_id.lower(), f"lock-{clean_num}", clean_num):
        current_app.config.setdefault("STATE_OVERRIDES", {})[k] = "UNLOCKED"
        current_app.config.setdefault("STATE_OVERRIDE_TIMES", {})[k] = now_ts
        current_app.config.setdefault("AUTO_LOCK_OVERRIDES", {})[k] = False
        current_app.config.setdefault("AUTO_LOCK_OVERRIDE_TIMES", {})[k] = now_ts

    _trigger_outgoing_webhook_if_configured(dev_id, "unlocked")

    resp_data = {
        "success": True,
        "state": "unlocked",
        "is_locked": False,
        "auto_lock_enabled": False,
        "device_id": dev_id,
        "action": "keep_unlocked",
        "dry_run": dry_run,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if duration_seconds is not None:
        resp_data["duration_seconds"] = duration_seconds
    return jsonify(resp_data), 200


@ha_bp.route("/lock/<string:dev_id>/auto_lock", methods=["POST"])
@ha_authenticated
def ha_auto_lock_device(dev_id: str):
    """Enables or disables auto-lock (DP 33) without actuating the physical deadbolt motor."""
    payload, err = _parse_json_dict()
    if err:
        return jsonify({"success": False, "error": err}), 400
    dry_run, dry_err = _parse_bool(payload, ("dry_run", "dryRun"), "dry_run", False)
    if dry_err:
        return jsonify({"success": False, "error": dry_err}), 400
    confirmed, conf_err = _parse_bool(payload, ("confirmed",), "confirmed", True)
    if conf_err:
        return jsonify({"success": False, "error": conf_err}), 400
    enabled, en_err = _parse_bool(payload, ("enabled", "auto_lock", "autoLock"), "enabled", True)
    if en_err:
        return jsonify({"success": False, "error": en_err}), 400
    time_keys = ("auto_lock_time", "autoLockTime", "auto_lock_seconds")
    auto_lock_time, time_err = _parse_positive_int(payload, time_keys, "auto_lock_time", default=5)
    if time_err:
        return jsonify({"success": False, "error": time_err}), 400
    action = "auto_lock_on" if enabled else "auto_lock_off"

    device = _resolve_device(dev_id)
    exec_fn = getattr(current_app, "_execute_device_action", None) or current_app.config.get("EXECUTE_DEVICE_ACTION")

    if not device and not exec_fn:
        return jsonify({"success": False, "error": f"Device '{dev_id}' not found"}), 404

    if exec_fn:
        try:
            try:
                res = exec_fn(dev_id, action, dry_run=dry_run, confirmed=confirmed, auto_lock_time=auto_lock_time)
            except TypeError:
                res = exec_fn(dev_id, action, dry_run=dry_run, confirmed=confirmed)
            if isinstance(res, tuple):
                resp_obj, code = res
                if code != 200:
                    return resp_obj, code
            elif hasattr(res, "status_code") and res.status_code != 200:
                return res
        except Exception as exc:
            return _handle_exec_exception(dev_id, action, exc)

    now_ts = time.time()
    clean_id = str(dev_id).strip()
    clean_num = clean_id.replace("lock-", "")
    for k in (clean_id, clean_id.lower(), f"lock-{clean_num}", clean_num):
        current_app.config.setdefault("AUTO_LOCK_OVERRIDES", {})[k] = bool(enabled)
        current_app.config.setdefault("AUTO_LOCK_OVERRIDE_TIMES", {})[k] = now_ts

    _trigger_outgoing_webhook_if_configured(dev_id, "state_update")

    return jsonify({
        "success": True,
        "auto_lock_enabled": bool(enabled),
        "device_id": dev_id,
        "action": action,
        "dry_run": dry_run,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }), 200


# ============================================================================
# Incoming Webhook Handler
# ============================================================================

@ha_bp.route("/webhook", methods=["POST"])
def ha_incoming_webhook():
    """Incoming webhook handler with secret validation."""
    token = request.args.get("token") or request.args.get("secret")
    if not token:
        token = request.headers.get("X-HA-Webhook-Secret") or request.headers.get("X-Webhook-Token")
    if not token:
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr[7:].strip()

    # Pre-parse candidate body to extract token if sent in JSON payload
    raw_payload = request.get_json(silent=True)
    if raw_payload is None and request.data:
        try:
            raw_payload = request.get_json(silent=True, force=True)
        except Exception:
            raw_payload = None

    if not token and isinstance(raw_payload, dict):
        token = raw_payload.get("token") or raw_payload.get("secret")

    expected_secret = str(
        current_app.config.get("HA_WEBHOOK_SECRET")
        or os.environ.get("HA_WEBHOOK_SECRET", "")
        or ""
    ).strip()

    token_valid = False
    if expected_secret and token:
        try:
            token_valid = constant_time_compare(str(token), expected_secret)
        except Exception as e:
            logger.warning("Error comparing HA webhook token: %s", e)
            token_valid = False

    if not token_valid:
        return jsonify({
            "success": False,
            "error": "Forbidden: Invalid or missing webhook token.",
        }), 403

    # Bypass CSRF for verified programmatic machine-to-machine webhook
    setattr(request, "_api_key_valid", True)

    # Strictly validate JSON body format for authenticated caller
    body, err = _parse_json_dict()
    if err:
        return jsonify({"success": False, "error": err}), 400

    action = str(body.get("action") or "").strip().lower()
    if not action:
        return jsonify({
            "success": False,
            "error": "Missing required 'action' parameter ('lock', 'unlock', 'keep_unlocked', 'status').",
        }), 400

    allowed_actions = ("lock", "unlock", "keep_unlocked", "auto_lock_off", "auto_lock_on", "status")
    if action not in allowed_actions:
        return jsonify({
            "success": False,
            "error": f"Invalid webhook action '{action}'. Permitted: {allowed_actions}",
        }), 400

    dev_id = str(body.get("device_id") or body.get("deviceId") or body.get("dev_id") or "lock-101").strip()
    dry_run, dry_err = _parse_bool(body, ("dry_run", "dryRun"), "dry_run", False)
    if dry_err:
        return jsonify({"success": False, "error": dry_err}), 400
    confirmed, conf_err = _parse_bool(body, ("confirmed",), "confirmed", True)
    if conf_err:
        return jsonify({"success": False, "error": conf_err}), 400
    time_keys = ("auto_lock_time", "autoLockTime", "auto_lock_seconds", "seconds", "duration")
    auto_lock_time, time_err = _parse_positive_int(body, time_keys, "auto_lock_time", default=None)
    if time_err:
        return jsonify({"success": False, "error": time_err}), 400

    # Handle read-only status inquiry without mutating state or triggering outgoing webhooks
    if action == "status":
        device = _resolve_device(dev_id)
        if device:
            raw_state = str(device.get("state", "LOCKED")).upper()
            is_locked = raw_state == "LOCKED"
            ha_state = "locked" if is_locked else ("unlocked" if raw_state == "UNLOCKED" else "unknown")
            battery = device.get("battery", 85)
            auto_lock = device.get("autoLockEnabled")
            if auto_lock is None:
                auto_lock = True if is_locked else False
        else:
            state_overrides = current_app.config.get("STATE_OVERRIDES", {})
            auto_overrides = current_app.config.get("AUTO_LOCK_OVERRIDES", {})
            raw_state = str(state_overrides.get(dev_id, "LOCKED")).upper()
            is_locked = raw_state == "LOCKED"
            ha_state = "locked" if is_locked else ("unlocked" if raw_state == "UNLOCKED" else "unknown")
            battery = 85
            auto_lock = auto_overrides.get(dev_id, True if is_locked else False)

        return jsonify({
            "success": True,
            "action": "status",
            "device_id": dev_id,
            "state": ha_state,
            "is_locked": is_locked,
            "battery": battery,
            "auto_lock_enabled": bool(auto_lock),
            "dry_run": dry_run,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }), 200

    exec_fn = getattr(current_app, "_execute_device_action", None) or current_app.config.get("EXECUTE_DEVICE_ACTION")
    if exec_fn:
        try:
            try:
                exec_fn(
                    dev_id=dev_id,
                    action=action,
                    dry_run=dry_run,
                    confirmed=confirmed,
                    auto_lock_time=auto_lock_time,
                )
            except TypeError:
                exec_fn(
                    dev_id=dev_id,
                    action=action,
                    dry_run=dry_run,
                    confirmed=confirmed,
                )
        except Exception as exc:
            logger.warning("Error executing device action via webhook: %s", exc)

    new_state = "locked" if action == "lock" else "unlocked"
    is_locked = action == "lock"
    auto_lock_enabled = False if action in ("keep_unlocked", "auto_lock_off") else True

    now_ts = time.time()
    clean_id = str(dev_id).strip()
    clean_num = clean_id.replace("lock-", "")
    for k in (clean_id, clean_id.lower(), f"lock-{clean_num}", clean_num):
        current_app.config.setdefault("STATE_OVERRIDES", {})[k] = new_state.upper()
        current_app.config.setdefault("STATE_OVERRIDE_TIMES", {})[k] = now_ts
        current_app.config.setdefault("AUTO_LOCK_OVERRIDES", {})[k] = auto_lock_enabled
        current_app.config.setdefault("AUTO_LOCK_OVERRIDE_TIMES", {})[k] = now_ts

    _trigger_outgoing_webhook_if_configured(dev_id, new_state)

    return jsonify({
        "success": True,
        "action": action,
        "device_id": dev_id,
        "state": new_state,
        "is_locked": is_locked,
        "auto_lock_enabled": auto_lock_enabled,
        "dry_run": dry_run,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }), 200


# ============================================================================
# Outgoing Webhook Dispatcher
# ============================================================================

def dispatch_ha_webhook(
    event_payload: Dict[str, Any],
    webhook_url: Optional[str] = None,
    timeout: float = 2.0,
) -> threading.Thread:
    """Dispatches event payload to Home Assistant webhook URL asynchronously.

    Runs in a background daemon thread with strict 2.0s socket timeout.
    Guarantees non-blocking execution (< 0.5s) and catches all exceptions.
    """
    target_url = webhook_url
    if not target_url:
        try:
            target_url = (
                current_app.config.get("HA_OUTGOING_WEBHOOK_URL")
                or current_app.config.get("HA_WEBHOOK_URL")
            )
        except Exception:
            pass
    if not target_url:
        target_url = (
            os.environ.get("HA_OUTGOING_WEBHOOK_URL")
            or os.environ.get("HA_WEBHOOK_URL")
        )

    def _worker(payload: Dict[str, Any], url: Optional[str]) -> None:
        if not url or not isinstance(url, str):
            logger.debug("No valid HA webhook URL configured; skipping dispatch")
            return
        try:
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "mydoor-ha-webhook/1.0",
            }
            resp = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=timeout,
            )
            if resp is not None and getattr(resp, "status_code", 200) >= 400:
                logger.warning(
                    "HA webhook to %s responded with HTTP %d: %s",
                    url,
                    getattr(resp, "status_code", 0),
                    getattr(resp, "text", "")[:200],
                )
            elif resp is not None:
                logger.debug(
                    "HA webhook successfully delivered to %s (HTTP %d)",
                    url,
                    getattr(resp, "status_code", 200),
                )
        except requests.exceptions.Timeout:
            logger.warning("HA webhook to %s timed out after %.1fs", url, timeout)
        except requests.exceptions.RequestException as req_exc:
            logger.warning("HA webhook network error to %s: %s", url, req_exc)
        except Exception as exc:
            logger.warning("Unexpected error during HA webhook dispatch to %s: %s", url, exc)

    safe_payload = dict(event_payload) if isinstance(event_payload, dict) else {}
    thread = threading.Thread(
        target=_worker,
        args=(safe_payload, target_url),
        daemon=True,
        name=f"ha-webhook-{time.time():.3f}",
    )
    thread.start()
    return thread


def trigger_ha_state_change_webhook(
    device_id: str,
    new_state: str,
    action: str,
    battery: Optional[Union[int, float]] = None,
    dry_run: bool = False,
    auto_lock_enabled: Optional[bool] = None,
    webhook_url: Optional[str] = None,
) -> None:
    """Constructs standardized Home Assistant event payload and dispatches outgoing webhook."""
    payload: Dict[str, Any] = {
        "event": "lock_state_changed",
        "service": "mydoor",
        "device_id": str(device_id),
        "new_state": str(new_state).lower(),
        "action": str(action).lower(),
        "dry_run": dry_run,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if battery is not None:
        payload["battery"] = battery
    if auto_lock_enabled is not None:
        payload["auto_lock_enabled"] = auto_lock_enabled

    dispatch_ha_webhook(payload, webhook_url)


# ============================================================================
# YAML Configuration Snippet Generator
# ============================================================================

def generate_ha_yaml_config(
    domain: str,
    bearer_token: str,
    device_id: str,
    lock_name: str = "Front Door Lock",
    use_https: bool = True,
    scan_interval: int = 30,
    include_automation: bool = True,
    webhook_secret: Optional[str] = None,
    **kwargs,
) -> str:
    """Generate production-ready, clean Home Assistant configuration.yaml snippets.

    Generates configuration for:
    1. Template Lock entity (`lock:` platform `template`).
    2. REST commands for lock, unlock, and keep_unlocked (`rest_command:`).
    3. REST sensor for lock state & attributes (`sensor:` platform `rest`).
    4. Template sensor for battery telemetry (`device_class: battery`).
    5. Optional push-state webhook automation (`automation:`).

    Args:
        domain: Host domain or IP (e.g. 'lock.example.com' or '192.168.1.100:5050').
        bearer_token: Long-Lived Home Assistant Bearer token.
        device_id: Physical or virtual lock identifier (e.g. 'lock-101').
        lock_name: Human-friendly name for the lock entity.
        use_https: Whether to default to https:// (True) or http:// (False).
        scan_interval: Polling frequency in seconds (default 30).
        include_automation: Whether to include the push state webhook automation snippet.
        webhook_secret: Optional secret for incoming webhook automation triggers.
        **kwargs: Tolerates additional parameters (name, friendly_name, etc.).

    Returns:
        Clean, ready-to-paste YAML string.
    """
    # 1. Normalize domain & base URL
    raw_domain = str(domain).strip() if domain else "localhost:5050"
    clean_domain = raw_domain.rstrip("/")
    if not (clean_domain.startswith("http://") or clean_domain.startswith("https://")):
        scheme = "https" if use_https else "http"
        base_url = f"{scheme}://{clean_domain}"
    else:
        base_url = clean_domain

    # 2. Normalize bearer token
    clean_token = str(bearer_token).strip() if bearer_token else "<YOUR_HA_BEARER_TOKEN>"
    if clean_token.lower().startswith("bearer "):
        clean_token = clean_token[7:].strip()

    # 3. Normalize device ID & slug
    clean_device_id = str(device_id).strip() if device_id is not None else "101"
    if not clean_device_id:
        clean_device_id = "101"
    device_slug = re.sub(r"[^a-zA-Z0-9_]+", "_", clean_device_id.lower()).strip("_") or "101"

    # 4. Normalize entity names and slugs
    name = kwargs.get("name") or kwargs.get("friendly_name") or lock_name or "Front Door Lock"
    safe_name = str(name).replace("\\", "\\\\").replace('"', '\\"')
    name_slug = re.sub(r"[^a-zA-Z0-9_]+", "_", str(name).lower()).strip("_") or "front_door_lock"

    sensor_name = f"{name} Status"
    safe_sensor_name = str(sensor_name).replace("\\", "\\\\").replace('"', '\\"')
    sensor_slug = f"{name_slug}_status"

    battery_sensor_name = f"{name} Battery"
    safe_battery_name = str(battery_sensor_name).replace("\\", "\\\\").replace('"', '\\"')
    battery_sensor_slug = f"{name_slug}_battery"

    # 5. Normalize scan interval
    try:
        interval = max(5, int(scan_interval))
    except (ValueError, TypeError):
        interval = 30

    yaml_parts = [
        "# ==============================================================================",
        "# MYDOOR HOME ASSISTANT CONFIGURATION",
        "# Add this snippet to your Home Assistant configuration.yaml",
        "# ==============================================================================",
        "",
        "lock:",
        "  - platform: template",
        f'    name: "{safe_name}"',
        f'    unique_id: "mydoor_lock_{device_slug}"',
        f'    value_template: "{{{{ is_state_attr(\'sensor.{sensor_slug}\', \'is_locked\', true) }}}}"',
        "    lock:",
        "      service: rest_command.mydoor_lock",
        "      data:",
        f'        device_id: "{clean_device_id}"',
        "    unlock:",
        "      service: rest_command.mydoor_unlock",
        "      data:",
        f'        device_id: "{clean_device_id}"',
        "    optimistic: false",
        "",
        "rest_command:",
        "  mydoor_lock:",
        f'    url: "{base_url}/api/ha/lock/{{{{ device_id | default(\'{clean_device_id}\') }}}}/lock"',
        "    method: POST",
        "    headers:",
        f'      Authorization: "Bearer {clean_token}"',
        '      Content-Type: "application/json"',
        '    payload: \'{"confirmed": true}\'',
        "",
        "  mydoor_unlock:",
        f'    url: "{base_url}/api/ha/lock/{{{{ device_id | default(\'{clean_device_id}\') }}}}/unlock"',
        "    method: POST",
        "    headers:",
        f'      Authorization: "Bearer {clean_token}"',
        '      Content-Type: "application/json"',
        '    payload: \'{"confirmed": true}\'',
        "",
        "  mydoor_keep_unlocked:",
        f'    url: "{base_url}/api/ha/lock/{{{{ device_id | default(\'{clean_device_id}\') }}}}/keep_unlocked"',
        "    method: POST",
        "    headers:",
        f'      Authorization: "Bearer {clean_token}"',
        '      Content-Type: "application/json"',
        '    payload: \'{"confirmed": true}\'',
        "",
        "sensor:",
        "  - platform: rest",
        f'    name: "{safe_sensor_name}"',
        f'    unique_id: "mydoor_sensor_{device_slug}"',
        f'    resource: "{base_url}/api/ha/lock/{clean_device_id}/state"',
        "    headers:",
        f'      Authorization: "Bearer {clean_token}"',
        '      Content-Type: "application/json"',
        "    json_attributes:",
        "      - state",
        "      - is_locked",
        "      - is_unlocked",
        "      - battery",
        "      - is_online",
        "      - auto_lock_enabled",
        "      - auto_lock_seconds",
        "      - device_id",
        "      - name",
        "      - timestamp",
        '    value_template: "{{ value_json.state }}"',
        f"    scan_interval: {interval}",
        "",
        "  - platform: template",
        "    sensors:",
        f"      {battery_sensor_slug}:",
        f'        friendly_name: "{safe_battery_name}"',
        f'        unique_id: "mydoor_battery_{device_slug}"',
        f'        value_template: "{{{{ state_attr(\'sensor.{sensor_slug}\', \'battery\') }}}}"',
        '        unit_of_measurement: "%"',
        "        device_class: battery",
    ]

    if include_automation:
        yaml_parts.extend([
            "",
            "automation:",
            '  - alias: "Mydoor Push State Update"',
            '    description: "Instantly update lock status sensor when mydoor pushes state change"',
            "    trigger:",
            "      - platform: webhook",
            '        webhook_id: "mydoor_state_push"',
            "        allowed_methods:",
            "          - POST",
            "        local_only: false",
            "    action:",
            "      - service: homeassistant.update_entity",
            "        target:",
            f"          entity_id: sensor.{sensor_slug}",
        ])

    return "\n".join(yaml_parts) + "\n"
