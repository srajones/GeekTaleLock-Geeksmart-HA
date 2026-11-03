"""Multi-Step Web UI Setup Walkthrough Wizard & State Machine.

Milestone 9 / Requirement R3 Implementation.
Handles:
1. Thread-safe persistent state machine (.setup_state.json) with strict 0o600 permissions.
2. Step 1: Welcome & Terms safety agreement.
3. Step 2: Environment pre-flight checks (OS, Python >= 3.9, disk space >= 1GB, ports, Nginx).
4. Step 3: Admin account & TOTP 2FA setup with pure-Python local SVG QR code and backup codes.
5. Step 4: Device discovery & Tuya mobile linkage in read-only mode with alias configuration.
6. Step 5: Domain & DNS setup (Namecheap safe API merger and guided manual DNS cards with live polling).
7. Step 6: SSL certificate issuance (Certbot webroot) and safe Nginx reverse proxy management.
8. Step 7: Completion summary & permanent production lockout.
9. One-key Nginx single-action restore integration.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
)

from server.auth import AuthManager, login_required
from server.dns_ssl_manager import (
    CertbotManager,
    DNSVerifier,
    NamecheapDNSManager,
    parse_domain_parts,
)
from server.nginx_manager import NginxManager
from server.security import (
    generate_csrf_token,
    validate_csrf_token,
    verify_token_signature,
)

logger = logging.getLogger("mydoor.setup_wizard")

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SETUP_STATE_PATH = os.environ.get(
    "SETUP_STATE_PATH",
    os.path.join(WORKSPACE_ROOT, ".setup_state.json"),
)

setup_bp = Blueprint("setup_wizard", __name__)
setup_wizard_bp = setup_bp


# ============================================================================
# Persistent State Machine Engine
# ============================================================================

class SetupStateManager:
    """Thread-safe persistent state manager with atomic writes and strict 0o600 permissions."""

    DEFAULT_INITIAL_STATE: Dict[str, Any] = {
        "version": 1,
        "is_setup_complete": False,
        "current_step": 1,
        "completed_steps": [],
        "created_at": None,
        "updated_at": None,
        "completed_at": None,
        "steps": {
            "1": {"terms_accepted": False, "accepted_at": None},
            "2": {"preflight_passed": False, "checks": None, "timestamp": None},
            "3": {
                "admin_created": False,
                "admin_username": None,
                "totp_enabled": False,
                "backup_codes_generated": False,
            },
            "4": {
                "tuya_linked": False,
                "device_count": 0,
                "device_aliases": {},
            },
            "5": {
                "domain": None,
                "subdomain": None,
                "dns_mode": None,
                "public_ip": None,
                "dns_propagated": False,
            },
            "6": {
                "ssl_enabled": False,
                "cert_issued": False,
                "nginx_configured": False,
                "nginx_backup_id": None,
            },
            "7": {
                "summary_acknowledged": False,
            },
        },
    }

    def __init__(self, state_file: Optional[str] = None) -> None:
        self.state_file = os.path.abspath(state_file or DEFAULT_SETUP_STATE_PATH)
        self._lock = threading.RLock()
        self._ensure_initialized()

    def _ensure_initialized(self) -> None:
        with self._lock:
            if not os.path.exists(self.state_file):
                initial = json.loads(json.dumps(self.DEFAULT_INITIAL_STATE))
                now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
                initial["created_at"] = now_str
                initial["updated_at"] = now_str
                self._atomic_save(initial)

    def load_state(self) -> Dict[str, Any]:
        with self._lock:
            if not os.path.exists(self.state_file):
                self._ensure_initialized()
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error("Failed to load setup state: %s", e)
                return json.loads(json.dumps(self.DEFAULT_INITIAL_STATE))

    def _atomic_save(self, data: Dict[str, Any]) -> None:
        with self._lock:
            data["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            dir_name = os.path.dirname(self.state_file)
            if dir_name and not os.path.exists(dir_name):
                os.makedirs(dir_name, mode=0o700, exist_ok=True)

            fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".setup_state_tmp_")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, sort_keys=True)
                os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
                os.replace(tmp_path, self.state_file)
            except Exception as e:
                if os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                raise e

    def is_complete(self) -> bool:
        state = self.load_state()
        return bool(state.get("is_setup_complete", False))

    def advance_step(self, step_num: int, step_data: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            state = self.load_state()
            if state.get("is_setup_complete", False):
                raise PermissionError("Setup wizard is permanently locked.")

            str_step = str(step_num)
            steps = state.setdefault("steps", {})
            current_data = steps.get(str_step, {})
            current_data.update(step_data)
            steps[str_step] = current_data

            completed = set(state.get("completed_steps", []))
            completed.add(step_num)
            state["completed_steps"] = sorted(list(completed))

            if step_num < 7:
                state["current_step"] = max(state.get("current_step", 1), step_num + 1)

            self._atomic_save(state)
            return state

    def finalize_setup(self) -> Dict[str, Any]:
        with self._lock:
            state = self.load_state()
            if state.get("is_setup_complete", False):
                return state

            completed = set(state.get("completed_steps", []))
            required_steps = {1, 2, 3}
            if not required_steps.issubset(completed):
                missing = required_steps - completed
                raise ValueError(f"Cannot finalize: required setup steps {sorted(list(missing))} not completed.")

            state["is_setup_complete"] = True
            state["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            state["current_step"] = 7
            steps = state.setdefault("steps", {})
            steps.setdefault("7", {})["summary_acknowledged"] = True
            self._atomic_save(state)
            return state


def get_setup_manager() -> SetupStateManager:
    mgr = current_app.config.get("SETUP_STATE_MANAGER")
    if mgr is None:
        mgr = SetupStateManager()
        current_app.config["SETUP_STATE_MANAGER"] = mgr
    return mgr


# ============================================================================
# Pre-Flight Checks Implementation (Step 2)
# ============================================================================

def run_preflight_checks(app_port: int = 5050) -> Dict[str, Any]:
    """Inspects host environment and returns pre-flight report."""
    checks: Dict[str, Any] = {}
    fatal_errors: List[str] = []
    warnings: List[str] = []

    # 1. OS & Platform
    os_name = sys.platform
    checks["os"] = {
        "platform": os_name,
        "is_linux": os_name.startswith("linux"),
        "is_darwin": os_name == "darwin",
        "status": "PASS",
    }

    # 2. Python Version (>= 3.9)
    py_ver = sys.version_info
    py_ver_str = f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}"
    py_ok = (py_ver.major == 3 and py_ver.minor >= 9) or (py_ver.major > 3)
    checks["python"] = {
        "version": py_ver_str,
        "required": ">= 3.9",
        "status": "PASS" if py_ok else "FAIL",
    }
    if not py_ok:
        fatal_errors.append(f"Python {py_ver_str} does not meet requirement (>= 3.9).")

    # 3. Disk Space (>= 1GB free)
    try:
        usage = shutil.disk_usage(WORKSPACE_ROOT)
        free_gb = usage.free / (1024 ** 3)
        disk_ok = free_gb >= 1.0
        checks["disk"] = {
            "free_gb": round(free_gb, 2),
            "total_gb": round(usage.total / (1024 ** 3), 2),
            "status": "PASS" if disk_ok else ("WARN" if free_gb >= 0.5 else "FAIL"),
        }
        if free_gb < 0.5:
            fatal_errors.append(f"Low disk space: {round(free_gb, 2)} GB free (< 500MB).")
        elif not disk_ok:
            warnings.append(f"Disk space is tight: {round(free_gb, 2)} GB free (recommended >= 1GB).")
    except Exception as e:
        checks["disk"] = {"error": str(e), "status": "WARN"}
        warnings.append(f"Could not inspect disk space: {e}")

    # 4. Port Availability
    def is_port_in_use(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex(("127.0.0.1", port)) == 0

    checks["ports"] = {
        "app_port": {"port": app_port, "in_use": is_port_in_use(app_port), "status": "PASS"},
        "http_port": {"port": 80, "in_use": is_port_in_use(80), "status": "PASS"},
        "https_port": {"port": 443, "in_use": is_port_in_use(443), "status": "PASS"},
    }

    # 5. Nginx Status
    nginx_path = shutil.which("nginx")
    checks["nginx"] = {
        "installed": bool(nginx_path),
        "path": nginx_path,
        "status": "PASS" if nginx_path else "WARN",
    }
    if not nginx_path:
        warnings.append("Nginx binary not found in PATH.")

    return {
        "success": len(fatal_errors) == 0,
        "checks": checks,
        "fatal_errors": fatal_errors,
        "warnings": warnings,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


# ============================================================================
# Security Middleware & Route Guards
# ============================================================================

@setup_bp.before_request
def _enforce_setup_security():
    """Enforces permanent lockout, CSRF validation, and authentication progression."""
    path = request.path or ""
    mgr = get_setup_manager()
    is_complete = mgr.is_complete()

    # 1. Permanent Lockout if setup is completed
    if is_complete:
        if path in ("/setup", "/setup/"):
            return redirect("/login")
        # Disaster recovery exception: Authenticated admin can still restore Nginx
        if path == "/api/setup/nginx/restore":
            if not (session.get("auth_user") and session.get("2fa_verified")):
                return jsonify({
                    "success": False,
                    "error": "Admin authentication required.",
                    "setup_locked": True,
                }), 403
            # Permit fall-through to CSRF validation block below instead of returning None
        else:
            return jsonify({
                "success": False,
                "error": "Setup wizard has been completed and is permanently locked.",
                "setup_locked": True,
            }), 403

    # 2. CSRF Validation on all mutating requests
    if request.method == "POST":
        cookie_csrf = request.cookies.get("mydoor_csrf_token")
        header_csrf = (
            request.headers.get("X-CSRF-Token")
            or request.headers.get("X-XSRF-Token")
            or (request.get_json(silent=True) or {}).get("csrf_token")
            or request.form.get("csrf_token")
        )
        if not validate_csrf_token(header_csrf, cookie_csrf):
            return jsonify({
                "success": False,
                "error": "Forbidden: CSRF token missing or invalid. Please reload the wizard.",
                "csrfRequired": True,
            }), 403

    # 3. Authentication Progression:
    # Steps 1-3 allowed unauthenticated; Steps 4-7 require active admin session
    match = re.search(r"/api/setup/step/(\d+)", path)
    step_num = int(match.group(1)) if match else None

    if (step_num is not None and step_num >= 4) or path.endswith("/finalize"):
        is_admin = bool(session.get("auth_user") and session.get("2fa_verified"))
        if not is_admin:
            return jsonify({
                "success": False,
                "error": "Admin authentication required. Please complete Step 3 first.",
                "requires_admin": True,
            }), 401

    return None


# ============================================================================
# Setup Wizard Routes
# ============================================================================

@setup_bp.route("/setup", methods=["GET"])
def setup_page():
    """Renders the interactive 7-step wizard UI."""
    mgr = get_setup_manager()
    if mgr.is_complete():
        return redirect("/login")

    state = mgr.load_state()

    # Generate or reuse signed CSRF token
    existing_csrf = request.cookies.get("mydoor_csrf_token")
    if existing_csrf and verify_token_signature(existing_csrf, current_app.secret_key):
        csrf_token = existing_csrf
    else:
        csrf_token = generate_csrf_token(current_app.secret_key)

    resp = make_response(render_template(
        "wizard.html",
        csrf_token=csrf_token,
        current_step=state.get("current_step", 1),
        completed_steps=state.get("completed_steps", []),
        port=current_app.config.get("PORT", 5050),
    ))
    resp.set_cookie("mydoor_csrf_token", csrf_token, samesite="Lax", path="/")
    return resp


@setup_bp.route("/api/setup/state", methods=["GET"])
def api_setup_state():
    """Returns current state machine progress."""
    mgr = get_setup_manager()
    state = mgr.load_state()
    return jsonify({
        "success": True,
        "current_step": state.get("current_step", 1),
        "completed_steps": state.get("completed_steps", []),
        "is_setup_complete": state.get("is_setup_complete", False),
        "steps": state.get("steps", {}),
    })


@setup_bp.route("/api/setup/step/<int:step_num>", methods=["POST"])
def api_setup_step(step_num: int):
    """Processes submission for a wizard step and advances state."""
    mgr = get_setup_manager()
    payload = request.get_json(silent=True) or {}

    # --- Step 1: Welcome & Terms ---
    if step_num == 1:
        terms_accepted = bool(payload.get("terms_accepted", False))
        if not terms_accepted:
            return jsonify({"success": False, "error": "You must accept the safety terms to proceed."}), 400
        mgr.advance_step(1, {
            "terms_accepted": True,
            "accepted_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        })
        return jsonify({"success": True, "next_step": 2})

    # --- Step 2: Environment Pre-Flight ---
    elif step_num == 2:
        report = run_preflight_checks(current_app.config.get("PORT", 5050))
        if not report["success"]:
            return jsonify({
                "success": False,
                "error": "Fatal pre-flight checks failed.",
                "report": report,
            }), 400
        mgr.advance_step(2, {
            "preflight_passed": True,
            "checks": report["checks"],
            "timestamp": report["timestamp"],
        })
        return jsonify({"success": True, "next_step": 3, "report": report})

    # --- Step 3: Admin & TOTP 2FA Setup ---
    elif step_num == 3:
        action = str(payload.get("action", "")).strip().lower()
        auth_mgr: Optional[AuthManager] = current_app.config.get("AUTH_MANAGER")
        if not auth_mgr:
            return jsonify({"success": False, "error": "AuthManager is not configured on server."}), 500

        if action == "create_credentials":
            username = str(payload.get("username", "")).strip()
            password = str(payload.get("password", "")).strip()
            confirm = str(payload.get("confirm_password", "")).strip()

            if not username or len(username) < 3 or not re.match(r"^[a-zA-Z0-9_\-\.]+$", username):
                return jsonify({"success": False, "error": "Username must be at least 3 alphanumeric characters."}), 400
            if len(password) < 8:
                return jsonify({"success": False, "error": "Password must be at least 8 characters long."}), 400
            if password != confirm:
                return jsonify({"success": False, "error": "Passwords do not match."}), 400

            auth_mgr.create_admin(username, password)
            totp_data = auth_mgr.generate_totp_secret(username)
            return jsonify({
                "success": True,
                "username": username,
                "secret": totp_data["secret"],
                "otpauth_uri": totp_data["otpauth_uri"],
                "qr_svg": totp_data["qr_svg"],
            })

        elif action == "verify_totp":
            username = str(payload.get("username", "")).strip()
            code = str(payload.get("code", "")).strip()

            if not auth_mgr.verify_totp(username, code):
                return jsonify({"success": False, "error": "Invalid 6-digit TOTP code."}), 400

            backup_codes = auth_mgr.generate_backup_codes(username, count=8)
            # Auto-authenticate active admin session
            session["auth_user"] = username
            session["login_time"] = time.time()
            session["2fa_verified"] = True
            current_app.config["AUTH_ENABLED"] = True

            mgr.advance_step(3, {
                "admin_created": True,
                "admin_username": username,
                "totp_enabled": True,
                "backup_codes_generated": True,
            })
            return jsonify({
                "success": True,
                "next_step": 4,
                "backup_codes": backup_codes,
            })

        return jsonify({"success": False, "error": f"Unknown Step 3 action '{action}'."}), 400

    # --- Step 4: Device Discovery & Cloud Linkage ---
    elif step_num == 4:
        action = str(payload.get("action", "save_devices")).strip().lower()
        if action == "discover":
            from client.device_extractor import extract_all_devices
            cache_path = current_app.config.get("SESSION_CACHE_PATH")
            devices = extract_all_devices(session_cache_path=cache_path)
            device_summaries = [
                {
                    "id": d.id,
                    "name": d.name,
                    "type": d.type,
                    "mac": d.mac,
                    "online": d.online,
                    "battery": d.battery,
                }
                for d in devices
            ]
            return jsonify({"success": True, "devices": device_summaries})

        elif action == "save_devices":
            aliases = payload.get("aliases", {})
            mgr.advance_step(4, {
                "tuya_linked": True,
                "device_aliases": aliases,
                "device_count": len(aliases),
            })
            return jsonify({"success": True, "next_step": 5})

        return jsonify({"success": False, "error": f"Unknown Step 4 action '{action}'."}), 400

    # --- Step 5: Domain & DNS Configuration ---
    elif step_num == 5:
        action = str(payload.get("action", "")).strip().lower()

        if action == "parse_domain":
            domain = str(payload.get("domain", "")).strip()
            sub, sld, tld = parse_domain_parts(domain)
            verifier = DNSVerifier()
            card = verifier.get_manual_dns_card(domain, payload.get("public_ip", "127.0.0.1"))
            return jsonify({"success": True, "parsed": {"sub": sub, "sld": sld, "tld": tld}, "card": card})

        elif action == "namecheap_set":
            domain = str(payload.get("domain", "")).strip()
            sub, sld, tld = parse_domain_parts(domain)
            mgr_nc = NamecheapDNSManager(
                api_user=str(payload.get("api_user", "")).strip(),
                api_key=str(payload.get("api_key", "")).strip(),
                client_ip=str(payload.get("client_ip", "")).strip(),
            )
            res = mgr_nc.safe_set_a_record(f"{sld}.{tld}", sub, payload.get("public_ip", ""))
            return jsonify(res)

        elif action == "check_dns":
            domain = str(payload.get("domain", "")).strip()
            expected_ip = str(payload.get("expected_ip", "")).strip()
            verifier = DNSVerifier()
            res = verifier.verify_propagation(domain, expected_ip)
            return jsonify(res)

        elif action == "save_dns":
            domain = str(payload.get("domain", "")).strip()
            sub, sld, tld = parse_domain_parts(domain)
            mgr.advance_step(5, {
                "domain": domain,
                "subdomain": sub,
                "sld": sld,
                "tld": tld,
                "dns_mode": payload.get("dns_mode", "manual"),
                "public_ip": payload.get("public_ip"),
                "dns_propagated": bool(payload.get("dns_propagated", False)),
            })
            return jsonify({"success": True, "next_step": 6})

        return jsonify({"success": False, "error": f"Unknown Step 5 action '{action}'."}), 400

    # --- Step 6: SSL & Safe Nginx Reverse Proxy ---
    elif step_num == 6:
        action = str(payload.get("action", "")).strip().lower()
        nginx_mgr: NginxManager = current_app.config.get("NGINX_MANAGER") or NginxManager()

        if action == "preview_nginx":
            domain = str(payload.get("domain", "")).strip()
            enable_ssl = bool(payload.get("enable_ssl", False))
            preview = nginx_mgr.render_config(domain=domain, backend_port=current_app.config.get("PORT", 5050), enable_ssl=enable_ssl)
            return jsonify({"success": True, "preview": preview})

        elif action == "apply_nginx":
            domain = str(payload.get("domain", "")).strip()
            enable_ssl = bool(payload.get("enable_ssl", False))
            stage_res = nginx_mgr.stage_and_validate(domain, backend_port=current_app.config.get("PORT", 5050), enable_ssl=enable_ssl)
            if not stage_res.get("success"):
                return jsonify(stage_res), 400

            apply_res = nginx_mgr.apply_staged_config()
            if not apply_res.get("success"):
                return jsonify(apply_res), 500

            mgr.advance_step(6, {
                "ssl_enabled": enable_ssl,
                "nginx_configured": True,
                "nginx_backup_id": apply_res.get("backup_id"),
            })
            return jsonify({"success": True, "next_step": 7, "backup_id": apply_res.get("backup_id")})

        return jsonify({"success": False, "error": f"Unknown Step 6 action '{action}'."}), 400

    return jsonify({"success": False, "error": f"Invalid step number {step_num}."}), 400


@setup_bp.route("/api/setup/finalize", methods=["POST"])
def api_setup_finalize():
    """Finalizes setup, sets permanent lock, and redirects to login."""
    mgr = get_setup_manager()
    try:
        final_state = mgr.finalize_setup()
        return jsonify({
            "success": True,
            "message": "Setup finalized successfully. Wizard is now permanently locked.",
            "redirect": "/login",
            "completed_at": final_state.get("completed_at"),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


# ============================================================================
# Setup Nginx Endpoints
# ============================================================================

@setup_bp.route("/api/setup/nginx/preview", methods=["GET", "POST"])
def api_setup_nginx_preview():
    """Previews Nginx configuration."""
    nginx_mgr: NginxManager = current_app.config.get("NGINX_MANAGER") or NginxManager()
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
    else:
        payload = request.args.to_dict()

    domain = str(payload.get("domain", "")).strip()
    if not domain:
        return jsonify({"success": False, "error": "Missing required parameter 'domain'."}), 400

    raw_port = payload.get("backend_port", payload.get("port", 5050))
    if raw_port is None or raw_port == "":
        raw_port = 5050
    try:
        backend_port = int(raw_port)
        if not (1 <= backend_port <= 65535):
            raise ValueError(f"Backend port must be between 1 and 65535 (got {backend_port}).")
    except (TypeError, ValueError) as exc:
        return jsonify({"success": False, "error": f"Invalid backend port '{raw_port}': must be an integer between 1 and 65535."}), 400

    enable_ssl = str(payload.get("enable_ssl", "false")).lower() in ("true", "1", "yes", "on")

    try:
        preview = nginx_mgr.render_config(domain=domain, backend_port=backend_port, enable_ssl=enable_ssl)
        return jsonify({"success": True, "config_preview": preview})
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400


@setup_bp.route("/api/setup/nginx/apply", methods=["POST"])
def api_setup_nginx_apply():
    """Stages, validates, and activates Nginx configuration."""
    nginx_mgr: NginxManager = current_app.config.get("NGINX_MANAGER") or NginxManager()
    payload = request.get_json(silent=True) or {}

    domain = str(payload.get("domain", "")).strip()
    if not domain:
        return jsonify({"success": False, "error": "Missing required parameter 'domain'."}), 400

    raw_port = payload.get("backend_port", payload.get("port", 5050))
    if raw_port is None or raw_port == "":
        raw_port = 5050
    try:
        backend_port = int(raw_port)
        if not (1 <= backend_port <= 65535):
            raise ValueError(f"Backend port must be between 1 and 65535 (got {backend_port}).")
    except (TypeError, ValueError) as exc:
        return jsonify({"success": False, "error": f"Invalid backend port '{raw_port}': must be an integer between 1 and 65535."}), 400

    enable_ssl = str(payload.get("enable_ssl", "false")).lower() in ("true", "1", "yes", "on")

    stage_res = nginx_mgr.stage_and_validate(domain=domain, backend_port=backend_port, enable_ssl=enable_ssl)
    if not stage_res.get("success"):
        return jsonify(stage_res), 400

    apply_res = nginx_mgr.apply_staged_config()
    status_code = 200 if apply_res.get("success") else 500
    return jsonify(apply_res), status_code


@setup_bp.route("/api/setup/nginx/backups", methods=["GET"])
def api_setup_nginx_backups():
    """Lists available Nginx backups."""
    nginx_mgr: NginxManager = current_app.config.get("NGINX_MANAGER") or NginxManager()
    backups = nginx_mgr.list_backups()
    return jsonify({"success": True, "backups": backups})


@setup_bp.route("/api/setup/nginx/restore", methods=["POST"])
def api_setup_nginx_restore():
    """Single-action restore endpoint reverting Nginx to prior working configuration."""
    nginx_mgr: NginxManager = current_app.config.get("NGINX_MANAGER") or NginxManager()
    payload = request.get_json(silent=True) or {}
    backup_id = payload.get("backup_id")

    restore_res = nginx_mgr.restore_backup(backup_id=backup_id)
    status_code = 200 if restore_res.get("success") else 500
    return jsonify(restore_res), status_code


# ============================================================================
# Setup DNS Endpoints
# ============================================================================

@setup_bp.route("/api/setup/dns/verify", methods=["POST"])
def api_setup_dns_verify():
    """Live DNS propagation check endpoint."""
    payload = request.get_json(silent=True) or {}
    domain = str(payload.get("domain", "")).strip()
    expected_ip = str(payload.get("expected_ip", "")).strip()
    timeout = float(payload.get("timeout", 5.0))

    if not domain or not expected_ip:
        return jsonify({"success": False, "error": "Both 'domain' and 'expected_ip' are required."}), 400

    verifier = DNSVerifier(timeout=timeout)
    res = verifier.verify_propagation(domain, expected_ip)
    return jsonify(res)


@setup_bp.route("/api/setup/dns/namecheap", methods=["POST"])
def api_setup_dns_namecheap():
    """Namecheap automated DNS setup endpoint."""
    payload = request.get_json(silent=True) or {}
    api_user = str(payload.get("api_user", "")).strip()
    api_key = str(payload.get("api_key", "")).strip()
    client_ip = str(payload.get("client_ip", "")).strip()
    domain = str(payload.get("domain", "")).strip()
    subdomain = str(payload.get("subdomain", "@")).strip()
    ip = str(payload.get("ip", "")).strip()
    ttl = int(payload.get("ttl", 300))

    if not domain or not ip:
        return jsonify({"success": False, "error": "Both 'domain' and 'ip' are required."}), 400

    mgr = NamecheapDNSManager(
        api_user=api_user,
        api_key=api_key,
        client_ip=client_ip,
        sandbox=bool(payload.get("sandbox", False)),
    )
    res = mgr.safe_set_a_record(domain=domain, subdomain=subdomain, ip=ip, ttl=ttl)
    status_code = 200 if res.get("success") else 400
    return jsonify(res), status_code
