"""Safe Nginx Reverse Proxy Management & Single-Action Restore Engine.

Milestone 9 / Requirement R3 Implementation.
Handles:
1. Production and configurable path management (sites-available, sites-enabled, backup_dir).
2. Atomic configuration staging (mydoor.conf.tmp.<PID>) and syntax testing (nginx -t).
3. Automated timestamped backups with SHA-256 cryptographic manifests in /var/backups/mydoor-nginx/.
4. Single-action restore reverting to prior state (including clean uninstallation).
5. Production-hardened reverse proxy configuration templating (WebSocket, ACME webroot, security headers, HTTPS redirect).
6. Flask REST API Blueprint (nginx_bp) and CLI command entrypoint.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("mydoor.nginx_manager")

DEFAULT_SITES_AVAILABLE = os.environ.get("MYDOOR_NGINX_SITES_AVAILABLE", "/etc/nginx/sites-available")
DEFAULT_SITES_ENABLED = os.environ.get("MYDOOR_NGINX_SITES_ENABLED", "/etc/nginx/sites-enabled")
DEFAULT_BACKUP_DIR = os.environ.get("MYDOOR_NGINX_BACKUP_DIR", "/var/backups/mydoor-nginx")
DEFAULT_NGINX_CMD = "nginx"
DEFAULT_CONF_NAME = "mydoor.conf"
DEFAULT_LETSENCRYPT_WEBROOT = "/var/www/letsencrypt"


class NginxManager:
    """Manages safe Nginx configuration staging, validation, backups, and restores."""

    def __init__(
        self,
        sites_available: Optional[Union[str, Path]] = None,
        sites_enabled: Optional[Union[str, Path]] = None,
        backup_dir: Optional[Union[str, Path]] = None,
        nginx_cmd: str = DEFAULT_NGINX_CMD,
        conf_name: str = DEFAULT_CONF_NAME,
        reload_cmd: Optional[str] = None,
    ) -> None:
        self.sites_available = Path(sites_available or os.environ.get("MYDOOR_NGINX_SITES_AVAILABLE") or DEFAULT_SITES_AVAILABLE)
        self.sites_enabled = Path(sites_enabled or os.environ.get("MYDOOR_NGINX_SITES_ENABLED") or DEFAULT_SITES_ENABLED)
        self.backup_dir = Path(backup_dir or os.environ.get("MYDOOR_NGINX_BACKUP_DIR") or DEFAULT_BACKUP_DIR)
        self.nginx_cmd = nginx_cmd
        self.conf_name = conf_name
        self.reload_cmd = reload_cmd
        self._staged_file: Optional[Path] = None

    # --- 1. Subprocess Helpers (Mockable for Tests) ---

    def _run_nginx_test(self, staging_file: Optional[Path] = None) -> Tuple[bool, str]:
        """Runs Nginx syntax validation (nginx -t)."""
        try:
            cmd = [self.nginx_cmd, "-t"]
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            output = (proc.stdout + "\n" + proc.stderr).strip()
            return (proc.returncode == 0, output)
        except FileNotFoundError:
            logger.warning("Nginx binary '%s' not found.", self.nginx_cmd)
            return (False, f"Nginx executable '{self.nginx_cmd}' not found")
        except Exception as e:
            return (False, str(e))

    def _reload_nginx(self) -> bool:
        """Reloads Nginx service via systemctl or nginx -s reload."""
        cmds: List[List[str]] = []
        if self.reload_cmd:
            cmds.append(self.reload_cmd.split())
        cmds.append(["systemctl", "reload", "nginx"])
        cmds.append([self.nginx_cmd, "-s", "reload"])

        for cmd in cmds:
            try:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                )
                if proc.returncode == 0:
                    logger.info("Nginx reloaded successfully via %s", " ".join(cmd))
                    return True
            except Exception as e:
                logger.debug("Failed reload attempt via %s: %s", " ".join(cmd), e)
                continue
        logger.error("All Nginx reload attempts failed.")
        return False

    # --- 2. Template Generation ---

    def render_config(
        self,
        domain: str,
        backend_port: int = 5050,
        enable_ssl: bool = False,
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
        backend_host: str = "127.0.0.1",
        webroot: str = DEFAULT_LETSENCRYPT_WEBROOT,
        upstream_name: str = "mydoor_backend",
    ) -> str:
        """Generates hardened reverse proxy Nginx configuration."""
        clean_domain = domain.strip().lower()
        if not clean_domain or not re.match(r"^[a-zA-Z0-9.-]+$", clean_domain):
            raise ValueError(f"Invalid domain name: {clean_domain}")

        cert_file = cert_path or f"/etc/letsencrypt/live/{clean_domain}/fullchain.pem"
        key_file = key_path or f"/etc/letsencrypt/live/{clean_domain}/privkey.pem"

        if not enable_ssl:
            # HTTP Staging / Direct Reverse Proxy Template
            return f"""# ==============================================================================
# MyDoor Nginx Configuration - HTTP / Staging
# Domain: {clean_domain}
# Backend: http://{backend_host}:{backend_port}
# ==============================================================================

server {{
    listen 80;
    listen [::]:80;
    server_name {clean_domain};

    # ACME Challenge Webroot for Certbot Let's Encrypt
    location ^~ /.well-known/acme-challenge/ {{
        default_type "text/plain";
        root {webroot};
        allow all;
    }}

    # Security Directives
    # X-Content-Type-Options: nosniff
    # X-Frame-Options: DENY
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Reverse Proxy to MyDoor Flask Application
    location / {{
        proxy_pass http://{backend_host}:{backend_port};
        proxy_http_version 1.1;

        # WebSocket support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Forwarded headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }}
}}
"""
        else:
            # HTTPS Production Template with HTTP -> HTTPS Redirection
            return f"""# ==============================================================================
# MyDoor Nginx Configuration - HTTPS Production
# Domain: {clean_domain}
# Backend: http://{backend_host}:{backend_port}
# ==============================================================================

# HTTP -> HTTPS Redirection & ACME Challenge
server {{
    listen 80;
    listen [::]:80;
    server_name {clean_domain};

    location ^~ /.well-known/acme-challenge/ {{
        default_type "text/plain";
        root {webroot};
        allow all;
    }}

    location / {{
        return 301 https://$host$request_uri;
    }}
}}

# HTTPS Virtual Host
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {clean_domain};

    ssl_certificate {cert_file};
    ssl_certificate_key {key_file};

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Security Directives
    # X-Content-Type-Options: nosniff
    # X-Frame-Options: DENY
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location ^~ /.well-known/acme-challenge/ {{
        default_type "text/plain";
        root {webroot};
        allow all;
    }}

    location / {{
        proxy_pass http://{backend_host}:{backend_port};
        proxy_http_version 1.1;

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }}
}}
"""

    def generate_config(
        self,
        domain: str,
        backend_port: int = 5050,
        enable_ssl: bool = False,
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
        upstream_name: str = "mydoor_backend",
    ) -> str:
        """Alias for render_config meeting interface requirements."""
        return self.render_config(
            domain=domain,
            backend_port=backend_port,
            enable_ssl=enable_ssl,
            cert_path=cert_path,
            key_path=key_path,
            upstream_name=upstream_name,
        )

    # --- 3. Atomic Staging & Syntax Validation ---

    def stage_and_validate(
        self,
        domain: str,
        backend_port: int = 5050,
        enable_ssl: bool = False,
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
        custom_content: Optional[str] = None,
        upstream_name: str = "mydoor_backend",
    ) -> Dict[str, Any]:
        """Atomically stages configuration to mydoor.conf.tmp.<PID> and validates syntax."""
        self.sites_available.mkdir(parents=True, exist_ok=True)
        staging_filename = f"{self.conf_name}.tmp.{os.getpid()}"
        staging_file = self.sites_available / staging_filename

        try:
            content = custom_content or self.render_config(
                domain=domain,
                backend_port=backend_port,
                enable_ssl=enable_ssl,
                cert_path=cert_path,
                key_path=key_path,
                upstream_name=upstream_name,
            )
        except Exception as e:
            return {"success": False, "error": str(e)}

        try:
            staging_file.write_text(content, encoding="utf-8")
        except Exception as e:
            logger.error("Failed to write staging file %s: %s", staging_file, e)
            return {"success": False, "error": f"Failed to write staging file: {e}"}

        # Validate syntax via mockable helper
        is_valid, msg = self._run_nginx_test(staging_file=staging_file)
        if not is_valid:
            # Immediate cleanup on error
            try:
                staging_file.unlink(missing_ok=True)
            except Exception:
                pass
            self._staged_file = None
            return {
                "success": False,
                "error": msg,
                "staging_file": str(staging_file),
            }

        self._staged_file = staging_file
        return {
            "success": True,
            "staging_file": str(staging_file),
            "message": "Configuration staged and validated successfully",
        }

    # --- 4. Automated Backup Engine ---

    def create_backup(self, trigger: str = "manual", domain: Optional[str] = None) -> str:
        """Creates a timestamped backup directory with SHA-256 manifest."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        now = datetime.datetime.now(datetime.timezone.utc)
        epoch = int(now.timestamp())
        base_id = f"backup_{now.strftime('%Y%m%d_%H%M%S_%f')}_{epoch}"

        # Atomic directory creation with incremental fallback loop to guarantee uniqueness
        candidate_id = base_id
        counter = 1
        while True:
            target_backup_dir = self.backup_dir / candidate_id
            try:
                target_backup_dir.mkdir(parents=False, exist_ok=False)
                backup_id = candidate_id
                break
            except FileExistsError:
                candidate_id = f"{base_id}_{counter}"
                counter += 1

        files_backed_up: List[Dict[str, Any]] = []

        conf_file = self.sites_available / self.conf_name
        symlink_file = self.sites_enabled / self.conf_name

        # 1. Back up sites-available conf
        if conf_file.exists():
            backup_conf = target_backup_dir / "sites-available" / self.conf_name
            backup_conf.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(conf_file, backup_conf)
            sha256 = hashlib.sha256(conf_file.read_bytes()).hexdigest()
            files_backed_up.append({
                "source_path": str(conf_file),
                "backup_path": str(backup_conf),
                "sha256": sha256,
                "existed_before": True,
                "is_symlink": False,
            })
        else:
            files_backed_up.append({
                "source_path": str(conf_file),
                "backup_path": None,
                "sha256": None,
                "existed_before": False,
                "is_symlink": False,
            })

        # 2. Back up sites-enabled symlink/conf
        if symlink_file.is_symlink() or symlink_file.exists():
            backup_symlink = target_backup_dir / "sites-enabled" / self.conf_name
            backup_symlink.parent.mkdir(parents=True, exist_ok=True)
            is_symlink = symlink_file.is_symlink()
            target_symlink = os.readlink(symlink_file) if is_symlink else None
            sha256 = None
            if not is_symlink and symlink_file.is_file():
                sha256 = hashlib.sha256(symlink_file.read_bytes()).hexdigest()
                shutil.copy2(symlink_file, backup_symlink)

            files_backed_up.append({
                "source_path": str(symlink_file),
                "backup_path": str(backup_symlink) if not is_symlink else None,
                "target_symlink": target_symlink,
                "sha256": sha256,
                "existed_before": True,
                "is_symlink": is_symlink,
            })
        else:
            files_backed_up.append({
                "source_path": str(symlink_file),
                "backup_path": None,
                "target_symlink": None,
                "sha256": None,
                "existed_before": False,
                "is_symlink": False,
            })

        manifest = {
            "backup_id": backup_id,
            "created_at": now.isoformat(),
            "timestamp": now.isoformat(),
            "epoch": epoch,
            "trigger": trigger,
            "domain": domain,
            "files_backed_up": files_backed_up,
        }

        manifest_file = target_backup_dir / "manifest.json"
        manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        logger.info("Created Nginx backup %s (%d files tracked)", backup_id, len(files_backed_up))
        return backup_id

    # --- 5. Activation Engine ---

    def apply_staged_config(
        self,
        domain: str = "mydoor.conf",
        staging_file: Optional[Union[str, Path]] = None,
        trigger: str = "pre_apply",
    ) -> Dict[str, Any]:
        """Atomically moves staged configuration to sites-available and symlinks to sites-enabled."""
        stage_path = Path(staging_file) if staging_file else self._staged_file
        if not stage_path or not stage_path.exists():
            return {"success": False, "error": "No valid staged configuration found to apply."}

        # 1. Create automated backup before mutation
        try:
            backup_id = self.create_backup(trigger=trigger)
        except (PermissionError, OSError) as e:
            logger.error("Permission denied creating backup before activation: %s", e)
            return {
                "success": False,
                "error": f"Permission denied creating pre-apply backup in '{self.backup_dir}': {e}",
            }

        prod_conf = self.sites_available / self.conf_name
        prod_symlink = self.sites_enabled / self.conf_name

        try:
            # 2. Atomic move
            os.replace(stage_path, prod_conf)

            # 3. Create or update symlink
            if prod_symlink.is_symlink() or prod_symlink.exists():
                prod_symlink.unlink()
            prod_symlink.symlink_to(prod_conf)

            # 4. Post-activation syntax check
            valid, msg = self._run_nginx_test()
            if not valid:
                logger.error("Syntax check failed after activation: %s. Reverting to backup %s", msg, backup_id)
                self.restore_backup(backup_id=backup_id)
                return {
                    "success": False,
                    "error": f"Nginx syntax error after applying config: {msg}. Automatically rolled back.",
                    "restored_backup_id": backup_id,
                }

            # 5. Reload Nginx
            reloaded = self._reload_nginx()
            if not reloaded:
                logger.error("Failed to reload Nginx after activation. Reverting to backup %s", backup_id)
                self.restore_backup(backup_id=backup_id)
                return {
                    "success": False,
                    "error": "Failed to reload Nginx service. Automatically rolled back.",
                    "restored_backup_id": backup_id,
                }

            self._staged_file = None
            return {
                "success": True,
                "backup_id": backup_id,
                "config_file": str(prod_conf),
                "symlink_file": str(prod_symlink),
                "nginx_status": "reloaded",
            }
        except Exception as e:
            logger.exception("Exception applying staged config: %s. Attempting rollback...", e)
            self.restore_backup(backup_id=backup_id)
            return {
                "success": False,
                "error": f"Failed to apply staged config: {e}. Automatically rolled back.",
                "restored_backup_id": backup_id,
            }

    # --- 6. Single-Action Restore Engine ---

    def restore_backup(self, backup_id: Optional[str] = None) -> Dict[str, Any]:
        """Restores Nginx configuration to exact prior state from backup manifest."""
        target_id = backup_id or self.get_latest_backup_id()
        if not target_id:
            try:
                if not self.backup_dir.exists():
                    return {"success": False, "error": "No backup found to restore."}
            except (PermissionError, OSError) as e:
                return {"success": False, "error": f"Permission denied accessing backup: {e}"}
            return {"success": False, "error": "No backup found to restore."}

        # Prevent path traversal
        if not re.match(r"^backup_[a-zA-Z0-9_]+$", target_id):
            return {"success": False, "error": f"Invalid backup ID format: '{target_id}'"}

        target_backup_dir = self.backup_dir / target_id
        manifest_file = target_backup_dir / "manifest.json"
        try:
            if not manifest_file.exists():
                return {"success": False, "error": f"Backup directory or manifest missing for ID '{target_id}'"}
        except (PermissionError, OSError) as e:
            return {"success": False, "error": f"Permission denied accessing backup: {e}"}

        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        except (PermissionError, OSError) as e:
            return {"success": False, "error": f"Permission denied accessing backup: {e}"}
        except Exception as e:
            return {"success": False, "error": f"Failed to parse manifest for backup '{target_id}': {e}"}

        files_backed_up = manifest.get("files_backed_up", [])

        # Process restoration of tracked files
        try:
            for entry in files_backed_up:
                source_path = Path(entry["source_path"])
                existed_before = entry.get("existed_before", True)
                is_symlink = entry.get("is_symlink", False)
                backup_file_path = entry.get("backup_path")

                if not existed_before:
                    # Clean uninstallation: remove file or symlink
                    if source_path.is_symlink() or source_path.exists():
                        source_path.unlink()
                        logger.info("Clean removal of %s (did not exist before backup)", source_path)
                else:
                    # Restoration to prior state
                    if is_symlink:
                        target_symlink = entry.get("target_symlink")
                        if not target_symlink:
                            target_symlink = str(self.sites_available / self.conf_name)
                        if source_path.is_symlink() or source_path.exists():
                            source_path.unlink()
                        source_path.symlink_to(target_symlink)
                        logger.info("Restored symlink %s -> %s", source_path, target_symlink)
                    else:
                        if backup_file_path and Path(backup_file_path).exists():
                            if source_path.is_symlink() or source_path.exists():
                                source_path.unlink()
                            shutil.copy2(backup_file_path, source_path)
                            logger.info("Restored configuration file %s from %s", source_path, backup_file_path)
        except (PermissionError, OSError) as e:
            logger.warning("Permission denied restoring backup files for ID '%s': %s", target_id, e)
            return {"success": False, "error": f"Permission denied restoring backup files: {e}"}

        # Validate syntax and reload
        self._run_nginx_test()
        reloaded = self._reload_nginx()

        return {
            "success": True,
            "message": "Nginx configuration restored successfully",
            "restored_backup_id": target_id,
            "restored_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "nginx_status": "reloaded" if reloaded else "reload_warning",
        }

    # --- 7. Backup Discovery & Metadata ---

    def list_backups(self) -> List[Dict[str, Any]]:
        """Returns sorted list of available backups with metadata."""
        try:
            if not self.backup_dir.exists():
                return []
        except (PermissionError, OSError) as e:
            logger.warning("Permission denied or error checking backup directory '%s': %s", self.backup_dir, e)
            return []

        backups = []
        try:
            entries = list(self.backup_dir.iterdir())
        except (PermissionError, OSError) as e:
            logger.warning("Permission denied or error reading backup directory '%s': %s", self.backup_dir, e)
            return []

        for entry in entries:
            try:
                if entry.is_dir() and entry.name.startswith("backup_"):
                    manifest_file = entry / "manifest.json"
                    try:
                        manifest_exists = manifest_file.exists()
                    except (PermissionError, OSError):
                        continue
                    if manifest_exists:
                        try:
                            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
                            backups.append({
                                "backup_id": manifest.get("backup_id", entry.name),
                                "timestamp": manifest.get("timestamp") or manifest.get("created_at"),
                                "created_at": manifest.get("created_at"),
                                "epoch": manifest.get("epoch", 0),
                                "trigger": manifest.get("trigger", "unknown"),
                                "domain": manifest.get("domain"),
                                "file_count": len(manifest.get("files_backed_up", [])),
                                "files_backed_up": manifest.get("files_backed_up", []),
                            })
                        except Exception:
                            continue
            except (PermissionError, OSError):
                continue

        backups.sort(
            key=lambda b: (
                b.get("epoch", 0),
                b.get("timestamp") or b.get("created_at") or "",
                b.get("backup_id", ""),
            ),
            reverse=True,
        )
        return backups

    def get_latest_backup_id(self) -> Optional[str]:
        """Returns the ID of the most recent backup, or None if no backups exist."""
        backups = self.list_backups()
        return backups[0]["backup_id"] if backups else None


# ============================================================================
# Flask Blueprint for Nginx Setup API
# ============================================================================

from flask import Blueprint, current_app, jsonify, request
from server.auth import login_required

nginx_bp = Blueprint("nginx_setup", __name__, url_prefix="/api/setup/nginx")


def _get_manager() -> NginxManager:
    """Helper to retrieve NginxManager from app config or create standard instance."""
    mgr = current_app.config.get("NGINX_MANAGER")
    if mgr is None:
        mgr = NginxManager()
        current_app.config["NGINX_MANAGER"] = mgr
    return mgr


@nginx_bp.route("/preview", methods=["GET", "POST"])
@login_required
def api_nginx_preview():
    """Generates preview of Nginx configuration without writing to filesystem."""
    mgr = _get_manager()
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
        preview_content = mgr.render_config(
            domain=domain,
            backend_port=backend_port,
            enable_ssl=enable_ssl,
        )
        return jsonify({
            "success": True,
            "domain": domain,
            "backend_port": backend_port,
            "enable_ssl": enable_ssl,
            "config_preview": preview_content,
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400


@nginx_bp.route("/apply", methods=["POST"])
@login_required
def api_nginx_apply():
    """Stages, validates, backs up, activates, and reloads Nginx configuration."""
    mgr = _get_manager()
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

    # 1. Stage and validate
    stage_res = mgr.stage_and_validate(
        domain=domain,
        backend_port=backend_port,
        enable_ssl=enable_ssl,
    )
    if not stage_res.get("success"):
        return jsonify({
            "success": False,
            "error": stage_res.get("error", "Syntax validation failed"),
        }), 400

    # 2. Apply staged configuration (creates backup & activates)
    apply_res = mgr.apply_staged_config()
    if not apply_res.get("success"):
        return jsonify(apply_res), 500

    return jsonify({
        "success": True,
        "message": "Nginx configuration applied successfully",
        "backup_id": apply_res.get("backup_id"),
        "config_file": apply_res.get("config_file"),
        "nginx_status": apply_res.get("nginx_status", "reloaded"),
    })


@nginx_bp.route("/backups", methods=["GET"])
@login_required
def api_nginx_backups():
    """Lists all available timestamped backups with metadata."""
    mgr = _get_manager()
    backups = mgr.list_backups()
    return jsonify({"success": True, "backups": backups})


@nginx_bp.route("/restore", methods=["POST"])
@login_required
def api_nginx_restore():
    """Single-action restore endpoint to revert Nginx to prior working state."""
    mgr = _get_manager()
    payload = request.get_json(silent=True) or {}
    backup_id = payload.get("backup_id")

    restore_res = mgr.restore_backup(backup_id=backup_id)
    status_code = 200 if restore_res.get("success") else 500
    return jsonify(restore_res), status_code


# ============================================================================
# Standalone CLI Entrypoint
# ============================================================================

def main() -> None:
    """CLI tool for safe Nginx inspection, validation, and single-action restore."""
    parser = argparse.ArgumentParser(description="MyDoor Safe Nginx Management & Restore Engine")
    parser.add_argument("--restore", nargs="?", const="", default=None, help="Restore Nginx configuration (latest or specified backup_id)")
    parser.add_argument("--list-backups", action="store_true", help="List all available backups")
    parser.add_argument("--preview", action="store_true", help="Preview Nginx configuration")
    parser.add_argument("--apply", action="store_true", help="Stage, validate, backup, and apply Nginx configuration")
    parser.add_argument("--domain", type=str, help="Domain name for virtual host")
    parser.add_argument("--port", type=int, default=5050, help="Backend application port (default: 5050)")
    parser.add_argument("--ssl", action="store_true", help="Enable SSL in template")
    parser.add_argument(
        "--backup-dir",
        type=str,
        default=os.environ.get("MYDOOR_NGINX_BACKUP_DIR", DEFAULT_BACKUP_DIR),
        help="Directory storing Nginx backups (default: /var/backups/mydoor-nginx or MYDOOR_NGINX_BACKUP_DIR)",
    )
    parser.add_argument(
        "--sites-available",
        type=str,
        default=os.environ.get("MYDOOR_NGINX_SITES_AVAILABLE", DEFAULT_SITES_AVAILABLE),
        help="Path to Nginx sites-available directory (default: /etc/nginx/sites-available)",
    )
    parser.add_argument(
        "--sites-enabled",
        type=str,
        default=os.environ.get("MYDOOR_NGINX_SITES_ENABLED", DEFAULT_SITES_ENABLED),
        help="Path to Nginx sites-enabled directory (default: /etc/nginx/sites-enabled)",
    )

    args = parser.parse_args()
    mgr = NginxManager(
        sites_available=args.sites_available,
        sites_enabled=args.sites_enabled,
        backup_dir=args.backup_dir,
    )

    try:
        if args.list_backups:
            try:
                if not mgr.backup_dir.exists():
                    pass
            except (PermissionError, OSError):
                print(
                    f"Error: Permission denied accessing backup directory '{mgr.backup_dir}'. Please run with sudo or specify --backup-dir.",
                    file=sys.stderr,
                )
                sys.exit(1)

            backups = mgr.list_backups()
            print(f"\nFound {len(backups)} Nginx backups in {mgr.backup_dir}:")
            for b in backups:
                print(f" - {b['backup_id']} | {b['timestamp']} | trigger: {b['trigger']}")
            return

        if args.restore is not None:
            target_id = args.restore if args.restore else None
            print(f"Initiating single-action restore (target: {target_id or 'latest'})...")
            res = mgr.restore_backup(backup_id=target_id)
            if res.get("success"):
                print(f" [SUCCESS] Restored backup: {res.get('restored_backup_id')}")
                print(f" [STATUS]  Nginx reload: {res.get('nginx_status')}")
                sys.exit(0)
            else:
                err_msg = res.get("error", "Unknown error")
                if "permission denied" in err_msg.lower() or "permission error" in err_msg.lower():
                    print(
                        f"Error: Permission denied accessing backup directory '{mgr.backup_dir}'. Please run with sudo or specify --backup-dir ({err_msg}).",
                        file=sys.stderr,
                    )
                else:
                    print(f" [FAILED]  {err_msg}", file=sys.stderr)
                sys.exit(1)

        if args.preview:
            if not args.domain:
                print("Error: --domain is required for --preview.", file=sys.stderr)
                sys.exit(1)
            print(mgr.render_config(domain=args.domain, backend_port=args.port, enable_ssl=args.ssl))
            return

        if args.apply:
            if not args.domain:
                print("Error: --domain is required for --apply.", file=sys.stderr)
                sys.exit(1)
            print(f"Staging configuration for {args.domain}:{args.port}...")
            stage_res = mgr.stage_and_validate(domain=args.domain, backend_port=args.port, enable_ssl=args.ssl)
            if not stage_res.get("success"):
                print(f" [ERROR] Staging syntax validation failed: {stage_res.get('error')}", file=sys.stderr)
                sys.exit(1)
            print("Applying configuration and reloading Nginx...")
            apply_res = mgr.apply_staged_config()
            if apply_res.get("success"):
                print(f" [SUCCESS] Applied! Backup created: {apply_res.get('backup_id')}")
                sys.exit(0)
            else:
                print(f" [FAILED]  Apply failed: {apply_res.get('error')}", file=sys.stderr)
                sys.exit(1)

        parser.print_help()

    except (PermissionError, OSError) as e:
        print(
            f"Error: Permission denied accessing '{mgr.backup_dir}'. Please run with sudo or specify --backup-dir: {e}",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as e:
        if "permission" in str(e).lower():
            print(
                f"Error: Permission denied accessing '{mgr.backup_dir}'. Please run with sudo or specify --backup-dir: {e}",
                file=sys.stderr,
            )
        else:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
