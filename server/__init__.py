"""Local Flask Mobile Dashboard Server Package for GeekSmart & Tuya Door Locks."""

from server.flask_app import create_app, detect_lan_ip, main

__all__ = ["create_app", "detect_lan_ip", "main"]
