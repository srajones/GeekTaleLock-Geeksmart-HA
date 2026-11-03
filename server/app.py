"""Alias module for server.flask_app so both `python3 -m server.flask_app` and `python3 -m server.app` work."""

from __future__ import annotations

from server.flask_app import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    create_app,
    detect_lan_ip,
    main,
)

app = create_app()

__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "app",
    "create_app",
    "detect_lan_ip",
    "main",
]

if __name__ == "__main__":
    main()
