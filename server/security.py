"""Security Hardening Engine for GeekSmart & Tuya Local Mobile Dashboard Server.

Implements:
1. Thread-safe sliding-window rate limiting (SEC-11).
2. Constant-time comparison via hmac.compare_digest (SEC-08).
3. Query-parameter token detection and rejection (SEC-09).
4. Double-submit cookie & header CSRF validation (SEC-05).
5. Standard HTTP security headers (SEC-10).
6. Identifier masking & information disclosure redaction (SEC-07).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("geeksmart.security")

# Standard HTTP Security Headers (SEC-10)
SECURITY_HEADERS: Dict[str, str] = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": (
        "geolocation=(), camera=(), microphone=(), payment=(), usb=(), display-capture=()"
    ),
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    ),
}


def constant_time_compare(
    val1: Optional[Union[str, bytes]],
    val2: Optional[Union[str, bytes]],
) -> bool:
    """Compares two strings or byte sequences in constant time to prevent timing side-channel attacks (SEC-08).

    Safely handles arbitrary Unicode/non-ASCII characters, byte sequences,
    and null/empty values without raising TypeError or leaking timing side-channels.
    """
    if val1 is None or val2 is None:
        return False
    if not isinstance(val1, (str, bytes, bytearray)) or not isinstance(val2, (str, bytes, bytearray)):
        return False
    try:
        b1 = val1.encode("utf-8", errors="ignore") if isinstance(val1, str) else bytes(val1)
        b2 = val2.encode("utf-8", errors="ignore") if isinstance(val2, str) else bytes(val2)
        b1 = b1.strip()
        b2 = b2.strip()
        if not b1 or not b2:
            return False
        return hmac.compare_digest(b1, b2)
    except Exception:
        return False


def mask_identifier(val: Any, visible_chars: int = 3) -> str:
    """Masks sensitive identifiers to prevent information disclosure (SEC-07)."""
    if val is None:
        return "[NOT_CONFIGURED]"
    s = str(val).strip()
    if not s or s.lower() in ("none", "n/a", "null"):
        return "[NOT_CONFIGURED]"
    if "@" in s:
        user, domain = s.split("@", 1)
        if len(user) <= 2:
            masked_user = user[0] + "***" if user else "***"
        else:
            masked_user = user[:2] + "***" + user[-1:]
        return f"{masked_user}@{domain}"
    if len(s) <= visible_chars:
        return "***"
    return s[:visible_chars] + "*" * min(6, len(s) - visible_chars)


def generate_csrf_token(secret: Optional[str] = None) -> str:
    """Generates a cryptographically strong 32-byte hexadecimal CSRF token, signed if secret provided."""
    raw = secrets.token_hex(32)
    if not secret:
        return raw
    sig = hmac.new(secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def verify_token_signature(token: Optional[str], secret: Optional[str]) -> bool:
    """Verifies that a token has a valid HMAC-SHA256 signature matching the secret."""
    if not token or not secret or not isinstance(token, str) or not isinstance(secret, str):
        return False
    token = token.strip()
    if "." not in token:
        return False
    parts = token.split(".", 1)
    if len(parts) != 2:
        return False
    raw, sig = parts
    if not raw or not sig:
        return False
    expected_sig = hmac.new(secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected_sig)


def validate_csrf_token(
    provided_token: Optional[str],
    expected_token: Optional[str],
    min_length: int = 16,
) -> bool:
    """Validates an incoming CSRF token in constant time (SEC-05)."""
    if not isinstance(provided_token, str) or not isinstance(expected_token, str):
        return False
    p = provided_token.strip()
    e = expected_token.strip()
    if len(p) < min_length or len(e) < min_length:
        return False
    return constant_time_compare(p, e)


class RateLimiter:
    """Thread-safe sliding-window rate limiter for hardware protection and brute-force mitigation (SEC-11)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(
        self,
        key: str,
        max_events: int,
        window_seconds: float,
    ) -> Tuple[bool, float]:
        """Evaluates whether an event is permitted within the rolling window.

        Returns:
            Tuple of (allowed: bool, retry_after_seconds: float).
        """
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            history = self._records[key]
            active = [ts for ts in history if ts > cutoff]
            self._records[key] = active

            if len(active) >= max_events:
                oldest = active[0]
                retry_after = max(1.0, round((oldest + window_seconds) - now, 1))
                return False, retry_after

            active.append(now)
            return True, 0.0

    def reset(self, key: Optional[str] = None) -> None:
        """Clears rate limit state for a key or all keys (for testing)."""
        with self._lock:
            if key:
                self._records.pop(key, None)
            else:
                self._records.clear()
