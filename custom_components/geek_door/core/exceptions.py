"""
GeekSmart Exception Hierarchy.

Authoritative exception classes for the GeekSmart IoT Cloud SDK.
Completely standalone and self-contained: production code imports only from here.
"""

from __future__ import annotations
from typing import Any, Optional


class GeekSmartError(Exception):
    """Base exception for all GeekSmart SDK operations."""
    pass


class GeekSmartAuthError(GeekSmartError):
    """Raised on authentication failures, bad passwords, or expired sessions."""
    def __init__(self, code: int = 401, msg: str = ""):
        if isinstance(code, str) and not msg:
            super().__init__(f"Auth failed: {code}")
            self.code = 401
            self.msg = code
        else:
            super().__init__(f"Auth failed (code {code}): {msg}")
            self.code = code
            self.msg = msg


class GeekSmartCryptoError(GeekSmartError):
    """Raised on encryption/decryption, padding, or ciphertext failures."""
    pass


class GeekSmartProtocolError(GeekSmartError):
    """Raised on malformed JSON or envelope structure violations."""
    pass


class GeekSmartControlError(GeekSmartError):
    """Raised when lock/unlock or status operations fail."""
    def __init__(self, code: Any = 500, msg: str = ""):
        if isinstance(code, str) and not msg:
            super().__init__(f"Control command failed: {code}")
            self.code = 500
            self.msg = code
        else:
            super().__init__(f"Control command failed (code {code}): {msg}")
            self.code = code
            self.msg = msg


class GeekSmartNetworkError(GeekSmartError):
    """Raised on HTTP transport or server 5xx errors."""
    def __init__(self, status_code: int = 500, msg: str = ""):
        super().__init__(f"Network error (HTTP {status_code}): {msg}")
        self.status_code = status_code
        self.msg = msg


class GeekSmartTimeoutError(GeekSmartNetworkError):
    """Raised when an API request times out."""
    def __init__(self, msg: str = "Request timed out", status_code: int = 408):
        super().__init__(status_code, msg)


class SafetyBarrierViolation(GeekSmartError):
    """
    Fatal error raised when an operation attempts to invoke a forbidden destructive endpoint,
    destructive parameter, or unauthorized operational mode.
    Guarantees pre-flight zero-I/O safety.
    """
    def __init__(self, message: str, endpoint: str = "", category: str = ""):
        if not message.startswith("CRITICAL SAFETY VIOLATION"):
            formatted_msg = f"CRITICAL SAFETY VIOLATION: {message} (Endpoint: '{endpoint}', Category: '{category}')"
        else:
            formatted_msg = message
        super().__init__(formatted_msg)
        self.endpoint = endpoint
        self.category = category


class TuyaApiError(GeekSmartError):
    """Raised when Tuya mobile gateway returns an error response."""
    def __init__(self, error_code: Any, error_msg: str):
        super().__init__(f"Tuya API Error [{error_code}]: {error_msg}")
        self.error_code = str(error_code)
        self.error_msg = error_msg


# Canonical alias for compatibility
SafetyViolationError = SafetyBarrierViolation

try:
    from homeassistant.exceptions import (
        HomeAssistantError,
        ConfigEntryAuthFailed,
        ConfigEntryNotReady,
    )
except ImportError:
    class HomeAssistantError(Exception):
        """Fallback HomeAssistantError when homeassistant is not installed."""
        pass

    class ConfigEntryAuthFailed(HomeAssistantError):
        """Fallback ConfigEntryAuthFailed when homeassistant is not installed."""
        pass

    class ConfigEntryNotReady(HomeAssistantError):
        """Fallback ConfigEntryNotReady when homeassistant is not installed."""
        pass

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
]
