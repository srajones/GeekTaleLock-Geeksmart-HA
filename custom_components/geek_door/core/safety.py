"""
Safety Barrier Guard and Verification Engine for GeekSmart SDK.
Enforces strict 5-layer safety architecture and read-only execution in Milestone 1,
hard-blocking all destructive endpoints and parameters prior to any network I/O.
"""

from __future__ import annotations

import enum
import logging
import posixpath
import re
import urllib.parse
from typing import Any, Dict, FrozenSet, Optional

from .exceptions import (
    GeekSmartError,
    SafetyBarrierViolation,
    SafetyViolationError,
)

logger = logging.getLogger("geeksmart.safety")


class ClientMode(str, enum.Enum):
    """Operational modes for the GeekSmart client."""
    READ_ONLY = "READ_ONLY"        # Milestone 1: Discovery only. Actuation & mutations strictly blocked.
    SAFE_CONTROL = "SAFE_CONTROL"  # Milestone 2+: Allows safe remote lock/unlock. Mutations permanently blocked.
    TEST_MOCK = "TEST_MOCK"        # CI / Offline testing: Forces all calls to mock fixtures.


# ============================================================================
# IMMUTABLE ALLOWLISTS & DENYLISTS (Normalized Lowercase)
# ============================================================================

# Tier 1: Permitted Read-Only Discovery Endpoints (Safe for Milestone 1 & 2)
ALLOWLIST_READ_ONLY: FrozenSet[str] = frozenset({
    "/app/client/loginbypassword",
    "/app/client/getclientinfo",
    "/app/home/getclientequipmentlistmap",
    "/app/home/getclientequipmentlist",
    "/app/doorbelllock/getlocklist",
    "/app/doorbelllock/getlock",
    "/app/home/getclientequipmentauthaccountlist",
    "/app/home/getclientequipmentaccountoperationlist",
    "/app/home/getequipmentmodellist",
    "/app/home/getequipmentmodellistbytype",
    "/app/home/getequipmenttypelist",
    "/app/home/ttlockgatewaylist",
    "/app/home/ttlockgatewaylistlock",
    "/app/home/ttlockgetclientinfo",
    "/app/home/ttlockgatewayqueryopenstate",
    "/app/system/getlatestappversion",
})

# Tier 2: Safe Actuation Endpoints (Permitted ONLY in SAFE_CONTROL mode, Milestone 2+)
ALLOWLIST_SAFE_CONTROL: FrozenSet[str] = frozenset({
    "/app/home/ttlockgatewayunlock",
    "/app/home/ttlockgatewaylock",
})

# Tier 3, 4, 5: Hard Denylist - Permanently FORBIDDEN Endpoints (All Milestones)
HARD_DENYLIST_ENDPOINTS: FrozenSet[str] = frozenset({
    # Tier 3: Destructive Device & Binding Mutators
    "/app/home/deleteclientequipment",
    "/app/doorbelllock/removelock",
    "/app/doorbelllock/bindlock",
    "/app/home/addequipment",
    "/app/home/addequipmenttoclient",
    "/app/home/alterequipmentnote",
    "/app/home/alterequipmentroom",
    "/app/home/alterequipmentaccountinfo",
    "/app/home/alterequipmentaccountroom",
    "/app/home/deleteclientequipmentauthaccount",
    "/app/home/deleteautoadapt",
    "/app/home/saveautoadapt",
    "/app/cesort/setsort",
    # Tier 4: Destructive Biometrics & Credential Mutators
    "/app/home/clearorcoverclientequipmentauth",
    "/app/home/clientequipmentauth",
    "/app/home/initclientequipmentauthkeys",
    "/app/home/ttlockresetkeyboardpwd",
    "/app/home/ttlockupdatespecialvalue",
    "/app/home/sendauthpwdtophoneoremail",
    # Underlying hardware/SDK wipe verbs
    "/resetlock",
    "/clearfingerprints",
    "/clearallfingerprints",
    "/deletefingerprint",
    "/modifyfingerprintvalidityperiod",
    "/addfingerprint",
    "/resetpasscode",
    "/deletepasscode",
    "/clearalliccard",
    "/deleteiccard",
    "/setadmin",
    "/modifyadminpasscode",
    "/removedevice",
    "/resetfactory",
    # Tier 5: Destructive Account & Administrative Mutators
    "/app/client/alterpassword",
    "/app/client/findbackpassword",
    "/app/client/alternickname",
    "/app/client/alterlocation",
    "/app/client/alterheadimg",
    "/app/client/altercurrentlang",
    "/app/client/bindemail",
    "/app/client/bindphone",
    "/app/client/reg",
    "/app/client/regverify",
    "/app/system/clientdeletemessage",
    "/app/home/addclientequipmentaccountoperation",
})

# Destructive keyword pattern matching (Defense-in-Depth Layer 3)
FORBIDDEN_KEYWORD_REGEX = re.compile(
    r"(delete|remove|bind|clear|reset|alter|init|destroy|unpair|unbind)",
    re.IGNORECASE
)


class SafetyBarrierGuard:
    """
    Synchronous pre-flight inspection engine.
    Must be invoked by GeekSmartClient prior to serializing or sending any HTTP request.
    Guarantees zero network I/O if a violation is detected.
    """

    @staticmethod
    def normalize_endpoint(endpoint: str) -> str:
        """
        Canonicalizes an endpoint URL to prevent bypass via casing, multiple slashes,
        query parameters, URL fragments, or relative directory traversal.
        """
        if not endpoint:
            return ""
        ep = endpoint.strip()
        if ep.startswith("http://") or ep.startswith("https://"):
            parsed = urllib.parse.urlparse(ep)
            path = parsed.path
        else:
            path = ep.split("?")[0].split("#")[0]

        while "//" in path:
            path = path.replace("//", "/")
        norm_path = posixpath.normpath("/" + path.lstrip("/"))
        return norm_path.lower()

    @classmethod
    def validate_request(
        cls,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        mode: ClientMode = ClientMode.READ_ONLY
    ) -> str:
        """
        Validates request against all safety layers.
        Returns the normalized endpoint if safe, or raises SafetyBarrierViolation.
        Guarantees zero network I/O if a violation is detected.
        """
        normalized = cls.normalize_endpoint(endpoint)

        # 1. Hard Denylist Check (Direct match or segment-based path containment)
        for forbidden in HARD_DENYLIST_ENDPOINTS:
            clean_forbidden = forbidden.lstrip("/")
            if (
                normalized == forbidden
                or normalized.startswith(forbidden + "/")
                or normalized.endswith("/" + clean_forbidden)
                or f"/{clean_forbidden}/" in normalized
            ):
                msg = f"Forbidden destructive endpoint blocked: '{endpoint}'"
                logger.critical(f"[SAFETY VIOLATION] {msg}")
                raise SafetyBarrierViolation(msg, normalized, "HARD_DENYLIST_MATCH")

        # 2. Hard Denylist Check (Keyword Regex)
        # Skip regex check only for verified whitelisted endpoints
        is_known_read_only = normalized in ALLOWLIST_READ_ONLY
        is_known_control = normalized in ALLOWLIST_SAFE_CONTROL

        if not is_known_read_only and not is_known_control:
            if FORBIDDEN_KEYWORD_REGEX.search(normalized):
                msg = f"Endpoint contains forbidden destructive verb: '{endpoint}'"
                logger.critical(f"[SAFETY VIOLATION] {msg}")
                raise SafetyBarrierViolation(msg, normalized, "KEYWORD_REGEX_VIOLATION")

        # 3. Operational Mode Verification
        if mode == ClientMode.READ_ONLY:
            if normalized in ALLOWLIST_SAFE_CONTROL:
                msg = (
                    f"Physical lock actuation endpoint '{endpoint}' is blocked in READ_ONLY mode. "
                    "Milestone 1 is strictly restricted to read-only device discovery."
                )
                logger.warning(f"[SAFETY VIOLATION] {msg}")
                raise SafetyBarrierViolation(msg, normalized, "MODE_VIOLATION_READ_ONLY")

            if normalized not in ALLOWLIST_READ_ONLY:
                msg = f"Endpoint '{endpoint}' is not in ALLOWLIST_READ_ONLY for Milestone 1."
                logger.critical(f"[SAFETY VIOLATION] {msg}")
                raise SafetyBarrierViolation(msg, normalized, "ALLOWLIST_VIOLATION")

        elif mode == ClientMode.SAFE_CONTROL:
            allowed_in_control = ALLOWLIST_READ_ONLY | ALLOWLIST_SAFE_CONTROL
            if normalized not in allowed_in_control:
                msg = f"Endpoint '{endpoint}' is not authorized in SAFE_CONTROL mode."
                logger.critical(f"[SAFETY VIOLATION] {msg}")
                raise SafetyBarrierViolation(msg, normalized, "ALLOWLIST_VIOLATION")

        # 4. Parameter-Level Inspection
        if params:
            for key, val in params.items():
                k_lower = key.lower()
                # Prevent unauthorized password altering via parameter injection
                if "newpassword" in k_lower or "alterpassword" in k_lower:
                    raise SafetyBarrierViolation(
                        f"Forbidden parameter detected: '{key}'", normalized, "PARAMETER_VIOLATION"
                    )
                # Prevent clearOrCover authType parameter invocation
                if k_lower == "authtype" and str(val) in ("5", "6", "7"):
                    raise SafetyBarrierViolation(
                        f"Dangerous authType wipe code detected: '{key}={val}'", normalized, "PARAMETER_VIOLATION"
                    )

        return normalized
