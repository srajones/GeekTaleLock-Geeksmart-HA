"""User Authentication & TOTP 2FA Engine (Milestone 7 / Requirement R5).

Implements:
1. Atomic file persistence for .auth_credentials.json with strict 0o600 permissions.
2. Adaptive password hashing (scrypt with PBKDF2-HMAC-SHA256 600,000 iterations fallback).
3. Minimum password length policy enforcement (>= 8 characters).
4. Sliding window brute-force lockout protection (5 consecutive failures -> 300s lockout).
5. Constant-time comparison (hmac.compare_digest) and dummy verification to mitigate enumeration timing attacks.
6. RFC 6238 Time-based One-Time Password (TOTP) engine with clock drift tolerance [-1, 0, +1] and anti-replay tracking.
7. Pure-Python Model 2 SVG QR code generator with zero external libraries and zero HTTP/HTTPS tracker links.
8. Single-use hashed backup recovery codes (8 codes, PBKDF2-HMAC-SHA256 salted storage, immediate invalidation).
9. Flask session authentication with @login_required route protection and API key bypass.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import json
import logging
import os
import secrets
import stat
import string
import struct
import threading
import time
import urllib.parse
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from flask import current_app, jsonify, redirect, request, session

from server.security import constant_time_compare

logger = logging.getLogger("mydoor.auth")

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_AUTH_PATH = os.environ.get(
    "AUTH_CREDENTIALS_PATH",
    os.environ.get(
        "AUTH_CONFIG_FILE",
        os.path.join(WORKSPACE_ROOT, ".auth_credentials.json"),
    ),
)


# ============================================================================
# Pure-Python Standalone SVG QR Code Generator (Model 2, Version 6-L)
# Zero external libraries. Zero HTTP/HTTPS tracker links.
# ============================================================================

_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _EXP[_i + 255] = _x
    _LOG[_x] = _i
    _x = (_x << 1) ^ (0x11D if (_x & 0x80) else 0)


def _gf_mul(x: int, y: int) -> int:
    return 0 if x == 0 or y == 0 else _EXP[_LOG[x] + _LOG[y]]


def _rs_poly_mul(p1: List[int], p2: List[int]) -> List[int]:
    res = [0] * (len(p1) + len(p2) - 1)
    for i, c1 in enumerate(p1):
        for j, c2 in enumerate(p2):
            res[i + j] ^= _gf_mul(c1, c2)
    return res


def _rs_encode(data: List[int], num_ec: int) -> List[int]:
    gen = [1]
    for i in range(num_ec):
        gen = _rs_poly_mul(gen, [1, _EXP[i]])
    rem = list(data) + [0] * num_ec
    for i in range(len(data)):
        c = rem[i]
        if c != 0:
            for j in range(len(gen)):
                rem[i + j] ^= _gf_mul(gen[j], c)
    return rem[len(data):]


def generate_qr_matrix(text: str) -> List[List[int]]:
    """Encodes text into a 41x41 QR Code matrix (Version 6, ECC Level L, Mask 0)."""
    data_bytes = text.encode("utf-8")
    if len(data_bytes) > 134:
        raise ValueError(f"Payload length {len(data_bytes)} exceeds Version 6-L capacity (134 bytes)")

    # 1. Byte mode data stream: Mode indicator (0100) + 8-bit length + data + terminator
    bits: List[int] = [0, 1, 0, 0]
    for i in range(7, -1, -1):
        bits.append((len(data_bytes) >> i) & 1)
    for b in data_bytes:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)

    # Terminator (up to 4 zeroes)
    bits.extend([0] * min(4, 136 * 8 - len(bits)))
    # Byte alignment
    while len(bits) % 8 != 0:
        bits.append(0)

    # Pack into data codewords
    codewords: List[int] = []
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i : i + 8]:
            byte = (byte << 1) | bit
        codewords.append(byte)

    # Pad codewords up to 136 with alternating 0xEC and 0x11
    pad = [0xEC, 0x11]
    p_idx = 0
    while len(codewords) < 136:
        codewords.append(pad[p_idx % 2])
        p_idx += 1

    # 2. Reed-Solomon error correction (36 codewords for Version 6-L)
    ec_codewords = _rs_encode(codewords, 36)
    all_codewords = codewords + ec_codewords

    all_bits: List[int] = []
    for cw in all_codewords:
        for i in range(7, -1, -1):
            all_bits.append((cw >> i) & 1)

    # 3. Construct 41x41 matrix
    N = 41
    matrix: List[List[int]] = [[0] * N for _ in range(N)]
    reserved: List[List[bool]] = [[False] * N for _ in range(N)]

    # Place 7x7 Finder Patterns and Separators
    def set_finder(r0: int, c0: int) -> None:
        for r in range(7):
            for c in range(7):
                v = 1 if (r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4)) else 0
                matrix[r0 + r][c0 + c] = v
                reserved[r0 + r][c0 + c] = True
        for r in range(-1, 8):
            for c in range(-1, 8):
                if 0 <= r0 + r < N and 0 <= c0 + c < N and not reserved[r0 + r][c0 + c]:
                    matrix[r0 + r][c0 + c] = 0
                    reserved[r0 + r][c0 + c] = True

    set_finder(0, 0)
    set_finder(0, N - 7)
    set_finder(N - 7, 0)

    # Timing Patterns (Row 6 and Column 6)
    for i in range(8, N - 8):
        v = 1 if i % 2 == 0 else 0
        if not reserved[6][i]:
            matrix[6][i] = v
            reserved[6][i] = True
        if not reserved[i][6]:
            matrix[i][6] = v
            reserved[i][6] = True

    # Alignment Pattern centered at (34, 34)
    r0, c0 = 34, 34
    for r in range(-2, 3):
        for c in range(-2, 3):
            v = 1 if (abs(r) == 2 or abs(c) == 2 or (r == 0 and c == 0)) else 0
            matrix[r0 + r][c0 + c] = v
            reserved[r0 + r][c0 + c] = True

    # Dark module at (33, 8)
    matrix[33][8] = 1
    reserved[33][8] = True

    # Reserve Format Information areas
    for c in range(9):
        if c != 6:
            reserved[8][c] = True
    for r in range(9):
        if r != 6:
            reserved[r][8] = True
    for c in range(N - 8, N):
        reserved[8][c] = True
    for r in range(N - 7, N):
        reserved[r][8] = True

    # 4. Place data bits in 2-column zigzag traversal from right to left
    bit_idx = 0
    col = N - 1
    direction = -1

    while col > 0:
        if col == 6:
            col -= 1
        r_range = range(N - 1, -1, -1) if direction == -1 else range(N)
        for r in r_range:
            for c in (col, col - 1):
                if not reserved[r][c]:
                    b = all_bits[bit_idx] if bit_idx < len(all_bits) else 0
                    bit_idx += 1
                    # Apply Mask 0: (r + c) % 2 == 0
                    if (r + c) % 2 == 0:
                        b ^= 1
                    matrix[r][c] = b
        direction = -direction
        col -= 2

    # 5. Format Information: ECC Level L (01) + Mask 0 (000) -> 01000b (8)
    # BCH(15, 5) with generator polynomial 0x537, XOR mask 0x5412
    g = 0x537
    val = 8 << 10
    for i in range(14, 9, -1):
        if (val >> i) & 1:
            val ^= (g << (i - 10))
    fmt_bits = ((8 << 10) | val) ^ 0x5412
    fmt = [(fmt_bits >> i) & 1 for i in range(15)]

    # Place Format bits
    coords_tl: List[Tuple[int, int]] = [
        (8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
        (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8),
    ]
    coords_tr_bl: List[Tuple[int, int]] = [
        (8, N - 1), (8, N - 2), (8, N - 3), (8, N - 4), (8, N - 5), (8, N - 6), (8, N - 7), (8, N - 8),
        (N - 7, 8), (N - 6, 8), (N - 5, 8), (N - 4, 8), (N - 3, 8), (N - 2, 8), (N - 1, 8),
    ]
    for i in range(15):
        r1, c1 = coords_tl[i]
        matrix[r1][c1] = fmt[i]
        r2, c2 = coords_tr_bl[i]
        matrix[r2][c2] = fmt[i]

    return matrix


def generate_qr_svg(text: str, border: int = 4, box_size: int = 8) -> str:
    """Generates clean standalone SVG for a given text.

    Contains NO http:// or https:// tags to comply with strict security policies.
    """
    matrix = generate_qr_matrix(text)
    N = len(matrix)
    total_size = (N + 2 * border) * box_size
    path_data: List[str] = []

    for r in range(N):
        for c in range(N):
            if matrix[r][c] == 1:
                x = (c + border) * box_size
                y = (r + border) * box_size
                path_data.append(f"M{x},{y}h{box_size}v{box_size}h-{box_size}z")

    return (
        f'<svg viewBox="0 0 {total_size} {total_size}" width="100%" height="100%" shape-rendering="crispEdges">\n'
        f'  <rect width="100%" height="100%" fill="#ffffff"/>\n'
        f'  <path d="{" ".join(path_data)}" fill="#000000"/>\n'
        f"</svg>"
    )


# ============================================================================
# AuthManager Core Engine
# ============================================================================

class AuthManager:
    """Thread-safe and process-safe authentication and TOTP 2FA manager for mydoor."""

    def __init__(
        self,
        auth_file: Optional[Union[str, Path]] = None,
        max_failed_attempts: int = 5,
        lockout_duration_seconds: float = 300.0,
    ) -> None:
        self.auth_file = os.path.abspath(str(auth_file or DEFAULT_AUTH_PATH))
        self.max_failed_attempts = int(max_failed_attempts)
        self.lockout_duration_seconds = float(lockout_duration_seconds)

        self._lock = threading.RLock()
        self._failed_attempts: Dict[str, List[float]] = defaultdict(list)
        self._lockouts: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------------
    # Persistence & Permissions
    # ------------------------------------------------------------------------

    def exists(self) -> bool:
        """Checks if credentials file exists and is non-empty."""
        try:
            return os.path.exists(self.auth_file) and os.path.getsize(self.auth_file) > 0
        except OSError:
            return False

    def verify_permissions(self) -> bool:
        """Checks if file permissions are restricted to owner (0o600)."""
        if not os.path.exists(self.auth_file):
            return True
        mode = stat.S_IMODE(os.stat(self.auth_file).st_mode)
        return (mode & 0o077) == 0

    def load_credentials(self) -> Dict[str, Any]:
        """Loads credentials JSON. Returns default structure if missing or corrupt."""
        default_payload: Dict[str, Any] = {
            "version": "1.0",
            "users": {},
            "api_tokens": {},
            "settings": {
                "max_failed_attempts": self.max_failed_attempts,
                "lockout_seconds": int(self.lockout_duration_seconds),
            },
        }
        with self._lock:
            if not self.exists():
                return default_payload
            try:
                with open(self.auth_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    if "users" not in data:
                        data["users"] = {}
                    return data
                return default_payload
            except Exception as exc:
                logger.warning("Failed to load auth credentials from %s: %s", self.auth_file, exc)
                return default_payload

    def save_credentials(self, data: Dict[str, Any]) -> None:
        """Atomically saves credentials to file with 0o600 permissions."""
        with self._lock:
            parent_dir = os.path.dirname(self.auth_file)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)

            temp_path = (
                f"{self.auth_file}.tmp.{os.getpid()}_"
                f"{threading.get_ident()}_{uuid.uuid4().hex[:8]}"
            )
            try:
                fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)

                try:
                    os.chmod(temp_path, 0o600)
                except OSError:
                    pass

                os.replace(temp_path, self.auth_file)
                try:
                    os.chmod(self.auth_file, 0o600)
                except OSError:
                    pass
                logger.debug("Auth credentials atomically saved to %s", self.auth_file)
            except Exception as exc:
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except OSError:
                        pass
                raise IOError(f"Failed to atomically persist auth credentials: {exc}") from exc

    def _save(self) -> None:
        """Internal save helper loading current credentials and re-saving atomically."""
        with self._lock:
            creds = self.load_credentials()
            self.save_credentials(creds)

    # ------------------------------------------------------------------------
    # Password Cryptography & Policy
    # ------------------------------------------------------------------------

    def _hash_password(self, password: str) -> Tuple[str, str]:
        """Hashes password using scrypt or PBKDF2-HMAC-SHA256 (600,000 iterations).

        Returns:
            Tuple of (password_hash: str, salt_hex: str)
        """
        salt = os.urandom(16).hex()
        # 1. Try Werkzeug's generate_password_hash
        try:
            import werkzeug.security as ws
            try:
                return ws.generate_password_hash(password, method="scrypt"), salt
            except (AttributeError, ValueError):
                return ws.generate_password_hash(password, method="pbkdf2:sha256:600000"), salt
        except ImportError:
            pass

        # 2. Standalone fallback via hashlib
        salt_bytes = bytes.fromhex(salt)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, 600000)
        p_hash = f"pbkdf2:sha256:600000${salt}${dk.hex()}"
        return p_hash, salt

    def _verify_hash(self, stored_hash: str, password: str) -> bool:
        """Verifies password against stored hash in constant time."""
        if not stored_hash or not password:
            return False

        # 1. Try Werkzeug check_password_hash
        try:
            import werkzeug.security as ws
            return ws.check_password_hash(stored_hash, password)
        except Exception:
            pass

        # 2. Standalone fallback parser
        parts = stored_hash.split("$")
        if len(parts) == 3 and parts[0].startswith("pbkdf2:sha256"):
            subparts = parts[0].split(":")
            iterations = int(subparts[2]) if len(subparts) >= 3 else 600000
            salt_str = parts[1]
            hash_hex = parts[2]
            try:
                salt_bytes = bytes.fromhex(salt_str)
            except ValueError:
                salt_bytes = salt_str.encode("utf-8")
            dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
            return hmac.compare_digest(dk.hex(), hash_hex)

        return False

    def _dummy_verify(self) -> None:
        """Performs a dummy hash comparison to mitigate user-enumeration timing attacks (600k iterations)."""
        dummy_salt = b"mydoor_timing_protection_salt"
        dummy_hash = b"0" * 32
        dk = hashlib.pbkdf2_hmac("sha256", b"dummy_password", dummy_salt, 600000)
        hmac.compare_digest(dk, dummy_hash)

    # ------------------------------------------------------------------------
    # User Administration
    # ------------------------------------------------------------------------

    def create_admin(self, username: str, password: str) -> bool:
        """Creates or resets an administrator account.

        Raises:
            ValueError: If username is empty or password is shorter than 8 characters.
        """
        if not username or not isinstance(username, str) or not username.strip():
            raise ValueError("Username cannot be empty")
        clean_user = username.strip()

        if not password or not isinstance(password, str) or len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")

        with self._lock:
            creds = self.load_credentials()
            p_hash, salt = self._hash_password(password)
            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            existing_user = creds.get("users", {}).get(clean_user, {})
            creds.setdefault("users", {})[clean_user] = {
                "username": clean_user,
                "hash": p_hash,
                "password_hash": p_hash,
                "salt": salt,
                "created_at": existing_user.get("created_at", now_iso),
                "updated_at": now_iso,
                "totp": existing_user.get("totp", {
                    "enabled": False,
                    "secret": None,
                    "digits": 6,
                    "step": 30,
                    "issuer": "mydoor",
                    "confirmed_at": None,
                    "last_verified_step": None,
                    "used_steps": [],
                }),
                "backup_codes": existing_user.get("backup_codes", []),
            }

            self.save_credentials(creds)
            self.reset_lockout(clean_user)
            logger.info("Admin user '%s' successfully created/updated in %s", clean_user, self.auth_file)
            return True

    def user_exists(self, username: str) -> bool:
        """Checks if a user is registered."""
        if not username:
            return False
        clean_user = username.strip()
        with self._lock:
            creds = self.load_credentials()
            return clean_user in creds.get("users", {})

    def has_users(self) -> bool:
        """Checks if any users exist in credentials store."""
        with self._lock:
            creds = self.load_credentials()
            return bool(creds.get("users"))

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieves user record dictionary if found."""
        if not username:
            return None
        with self._lock:
            creds = self.load_credentials()
            return creds.get("users", {}).get(username.strip())

    # ------------------------------------------------------------------------
    # Brute-Force Lockout Engine
    # ------------------------------------------------------------------------

    def is_locked_out(self, username: str) -> bool:
        """Returns True if the user is currently locked out."""
        if not username:
            return False
        clean_user = username.strip()
        with self._lock:
            lock_info = self._lockouts.get(clean_user)
            if not lock_info:
                return False
            now = time.time()
            if now < lock_info["locked_until"]:
                return True
            # Lockout expired
            self._lockouts.pop(clean_user, None)
            self._failed_attempts.pop(clean_user, None)
            return False

    def reset_lockout(self, username: Optional[str] = None) -> None:
        """Clears lockout state for a specific user or all users."""
        with self._lock:
            if username:
                clean_user = username.strip()
                self._lockouts.pop(clean_user, None)
                self._failed_attempts.pop(clean_user, None)
            else:
                self._lockouts.clear()
                self._failed_attempts.clear()

    def _record_failure(self, username: str) -> None:
        """Records a failed attempt and triggers lockout if threshold is reached."""
        clean_user = username.strip() if username else "unknown"
        with self._lock:
            now = time.time()
            cutoff = now - self.lockout_duration_seconds
            active = [ts for ts in self._failed_attempts[clean_user] if ts > cutoff]
            active.append(now)
            self._failed_attempts[clean_user] = active

            if len(active) >= self.max_failed_attempts:
                self._lockouts[clean_user] = {
                    "locked_until": now + self.lockout_duration_seconds,
                    "locked_at": now,
                }
                logger.warning(
                    "User '%s' locked out after %d failed attempts for %ds",
                    clean_user,
                    len(active),
                    int(self.lockout_duration_seconds),
                )

    def record_failure(self, username: str) -> None:
        """Records an authentication failure for username, enforcing brute-force lockout."""
        self._record_failure(username)

    def verify_password(self, username: str, password: str) -> bool:
        """Verifies user password with timing attack mitigation and brute-force tracking."""
        if not username or not isinstance(username, str):
            return False

        clean_user = username.strip()
        if not clean_user:
            return False

        if self.is_locked_out(clean_user):
            logger.info("Rejected login for '%s': Account currently locked out", clean_user)
            return False

        if not password or not isinstance(password, str):
            self._record_failure(clean_user)
            return False

        with self._lock:
            user = self.get_user(clean_user)
            stored_hash = (user.get("password_hash") or user.get("hash")) if user else None
            if not user or not stored_hash:
                self._dummy_verify()
                self._record_failure(clean_user)
                return False

            valid = self._verify_hash(stored_hash, password)
            if valid:
                self.reset_lockout(clean_user)
                return True
            else:
                self._record_failure(clean_user)
                return False

    # ------------------------------------------------------------------------
    # RFC 6238 TOTP Engine
    # ------------------------------------------------------------------------

    def generate_totp_secret(self, username: str) -> Dict[str, str]:
        """Generates a 20-byte Base32 TOTP secret, standard OTPAuth URI, and local SVG QR code."""
        if not username:
            raise ValueError("Username cannot be empty")
        clean_user = username.strip()

        with self._lock:
            user = self.get_user(clean_user)
            if not user:
                raise ValueError(f"User '{clean_user}' does not exist")

            raw_secret = secrets.token_bytes(20)
            secret = base64.b32encode(raw_secret).decode("ascii").rstrip("=")
            # Compact URI: omit redundant defaults (&algorithm=SHA1&digits=6&period=30)
            # Base static URI is 75 bytes, allowing usernames up to 58 bytes in Version 6-L (134 bytes)
            label_user = clean_user
            if len(label_user.encode("utf-8")) > 58:
                # Safely truncate label by UTF-8 bytes to prevent Version 6-L overflow
                encoded = label_user.encode("utf-8")[:55]
                label_user = encoded.decode("utf-8", errors="ignore") + "..."
            otpauth_uri = (
                f"otpauth://totp/mydoor:{label_user}"
                f"?secret={secret}&issuer=mydoor"
            )
            qr_svg = generate_qr_svg(otpauth_uri)

            creds = self.load_credentials()
            creds.setdefault("users", {}).setdefault(clean_user, {})["totp"] = {
                "enabled": True,
                "secret": secret,
                "digits": 6,
                "step": 30,
                "issuer": "mydoor",
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "last_verified_step": None,
                "used_steps": [],
            }
            self.save_credentials(creds)

            return {
                "secret": secret,
                "otpauth_uri": otpauth_uri,
                "qr_svg": qr_svg,
            }

    def is_totp_enabled(self, username: str) -> bool:
        """Returns True if TOTP 2FA is active and configured for username."""
        if not username:
            return False
        with self._lock:
            user = self.get_user(username)
            if not user:
                return False
            totp = user.get("totp", {})
            return bool(totp.get("enabled", False) and totp.get("secret"))

    def verify_totp(
        self,
        username: str,
        code: Any,
        timestamp: Optional[int] = None,
    ) -> bool:
        """Verifies a 6-digit TOTP code with clock drift tolerance [-1, 0, +1] and anti-replay."""
        if not username:
            return False
        clean_user = username.strip()

        with self._lock:
            user = self.get_user(clean_user)
            if not user or not user.get("totp", {}).get("secret"):
                return False

            if self.is_locked_out(clean_user):
                return False

            code_str = str(code).strip().replace(" ", "")
            if not code_str.isdigit() or len(code_str) != 6:
                return False

            secret = user["totp"]["secret"]
            pad_len = (8 - len(secret) % 8) % 8
            secret_bytes = base64.b32decode((secret + "=" * pad_len).encode("ascii"), casefold=True)

            ts = int(time.time()) if timestamp is None else int(timestamp)
            current_step = ts // 30
            used_steps = list(user["totp"].get("used_steps", []))

            # Check [-1, 0, +1] window, checking current step first
            for step in (current_step, current_step - 1, current_step + 1):
                counter_bytes = struct.pack(">Q", step)
                digest = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
                offset = digest[-1] & 0x0F
                code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
                expected_code = str(code_int % 1000000).zfill(6)

                if hmac.compare_digest(code_str, expected_code):
                    # Anti-replay check: step must not have been used yet
                    if step in used_steps:
                        return False

                    # Successful validation
                    used_steps.append(step)
                    # Keep bounded history (last 10 steps)
                    pruned_steps = [s for s in used_steps if s >= current_step - 10]

                    creds = self.load_credentials()
                    target_user = creds.setdefault("users", {}).setdefault(clean_user, {})
                    target_totp = target_user.setdefault("totp", {})
                    target_totp["used_steps"] = pruned_steps
                    target_totp["last_verified_step"] = max(target_totp.get("last_verified_step") or 0, step)
                    target_totp["enabled"] = True
                    self.save_credentials(creds)
                    return True

            return False

    # ------------------------------------------------------------------------
    # Single-Use Backup Recovery Codes
    # ------------------------------------------------------------------------

    def generate_backup_codes(self, username: str, count: int = 8) -> List[str]:
        """Generates 8 single-use backup recovery codes formatted XXXX-XXXX."""
        if not username:
            raise ValueError("Username cannot be empty")
        clean_user = username.strip()

        chars = string.ascii_uppercase + string.digits
        codes: List[str] = []
        stored_entries: List[Dict[str, Any]] = []

        with self._lock:
            user = self.get_user(clean_user)
            if not user:
                raise ValueError(f"User '{clean_user}' does not exist")

            for _ in range(count):
                part1 = "".join(secrets.choice(chars) for _ in range(4))
                part2 = "".join(secrets.choice(chars) for _ in range(4))
                code = f"{part1}-{part2}"
                codes.append(code)

                salt = secrets.token_bytes(16)
                code_hash = hashlib.pbkdf2_hmac("sha256", code.encode("utf-8"), salt, 100_000).hex()
                stored_entries.append({
                    "hash": code_hash,
                    "salt": salt.hex(),
                    "used": False,
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "used_at": None,
                })

            creds = self.load_credentials()
            creds.setdefault("users", {}).setdefault(clean_user, {})["backup_codes"] = stored_entries
            self.save_credentials(creds)
            return codes

    def verify_backup_code(self, username: str, code: str) -> bool:
        """Verifies and immediately invalidates a single-use backup recovery code."""
        if not username or not code:
            return False
        clean_user = username.strip()

        with self._lock:
            user = self.get_user(clean_user)
            if not user:
                return False

            if self.is_locked_out(clean_user):
                return False

            raw = str(code).strip().upper().replace(" ", "")
            # Canonicalize XXXX-XXXX format if hyphen was omitted
            canonical = f"{raw[:4]}-{raw[4:]}" if len(raw) == 8 and "-" not in raw else raw

            creds = self.load_credentials()
            user_rec = creds.get("users", {}).get(clean_user, {})
            entries = user_rec.get("backup_codes", [])

            for entry in entries:
                if entry.get("used"):
                    continue

                salt = bytes.fromhex(entry["salt"])
                computed_hash = hashlib.pbkdf2_hmac("sha256", canonical.encode("utf-8"), salt, 100_000).hex()

                if hmac.compare_digest(computed_hash, entry["hash"]):
                    entry["used"] = True
                    entry["used_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    self.save_credentials(creds)
                    return True

            return False


# ============================================================================
# Route Protection Decorator (@login_required)
# ============================================================================

def login_required(f):
    """Route protection decorator enforcing signed session or API key authentication."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Global auth bypass if disabled in testing configuration
        if not current_app.config.get("AUTH_ENABLED", False):
            return f(*args, **kwargs)

        # 2. API Key / Bearer token header bypass (preserves curl & Home Assistant automation)
        if getattr(request, "_api_key_valid", False):
            return f(*args, **kwargs)

        # Direct header check for Authorization / X-API-Key against configured API_KEY
        configured_key = (current_app.config.get("API_KEY") or "").strip()
        if configured_key:
            auth_hdr = request.headers.get("Authorization", "").strip()
            bearer = auth_hdr[7:].strip() if auth_hdr.lower().startswith("bearer ") else ""
            x_key = request.headers.get("X-API-Key", "").strip()
            token = bearer or x_key
            if token and constant_time_compare(token, configured_key):
                setattr(request, "_api_key_valid", True)
                return f(*args, **kwargs)

        # 3. Check session authentication
        auth_user = session.get("auth_user")
        is_2fa_verified = session.get("2fa_verified", False)
        pending_2fa_user = session.get("2fa_pending_user")
        # 4. Check 12-hour session lifetime (43200 seconds) - fail-secure if login_time is falsy or missing
        max_lifetime = current_app.config.get("PERMANENT_SESSION_LIFETIME", 43200)
        if auth_user:
            try:
                login_ts = float(session.get("login_time") or 0)
            except (ValueError, TypeError):
                login_ts = 0.0

            if not login_ts or (time.time() - login_ts > max_lifetime):
                session.clear()
                auth_user = None

        # 5. Check completed authentication
        if auth_user:
            auth_mgr = current_app.config.get("AUTH_MANAGER")
            requires_2fa = auth_mgr.is_totp_enabled(auth_user) if auth_mgr else False
            if requires_2fa and not is_2fa_verified:
                if request.path.startswith("/api/"):
                    return jsonify({
                        "success": False,
                        "error": "Two-factor authentication required.",
                        "requires_2fa": True,
                        "authenticated": False,
                    }), 403
                return redirect("/login?step=2fa")

            return f(*args, **kwargs)

        # 6. Check pending 2FA step
        if pending_2fa_user:
            if request.path.startswith("/api/"):
                return jsonify({
                    "success": False,
                    "error": "Two-factor authentication verification pending.",
                    "requires_2fa": True,
                    "authenticated": False,
                }), 401
            return redirect("/login?step=2fa")

        # 7. Unauthenticated request
        if request.path.startswith("/api/"):
            return jsonify({
                "success": False,
                "error": "Authentication required.",
                "authenticated": False,
            }), 401

        # Browser HTML navigation -> redirect to login
        dest = request.full_path if request.query_string else request.path
        return redirect(f"/login?next={urllib.parse.quote(dest)}")

    return decorated_function
