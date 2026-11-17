"""Crypto and credential helpers: TOTP (RFC 6238), secret encryption,
password hashing, backup codes.

TOTP is implemented directly on top of hmac/hashlib so the module has no
dependency on a third-party OTP library. It is validated against the
RFC 6238 test vectors in tests/test_auth.py.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import check_password_hash, generate_password_hash

TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 6
_DIGITS = "0123456789"
_HEX = "0123456789abcdef"

# Used to burn the same CPU time for unknown usernames (prevents user enumeration by timing).
DUMMY_PASSWORD_HASH = generate_password_hash("dummy-password-for-timing-only")


# --------------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    return generate_password_hash(password, method="scrypt")


def verify_password(stored_hash: str, password: str) -> bool:
    return check_password_hash(stored_hash, password)


def validate_password(password: str, username: str, min_length: int) -> str | None:
    """Return an error message, or None if the password is acceptable."""
    if len(password) < min_length:
        return f"Password must be at least {min_length} characters long."
    if password.lower() == username.lower():
        return "Password must not equal the username."
    if len(set(password)) < 5:
        return "Password is too repetitive."
    return None


# -------------------------------------------------------------------------- TOTP
def new_totp_secret() -> str:
    """160-bit random secret, base32 (the format authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int, digits: int = TOTP_DIGITS) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def totp_at(secret_b32: str, timestamp: float) -> str:
    return _hotp(secret_b32, int(timestamp // TOTP_STEP_SECONDS))


def verify_totp(secret_b32: str, code: str, last_step: int = 0, window: int = 1,
                now: float | None = None) -> int | None:
    """Check a user-supplied code.

    Returns the matching time step (so the caller can store it) or None.
    Steps <= last_step are rejected: a code can be used only once (replay protection).
    All candidate steps are always evaluated to keep timing independent of which one matches.
    """
    code = "".join(ch for ch in code if ch in _DIGITS)
    if len(code) != TOTP_DIGITS:
        return None
    current = int((time.time() if now is None else now) // TOTP_STEP_SECONDS)
    match = None
    for offset in range(-window, window + 1):
        step = current + offset
        if hmac.compare_digest(_hotp(secret_b32, step), code) and step > last_step:
            match = step
    return match


def provisioning_uri(secret_b32: str, username: str, issuer: str) -> str:
    label = quote(f"{issuer}:{username}")
    return (f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}")


def qr_svg(data: str) -> str | None:
    """Inline SVG QR code, or None if the optional `segno` package is missing."""
    try:
        import segno
    except ImportError:
        return None
    return segno.make(data, error="m").svg_inline(scale=5, border=2, dark="#111", light="#fff")


# ------------------------------------------------------- encryption of TOTP secrets
def _fernet(key: str) -> Fernet:
    return Fernet(key.encode("ascii"))


def encrypt_secret(key: str, secret_b32: str) -> str:
    return _fernet(key).encrypt(secret_b32.encode("ascii")).decode("ascii")


def decrypt_secret(key: str, token: str) -> str | None:
    try:
        return _fernet(key).decrypt(token.encode("ascii")).decode("ascii")
    except InvalidToken:
        return None


# ------------------------------------------------------------------ backup codes
def generate_backup_codes(count: int) -> list[str]:
    """48 bits of entropy each, shown as xxxx-xxxx-xxxx."""
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(6)
        codes.append("-".join(raw[i:i + 4] for i in range(0, 12, 4)))
    return codes


def normalize_backup_code(code: str) -> str | None:
    cleaned = "".join(ch for ch in code.lower() if ch in _HEX)
    return cleaned if len(cleaned) == 12 else None


def hash_backup_code(pepper: str, normalized_code: str) -> str:
    return hmac.new(pepper.encode(), normalized_code.encode(), hashlib.sha256).hexdigest()
