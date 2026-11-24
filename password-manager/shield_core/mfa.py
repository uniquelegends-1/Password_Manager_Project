"""Multi-Factor Authentication (MFA): RFC 6238 TOTP with anti-replay protection, recovery codes, and QR matrix."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import parse_qs, quote, urlparse

try:
    import qrcode
except ImportError:  # pragma: no cover
    qrcode = None


class TOTPReplayError(Exception):
    """Raised when a previously accepted TOTP time-step is replayed."""


def generate_totp_secret(num_bytes: int = 20) -> str:
    """Generate a random RFC 4648 Base32 TOTP secret (160-bit default)."""
    raw = secrets.token_bytes(num_bytes)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def normalize_totp_secret(raw: str) -> str:
    """Extract and normalize a Base32 TOTP secret from a raw string or otpauth:// URI."""
    cleaned = raw.strip()
    if not cleaned:
        return ""
    if cleaned.lower().startswith("otpauth://"):
        parsed = urlparse(cleaned)
        qs = parse_qs(parsed.query)
        secret_vals = qs.get("secret", [])
        if not secret_vals:
            raise ValueError("otpauth:// URI does not contain a 'secret' parameter.")
        cleaned = secret_vals[0]

    normalized = "".join(cleaned.split()).replace("-", "").upper().rstrip("=")
    if not normalized:
        raise ValueError("TOTP secret is empty.")

    padded = normalized + "=" * ((8 - len(normalized) % 8) % 8)
    try:
        base64.b32decode(padded, casefold=True)
    except Exception as exc:
        raise ValueError("Invalid Base32 TOTP secret.") from exc

    return normalized


def _decode_b32(secret: str) -> bytes:
    norm = normalize_totp_secret(secret)
    padded = norm + "=" * ((8 - len(norm) % 8) % 8)
    return base64.b32decode(padded, casefold=True)


def _hotp(key: bytes, counter: int, digits: int = 6) -> str:
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


def get_totp_code(
    secret: str,
    at_time: float | None = None,
    period: int = 30,
    digits: int = 6,
) -> tuple[str, int]:
    """Compute the current RFC 6238 TOTP code and seconds remaining in the time step."""
    key = _decode_b32(secret)
    now = time.time() if at_time is None else at_time
    counter = int(now // period)
    remaining = period - int(now % period)
    return _hotp(key, counter, digits), remaining


def verify_totp_with_step(
    secret: str,
    code: str,
    *,
    last_used_step: int = -1,
    window: int = 1,
    at_time: float | None = None,
    period: int = 30,
    digits: int = 6,
) -> tuple[bool, int]:
    """Verify a TOTP code with anti-replay time-step tracking.

    Returns (is_valid, matched_step). Raises TOTPReplayError if the code matches a step <= last_used_step.
    """
    cleaned = "".join(ch for ch in code if ch.isdigit())
    if len(cleaned) != digits:
        return False, last_used_step

    key = _decode_b32(secret)
    now = time.time() if at_time is None else at_time
    current_step = int(now // period)

    for offset in range(-window, window + 1):
        step = current_step + offset
        expected = _hotp(key, step, digits)
        if hmac.compare_digest(expected, cleaned):
            if step <= last_used_step:
                raise TOTPReplayError(
                    "This 6-digit code was already used. Wait for the next 30-second code."
                )
            return True, step

    return False, last_used_step


def verify_totp(
    secret: str,
    code: str,
    window: int = 1,
    at_time: float | None = None,
    period: int = 30,
    digits: int = 6,
) -> bool:
    """Simple stateless TOTP check (e.g., initial setup verification)."""
    ok, _ = verify_totp_with_step(
        secret, code, last_used_step=-1, window=window, at_time=at_time, period=period, digits=digits
    )
    return ok


def build_otpauth_uri(secret: str, account_name: str = "SHIELD-Vault", issuer: str = "P.U.L.S.E. SHIELD") -> str:
    """Build standard otpauth:// URI compatible with Google/Microsoft Authenticator, Aegis, and 2FAS."""
    norm = normalize_totp_secret(secret)
    label = f"{quote(issuer)}:{quote(account_name)}"
    return f"otpauth://totp/{label}?secret={norm}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def generate_recovery_codes(count: int = 8) -> list[str]:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    codes: list[str] = []
    for _ in range(count):
        p1 = "".join(secrets.choice(alphabet) for _ in range(4))
        p2 = "".join(secrets.choice(alphabet) for _ in range(4))
        codes.append(f"{p1}-{p2}")
    return codes


def hash_recovery_code(code: str) -> str:
    norm = "".join(ch for ch in code.upper() if ch.isalnum())
    return hashlib.sha256(f"shield-mfa-recovery:{norm}".encode("utf-8")).hexdigest()


def build_qr_matrix(data: str) -> list[list[bool]] | None:
    if qrcode is None:
        return None
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=1,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)
    return qr.get_matrix()
