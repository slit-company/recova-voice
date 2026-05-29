"""Privacy helpers for preview-call phone verification.

The preview call path stores phone numbers only in lookup/display-safe forms by
default:

* canonical E.164 value for dialing/routing,
* masked value for UI/log-safe display,
* keyed HMAC hash for equality lookup,
* optional encrypted raw value when an encryption key is configured.

OTP values are one-way PBKDF2 hashes.  The module intentionally avoids importing
``api.constants`` so tests and standalone helper usage do not require database
environment variables at import time.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass

from api.utils.telephony_address import normalize_telephony_address

_PHONE_HASH_SECRET_ENVS = (
    "PHONE_HASH_SECRET",
    "PREVIEW_PHONE_HASH_SECRET",
    "OSS_JWT_SECRET",
)
_PHONE_ENCRYPTION_KEY_ENVS = (
    "PHONE_RAW_ENCRYPTION_KEY",
    "PREVIEW_PHONE_ENCRYPTION_KEY",
)
_DEFAULT_HASH_SECRET = "change-me-in-production"
_OTP_HASH_NAME = "sha256"
_OTP_ITERATIONS = 210_000
_OTP_SALT_BYTES = 16


@dataclass(frozen=True)
class StoredPhoneNumber:
    """Safe persisted representation of a user-entered phone number."""

    normalized: str
    masked: str
    lookup_hash: str
    encrypted_raw: str | None
    country_code: str | None = None


def normalize_kr_phone_number(raw_phone_number: str) -> str:
    """Normalize a Korean local/E.164 phone number to canonical E.164."""

    return normalize_telephony_address(raw_phone_number, country_hint="KR").canonical


def build_stored_phone_number(
    raw_phone_number: str,
    *,
    country_code: str | None = "KR",
    hash_secret: str | None = None,
    encryption_secret: str | None = None,
) -> StoredPhoneNumber:
    """Build the privacy-preserving phone fields used by preview persistence."""

    normalized = normalize_telephony_address(
        raw_phone_number, country_hint=country_code
    ).canonical
    return StoredPhoneNumber(
        normalized=normalized,
        masked=mask_phone_number(normalized),
        lookup_hash=hash_phone_number(normalized, secret=hash_secret),
        encrypted_raw=encrypt_phone_number(
            raw_phone_number, secret=encryption_secret
        ),
        country_code=country_code.upper() if country_code else None,
    )


def mask_phone_number(phone_number: str) -> str:
    """Return a display-safe mask that keeps enough suffix for user matching."""

    normalized = phone_number.strip()
    if not normalized:
        return ""

    if normalized.startswith("+"):
        digits = re.sub(r"\D", "", normalized)
        if len(digits) <= 4:
            return "+" + "*" * len(digits)
        country_prefix = _display_country_prefix(digits)
        suffix = digits[-4:]
        hidden = max(len(digits) - len(country_prefix) - len(suffix), 1)
        return f"+{country_prefix}{'*' * hidden}{suffix}"

    # SIP/extension fallback: preserve the end only.
    if len(normalized) <= 4:
        return "*" * len(normalized)
    return f"{'*' * (len(normalized) - 4)}{normalized[-4:]}"


def hash_phone_number(phone_number: str, *, secret: str | None = None) -> str:
    """Keyed lookup hash for phone equality checks without storing raw numbers."""

    canonical = phone_number.strip()
    key_source = secret or _lookup_secret(_PHONE_HASH_SECRET_ENVS, _DEFAULT_HASH_SECRET)
    if key_source is None:  # defensive; default above is intentionally non-null
        raise ValueError("phone hash secret is not configured")
    key = key_source.encode("utf-8")
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def generate_preview_session_token() -> str:
    """Generate the raw bearer token returned to the client once."""

    return f"wps_{secrets.token_urlsafe(32)}"


def hash_preview_session_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_otp_code(length: int = 6) -> str:
    """Generate a numeric OTP code."""

    if length < 4 or length > 10:
        raise ValueError("OTP length must be between 4 and 10 digits")
    upper_bound = 10**length
    return f"{secrets.randbelow(upper_bound):0{length}d}"


def hash_otp_code(otp_code: str, *, salt: bytes | None = None) -> str:
    """Return a salted PBKDF2 hash string for an OTP code."""

    _validate_otp_shape(otp_code)
    salt = salt or secrets.token_bytes(_OTP_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        _OTP_HASH_NAME,
        otp_code.encode("utf-8"),
        salt,
        _OTP_ITERATIONS,
    )
    return (
        f"pbkdf2_{_OTP_HASH_NAME}"
        f"${_OTP_ITERATIONS}"
        f"${base64.urlsafe_b64encode(salt).decode('ascii')}"
        f"${base64.urlsafe_b64encode(digest).decode('ascii')}"
    )


def verify_otp_code(otp_code: str, otp_hash: str) -> bool:
    """Constant-time OTP hash verification."""

    try:
        _validate_otp_shape(otp_code)
        algorithm, iterations, salt_b64, expected_b64 = otp_hash.split("$", 3)
        if algorithm != f"pbkdf2_{_OTP_HASH_NAME}":
            return False
        salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
        expected = base64.urlsafe_b64decode(expected_b64.encode("ascii"))
        actual = hashlib.pbkdf2_hmac(
            _OTP_HASH_NAME,
            otp_code.encode("utf-8"),
            salt,
            int(iterations),
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def encrypt_phone_number(
    raw_phone_number: str, *, secret: str | None = None
) -> str | None:
    """Encrypt a raw phone value when an encryption key is configured.

    Returns ``None`` when no encryption key is configured so callers can keep
    the database field nullable instead of silently storing plaintext.
    """

    key_source = secret or _lookup_secret(_PHONE_ENCRYPTION_KEY_ENVS, None)
    if not key_source:
        return None

    try:
        from nacl import secret as nacl_secret
        from nacl import utils as nacl_utils
    except ImportError as exc:  # pragma: no cover - exercised only in slim envs
        raise RuntimeError("PyNaCl is required for phone-number encryption") from exc

    key = _derive_secretbox_key(key_source)
    nonce = nacl_utils.random(nacl_secret.SecretBox.NONCE_SIZE)
    box = nacl_secret.SecretBox(key)
    encrypted = box.encrypt(raw_phone_number.encode("utf-8"), nonce)
    return base64.urlsafe_b64encode(bytes(encrypted)).decode("ascii")


def decrypt_phone_number(
    encrypted_phone_number: str | None, *, secret: str | None = None
) -> str | None:
    """Decrypt a phone value previously encrypted with :func:`encrypt_phone_number`."""

    if encrypted_phone_number is None:
        return None

    key_source = secret or _lookup_secret(_PHONE_ENCRYPTION_KEY_ENVS, None)
    if not key_source:
        raise ValueError("phone encryption key is not configured")

    try:
        from nacl import secret as nacl_secret
    except ImportError as exc:  # pragma: no cover - exercised only in slim envs
        raise RuntimeError("PyNaCl is required for phone-number decryption") from exc

    box = nacl_secret.SecretBox(_derive_secretbox_key(key_source))
    encrypted = base64.urlsafe_b64decode(encrypted_phone_number.encode("ascii"))
    return box.decrypt(encrypted).decode("utf-8")


def _display_country_prefix(digits: str) -> str:
    # Enough for KR (+82), NANP (+1), and most display cases without needing a
    # country database. The masked value is display-only; lookup uses E.164 hash.
    if digits.startswith("82"):
        return "82"
    if digits.startswith("1"):
        return "1"
    return digits[:2]


def _lookup_secret(env_names: tuple[str, ...], default: str | None) -> str | None:
    for env_name in env_names:
        value = os.getenv(env_name)
        if value:
            return value
    return default


def _derive_secretbox_key(key_source: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(key_source.encode("ascii"))
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass
    return hashlib.sha256(key_source.encode("utf-8")).digest()


def _validate_otp_shape(otp_code: str) -> None:
    if not re.fullmatch(r"\d{4,10}", otp_code or ""):
        raise ValueError("OTP must be 4 to 10 numeric digits")
