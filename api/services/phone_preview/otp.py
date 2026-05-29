from __future__ import annotations

import hashlib
import hmac
import secrets

from api.services.phone_preview.config import get_preview_secret


def generate_otp_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def generate_otp_salt() -> str:
    return secrets.token_urlsafe(18)


def hash_otp_code(code: str, salt: str) -> str:
    normalized = (code or "").strip()
    msg = f"{salt}:{normalized}".encode()
    return hmac.new(get_preview_secret().encode(), msg, hashlib.sha256).hexdigest()


def otp_matches(code: str, salt: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_otp_code(code, salt), expected_hash or "")
