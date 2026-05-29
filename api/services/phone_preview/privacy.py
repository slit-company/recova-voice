from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from itertools import count

from api.services.phone_preview.config import get_preview_secret
from api.utils.telephony_address import normalize_telephony_address


def normalize_preview_phone(raw: str) -> str:
    normalized = normalize_telephony_address(raw, country_hint="KR")
    if normalized.address_type != "pstn":
        raise ValueError("invalid_phone_number")
    if not re.fullmatch(r"^\+\d{8,15}$", normalized.canonical):
        raise ValueError("invalid_phone_number")
    return normalized.canonical


def mask_phone(e164: str) -> str:
    digits = re.sub(r"\D", "", e164)
    if len(digits) <= 6:
        return "+***"
    return f"+{digits[:2]}****{digits[-4:]}"


def phone_hash(e164: str, *, organization_id: int, user_id: int) -> str:
    msg = f"{organization_id}:{user_id}:{e164}".encode()
    return hmac.new(get_preview_secret().encode(), msg, hashlib.sha256).hexdigest()


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    chunks: list[bytes] = []
    for idx in count():
        chunks.append(hashlib.sha256(key + nonce + idx.to_bytes(4, "big")).digest())
        data = b"".join(chunks)
        if len(data) >= length:
            return data[:length]
    raise RuntimeError("unreachable")


def encrypt_phone(e164: str) -> str:
    """Encrypt an E.164 destination for short-lived provider execution storage.

    The project intentionally avoids adding dependencies here. This uses a
    keyed SHA-256 stream with a per-value nonce and HMAC authentication. It is
    reversible only with the preview secret and is sufficient for the MVP's
    nullable, short-retention raw destination field.
    """

    nonce = os.urandom(16)
    key = hashlib.sha256(get_preview_secret().encode()).digest()
    plain = e164.encode()
    stream = _keystream(key, nonce, len(plain))
    cipher = bytes(a ^ b for a, b in zip(plain, stream))
    tag = hmac.new(key, nonce + cipher, hashlib.sha256).digest()[:16]
    payload = base64.urlsafe_b64encode(nonce + tag + cipher).decode()
    return f"v1:{payload}"


def decrypt_phone(value: str) -> str:
    if not value or not value.startswith("v1:"):
        raise ValueError("invalid_encrypted_phone")
    raw = base64.urlsafe_b64decode(value[3:].encode())
    nonce, tag, cipher = raw[:16], raw[16:32], raw[32:]
    key = hashlib.sha256(get_preview_secret().encode()).digest()
    expected = hmac.new(key, nonce + cipher, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, expected):
        raise ValueError("invalid_encrypted_phone")
    stream = _keystream(key, nonce, len(cipher))
    return bytes(a ^ b for a, b in zip(cipher, stream)).decode()
