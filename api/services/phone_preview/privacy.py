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


def global_phone_hash(e164: str) -> str:
    """Hash a destination phone number for cross-account abuse throttling."""

    msg = f"global:{e164}".encode()
    return hmac.new(get_preview_secret().encode(), msg, hashlib.sha256).hexdigest()


_PREVIEW_CONTEXT_PRIVATE_KEYS = {
    "account_sid",
    "accountsid",
    "authorization",
    "call_sid",
    "callsid",
    "provider",
    "provider_call_id",
    "call_id",
    "proxy-authorization",
    "telephony_configuration_id",
    "telephony_configuration_organization_id",
    "preview_user_id",
}

_PREVIEW_CONTEXT_PRIVATE_KEY_FRAGMENTS = (
    "account",
    "auth",
    "credential",
    "secret",
    "signature",
    "token",
)

_PREVIEW_LOG_PRIVATE_EXACT_KEYS = {
    *(_PREVIEW_CONTEXT_PRIVATE_KEYS),
    "callsid",
    "call_sid",
    "accountsid",
    "account_sid",
    "authorization",
    "from",
    "proxy-authorization",
    "to",
}

_PREVIEW_LOG_PRIVATE_KEY_FRAGMENTS = (
    "account",
    "auth",
    "credential",
    "destination",
    "caller",
    "called",
    "number",
    "phone",
    "secret",
    "signature",
    "token",
)


def _has_preview_marker(context: dict | None) -> bool:
    if not isinstance(context, dict):
        return False
    return bool(context.get("telephony_preview") or context.get("preview_session_id"))


def _preview_context_key_is_private(key: object) -> bool:
    key_text = str(key).lower()
    return key_text in _PREVIEW_CONTEXT_PRIVATE_KEYS or any(
        fragment in key_text for fragment in _PREVIEW_CONTEXT_PRIVATE_KEY_FRAGMENTS
    )


def _sanitize_preview_context(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: _sanitize_preview_context(item)
            for key, item in value.items()
            if not _preview_context_key_is_private(key)
        }
    if isinstance(value, list):
        return [_sanitize_preview_context(item) for item in value]
    return value


def sanitize_preview_workflow_run_contexts(
    initial_context: dict | None,
    gathered_context: dict | None,
) -> tuple[dict | None, dict | None]:
    """Remove Recova/provider internals from user-visible preview run contexts."""

    if not (
        _has_preview_marker(initial_context) or _has_preview_marker(gathered_context)
    ):
        return initial_context, gathered_context
    return (
        (
            _sanitize_preview_context(initial_context)
            if initial_context is not None
            else None
        ),
        (
            _sanitize_preview_context(gathered_context)
            if gathered_context is not None
            else None
        ),
    )


def _preview_log_key_is_private(key: object) -> bool:
    key_text = str(key).lower()
    return key_text in _PREVIEW_LOG_PRIVATE_EXACT_KEYS or any(
        fragment in key_text for fragment in _PREVIEW_LOG_PRIVATE_KEY_FRAGMENTS
    )


def _sanitize_preview_log(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: _sanitize_preview_log(item)
            for key, item in value.items()
            if not _preview_log_key_is_private(key)
        }
    if isinstance(value, list):
        return [_sanitize_preview_log(item) for item in value]
    return value


def sanitize_preview_workflow_run_logs(
    initial_context: dict | None,
    gathered_context: dict | None,
    logs: dict | None,
) -> dict | None:
    """Remove provider/callback internals from user-visible preview run logs."""

    if not logs or not (
        _has_preview_marker(initial_context) or _has_preview_marker(gathered_context)
    ):
        return logs
    sanitized = _sanitize_preview_log(logs)
    return sanitized if isinstance(sanitized, dict) else None


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
