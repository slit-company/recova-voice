from __future__ import annotations

import os
from dataclasses import dataclass

from api.enums import Environment


def _int_env(name: str, default: int | None = None) -> int | None:
    value = os.getenv(name)
    if value in (None, ""):
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _defaulted_int_env(name: str, default: int) -> int:
    value = _int_env(name, default)
    if value is None:
        return default
    return value

def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value in (None, ""):
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _string_env(name: str) -> str | None:
    value = os.getenv(name)
    return value.strip() if value and value.strip() else None


_SMOKE_GATE_NAMES = (
    "DEPENDENCY_MANIFEST",
    "CANDIDATE",
    "ENDPOINT_IDENTITY",
    "COST",
    "LIVE_WINDOW",
    "SIP_REGISTER",
    "RTP",
    "OUTBOUND_CALL",
    "INBOUND_CALL",
)

@dataclass(frozen=True)
class PreviewTelephonySettings:
    organization_id: int | None
    configuration_id: int | None
    from_phone_number_id: int | None
    max_duration_seconds: int
    session_ttl_seconds: int
    otp_ttl_seconds: int
    verified_ttl_seconds: int
    max_otp_attempts: int
    daily_user_call_limit: int
    daily_org_call_limit: int
    daily_phone_call_limit: int
    otp_delivery_webhook_url: str | None
    otp_delivery_webhook_bearer_token: str | None
    otp_delivery_timeout_seconds: int
    smoke_envelope_uuid: str | None = None
    smoke_proof_id: int | None = None
    smoke_inventory_id: int | None = None
    smoke_workflow_id: int | None = None
    smoke_application_id: str | None = None
    destination_hmac_key_id: str | None = None
    destination_hmac_key_version: str | None = None
    smoke_gates: tuple[tuple[str, bool], ...] = ()

    @property
    def is_configured(self) -> bool:
        return self.organization_id is not None and self.configuration_id is not None

    @property
    def is_classified_smoke(self) -> bool:
        values = self._classified_tuple()
        return bool(values) and all(value is not None for value in values)

    def _classified_tuple(self) -> tuple[int | str | None, ...]:
        return (
            self.smoke_envelope_uuid,
            self.smoke_proof_id,
            self.smoke_inventory_id,
            self.smoke_workflow_id,
            self.smoke_application_id,
            self.destination_hmac_key_id,
            self.destination_hmac_key_version,
        )

    def validate_classified_staging(self) -> None:
        classified = self._classified_tuple()
        configured = [value is not None for value in classified]
        if any(configured) and not all(configured):
            raise ValueError("classified Onnuri smoke identifiers are incomplete")
        if not all(configured):
            return
        if (
            self.organization_id is None
            or self.configuration_id is None
            or self.from_phone_number_id is None
        ):
            raise ValueError("classified Onnuri smoke identifiers are incomplete")
        if self.max_duration_seconds != 60:
            raise ValueError("classified Onnuri smoke duration must be exactly 60 seconds")
        if should_expose_dev_otp():
            raise ValueError("classified Onnuri smoke forbids development OTP exposure")
        configured_gate_names = {name for name, _ in self.smoke_gates}
        if configured_gate_names != set(_SMOKE_GATE_NAMES):
            raise ValueError("classified Onnuri smoke gates are incomplete")


def get_preview_telephony_settings() -> PreviewTelephonySettings:
    settings = PreviewTelephonySettings(
        organization_id=_int_env("RECOVA_PREVIEW_TELEPHONY_ORGANIZATION_ID"),
        configuration_id=_int_env("RECOVA_PREVIEW_TELEPHONY_CONFIGURATION_ID"),
        from_phone_number_id=_int_env("RECOVA_PREVIEW_FROM_PHONE_NUMBER_ID"),
        max_duration_seconds=_defaulted_int_env(
            "RECOVA_PREVIEW_MAX_DURATION_SECONDS", 300
        ),
        session_ttl_seconds=_defaulted_int_env(
            "RECOVA_PREVIEW_SESSION_TTL_SECONDS", 900
        ),
        otp_ttl_seconds=_defaulted_int_env("RECOVA_PREVIEW_OTP_TTL_SECONDS", 300),
        verified_ttl_seconds=_defaulted_int_env(
            "RECOVA_PREVIEW_VERIFIED_TTL_SECONDS", 24 * 60 * 60
        ),
        max_otp_attempts=_defaulted_int_env("RECOVA_PREVIEW_MAX_OTP_ATTEMPTS", 5),
        daily_user_call_limit=_defaulted_int_env(
            "RECOVA_PREVIEW_DAILY_USER_CALL_LIMIT", 5
        ),
        daily_org_call_limit=_defaulted_int_env(
            "RECOVA_PREVIEW_DAILY_ORG_CALL_LIMIT", 50
        ),
        daily_phone_call_limit=_defaulted_int_env(
            "RECOVA_PREVIEW_DAILY_PHONE_CALL_LIMIT", 5
        ),
        otp_delivery_webhook_url=os.getenv("RECOVA_PREVIEW_OTP_WEBHOOK_URL") or None,
        otp_delivery_webhook_bearer_token=os.getenv(
            "RECOVA_PREVIEW_OTP_WEBHOOK_BEARER_TOKEN"
        )
        or None,
        otp_delivery_timeout_seconds=_defaulted_int_env(
            "RECOVA_PREVIEW_OTP_DELIVERY_TIMEOUT_SECONDS", 5
        ),
        smoke_envelope_uuid=_string_env("RECOVA_ONNURI_SMOKE_ENVELOPE_UUID"),
        smoke_proof_id=_int_env("RECOVA_ONNURI_SMOKE_PROOF_ID"),
        smoke_inventory_id=_int_env("RECOVA_ONNURI_SMOKE_INVENTORY_ID"),
        smoke_workflow_id=_int_env("RECOVA_ONNURI_SMOKE_WORKFLOW_ID"),
        smoke_application_id=_string_env("RECOVA_ONNURI_SMOKE_APPLICATION_ID"),
        destination_hmac_key_id=_string_env(
            "RECOVA_ONNURI_SMOKE_DESTINATION_HMAC_KEY_ID"
        ),
        destination_hmac_key_version=_string_env(
            "RECOVA_ONNURI_SMOKE_DESTINATION_HMAC_KEY_VERSION"
        ),
        smoke_gates=tuple(
            (
                name,
                _bool_env(f"RECOVA_ONNURI_SMOKE_{name}_GATE"),
            )
            for name in _SMOKE_GATE_NAMES
        ),
    )
    settings.validate_classified_staging()
    return settings


def get_preview_secret() -> str:
    secret = (
        os.getenv("RECOVA_PREVIEW_SECRET_KEY")
        or os.getenv("RECOVA_PREVIEW_PHONE_ENCRYPTION_KEY")
        or os.getenv("DOGRAH_MPS_SECRET_KEY")
    )
    if secret:
        return secret

    if (
        os.getenv("ENVIRONMENT", Environment.LOCAL.value)
        == Environment.PRODUCTION.value
    ):
        raise ValueError("RECOVA_PREVIEW_SECRET_KEY is required in production")

    # Local/test fallback only. This keeps automated tests deterministic without
    # adding a new dependency or requiring secrets.
    return "local-recova-phone-preview-secret"


def should_expose_dev_otp() -> bool:
    if (
        os.getenv("ENVIRONMENT", Environment.LOCAL.value)
        == Environment.PRODUCTION.value
    ):
        return False
    configured = os.getenv("RECOVA_PREVIEW_EXPOSE_DEV_OTP")
    if configured not in (None, ""):
        return _bool_env("RECOVA_PREVIEW_EXPOSE_DEV_OTP")
    return (
        os.getenv("ENVIRONMENT", Environment.LOCAL.value)
        != Environment.PRODUCTION.value
    )
