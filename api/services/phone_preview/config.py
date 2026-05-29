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

    @property
    def is_configured(self) -> bool:
        return self.organization_id is not None and self.configuration_id is not None


def get_preview_telephony_settings() -> PreviewTelephonySettings:
    return PreviewTelephonySettings(
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
    )


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
    if os.getenv("RECOVA_PREVIEW_EXPOSE_DEV_OTP", "").lower() in {"1", "true", "yes"}:
        return True
    return (
        os.getenv("ENVIRONMENT", Environment.LOCAL.value)
        != Environment.PRODUCTION.value
    )
