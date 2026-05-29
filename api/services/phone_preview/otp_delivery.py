from __future__ import annotations

from typing import Any

import httpx
from loguru import logger

from api.services.phone_preview.config import (
    PreviewTelephonySettings,
    get_preview_telephony_settings,
    should_expose_dev_otp,
)


class PhonePreviewOtpDeliveryError(Exception):
    """Raised when production OTP delivery cannot be completed."""


async def deliver_otp_code(
    *,
    phone_number: str,
    code: str,
    masked_phone: str,
    settings: PreviewTelephonySettings | None = None,
) -> None:
    """Deliver a phone-preview OTP through the configured webhook.

    Local/test environments expose the OTP in the API response instead. In
    production, preview verification must fail closed unless a delivery webhook
    accepts the OTP payload.
    """

    if should_expose_dev_otp():
        logger.debug("Skipping phone preview OTP webhook in dev/test mode")
        return

    settings = settings or get_preview_telephony_settings()
    if not settings.otp_delivery_webhook_url:
        raise PhonePreviewOtpDeliveryError("otp_delivery_not_configured")

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if settings.otp_delivery_webhook_bearer_token:
        headers["Authorization"] = (
            f"Bearer {settings.otp_delivery_webhook_bearer_token}"
        )

    payload: dict[str, Any] = {
        "channel": "sms",
        "product": "recova",
        "purpose": "phone_preview_verification",
        "phone_number": phone_number,
        "masked_phone": masked_phone,
        "code": code,
    }

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.otp_delivery_timeout_seconds)
        ) as client:
            response = await client.post(
                settings.otp_delivery_webhook_url,
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise PhonePreviewOtpDeliveryError("otp_delivery_failed") from exc
