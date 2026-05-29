from types import SimpleNamespace

import pytest

from api.services.phone_preview.config import PreviewTelephonySettings
from api.services.phone_preview.otp_delivery import (
    PhonePreviewOtpDeliveryError,
    deliver_otp_code,
)


def _settings(**overrides):
    defaults = dict(
        organization_id=900,
        configuration_id=901,
        from_phone_number_id=None,
        max_duration_seconds=300,
        session_ttl_seconds=900,
        otp_ttl_seconds=300,
        verified_ttl_seconds=86400,
        max_otp_attempts=5,
        daily_user_call_limit=5,
        daily_phone_call_limit=5,
        otp_delivery_webhook_url="https://sms.example/send",
        otp_delivery_webhook_bearer_token="token-123",
        otp_delivery_timeout_seconds=7,
    )
    defaults.update(overrides)
    return PreviewTelephonySettings(**defaults)


@pytest.mark.asyncio
async def test_deliver_otp_code_posts_configured_webhook(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    requests = []

    class FakeResponse:
        def raise_for_status(self):
            return None

    class FakeAsyncClient:
        def __init__(self, *, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url, *, json, headers):
            requests.append(
                SimpleNamespace(
                    timeout=self.timeout,
                    url=url,
                    json=json,
                    headers=headers,
                )
            )
            return FakeResponse()

    monkeypatch.setattr(
        "api.services.phone_preview.otp_delivery.httpx.AsyncClient",
        FakeAsyncClient,
    )

    await deliver_otp_code(
        phone_number="+821012345678",
        code="123456",
        masked_phone="+82****5678",
        settings=_settings(),
    )

    assert len(requests) == 1
    request = requests[0]
    assert request.url == "https://sms.example/send"
    assert request.timeout.connect == 7
    assert request.headers["Authorization"] == "Bearer token-123"
    assert request.json == {
        "channel": "sms",
        "product": "recova",
        "purpose": "phone_preview_verification",
        "phone_number": "+821012345678",
        "masked_phone": "+82****5678",
        "code": "123456",
    }


@pytest.mark.asyncio
async def test_deliver_otp_code_requires_webhook_in_production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")

    with pytest.raises(PhonePreviewOtpDeliveryError) as exc:
        await deliver_otp_code(
            phone_number="+821012345678",
            code="123456",
            masked_phone="+82****5678",
            settings=_settings(otp_delivery_webhook_url=None),
        )

    assert str(exc.value) == "otp_delivery_not_configured"
