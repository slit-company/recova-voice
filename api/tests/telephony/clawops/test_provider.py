import base64
import hashlib
import hmac
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import urlencode

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from api.services.telephony.providers.clawops import SPEC
from api.services.telephony.providers.clawops.provider import ClawOpsProvider
from api.services.telephony.providers.clawops.routes import (
    handle_clawops_status_callback,
    handle_clawops_voiceml_webhook,
)


class _FakeResponse:
    def __init__(self, status: int, body: dict):
        self.status = status
        self.body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def json(self):
        return self.body

    async def text(self):
        return str(self.body)


class _FakeSession:
    def __init__(self, response: _FakeResponse):
        self.response = response
        self.posts = []
        self.puts = []
        self.gets = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, *, json=None, headers=None):
        self.posts.append({"url": url, "json": json, "headers": headers})
        return self.response

    def put(self, url, *, json=None, headers=None):
        self.puts.append({"url": url, "json": json, "headers": headers})
        return self.response

    def get(self, url, *, headers=None):
        self.gets.append({"url": url, "headers": headers})
        return self.response


def _provider(**overrides) -> ClawOpsProvider:
    config = {
        "account_id": "AC123",
        "api_key": "clawops-api-key",
        "signing_key": "clawops-signing-key",
        "from_numbers": ["+827012345678"],
    }
    config.update(overrides)
    return ClawOpsProvider(config)


def _signature(provider: ClawOpsProvider, *, url: str, params: dict[str, str]) -> str:
    signed_data = url + "".join(f"{key}{params[key]}" for key in sorted(params))
    return base64.b64encode(
        hmac.new(
            provider.signing_key.encode("utf-8"),
            signed_data.encode("utf-8"),
            hashlib.sha256,
        ).digest()
    ).decode("ascii")


def _request(
    *,
    path: str,
    query: dict[str, str | int] | None = None,
    form_data: dict[str, str],
    headers: dict[str, str] | None = None,
) -> Request:
    body = urlencode(form_data).encode("utf-8")
    query_string = urlencode(query or {}).encode("utf-8")
    request_headers = [
        (b"content-type", b"application/x-www-form-urlencoded"),
        *[
            (name.lower().encode("ascii"), value.encode("ascii"))
            for name, value in (headers or {}).items()
        ],
    ]

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "server": ("example.test", 443),
            "path": path,
            "query_string": query_string,
            "headers": request_headers,
        },
        receive,
    )


def test_clawops_config_is_hidden_but_media_capable():
    assert SPEC.visible_in_self_serve is False
    assert SPEC.supports_media_transport is True
    assert SPEC.account_id_credential_field == "account_id"


def test_validate_config_requires_signing_key_and_from_number():
    assert _provider().validate_config() is True
    assert _provider(signing_key="").validate_config() is False
    assert _provider(from_numbers=[]).validate_config() is False


@pytest.mark.asyncio
async def test_initiate_call_uses_clawops_calls_api_and_korean_domestic_numbers():
    fake_session = _FakeSession(
        _FakeResponse(
            201,
            {
                "callId": "CA123",
                "status": "queued",
                "from": "07012345678",
                "to": "01012345678",
            },
        )
    )
    provider = _provider()

    with (
        patch(
            "api.services.telephony.providers.clawops.provider.aiohttp.ClientSession",
            return_value=fake_session,
        ),
        patch(
            "api.services.telephony.providers.clawops.provider.get_backend_endpoints",
            new_callable=AsyncMock,
            return_value=("https://backend.example", "wss://backend.example"),
        ),
    ):
        result = await provider.initiate_call(
            to_number="+821012345678",
            webhook_url="https://backend.example/api/v1/telephony/clawops-voiceml",
            workflow_run_id=123,
            from_number="+827012345678",
            workflow_id=7,
            user_id=8,
            Timeout=25,
        )

    assert result.call_id == "CA123"
    assert result.caller_number == "+827012345678"
    request = fake_session.posts[0]
    assert request["url"] == "https://api.claw-ops.com/v1/accounts/AC123/calls"
    assert request["headers"]["Authorization"] == "Bearer clawops-api-key"
    assert request["json"]["To"] == "01012345678"
    assert request["json"]["From"] == "07012345678"
    assert request["json"]["Timeout"] == 25
    assert request["json"]["StatusCallback"].endswith(
        "/api/v1/telephony/clawops/status-callback/123"
    )
    assert "workflow_id" not in request["json"]
    assert "user_id" not in request["json"]


@pytest.mark.asyncio
async def test_verify_inbound_signature_accepts_official_url_plus_sorted_params_shape():
    provider = _provider()
    url = "https://example.test/api/v1/telephony/clawops/status-callback/123"
    params = {
        "CallStatus": "completed",
        "CallId": "CA123",
        "AccountId": "AC123",
    }
    signature = _signature(provider, url=url, params=params)

    assert await provider.verify_inbound_signature(
        url, params, {"X-Signature": signature}
    )


@pytest.mark.asyncio
async def test_verify_inbound_signature_rejects_missing_signature():
    assert not await _provider().verify_inbound_signature(
        "https://example.test/webhook", {"CallId": "CA123"}, {}
    )


def test_parse_inbound_webhook_normalizes_korean_numbers():
    data = ClawOpsProvider.parse_inbound_webhook(
        {
            "CallId": "CA123",
            "AccountId": "AC123",
            "From": "01012345678",
            "To": "07012345678",
            "Direction": "inbound",
            "CallStatus": "ringing",
        }
    )

    assert data.provider == "clawops"
    assert data.call_id == "CA123"
    assert data.account_id == "AC123"
    assert data.from_number == "+821012345678"
    assert data.to_number == "+827012345678"
    assert data.to_country == "KR"


@pytest.mark.asyncio
async def test_voiceml_route_verifies_signature_before_returning_xml():
    provider = _provider()
    query = {
        "workflow_id": 7,
        "user_id": 8,
        "workflow_run_id": 123,
        "organization_id": 11,
    }
    form_data = {"CallId": "CA123", "AccountId": "AC123", "CallStatus": "answered"}
    url = f"https://example.test/api/v1/telephony/clawops-voiceml?{urlencode(query)}"
    request = _request(
        path="/api/v1/telephony/clawops-voiceml",
        query=query,
        form_data=form_data,
        headers={"X-Signature": _signature(provider, url=url, params=form_data)},
    )

    with (
        patch("api.services.telephony.providers.clawops.routes.db_client") as db_client,
        patch(
            "api.services.telephony.providers.clawops.routes.get_telephony_provider_for_run",
            new_callable=AsyncMock,
            return_value=provider,
        ),
        patch.object(
            provider,
            "get_webhook_response",
            new_callable=AsyncMock,
            return_value="<Response/>",
        ) as get_webhook_response,
    ):
        db_client.get_workflow_run_by_id = AsyncMock(
            return_value=SimpleNamespace(id=123)
        )
        response = await handle_clawops_voiceml_webhook(
            workflow_id=7,
            user_id=8,
            workflow_run_id=123,
            organization_id=11,
            request=request,
        )

    assert response.body == b"<Response/>"
    get_webhook_response.assert_awaited_once_with(7, 8, 123)


@pytest.mark.asyncio
async def test_voiceml_route_rejects_missing_signature():
    provider = _provider()
    request = _request(
        path="/api/v1/telephony/clawops-voiceml",
        query={
            "workflow_id": 7,
            "user_id": 8,
            "workflow_run_id": 123,
            "organization_id": 11,
        },
        form_data={"CallId": "CA123", "AccountId": "AC123"},
    )

    with (
        patch("api.services.telephony.providers.clawops.routes.db_client") as db_client,
        patch(
            "api.services.telephony.providers.clawops.routes.get_telephony_provider_for_run",
            new_callable=AsyncMock,
            return_value=provider,
        ),
    ):
        db_client.get_workflow_run_by_id = AsyncMock(
            return_value=SimpleNamespace(id=123)
        )
        with pytest.raises(HTTPException) as exc_info:
            await handle_clawops_voiceml_webhook(
                workflow_id=7,
                user_id=8,
                workflow_run_id=123,
                organization_id=11,
                request=request,
            )

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_status_callback_verifies_signature_and_processes_update():
    provider = _provider()
    form_data = {
        "CallId": "CA123",
        "AccountId": "AC123",
        "CallStatus": "completed",
        "From": "07012345678",
        "To": "01012345678",
        "Direction": "outbound",
        "Duration": "30",
    }
    url = "https://example.test/api/v1/telephony/clawops/status-callback/123"
    request = _request(
        path="/api/v1/telephony/clawops/status-callback/123",
        form_data=form_data,
        headers={"X-Signature": _signature(provider, url=url, params=form_data)},
    )

    with (
        patch("api.services.telephony.providers.clawops.routes.db_client") as db_client,
        patch(
            "api.services.telephony.providers.clawops.routes.get_telephony_provider_for_run",
            new_callable=AsyncMock,
            return_value=provider,
        ),
        patch(
            "api.services.telephony.providers.clawops.routes._process_status_update",
            new_callable=AsyncMock,
        ) as process_status,
    ):
        db_client.get_workflow_run_by_id = AsyncMock(
            return_value=SimpleNamespace(workflow_id=7)
        )
        db_client.get_workflow_by_id = AsyncMock(
            return_value=SimpleNamespace(organization_id=11)
        )

        result = await handle_clawops_status_callback(
            workflow_run_id=123,
            request=request,
        )

    assert result == {"status": "success"}
    process_status.assert_awaited_once()
