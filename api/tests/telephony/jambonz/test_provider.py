import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import api.services.telephony.providers.jambonz.provider as jambonz_provider_module
from api.services.telephony.providers.jambonz.contract import (
    JAMBONZ_CONTRACT_VERSION,
    JambonzContractSimulator,
    JambonzOutboundCallRequest,
    JambonzReplayGuard,
    verify_signed_payload,
)
from api.services.telephony.providers.jambonz.provider import JambonzProvider


@pytest.mark.asyncio
async def test_contract_signature_rejects_unsigned_malformed_and_replayed_payloads():
    simulator = JambonzContractSimulator(webhook_secret="secret")
    payload, headers, raw_body = simulator.inbound()
    guard = JambonzReplayGuard()

    assert verify_signed_payload(
        "secret", raw_body, headers, replay_guard=guard, now=simulator.base_timestamp + 1
    )
    assert not verify_signed_payload(
        "secret", raw_body, headers, replay_guard=guard, now=simulator.base_timestamp + 1
    )

    unsigned_payload, unsigned_headers, unsigned_body = simulator.unsigned()
    assert unsigned_payload["contract_version"] == JAMBONZ_CONTRACT_VERSION
    assert not verify_signed_payload("secret", unsigned_body, unsigned_headers)

    _, malformed_headers, malformed_body = simulator.malformed_signature()
    assert not verify_signed_payload("secret", malformed_body, malformed_headers)


def test_contract_fixtures_cover_kr_inbound_and_media_start():
    simulator = JambonzContractSimulator()
    inbound_payload, _, _ = simulator.inbound(
        from_number="01012345678", to_number="07012345678"
    )
    normalized = JambonzProvider.parse_inbound_webhook(inbound_payload)

    assert normalized.provider == "jambonz"
    assert normalized.from_number == "+821012345678"
    assert normalized.to_number == "+827012345678"
    assert normalized.account_id == simulator.account_id

    media_start = simulator.media_start(direction="inbound")
    assert media_start["event"] == "start"
    assert media_start["codec"] == "PCMU"
    assert media_start["sample_rate"] == 8000

    injected_payload, _, _ = simulator.inbound_live_validation_injection()
    assert injected_payload["live_trunk_validated"] is True
    assert injected_payload["live_validation_source"] == "simulator"


@pytest.mark.asyncio
async def test_initiate_call_posts_outbound_contract_payload(monkeypatch):
    captured = {}

    class FakeResponse:
        status = 201

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def text(self):
            return json.dumps(
                {
                    "call_id": "jb-out-123",
                    "status": "initiated",
                    "is_contract_fixture": True,
                }
            )

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def post(self, endpoint, json, headers):
            captured["endpoint"] = endpoint
            captured["payload"] = json
            captured["headers"] = headers
            return FakeResponse()

    monkeypatch.setattr(
        jambonz_provider_module.aiohttp,
        "ClientSession",
        lambda: FakeSession(),
    )
    monkeypatch.setattr(
        jambonz_provider_module,
        "get_backend_endpoints",
        AsyncMock(return_value=("https://api.recova.test", "wss://api.recova.test")),
    )

    provider = JambonzProvider(
        {
            "base_url": "https://jambonz.recova.test",
            "account_id": "acct-kr",
            "application_id": "app-voice",
            "api_key": "secret-key",
            "webhook_secret": "webhook-secret",
            "outbound_profile_id": "profile-070",
            "from_numbers": ["+827012345678"],
        }
    )

    result = await provider.initiate_call(
        to_number="+821012345678",
        from_number="+827012345678",
        webhook_url="https://api.recova.test/api/v1/telephony/jambonz/answer",
        workflow_run_id=501,
        workflow_id=33,
        user_id=99,
    )

    assert result.call_id == "jb-out-123"
    assert result.caller_number == "+827012345678"
    assert captured["endpoint"] == (
        "https://jambonz.recova.test/v1/jambonz-contract/accounts/acct-kr/calls"
    )

    request = JambonzOutboundCallRequest.model_validate(captured["payload"])
    assert request.contract_version == JAMBONZ_CONTRACT_VERSION
    assert request.from_number == "+827012345678"
    assert request.to_number == "+821012345678"
    assert request.status_callback_url.endswith("/api/v1/telephony/jambonz/status/501")
    assert request.outbound_profile_id == "profile-070"
    assert captured["headers"]["Authorization"] == "Bearer secret-key"



@pytest.mark.asyncio
async def test_get_call_status_uses_contract_owned_endpoint(monkeypatch):
    captured = {}

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def json(self):
            return {"call_id": "jb-out-123", "status": "completed"}

        async def text(self):
            return ""

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def get(self, endpoint, headers):
            captured["endpoint"] = endpoint
            captured["headers"] = headers
            return FakeResponse()

    monkeypatch.setattr(
        jambonz_provider_module.aiohttp,
        "ClientSession",
        lambda: FakeSession(),
    )

    provider = JambonzProvider(
        {
            "base_url": "https://jambonz.recova.test",
            "account_id": "acct-kr",
            "application_id": "app-voice",
            "api_key": "secret-key",
            "webhook_secret": "webhook-secret",
            "from_numbers": ["+827012345678"],
        }
    )

    status = await provider.get_call_status("jb-out-123")

    assert captured["endpoint"] == (
        "https://jambonz.recova.test/v1/jambonz-contract/accounts/"
        "acct-kr/calls/jb-out-123/status"
    )
    assert captured["headers"]["Authorization"] == "Bearer secret-key"
    assert status["contract_version"] == JAMBONZ_CONTRACT_VERSION

def test_parse_status_callback_normalizes_failures_and_cdr():
    provider = JambonzProvider(
        {
            "base_url": "https://jambonz.recova.test",
            "account_id": "acct-kr",
            "application_id": "app-voice",
            "api_key": "secret-key",
            "webhook_secret": "webhook-secret",
            "from_numbers": ["+827012345678"],
        }
    )

    failed = provider.parse_status_callback(
        {
            "provider": "jambonz",
            "call_id": "jb-1",
            "status": "media-error",
            "from_number": "+827012345678",
            "to_number": "+821012345678",
            "direction": "outbound",
        }
    )
    assert failed["status"] == "error"

    cdr = provider.parse_status_callback(
        {
            "provider": "jambonz",
            "event_type": "cdr",
            "call_id": "jb-1",
            "duration_seconds": 42,
            "direction": "outbound",
        }
    )
    assert cdr["status"] == "completed"
    assert cdr["duration"] == "42"
