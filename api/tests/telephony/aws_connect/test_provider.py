from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from api.services.telephony.providers.aws_connect import SPEC
from api.services.telephony.providers.aws_connect.config import (
    AWSConnectConfigurationRequest,
)
from api.services.telephony.providers.aws_connect.provider import AWSConnectProvider

_TEST_DESTINATION = "+15555550100"


class _FakeConnectClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def start_outbound_voice_contact(self, **kwargs):
        self.calls.append(("start", kwargs))
        return self.response

    async def describe_contact(self, **kwargs):
        self.calls.append(("describe", kwargs))
        return self.response


class _FakeSession:
    def __init__(self, client):
        self.client_instance = client
        self.client_calls = []

    def client(self, service_name, region_name=None):
        self.client_calls.append((service_name, region_name))
        return self.client_instance


def _provider(**overrides):
    config = {
        "region": "ap-northeast-2",
        "instance_id": "instance-id",
        "contact_flow_id": "flow-id",
        "queue_id": "queue-id",
        "from_numbers": ["+827040223234"],
        "ring_timeout_seconds": None,
    }
    config.update(overrides)
    return AWSConnectProvider(config)


@pytest.mark.asyncio
async def test_initiate_call_prefers_explicit_source_phone_number():
    client = _FakeConnectClient({"ContactId": "contact-123"})
    session = _FakeSession(client)
    provider = _provider(queue_id="queue-with-different-caller-id")
    provider._session = lambda: session

    result = await provider.initiate_call(
        to_number=_TEST_DESTINATION,
        webhook_url="https://ignored.example/twiml",
        workflow_run_id=501,
        from_number="+827040223234",
        workflow_id=33,
        user_id=7,
    )

    assert result.call_id == "contact-123"
    assert result.caller_number == "+827040223234"
    assert session.client_calls == [("connect", "ap-northeast-2")]
    operation, request = client.calls[0]
    assert operation == "start"
    assert request["InstanceId"] == "instance-id"
    assert request["ContactFlowId"] == "flow-id"
    assert request["DestinationPhoneNumber"] == _TEST_DESTINATION
    assert request["SourcePhoneNumber"] == "+827040223234"
    assert "QueueId" not in request
    assert "RingTimeoutInSeconds" not in request
    assert request["Attributes"]["recova_workflow_run_id"] == "501"


@pytest.mark.asyncio
async def test_initiate_call_uses_queue_when_no_source_number_is_available():
    client = _FakeConnectClient({"ContactId": "contact-queue"})
    session = _FakeSession(client)
    provider = _provider(from_numbers=[])
    provider._session = lambda: session

    result = await provider.initiate_call(
        to_number=_TEST_DESTINATION,
        webhook_url="https://ignored.example/twiml",
    )

    assert result.call_id == "contact-queue"
    _, request = client.calls[0]
    assert request["QueueId"] == "queue-id"
    assert "SourcePhoneNumber" not in request


@pytest.mark.asyncio
async def test_initiate_call_uses_first_configured_source_number_when_not_explicit():
    client = _FakeConnectClient({"ContactId": "contact-first"})
    session = _FakeSession(client)
    provider = _provider(from_numbers=["+827040223234", "+827040223235"])
    provider._session = lambda: session

    result = await provider.initiate_call(
        to_number=_TEST_DESTINATION,
        webhook_url="https://ignored.example/twiml",
    )

    assert result.caller_number == "+827040223234"
    _, request = client.calls[0]
    assert request["SourcePhoneNumber"] == "+827040223234"
    assert "QueueId" not in request


@pytest.mark.asyncio
async def test_get_call_status_maps_disconnect_timestamp_to_completed():
    disconnected_at = datetime(2026, 5, 29, tzinfo=timezone.utc)
    client = _FakeConnectClient(
        {
            "Contact": {
                "Id": "contact-123",
                "InitiationMethod": "API",
                "DisconnectTimestamp": disconnected_at,
                "DisconnectReason": "CONTACT_FLOW_DISCONNECT",
            }
        }
    )
    session = _FakeSession(client)
    provider = _provider()
    provider._session = lambda: session

    status = await provider.get_call_status("contact-123")

    assert status["status"] == "completed"
    assert status["call_id"] == "contact-123"
    assert status["disconnect_reason"] == "CONTACT_FLOW_DISCONNECT"
    assert status["disconnect_timestamp"] == "2026-05-29T00:00:00+00:00"
    _, request = client.calls[0]
    assert request == {"InstanceId": "instance-id", "ContactId": "contact-123"}


@pytest.mark.asyncio
async def test_initiate_call_includes_ring_timeout_only_when_configured():
    client = _FakeConnectClient({"ContactId": "contact-timeout"})
    session = _FakeSession(client)
    provider = _provider(ring_timeout_seconds=30)
    provider._session = lambda: session

    await provider.initiate_call(
        to_number=_TEST_DESTINATION,
        webhook_url="https://ignored.example/twiml",
        from_number="+827040223234",
    )

    _, request = client.calls[0]
    assert request["RingTimeoutInSeconds"] == 30


def test_validate_config_requires_flow_and_source_or_queue():
    assert _provider().validate_config() is True
    assert _provider(contact_flow_id="").validate_config() is False
    assert _provider(from_numbers=[], queue_id=None).validate_config() is False
    assert _provider(from_numbers=None, queue_id=None).validate_config() is False
    assert _provider(ring_timeout_seconds=61).validate_config() is False


def test_aws_profile_is_server_controlled(monkeypatch):
    monkeypatch.setenv("AWS_CONNECT_AWS_PROFILE", "recova-dev")
    monkeypatch.setenv("AWS_PROFILE", "tenant-ignored")

    with patch(
        "api.services.telephony.providers.aws_connect.provider.aioboto3.Session"
    ) as session_cls:
        _provider(aws_profile="tenant-controlled-profile")._session()

    session_cls.assert_called_once_with(profile_name="recova-dev")


def test_aws_profile_is_not_part_of_public_config_or_self_serve_metadata():
    assert "aws_profile" not in AWSConnectConfigurationRequest.model_fields
    assert all(field.name != "aws_profile" for field in SPEC.ui_metadata.fields)
    assert SPEC.visible_in_self_serve is False
    assert SPEC.supports_media_transport is False
    assert SPEC.supports_preview_smoke is True
