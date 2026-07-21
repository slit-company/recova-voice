import json
import base64
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Response
from fastapi.testclient import TestClient
import pytest
from pydantic import SecretStr
from starlette.websockets import WebSocketDisconnect

from api.routes.telephony import router
from api.services.telephony.providers.jambonz.contract import JambonzContractSimulator
from api.services.telephony.providers.jambonz.facade.app import (
    _jambonz_verbs,
    create_facade_app,
)
from api.services.telephony.providers.jambonz.facade.auth import VerificationPolicy
from api.services.telephony.providers.jambonz.facade.models import (
    HookResponse,
    ListenVerb,
    WsAuth,
)
import api.services.telephony.providers.jambonz.routes as jambonz_routes


class _InboundJambonzProviderClass:
    PROVIDER_NAME = "jambonz"

    @staticmethod
    def can_handle_webhook(webhook_data, headers):
        return webhook_data.get("provider") == "jambonz"

    @staticmethod
    def parse_inbound_webhook(webhook_data):
        return SimpleNamespace(
            provider="jambonz",
            call_id=webhook_data["call_id"],
            from_number="+821012345678",
            to_number="+827012345678",
            direction="inbound",
            call_status=webhook_data.get("call_status", "ringing"),
            account_id=webhook_data["account_id"],
            from_country="KR",
            to_country="KR",
            raw_data=webhook_data,
        )

    @staticmethod
    def generate_validation_error_response(error_type):
        return Response(
            content=f"<Response><Say>{error_type.value}</Say></Response>",
            media_type="application/xml",
        )


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def _facade_app() -> FastAPI:
    dependency = SimpleNamespace(ready=AsyncMock(return_value=True))
    verifier = SimpleNamespace(verify=lambda **_kwargs: True)
    return create_facade_app(
        f12_client=dependency,
        stock_client=dependency,
        signature_verifier=verifier,
        verification_policy=VerificationPolicy(
            dispatch_key_id="dispatch-key", media_key_id="media-key"
        ),
        media_websocket_url="wss://media.recova.invalid/calls",
    )


def test_facade_validation_failure_is_redacted_and_returns_no_call_verbs():
    raw_capability = "raw-dispatch-capability-must-not-leak"
    raw_address = "+821012345678"
    response = TestClient(_facade_app()).post(
        "/v1/jambonz-contract/hooks/outbound/record-answer-and-mint-media",
        json={
            "context": {
                "account_id": "other-tenant",
                "application_id": "application-1",
                "run_id": "run-1",
                "attempt_id": "attempt-1",
                "direction": "inbound",
                "stock_call_id": "stock-call",
                "authority_deadline": "not-a-deadline",
            },
            "stock_call_id": "changed-call",
            "idempotency_key": "idem-0000000000000001",
            "request_digest": "a" * 64,
            "event_nonce": raw_capability,
            "observed_wall_time": "invalid",
            "proposed_deadline": "invalid",
            "candidate_digest": "b" * 64,
            "to_address": raw_address,
        },
    )

    assert response.status_code == 422
    assert response.json() == {"category": "contract_mismatch"}
    serialized = response.text
    assert raw_capability not in serialized
    assert raw_address not in serialized
    assert "answer" not in serialized
    assert "listen" not in serialized


def test_facade_has_no_docs_or_ambient_readiness_authority():
    client = TestClient(_facade_app())

    assert client.get("/openapi.json").status_code == 404
    assert client.get("/docs").status_code == 404
    assert client.get("/readyz").json() == {"status": "ready"}


def test_facade_renders_official_ws_auth_without_serializing_other_authority():
    response = HookResponse(
        organization_id=7,
        verbs=(
            ListenVerb(
                url="wss://media.recova.invalid/calls",
                ws_auth=WsAuth(password=SecretStr("opaque-media-token")),
            ),
        ),
        authority_receipt_id="media-receipt",
        idempotency_key="idem-0000000000000001",
        request_digest="a" * 64,
    )

    rendered = _jambonz_verbs(response)

    assert rendered == [
        {
            "verb": "listen",
            "url": "wss://media.recova.invalid/calls",
            "wsAuth": {
                "username": "recova-media",
                "password": "opaque-media-token",
            },
            "sampleRate": 8000,
            "mixType": "mono",
            "bidirectionalAudio": {
                "enabled": True,
                "streaming": True,
                "sampleRate": 8000,
            },
        }
    ]
    assert "media-receipt" not in json.dumps(rendered)


def _assigned_phone_row(*, inbound_workflow_id):
    return SimpleNamespace(
        id=902,
        inbound_workflow_id=inbound_workflow_id,
        is_active=True,
        address_normalized="+827012345678",
        country_code="KR",
        extra_metadata={"recova_inventory_state": "assigned"},
    )


def _jambonz_payload():
    return {
        "provider": "jambonz",
        "account_id": "acct-kr",
        "call_id": "jb-in-123",
        "from_number": "01012345678",
        "to_number": "07012345678",
        "direction": "inbound",
        "call_status": "ringing",
    }


def test_inbound_run_rejects_unassigned_jambonz_route_before_workflow_lookup():
    client = TestClient(_app())
    provider_instance = SimpleNamespace(
        PROVIDER_NAME="jambonz",
        verify_inbound_signature=AsyncMock(return_value=True),
    )

    with (
        patch(
            "api.routes.telephony.get_all_telephony_providers",
            new=AsyncMock(return_value=[_InboundJambonzProviderClass]),
        ),
        patch("api.routes.telephony.db_client") as mock_db,
        patch(
            "api.routes.telephony.get_telephony_provider_by_id",
            new=AsyncMock(return_value=provider_instance),
        ),
        patch(
            "api.routes.telephony.record_rejected_call",
            new=AsyncMock(),
        ),
        patch(
            "api.routes.telephony.telephony_ops_alert_sink.emit",
            new=AsyncMock(),
        ),
    ):
        config = SimpleNamespace(id=901, organization_id=11)
        phone_row = SimpleNamespace(
            id=902,
            inbound_workflow_id=33,
            is_active=True,
            address_normalized="+821012345678",
            country_code="KR",
            extra_metadata={"recova_inventory_state": "assigned"},
        )
        mock_db.find_inbound_route_by_account = AsyncMock(return_value=(config, phone_row))
        mock_db.get_workflow = AsyncMock()

        response = client.post("/telephony/inbound/run", json=_jambonz_payload())

    assert response.status_code == 200
    assert "PHONE_NUMBER_NOT_CONFIGURED" in response.text
    mock_db.get_workflow.assert_not_awaited()


def test_inbound_run_rejects_unbound_assigned_jambonz_route_without_preview():
    client = TestClient(_app())
    provider_instance = SimpleNamespace(
        PROVIDER_NAME="jambonz",
        verify_inbound_signature=AsyncMock(return_value=True),
    )

    with (
        patch(
            "api.routes.telephony.get_all_telephony_providers",
            new=AsyncMock(return_value=[_InboundJambonzProviderClass]),
        ),
        patch("api.routes.telephony.db_client") as mock_db,
        patch(
            "api.routes.telephony.get_telephony_provider_by_id",
            new=AsyncMock(return_value=provider_instance),
        ),
        patch(
            "api.routes.telephony.record_rejected_call",
            new=AsyncMock(),
        ),
        patch(
            "api.routes.telephony.telephony_ops_alert_sink.emit",
            new=AsyncMock(),
        ),

    ):
        config = SimpleNamespace(id=901, organization_id=11)
        mock_db.find_inbound_route_by_account = AsyncMock(
            return_value=(config, _assigned_phone_row(inbound_workflow_id=None))
        )
        mock_db.get_workflow = AsyncMock()

        response = client.post("/telephony/inbound/run", json=_jambonz_payload())

    assert response.status_code == 200
    assert "PHONE_NUMBER_NOT_CONFIGURED" in response.text
    mock_db.get_workflow.assert_not_awaited()


def test_inbound_run_strips_live_validation_injection_before_workflow_match():
    client = TestClient(_app())
    payload = {
        **_jambonz_payload(),
        "contract_version": "jambonz_contract_v1",
        "is_contract_fixture": True,
        "live_trunk_validated": True,
        "live_validation_source": "simulator",
        "live_validation_evidence_id": "fake-live-proof",
    }
    record_rejected = AsyncMock()

    with (
        patch(
            "api.routes.telephony.get_all_telephony_providers",
            new=AsyncMock(return_value=[_InboundJambonzProviderClass]),
        ),
        patch("api.routes.telephony.db_client") as mock_db,
        patch(
            "api.routes.telephony.record_rejected_call",
            new=record_rejected,
        ),
    ):
        mock_db.find_inbound_route_by_account = AsyncMock(return_value=None)

        response = client.post("/telephony/inbound/run", json=payload)

    assert response.status_code == 200
    kwargs = record_rejected.await_args.kwargs
    assert kwargs["contract_version"] == "jambonz_contract_v1"
    assert kwargs["is_contract_fixture"] is True
    assert kwargs["live_validation_source"] is None
    assert kwargs["live_validation_evidence_id"] is None
    assert kwargs["artifact_payload"]["evidence_markers"]["live_trunk_validated"] is False


def test_inbound_run_accepts_signed_contract_fixture_for_bound_workflow():
    client = TestClient(_app())
    simulator = JambonzContractSimulator(account_id="acct-kr")
    payload, headers, _ = simulator.inbound()
    provider_response = Response(content="[]", media_type="application/json")
    provider_instance = SimpleNamespace(
        PROVIDER_NAME="jambonz",
        verify_inbound_signature=AsyncMock(return_value=True),
        start_inbound_stream=AsyncMock(return_value=provider_response),
    )
    record_event = AsyncMock()

    with (
        patch(
            "api.routes.telephony.get_all_telephony_providers",
            new=AsyncMock(return_value=[_InboundJambonzProviderClass]),
        ),
        patch("api.routes.telephony.db_client") as mock_db,
        patch(
            "api.routes.telephony.get_telephony_provider_by_id",
            new=AsyncMock(return_value=provider_instance),
        ),
        patch(
            "api.routes.telephony.is_assigned_recova_jambonz_070",
            new=AsyncMock(return_value=True),
        ),
        patch(
            "api.routes.telephony.is_dispatch_purpose_allowed",
            return_value=True,
        ),
        patch(
            "api.routes.telephony.check_dograh_quota_by_user_id",
            new=AsyncMock(return_value=SimpleNamespace(has_quota=True)),
        ),
        patch(
            "api.routes.telephony._create_inbound_workflow_run",
            new=AsyncMock(return_value=777),
        ),
        patch(
            "api.routes.telephony.telephony_admission_controller.acquire",
            new=AsyncMock(
                return_value=SimpleNamespace(
                    allowed=True,
                    call_attempt_id="call-attempt-inbound",
                    slot_id="slot-inbound",
                )
            ),
        ),
        patch("api.routes.telephony.get_backend_endpoints",
            new=AsyncMock(return_value=("https://api.recova.test", "wss://api.recova.test")),
        ),
        patch("api.routes.telephony.record_telephony_event", new=record_event),
        patch("api.routes.telephony.record_rejected_call", new=AsyncMock()),
    ):
        config = SimpleNamespace(id=901, organization_id=11)
        phone_row = SimpleNamespace(
            id=902,
            inbound_workflow_id=33,
            is_active=True,
            address_normalized="+827012345678",
            country_code="KR",
            extra_metadata={
                "recova_inventory_state": "assigned",
                "managed_by": "recova_number_inventory",
                "inventory_id": 1234,
            },
        )
        mock_db.find_inbound_route_by_account = AsyncMock(return_value=(config, phone_row))
        mock_db.get_workflow = AsyncMock(
            return_value=SimpleNamespace(id=33, user_id=44, organization_id=11)
        )
        mock_db.update_workflow_run = AsyncMock()

        response = client.post("/telephony/inbound/run", json=payload, headers=headers)

    assert response.status_code == 200
    provider_instance.start_inbound_stream.assert_awaited_once()
    event = record_event.await_args.args[0]
    assert event.event_type == "media_started"
    assert event.is_contract_fixture is True
    assert event.live_trunk_validated is False
    assert event.inventory_id == 1234
    assert event.artifact_payload["evidence_markers"]["is_contract_fixture"] is True
    assert event.artifact_payload["evidence_markers"]["live_trunk_validated"] is False


def _media_token(*, expires_delta=timedelta(seconds=45), **claim_overrides):
    now = datetime.now(timezone.utc)
    expires_at = now + expires_delta
    claims = {
        "account_id": "acct-kr",
        "application_id": "app-voice",
        "attempt_id": "attempt-uuid",
        "authority_deadline": expires_at.isoformat(),
        "callback_event_nonce": "event-nonce",
        "candidate_digest": "a" * 64,
        "contract_version": "recova-jambonz-facade-v1",
        "direction": "outbound",
        "gate_envelope_digest": "b" * 64,
        "idempotency_key": "idem-0000000000000001",
        "observed_event_wall_time": now.isoformat(),
        "organization_id": 7,
        "request_digest": "c" * 64,
        "run_id": "501",
        "stock_call_id": "stock-call-1",
    }
    claims.update(claim_overrides)
    payload = {
        "algorithm": "ES256",
        "claims": claims,
        "contract_version": "recova-jambonz-facade-v1",
        "expires_at": expires_at.isoformat(),
        "issued_at": now.isoformat(),
        "key_id": "media-key",
        "nonce": "media-nonce",
        "signature": "media-signature",
        "verification_domain": "recova.onnuri.smoke.media.v1",
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _media_auth(token, *, username="recova-media"):
    encoded = base64.b64encode(f"{username}:{token}".encode()).decode()
    return {"authorization": f"Basic {encoded}"}


def test_jambonz_media_rejects_missing_duplicate_and_wrong_basic_auth():
    client = TestClient(_app())
    token = _media_token()
    authorization = _media_auth(token)["authorization"].encode()
    duplicate = SimpleNamespace(
        scope={
            "headers": [
                (b"authorization", authorization),
                (b"authorization", authorization),
            ]
        }
    )
    assert jambonz_routes._basic_media_capability(duplicate) is None

    for headers in ({}, _media_auth(token, username="other-user")):
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                "/telephony/jambonz/onnuri-smoke/media",
                headers=headers,
            ):
                pass


@pytest.mark.parametrize(
    "token",
    [
        "not-json",
        _media_token(run_id="0"),
        _media_token(run_id="smoke-envelope-uuid"),
        _media_token(expires_delta=timedelta(seconds=-1)),
        _media_token(candidate_digest="wrong"),
    ],
)
def test_jambonz_media_rejects_malformed_misbound_or_expired_capability(token):
    pipeline = AsyncMock()
    with patch(
        "api.services.telephony.providers.jambonz.routes._run_media_pipeline", new=pipeline
    ):
        with pytest.raises(WebSocketDisconnect):
            with TestClient(_app()).websocket_connect(
                "/telephony/jambonz/onnuri-smoke/media",
                headers=_media_auth(token),
            ):
                pass
    pipeline.assert_not_awaited()


def test_jambonz_media_rejects_wrong_stock_metadata_before_consume():
    consume = AsyncMock()
    pipeline = AsyncMock()
    with (
        patch.object(jambonz_routes.onnuri_smoke_f12, "consume_media", consume),
        patch(
            "api.services.telephony.providers.jambonz.routes._run_media_pipeline", new=pipeline
        ),
        TestClient(_app()).websocket_connect(
            "/telephony/jambonz/onnuri-smoke/media",
            headers=_media_auth(_media_token()),
        ) as websocket,
    ):
        websocket.send_json({"callSid": "different-stock-call"})
        with pytest.raises(WebSocketDisconnect):
            websocket.receive_json()

    consume.assert_not_awaited()
    pipeline.assert_not_awaited()


@pytest.mark.parametrize("consume_error", [RuntimeError("replay"), RuntimeError("terminal")])
def test_jambonz_media_rejects_replay_or_consume_failure(consume_error):
    consume = AsyncMock(side_effect=consume_error)
    pipeline = AsyncMock()
    with (
        patch.object(jambonz_routes.onnuri_smoke_f12, "consume_media", consume),
        patch(
            "api.services.telephony.providers.jambonz.routes._run_media_pipeline", new=pipeline
        ),
        TestClient(_app()).websocket_connect(
            "/telephony/jambonz/onnuri-smoke/media",
            headers=_media_auth(_media_token()),
        ) as websocket,
    ):
        websocket.send_json({"callSid": "stock-call-1"})
        with pytest.raises(WebSocketDisconnect):
            websocket.receive_json()

    consume.assert_awaited_once()
    pipeline.assert_not_awaited()


@pytest.mark.parametrize(
    ("organization_id", "state", "is_completed"),
    [(8, "initialized", False), (7, "completed", True)],
)
def test_jambonz_media_rejects_cross_tenant_or_terminal_run(
    organization_id, state, is_completed
):
    workflow_run = SimpleNamespace(
        id=501,
        workflow_id=33,
        state=state,
        call_type="outbound",
        is_completed=is_completed,
        gathered_context={"call_id": "stock-call-1"},
    )
    workflow = SimpleNamespace(id=33, organization_id=organization_id, user_id=99)
    pipeline = AsyncMock()
    with (
        patch.object(
            jambonz_routes.onnuri_smoke_f12,
            "consume_media",
            new=AsyncMock(return_value={}),
        ),
        patch.object(
            jambonz_routes.db_client,
            "get_workflow_run_by_id",
            new=AsyncMock(return_value=workflow_run),
        ),
        patch.object(
            jambonz_routes.db_client,
            "get_workflow_by_id",
            new=AsyncMock(return_value=workflow),
        ),
        patch(
            "api.services.telephony.providers.jambonz.routes._run_media_pipeline", new=pipeline
        ),
        TestClient(_app()).websocket_connect(
            "/telephony/jambonz/onnuri-smoke/media",
            headers=_media_auth(_media_token()),
        ) as websocket,
    ):
        websocket.send_json({"callSid": "stock-call-1"})
        with pytest.raises(WebSocketDisconnect):
            websocket.receive_json()

    pipeline.assert_not_awaited()


def test_jambonz_media_happy_path_consumes_once_and_runs_shared_pipeline_once():
    workflow_run = SimpleNamespace(
        id=501,
        workflow_id=33,
        state="initialized",
        call_type="outbound",
        is_completed=False,
        gathered_context={"call_id": "stock-call-1"},
        initial_context={"telephony_preview": True},
    )
    workflow = SimpleNamespace(id=33, organization_id=7, user_id=99)
    provider = SimpleNamespace(
        PROVIDER_NAME="jambonz",
        account_id="acct-kr",
        application_id="app-voice",
    )
    consume = AsyncMock(return_value={})
    pipeline = AsyncMock()
    update = AsyncMock()
    with (
        patch.object(jambonz_routes.onnuri_smoke_f12, "consume_media", consume),
        patch.object(
            jambonz_routes.db_client,
            "get_workflow_run_by_id",
            new=AsyncMock(return_value=workflow_run),
        ),
        patch.object(
            jambonz_routes.db_client,
            "get_workflow_by_id",
            new=AsyncMock(return_value=workflow),
        ),
        patch.object(jambonz_routes.db_client, "update_workflow_run", new=update),
        patch.object(
            jambonz_routes,
            "get_telephony_provider_for_run",
            new=AsyncMock(return_value=provider),
        ),
        patch(
            "api.services.telephony.providers.jambonz.routes._run_media_pipeline", new=pipeline
        ),
        TestClient(_app()).websocket_connect(
            "/telephony/jambonz/onnuri-smoke/media",
            headers=_media_auth(_media_token()),
        ) as websocket,
    ):
        websocket.send_json({"callSid": "stock-call-1"})

    consume.assert_awaited_once()
    pipeline.assert_awaited_once()
    kwargs = pipeline.await_args.kwargs
    assert kwargs["workflow_id"] == 33
    assert kwargs["workflow_run_id"] == 501
    assert kwargs["user_id"] == 99
    assert kwargs["transport_kwargs"]["jambonz_sample_rate"] == 8000
