from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

from api.routes.telephony import router
from api.services.telephony.providers.jambonz.contract import JambonzContractSimulator


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
