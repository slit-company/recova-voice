from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

from api.routes.telephony import router


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

    ):
        config = SimpleNamespace(id=901, organization_id=11)
        mock_db.find_inbound_route_by_account = AsyncMock(
            return_value=(config, _assigned_phone_row(inbound_workflow_id=None))
        )
        mock_db.get_workflow = AsyncMock()

        response = client.post("/telephony/inbound/run", json=_jambonz_payload())

    assert response.status_code == 200
    assert "WORKFLOW_NOT_FOUND" in response.text
    mock_db.get_workflow.assert_not_awaited()
