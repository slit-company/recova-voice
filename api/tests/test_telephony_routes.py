from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from fastapi import FastAPI
from fastapi import Response
from fastapi.testclient import TestClient

from api.routes.telephony import router
from api.services.auth.depends import get_user


def _make_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_user] = lambda: SimpleNamespace(
        id=7,
        provider_id="stack-user-7",
        selected_organization_id=11,
        is_superuser=True,
    )
    return app


def _workflow(*, workflow_id: int = 33, user_id: int = 99):
    return SimpleNamespace(
        id=workflow_id,
        user_id=user_id,
        organization_id=11,
        template_context_variables={"template_key": "template-value"},
    )


def _provider():
    return SimpleNamespace(
        PROVIDER_NAME="twilio",
        WEBHOOK_ENDPOINT="twilio/voice",
        validate_config=Mock(return_value=True),
        initiate_call=AsyncMock(
            return_value=SimpleNamespace(
                caller_number="+15550001111",
                provider_metadata={"call_id": "call-123"},
            )
        ),
    )


class _InboundPreviewProviderClass:
    PROVIDER_NAME = "clawops"

    @staticmethod
    def can_handle_webhook(webhook_data, headers):
        return webhook_data.get("AccountId") == "AC123"

    @staticmethod
    def parse_inbound_webhook(webhook_data):
        return SimpleNamespace(
            provider="clawops",
            call_id=webhook_data["CallId"],
            from_number="+821012345678",
            to_number="+827000000000",
            direction="inbound",
            call_status=webhook_data.get("CallStatus", "in-progress"),
            account_id=webhook_data["AccountId"],
            from_country="KR",
            to_country="KR",
            raw_data=webhook_data,
        )

    @staticmethod
    def generate_validation_error_response(error_type):
        return Response(
            content=f"<Response><Say>{error_type}</Say></Response>",
            media_type="application/xml",
        )


def test_initiate_call_executes_as_workflow_owner_for_shared_org_workflow():
    app = _make_test_app()
    client = TestClient(app)

    workflow = _workflow()
    provider = _provider()
    quota_mock = AsyncMock(
        return_value=SimpleNamespace(has_quota=True, error_message="")
    )

    with (
        patch("api.routes.telephony.db_client") as mock_db,
        patch(
            "api.routes.telephony.check_dograh_quota_by_user_id",
            new=quota_mock,
        ),
        patch(
            "api.routes.telephony.get_default_telephony_provider",
            new=AsyncMock(return_value=provider),
        ),
        patch(
            "api.routes.telephony.get_backend_endpoints",
            new=AsyncMock(return_value=("https://api.example.com", "wss://ignored")),
        ),
    ):
        mock_db.get_user_configurations = AsyncMock(
            return_value=SimpleNamespace(test_phone_number=None)
        )
        mock_db.get_default_telephony_configuration = AsyncMock(
            return_value=SimpleNamespace(id=55)
        )
        mock_db.get_workflow = AsyncMock(return_value=workflow)
        mock_db.create_workflow_run = AsyncMock(
            return_value=SimpleNamespace(
                id=501,
                name="WR-TEL-OUT-00000001",
                initial_context={"template_key": "template-value"},
            )
        )
        mock_db.update_workflow_run = AsyncMock()

        response = client.post(
            "/telephony/initiate-call",
            json={"workflow_id": workflow.id, "phone_number": "+15551234567"},
        )

    assert response.status_code == 200
    quota_mock.assert_awaited_once_with(workflow.user_id, workflow_id=workflow.id)
    mock_db.get_workflow.assert_awaited_once_with(workflow.id, organization_id=11)

    create_call = mock_db.create_workflow_run.await_args
    create_args = create_call.args
    create_kwargs = create_call.kwargs
    assert create_args[1] == workflow.id
    assert create_kwargs["user_id"] == workflow.user_id
    assert create_kwargs["organization_id"] == workflow.organization_id
    assert create_kwargs["initial_context"]["template_key"] == "template-value"

    initiate_kwargs = provider.initiate_call.await_args.kwargs
    assert initiate_kwargs["workflow_id"] == workflow.id
    assert initiate_kwargs["user_id"] == workflow.user_id
    assert "user_id=99" in initiate_kwargs["webhook_url"]

def test_initiate_call_jambonz_uses_assigned_recova_070_default_caller():
    app = _make_test_app()
    client = TestClient(app)

    workflow = _workflow()
    provider = _provider()
    provider.PROVIDER_NAME = "jambonz"
    provider.WEBHOOK_ENDPOINT = "jambonz/answer"
    quota_mock = AsyncMock(
        return_value=SimpleNamespace(has_quota=True, error_message="")
    )
    caller = SimpleNamespace(phone_number_id=902, from_number="+827012345678")

    with (
        patch("api.routes.telephony.db_client") as mock_db,
        patch(
            "api.routes.telephony.check_dograh_quota_by_user_id",
            new=quota_mock,
        ),
        patch(
            "api.routes.telephony.get_default_telephony_provider",
            new=AsyncMock(return_value=provider),
        ),
        patch(
            "api.routes.telephony.resolve_jambonz_outbound_caller",
            new=AsyncMock(return_value=caller),
        ) as resolve_caller,
        patch(
            "api.routes.telephony.get_backend_endpoints",
            new=AsyncMock(return_value=("https://api.example.com", "wss://ignored")),
        ),
    ):
        mock_db.get_user_configurations = AsyncMock(
            return_value=SimpleNamespace(test_phone_number=None)
        )
        mock_db.get_default_telephony_configuration = AsyncMock(
            return_value=SimpleNamespace(id=55)
        )
        mock_db.get_workflow = AsyncMock(return_value=workflow)
        mock_db.create_workflow_run = AsyncMock(
            return_value=SimpleNamespace(
                id=501,
                name="WR-TEL-OUT-00000001",
                initial_context={},
            )
        )
        mock_db.update_workflow_run = AsyncMock()

        response = client.post(
            "/telephony/initiate-call",
            json={"workflow_id": workflow.id, "phone_number": "+821012345678"},
        )

    assert response.status_code == 200
    resolve_caller.assert_awaited_once_with(
        telephony_configuration_id=55,
        from_phone_number_id=None,
    )
    initiate_kwargs = provider.initiate_call.await_args.kwargs
    assert initiate_kwargs["from_number"] == "+827012345678"
    assert "/telephony/jambonz/answer" in initiate_kwargs["webhook_url"]

    update_context = mock_db.update_workflow_run.await_args.kwargs["initial_context"]
    assert update_context["caller_number"] == "+15550001111"
    assert update_context["from_phone_number_id"] == 902

def test_initiate_call_rejects_existing_run_for_different_workflow():
    app = _make_test_app()
    client = TestClient(app)

    workflow = _workflow()
    provider = _provider()
    quota_mock = AsyncMock(
        return_value=SimpleNamespace(has_quota=True, error_message="")
    )

    with (
        patch("api.routes.telephony.db_client") as mock_db,
        patch(
            "api.routes.telephony.check_dograh_quota_by_user_id",
            new=quota_mock,
        ),
        patch(
            "api.routes.telephony.get_default_telephony_provider",
            new=AsyncMock(return_value=provider),
        ),
    ):
        mock_db.get_user_configurations = AsyncMock(
            return_value=SimpleNamespace(test_phone_number=None)
        )
        mock_db.get_default_telephony_configuration = AsyncMock(
            return_value=SimpleNamespace(id=55)
        )
        mock_db.get_workflow = AsyncMock(return_value=workflow)
        mock_db.get_workflow_run = AsyncMock(
            return_value=SimpleNamespace(
                id=501,
                workflow_id=44,
                name="WR-TEL-OUT-00000044",
                initial_context={},
            )
        )

        response = client.post(
            "/telephony/initiate-call",
            json={
                "workflow_id": workflow.id,
                "workflow_run_id": 501,
                "phone_number": "+15551234567",
            },
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "workflow_run_workflow_mismatch"
    mock_db.get_workflow_run.assert_awaited_once_with(501, organization_id=11)
    assert not mock_db.create_workflow_run.called
    assert provider.initiate_call.await_count == 0


def test_initiate_call_rejects_outbound_control_only_provider_before_dispatch():
    app = _make_test_app()
    client = TestClient(app)

    provider = _provider()
    provider.PROVIDER_NAME = "aws_connect"
    provider.WEBHOOK_ENDPOINT = None
    provider.SUPPORTS_MEDIA_TRANSPORT = False

    with (
        patch("api.routes.telephony.db_client") as mock_db,
        patch(
            "api.routes.telephony.get_default_telephony_provider",
            new=AsyncMock(return_value=provider),
        ),
    ):
        mock_db.get_user_configurations = AsyncMock(
            return_value=SimpleNamespace(test_phone_number=None)
        )
        mock_db.get_default_telephony_configuration = AsyncMock(
            return_value=SimpleNamespace(id=55)
        )
        mock_db.get_workflow = AsyncMock()

        response = client.post(
            "/telephony/initiate-call",
            json={"workflow_id": 33, "phone_number": "+15551234567"},
        )

    assert response.status_code == 400
    assert (
        response.json()["detail"] == "telephony_provider_not_supported_for_direct_calls"
    )
    mock_db.get_workflow.assert_not_awaited()
    provider.initiate_call.assert_not_awaited()


def test_inbound_run_routes_unassigned_recova_number_to_preview_reservation():
    app = _make_test_app()
    client = TestClient(app)
    provider_instance = SimpleNamespace(
        PROVIDER_NAME="clawops",
        verify_inbound_signature=AsyncMock(return_value=True),
    )
    preview_response = Response(
        content="<Response><Connect/></Response>", media_type="application/xml"
    )

    with (
        patch(
            "api.routes.telephony.get_all_telephony_providers",
            new=AsyncMock(return_value=[_InboundPreviewProviderClass]),
        ),
        patch("api.routes.telephony.db_client") as mock_db,
        patch(
            "api.routes.telephony.get_telephony_provider_by_id",
            new=AsyncMock(return_value=provider_instance),
        ) as get_provider,
        patch(
            "api.services.phone_preview.service.phone_preview_service.answer_inbound_preview",
            new=AsyncMock(return_value=preview_response),
        ) as answer_preview,
    ):
        config = SimpleNamespace(id=901, organization_id=900)
        phone_row = SimpleNamespace(id=902, inbound_workflow_id=None)
        mock_db.find_inbound_route_by_account = AsyncMock(
            return_value=(config, phone_row)
        )
        mock_db.get_workflow = AsyncMock()

        response = client.post(
            "/telephony/inbound/run",
            data={
                "CallId": "CA123",
                "AccountId": "AC123",
                "From": "01012345678",
                "To": "07000000000",
                "CallStatus": "in-progress",
                "Direction": "inbound",
            },
            headers={"X-Signature": "valid"},
        )

    assert response.status_code == 200
    assert "<Connect" in response.text
    get_provider.assert_awaited_once_with(901, 900)
    provider_instance.verify_inbound_signature.assert_awaited_once()
    answer_preview.assert_awaited_once()
    preview_kwargs = answer_preview.await_args.kwargs
    assert preview_kwargs["provider_instance"] is provider_instance
    assert preview_kwargs["normalized_data"].call_id == "CA123"
    assert preview_kwargs["organization_id"] == 900
    assert preview_kwargs["telephony_configuration_id"] == 901
    assert preview_kwargs["from_phone_number_id"] == 902
    mock_db.get_workflow.assert_not_awaited()
