from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from api.services.phone_preview.privacy import encrypt_phone
from api.services.phone_preview.service import PhonePreviewService


@pytest.mark.asyncio
async def test_start_creates_pending_verification_with_kr_normalization(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    created_session = SimpleNamespace(
        id=123,
        status="pending_verification",
        phone_number_masked="+82****5678",
        expires_at=expires_at,
        workflow_run_id=None,
        provider_call_id=None,
        failure_reason=None,
    )

    with patch("api.services.phone_preview.service.db_client") as mock_db:
        mock_db.get_workflow = AsyncMock(
            return_value=SimpleNamespace(id=33, user_id=99, organization_id=11)
        )
        mock_db.get_recent_verified_phone_preview_verification = AsyncMock(
            return_value=None
        )
        mock_db.create_phone_preview_verification = AsyncMock(
            return_value=SimpleNamespace(id=55)
        )
        mock_db.create_phone_preview_session = AsyncMock(return_value=created_session)

        result = await service.start(
            user=user, workflow_id=33, phone_number="010-1234-5678"
        )

    assert result.session_id == 123
    assert result.status == "pending_verification"
    assert result.otp_required is True
    assert result.dev_otp_code and result.dev_otp_code.isdigit()
    create_session_kwargs = mock_db.create_phone_preview_session.await_args.kwargs
    assert create_session_kwargs["phone_number_masked"] == "+82****5678"
    assert create_session_kwargs["status"] == "pending_verification"


@pytest.mark.asyncio
async def test_call_after_verification_uses_system_provider_and_preview_markers(
    monkeypatch,
):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("RECOVA_PREVIEW_TELEPHONY_ORGANIZATION_ID", "900")
    monkeypatch.setenv("RECOVA_PREVIEW_TELEPHONY_CONFIGURATION_ID", "901")
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    encrypted_phone = encrypt_phone("+821012345678")
    session = SimpleNamespace(
        id=123,
        organization_id=11,
        user_id=7,
        workflow_id=33,
        workflow_run_id=None,
        status="verified",
        phone_number_hash="hash",
        phone_number_masked="+82****5678",
        destination_phone_encrypted=encrypted_phone,
        display_name="Tester",
        max_duration_seconds=300,
        expires_at=expires_at,
        provider_call_id=None,
        failure_reason=None,
    )
    provider = SimpleNamespace(
        PROVIDER_NAME="twilio",
        WEBHOOK_ENDPOINT="twilio/voice",
        validate_config=Mock(return_value=True),
        initiate_call=AsyncMock(
            return_value=SimpleNamespace(
                call_id="call-123",
                caller_number="+82200000000",
                provider_metadata={"call_id": "call-123"},
            )
        ),
    )

    async def create_run(*args, **kwargs):
        return SimpleNamespace(id=501, name=args[0], initial_context=kwargs["initial_context"])

    attached_session = SimpleNamespace(
        **{
            **session.__dict__,
            "status": "calling",
            "workflow_run_id": 501,
            "provider": "twilio",
            "provider_call_id": "call-123",
        }
    )

    with (
        patch("api.services.phone_preview.service.db_client") as mock_db,
        patch(
            "api.services.phone_preview.service._get_preview_telephony_provider_by_id",
            new=AsyncMock(return_value=provider),
        ) as get_provider,
        patch(
            "api.services.phone_preview.service.check_dograh_quota_by_user_id",
            new=AsyncMock(
                return_value=SimpleNamespace(has_quota=True, error_message="")
            ),
        ),
        patch(
            "api.services.phone_preview.service.get_backend_endpoints",
            new=AsyncMock(return_value=("https://api.example.com", "wss://ignored")),
        ),
    ):
        mock_db.begin_phone_preview_call = AsyncMock(return_value=(session, True))
        mock_db.get_workflow = AsyncMock(
            return_value=SimpleNamespace(id=33, user_id=99, organization_id=11)
        )
        mock_db.get_draft_version = AsyncMock(
            return_value=SimpleNamespace(
                id=44, template_context_variables={"template_key": "template-value"}
            )
        )
        mock_db.count_phone_preview_sessions_since = AsyncMock(return_value=1)
        mock_db.create_workflow_run = AsyncMock(side_effect=create_run)
        mock_db.update_workflow_run = AsyncMock()
        mock_db.attach_phone_preview_call = AsyncMock(return_value=attached_session)

        result = await service.call(user=user, session_id=123)

    assert result.status == "calling"
    assert result.workflow_run_id == 501
    get_provider.assert_awaited_once_with(901, 900)
    create_kwargs = mock_db.create_workflow_run.await_args.kwargs
    assert create_kwargs["use_draft"] is True
    context = create_kwargs["initial_context"]
    assert context["telephony_preview"] is True
    assert context["preview_session_id"] == 123
    assert context["preview_user_id"] == 7
    assert context["telephony_configuration_id"] == 901
    assert context["telephony_configuration_organization_id"] == 900
    provider.initiate_call.assert_awaited_once()
    assert provider.initiate_call.await_args.kwargs["to_number"] == "+821012345678"
    mock_db.attach_phone_preview_call.assert_awaited_once()
    assert (
        mock_db.attach_phone_preview_call.await_args.kwargs[
            "clear_destination_phone"
        ]
        is True
    )


@pytest.mark.asyncio
async def test_status_marks_completed_run_and_clears_preview_destination():
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    session = SimpleNamespace(
        id=123,
        status="calling",
        phone_number_masked="+82****5678",
        expires_at=expires_at,
        workflow_run_id=501,
        provider_call_id="call-123",
        failure_reason=None,
    )
    completed_session = SimpleNamespace(**{**session.__dict__, "status": "completed"})

    with patch("api.services.phone_preview.service.db_client") as mock_db:
        mock_db.get_phone_preview_session = AsyncMock(return_value=session)
        mock_db.get_workflow_run = AsyncMock(return_value=SimpleNamespace(is_completed=True))
        mock_db.update_phone_preview_session_status = AsyncMock(
            return_value=completed_session
        )

        result = await service.status(user=user, session_id=123)

    assert result.status == "completed"
    mock_db.get_workflow_run.assert_awaited_once_with(501, organization_id=11)
    mock_db.update_phone_preview_session_status.assert_awaited_once_with(
        123, status="completed", completed=True
    )
