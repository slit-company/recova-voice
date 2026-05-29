from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException

from api.services.phone_preview.otp import generate_otp_salt, hash_otp_code
from api.services.phone_preview.otp_delivery import PhonePreviewOtpDeliveryError
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
async def test_start_reuses_recent_verified_phone_without_new_otp(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)
    expires_at = datetime.now(UTC) + timedelta(minutes=15)
    verified = SimpleNamespace(id=55)
    created_session = SimpleNamespace(
        id=123,
        status="verified",
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
            return_value=verified
        )
        mock_db.create_phone_preview_verification = AsyncMock()
        mock_db.create_phone_preview_session = AsyncMock(return_value=created_session)

        result = await service.start(
            user=user, workflow_id=33, phone_number="010-1234-5678"
        )

    assert result.status == "verified"
    assert result.otp_required is False
    assert result.dev_otp_code is None
    mock_db.create_phone_preview_verification.assert_not_awaited()
    assert mock_db.create_phone_preview_session.await_args.kwargs["verification_id"] == 55


@pytest.mark.asyncio
async def test_start_delivers_otp_in_production_without_exposing_code(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("RECOVA_PREVIEW_SECRET_KEY", "production-preview-secret")
    monkeypatch.setenv("RECOVA_PREVIEW_OTP_WEBHOOK_URL", "https://sms.example/send")
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

    with (
        patch("api.services.phone_preview.service.db_client") as mock_db,
        patch(
            "api.services.phone_preview.service.deliver_otp_code",
            new=AsyncMock(),
        ) as deliver_otp,
    ):
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

    assert result.otp_required is True
    assert result.dev_otp_code is None
    deliver_otp.assert_awaited_once()
    assert deliver_otp.await_args.kwargs["phone_number"] == "+821012345678"
    assert deliver_otp.await_args.kwargs["masked_phone"] == "+82****5678"
    assert deliver_otp.await_args.kwargs["code"].isdigit()


@pytest.mark.asyncio
async def test_start_ignores_dev_otp_override_in_production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("RECOVA_PREVIEW_SECRET_KEY", "production-preview-secret")
    monkeypatch.setenv("RECOVA_PREVIEW_EXPOSE_DEV_OTP", "true")
    monkeypatch.setenv("RECOVA_PREVIEW_OTP_WEBHOOK_URL", "https://sms.example/send")
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

    with (
        patch("api.services.phone_preview.service.db_client") as mock_db,
        patch(
            "api.services.phone_preview.service.deliver_otp_code",
            new=AsyncMock(),
        ) as deliver_otp,
    ):
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

    assert result.otp_required is True
    assert result.dev_otp_code is None
    deliver_otp.assert_awaited_once()


@pytest.mark.asyncio
async def test_start_fails_closed_when_production_otp_delivery_fails(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("RECOVA_PREVIEW_SECRET_KEY", "production-preview-secret")
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

    with (
        patch("api.services.phone_preview.service.db_client") as mock_db,
        patch(
            "api.services.phone_preview.service.deliver_otp_code",
            new=AsyncMock(
                side_effect=PhonePreviewOtpDeliveryError(
                    "otp_delivery_not_configured"
                )
            ),
        ),
    ):
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
        mock_db.set_phone_preview_verification_status = AsyncMock()
        mock_db.update_phone_preview_session_status = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await service.start(
                user=user, workflow_id=33, phone_number="010-1234-5678"
            )

    assert exc.value.status_code == 503
    assert exc.value.detail == "otp_delivery_failed"
    mock_db.set_phone_preview_verification_status.assert_awaited_once_with(
        55, status="delivery_failed"
    )
    mock_db.update_phone_preview_session_status.assert_awaited_once_with(
        123, status="failed", failure_reason="otp_delivery_not_configured"
    )


@pytest.mark.asyncio
async def test_verify_locks_after_max_otp_attempts(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("RECOVA_PREVIEW_MAX_OTP_ATTEMPTS", "2")
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    session = SimpleNamespace(
        id=123,
        status="pending_verification",
        verification_id=55,
        phone_number_hash="hash",
        phone_number_masked="+82****5678",
        expires_at=expires_at,
        workflow_run_id=None,
        provider_call_id=None,
        failure_reason=None,
    )
    salt = generate_otp_salt()
    verification = SimpleNamespace(
        id=55,
        organization_id=11,
        user_id=7,
        phone_number_hash="hash",
        status="pending",
        expires_at=expires_at,
        attempts=1,
        code_salt=salt,
        code_hash=hash_otp_code("123456", salt),
    )

    with patch("api.services.phone_preview.service.db_client") as mock_db:
        mock_db.get_phone_preview_session = AsyncMock(return_value=session)
        mock_db.get_phone_preview_verification = AsyncMock(return_value=verification)
        mock_db.increment_phone_preview_verification_attempts = AsyncMock()
        mock_db.update_phone_preview_session_status = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await service.verify(user=user, session_id=123, otp_code="000000")

    assert exc.value.status_code == 400
    assert exc.value.detail == "otp_invalid"
    mock_db.increment_phone_preview_verification_attempts.assert_awaited_once_with(
        55, status="locked"
    )
    mock_db.update_phone_preview_session_status.assert_awaited_once_with(
        123, status="failed", failure_reason="otp_locked"
    )


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
    events: list[str] = []

    async def initiate_call(**kwargs):
        events.append("provider_dispatch")
        return SimpleNamespace(
            call_id="call-123",
            caller_number="+82200000000",
            provider_metadata={
                "call_id": "call-123",
                "To": "+821012345678",
                "From": "+82200000000",
                "nested": {"phone_number": "+821012345678"},
            },
        )

    provider = SimpleNamespace(
        PROVIDER_NAME="twilio",
        WEBHOOK_ENDPOINT="twilio/voice",
        validate_config=Mock(return_value=True),
        initiate_call=AsyncMock(side_effect=initiate_call),
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

    async def attach_call(*args, **kwargs):
        events.append("attach")
        return attached_session

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
        mock_db.attach_phone_preview_call = AsyncMock(side_effect=attach_call)

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
    assert context["phone_number"] == "+82****5678"
    assert context["called_number"] == "+82****5678"
    assert context["phone_number_masked"] == "+82****5678"
    assert context["telephony_configuration_id"] == 901
    assert context["telephony_configuration_organization_id"] == 900
    assert "+821012345678" not in str(context)
    update_kwargs = mock_db.update_workflow_run.await_args.kwargs
    assert "+821012345678" not in str(update_kwargs)
    assert "+82200000000" not in str(update_kwargs)
    assert update_kwargs["gathered_context"]["To"] == "[redacted]"
    assert update_kwargs["gathered_context"]["nested"]["phone_number"] == "[redacted]"
    assert update_kwargs["initial_context"]["caller_number_masked"] == "+82****0000"
    assert "caller_number" not in update_kwargs["initial_context"]
    provider.initiate_call.assert_awaited_once()
    assert provider.initiate_call.await_args.kwargs["to_number"] == "+821012345678"
    assert events == ["attach", "provider_dispatch", "attach"]
    assert mock_db.attach_phone_preview_call.await_count == 2
    assert (
        mock_db.attach_phone_preview_call.await_args_list[0].kwargs[
            "clear_destination_phone"
        ]
        is True
    )


@pytest.mark.asyncio
async def test_call_is_idempotent_after_session_is_already_calling(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("RECOVA_PREVIEW_TELEPHONY_ORGANIZATION_ID", "900")
    monkeypatch.setenv("RECOVA_PREVIEW_TELEPHONY_CONFIGURATION_ID", "901")
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

    with patch("api.services.phone_preview.service.db_client") as mock_db:
        mock_db.begin_phone_preview_call = AsyncMock(return_value=(session, False))
        mock_db.create_workflow_run = AsyncMock()

        result = await service.call(user=user, session_id=123)

    assert result.status == "calling"
    assert result.workflow_run_id == 501
    assert result.provider_call_id == "call-123"
    mock_db.create_workflow_run.assert_not_awaited()


@pytest.mark.asyncio
async def test_call_rate_limits_user_before_provider_dispatch(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("RECOVA_PREVIEW_TELEPHONY_ORGANIZATION_ID", "900")
    monkeypatch.setenv("RECOVA_PREVIEW_TELEPHONY_CONFIGURATION_ID", "901")
    monkeypatch.setenv("RECOVA_PREVIEW_DAILY_USER_CALL_LIMIT", "5")
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
        display_name=None,
        max_duration_seconds=300,
        expires_at=expires_at,
        provider_call_id=None,
        failure_reason=None,
    )

    with (
        patch("api.services.phone_preview.service.db_client") as mock_db,
        patch(
            "api.services.phone_preview.service._get_preview_telephony_provider_by_id",
            new=AsyncMock(),
        ) as get_provider,
        patch(
            "api.services.phone_preview.service.check_dograh_quota_by_user_id",
            new=AsyncMock(
                return_value=SimpleNamespace(has_quota=True, error_message="")
            ),
        ),
    ):
        mock_db.begin_phone_preview_call = AsyncMock(return_value=(session, True))
        mock_db.get_workflow = AsyncMock(
            return_value=SimpleNamespace(id=33, user_id=99, organization_id=11)
        )
        mock_db.get_draft_version = AsyncMock(
            return_value=SimpleNamespace(id=44, template_context_variables={})
        )
        mock_db.count_phone_preview_sessions_since = AsyncMock(side_effect=[6, 1])
        mock_db.update_phone_preview_session_status = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await service.call(user=user, session_id=123)

    assert exc.value.status_code == 429
    assert exc.value.detail == "preview_rate_limited"
    get_provider.assert_not_awaited()
    mock_db.update_phone_preview_session_status.assert_awaited_once_with(
        123, status="failed", failure_reason="preview_rate_limited"
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
