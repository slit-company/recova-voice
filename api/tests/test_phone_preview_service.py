from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException

from api.services.phone_preview.otp import generate_otp_salt, hash_otp_code
from api.services.phone_preview.otp_delivery import PhonePreviewOtpDeliveryError
from api.services.phone_preview.privacy import encrypt_phone, global_phone_hash
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
        mock_db.count_phone_preview_sessions_since = AsyncMock(return_value=0)
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
    assert len(create_session_kwargs["phone_number_hash"]) == 64
    assert len(create_session_kwargs["phone_number_global_hash"]) == 64
    assert (
        create_session_kwargs["phone_number_hash"]
        != create_session_kwargs["phone_number_global_hash"]
    )
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
        mock_db.count_phone_preview_sessions_since = AsyncMock(return_value=0)
        mock_db.create_phone_preview_verification = AsyncMock()
        mock_db.create_phone_preview_session = AsyncMock(return_value=created_session)

        result = await service.start(
            user=user, workflow_id=33, phone_number="010-1234-5678"
        )

    assert result.status == "verified"
    assert result.otp_required is False
    assert result.dev_otp_code is None
    mock_db.create_phone_preview_verification.assert_not_awaited()
    assert (
        mock_db.create_phone_preview_session.await_args.kwargs["verification_id"] == 55
    )


@pytest.mark.asyncio
async def test_start_rejects_non_pstn_phone_without_persisting(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)

    with patch("api.services.phone_preview.service.db_client") as mock_db:
        mock_db.get_workflow = AsyncMock(
            return_value=SimpleNamespace(id=33, user_id=99, organization_id=11)
        )
        mock_db.create_phone_preview_verification = AsyncMock()
        mock_db.create_phone_preview_session = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await service.start(
                user=user, workflow_id=33, phone_number="sip:attacker@example.com"
            )

    assert exc.value.status_code == 422
    assert exc.value.detail == "invalid_phone_number"
    mock_db.create_phone_preview_verification.assert_not_awaited()
    mock_db.create_phone_preview_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_start_rate_limits_before_otp_creation_or_delivery(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("RECOVA_PREVIEW_SECRET_KEY", "production-preview-secret")
    monkeypatch.setenv("RECOVA_PREVIEW_OTP_WEBHOOK_URL", "https://sms.example/send")
    monkeypatch.setenv("RECOVA_PREVIEW_DAILY_USER_CALL_LIMIT", "5")
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)

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
        mock_db.count_phone_preview_sessions_since = AsyncMock(side_effect=[5])
        mock_db.get_recent_verified_phone_preview_verification = AsyncMock()
        mock_db.create_phone_preview_verification = AsyncMock()
        mock_db.create_phone_preview_session = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await service.start(user=user, workflow_id=33, phone_number="010-1234-5678")

    assert exc.value.status_code == 429
    assert exc.value.detail == "preview_rate_limited"
    mock_db.get_recent_verified_phone_preview_verification.assert_not_awaited()
    mock_db.create_phone_preview_verification.assert_not_awaited()
    mock_db.create_phone_preview_session.assert_not_awaited()
    deliver_otp.assert_not_awaited()


@pytest.mark.asyncio
async def test_start_phone_limit_uses_global_hash_before_otp_creation(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("RECOVA_PREVIEW_SECRET_KEY", "production-preview-secret")
    monkeypatch.setenv("RECOVA_PREVIEW_OTP_WEBHOOK_URL", "https://sms.example/send")
    monkeypatch.setenv("RECOVA_PREVIEW_DAILY_PHONE_CALL_LIMIT", "5")
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)

    with patch("api.services.phone_preview.service.db_client") as mock_db:
        mock_db.get_workflow = AsyncMock(
            return_value=SimpleNamespace(id=33, user_id=99, organization_id=11)
        )
        mock_db.count_phone_preview_sessions_since = AsyncMock(side_effect=[0, 0, 5])
        mock_db.get_recent_verified_phone_preview_verification = AsyncMock()
        mock_db.create_phone_preview_verification = AsyncMock()
        mock_db.create_phone_preview_session = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await service.start(user=user, workflow_id=33, phone_number="010-1234-5678")

    assert exc.value.status_code == 429
    assert exc.value.detail == "preview_phone_rate_limited"
    phone_limit_call = mock_db.count_phone_preview_sessions_since.await_args_list[2]
    assert phone_limit_call.kwargs["phone_number_global_hash"] == global_phone_hash(
        "+821012345678"
    )
    assert "phone_number_hash" not in phone_limit_call.kwargs
    mock_db.create_phone_preview_verification.assert_not_awaited()
    mock_db.create_phone_preview_session.assert_not_awaited()


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
        mock_db.count_phone_preview_sessions_since = AsyncMock(return_value=0)
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
        mock_db.count_phone_preview_sessions_since = AsyncMock(return_value=0)
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
                side_effect=PhonePreviewOtpDeliveryError("otp_delivery_not_configured")
            ),
        ),
    ):
        mock_db.get_workflow = AsyncMock(
            return_value=SimpleNamespace(id=33, user_id=99, organization_id=11)
        )
        mock_db.get_recent_verified_phone_preview_verification = AsyncMock(
            return_value=None
        )
        mock_db.count_phone_preview_sessions_since = AsyncMock(return_value=0)
        mock_db.create_phone_preview_verification = AsyncMock(
            return_value=SimpleNamespace(id=55)
        )
        mock_db.create_phone_preview_session = AsyncMock(return_value=created_session)
        mock_db.set_phone_preview_verification_status = AsyncMock()
        mock_db.update_phone_preview_session_status = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await service.start(user=user, workflow_id=33, phone_number="010-1234-5678")

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
async def test_verify_expires_stale_verified_session(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)
    expired_at = datetime.now(UTC) - timedelta(seconds=1)
    session = SimpleNamespace(
        id=123,
        status="verified",
        verification_id=55,
        phone_number_hash="hash",
        phone_number_masked="+82****5678",
        expires_at=expired_at,
        workflow_run_id=None,
        provider_call_id=None,
        failure_reason=None,
    )
    expired_session = SimpleNamespace(
        **{
            **session.__dict__,
            "status": "expired",
            "failure_reason": "expired",
        }
    )

    with patch("api.services.phone_preview.service.db_client") as mock_db:
        mock_db.get_phone_preview_session = AsyncMock(return_value=session)
        mock_db.update_phone_preview_session_status = AsyncMock(
            return_value=expired_session
        )
        mock_db.get_phone_preview_verification = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await service.verify(user=user, session_id=123, otp_code="123456")

    assert exc.value.status_code == 400
    assert exc.value.detail == "expired"
    mock_db.update_phone_preview_session_status.assert_awaited_once_with(
        123, status="expired", failure_reason="expired"
    )
    mock_db.get_phone_preview_verification.assert_not_awaited()


@pytest.mark.asyncio
async def test_status_expires_stale_pending_session(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)
    expired_at = datetime.now(UTC) - timedelta(seconds=1)
    session = SimpleNamespace(
        id=123,
        status="pending_verification",
        verification_id=55,
        phone_number_hash="hash",
        phone_number_masked="+82****5678",
        expires_at=expired_at,
        workflow_run_id=None,
        provider_call_id=None,
        failure_reason=None,
    )
    expired_session = SimpleNamespace(
        **{
            **session.__dict__,
            "status": "expired",
            "failure_reason": "expired",
        }
    )

    with patch("api.services.phone_preview.service.db_client") as mock_db:
        mock_db.get_phone_preview_session = AsyncMock(return_value=session)
        mock_db.update_phone_preview_session_status = AsyncMock(
            return_value=expired_session
        )
        mock_db.get_workflow_run = AsyncMock()

        result = await service.status(user=user, session_id=123)

    assert result.status == "expired"
    assert result.otp_required is False
    assert result.failure_reason == "expired"
    mock_db.update_phone_preview_session_status.assert_awaited_once_with(
        123, status="expired", failure_reason="expired"
    )
    mock_db.get_workflow_run.assert_not_awaited()


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
        phone_number_global_hash="global-hash",
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
        return SimpleNamespace(
            id=501, name=args[0], initial_context=kwargs["initial_context"]
        )

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
    assert context["phone_number"] == "+82****5678"
    assert context["called_number"] == "+82****5678"
    assert context["phone_number_masked"] == "+82****5678"
    assert "provider" not in context
    assert "preview_user_id" not in context
    assert "telephony_configuration_id" not in context
    assert "telephony_configuration_organization_id" not in context
    assert "+821012345678" not in str(context)
    update_kwargs = mock_db.update_workflow_run.await_args.kwargs
    assert "+821012345678" not in str(update_kwargs)
    assert "+82200000000" not in str(update_kwargs)
    assert update_kwargs["gathered_context"]["To"] == "[redacted]"
    assert update_kwargs["gathered_context"]["nested"]["phone_number"] == "[redacted]"
    assert update_kwargs["initial_context"]["caller_number_masked"] == "+82****0000"
    assert "caller_number" not in update_kwargs["initial_context"]
    assert "telephony_configuration_id" not in update_kwargs["initial_context"]
    assert (
        "telephony_configuration_organization_id"
        not in update_kwargs["initial_context"]
    )
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
async def test_aws_connect_preview_requires_configured_source_number(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("RECOVA_PREVIEW_TELEPHONY_ORGANIZATION_ID", "900")
    monkeypatch.setenv("RECOVA_PREVIEW_TELEPHONY_CONFIGURATION_ID", "901")
    monkeypatch.delenv("RECOVA_PREVIEW_FROM_PHONE_NUMBER_ID", raising=False)
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    session = SimpleNamespace(
        id=123,
        organization_id=11,
        user_id=7,
        workflow_id=33,
        workflow_run_id=None,
        status="verified",
        phone_number_hash="hash",
        phone_number_global_hash="global-hash",
        phone_number_masked="+82****5678",
        destination_phone_encrypted=encrypt_phone("+821012345678"),
        display_name=None,
        max_duration_seconds=300,
        expires_at=expires_at,
        provider_call_id=None,
        failure_reason=None,
    )
    provider = SimpleNamespace(
        PROVIDER_NAME="aws_connect",
        WEBHOOK_ENDPOINT=None,
        validate_config=Mock(return_value=True),
        get_available_phone_numbers=AsyncMock(return_value=["+827040223234"]),
        initiate_call=AsyncMock(),
    )

    with (
        patch("api.services.phone_preview.service.db_client") as mock_db,
        patch(
            "api.services.phone_preview.service._get_preview_telephony_provider_by_id",
            new=AsyncMock(return_value=provider),
        ),
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
        mock_db.count_phone_preview_sessions_since = AsyncMock(return_value=1)
        mock_db.create_workflow_run = AsyncMock()
        mock_db.update_phone_preview_session_status = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await service.call(user=user, session_id=123)

    assert exc.value.status_code == 400
    assert exc.value.detail == "preview_from_phone_number_required"
    provider.get_available_phone_numbers.assert_not_awaited()
    provider.initiate_call.assert_not_awaited()
    mock_db.create_workflow_run.assert_not_awaited()
    mock_db.update_phone_preview_session_status.assert_awaited_once_with(
        123,
        status="failed",
        failure_reason="preview_from_phone_number_required",
    )


@pytest.mark.asyncio
async def test_call_provider_error_returns_generic_preview_failure(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("RECOVA_PREVIEW_TELEPHONY_ORGANIZATION_ID", "900")
    monkeypatch.setenv("RECOVA_PREVIEW_TELEPHONY_CONFIGURATION_ID", "901")
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)
    raw_to = "+821012345678"
    raw_provider_detail = (
        '{"message":"failed","to":"+821012345678","account_sid":"ACSECRET"}'
    )
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    session = SimpleNamespace(
        id=123,
        organization_id=11,
        user_id=7,
        workflow_id=33,
        workflow_run_id=None,
        status="verified",
        phone_number_hash="hash",
        phone_number_global_hash="global-hash",
        phone_number_masked="+82****5678",
        destination_phone_encrypted=encrypt_phone(raw_to),
        display_name=None,
        max_duration_seconds=300,
        expires_at=expires_at,
        provider_call_id=None,
        failure_reason=None,
    )
    attached_session = SimpleNamespace(
        **{
            **session.__dict__,
            "status": "calling",
            "workflow_run_id": 501,
            "provider": "twilio",
        }
    )
    provider = SimpleNamespace(
        PROVIDER_NAME="twilio",
        WEBHOOK_ENDPOINT="twilio/voice",
        validate_config=Mock(return_value=True),
        initiate_call=AsyncMock(
            side_effect=HTTPException(status_code=400, detail=raw_provider_detail)
        ),
    )

    async def create_run(*args, **kwargs):
        return SimpleNamespace(
            id=501, name=args[0], initial_context=kwargs["initial_context"]
        )

    with (
        patch("api.services.phone_preview.service.db_client") as mock_db,
        patch(
            "api.services.phone_preview.service._get_preview_telephony_provider_by_id",
            new=AsyncMock(return_value=provider),
        ),
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
            return_value=SimpleNamespace(id=44, template_context_variables={})
        )
        mock_db.count_phone_preview_sessions_since = AsyncMock(return_value=1)
        mock_db.create_workflow_run = AsyncMock(side_effect=create_run)
        mock_db.attach_phone_preview_call = AsyncMock(return_value=attached_session)
        mock_db.update_phone_preview_session_status = AsyncMock()
        mock_db.update_workflow_run = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await service.call(user=user, session_id=123)

    assert exc.value.status_code == 502
    assert exc.value.detail == "preview_call_failed"
    mock_db.update_phone_preview_session_status.assert_awaited_once_with(
        123, status="failed", failure_reason="preview_call_failed"
    )
    assert raw_to not in str(mock_db.update_phone_preview_session_status.await_args)
    assert "ACSECRET" not in str(mock_db.update_phone_preview_session_status.await_args)
    mock_db.update_workflow_run.assert_not_awaited()
    assert (
        mock_db.attach_phone_preview_call.await_args.kwargs["clear_destination_phone"]
        is True
    )


@pytest.mark.asyncio
async def test_call_generic_provider_exception_returns_generic_failure(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("RECOVA_PREVIEW_TELEPHONY_ORGANIZATION_ID", "900")
    monkeypatch.setenv("RECOVA_PREVIEW_TELEPHONY_CONFIGURATION_ID", "901")
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)
    raw_to = "+821012345678"
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    session = SimpleNamespace(
        id=123,
        organization_id=11,
        user_id=7,
        workflow_id=33,
        workflow_run_id=None,
        status="verified",
        phone_number_hash="hash",
        phone_number_global_hash="global-hash",
        phone_number_masked="+82****5678",
        destination_phone_encrypted=encrypt_phone(raw_to),
        display_name=None,
        max_duration_seconds=300,
        expires_at=expires_at,
        provider_call_id=None,
        failure_reason=None,
    )
    attached_session = SimpleNamespace(
        **{
            **session.__dict__,
            "status": "calling",
            "workflow_run_id": 501,
            "provider": "twilio",
        }
    )
    provider = SimpleNamespace(
        PROVIDER_NAME="twilio",
        WEBHOOK_ENDPOINT="twilio/voice",
        validate_config=Mock(return_value=True),
        initiate_call=AsyncMock(side_effect=RuntimeError("raw +821012345678 ACSECRET")),
    )

    async def create_run(*args, **kwargs):
        return SimpleNamespace(
            id=501, name=args[0], initial_context=kwargs["initial_context"]
        )

    with (
        patch("api.services.phone_preview.service.db_client") as mock_db,
        patch(
            "api.services.phone_preview.service._get_preview_telephony_provider_by_id",
            new=AsyncMock(return_value=provider),
        ),
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
            return_value=SimpleNamespace(id=44, template_context_variables={})
        )
        mock_db.count_phone_preview_sessions_since = AsyncMock(return_value=1)
        mock_db.create_workflow_run = AsyncMock(side_effect=create_run)
        mock_db.attach_phone_preview_call = AsyncMock(return_value=attached_session)
        mock_db.update_phone_preview_session_status = AsyncMock()
        mock_db.update_workflow_run = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await service.call(user=user, session_id=123)

    assert exc.value.status_code == 500
    assert exc.value.detail == "call_failed"
    mock_db.update_phone_preview_session_status.assert_awaited_once_with(
        123, status="failed", failure_reason="call_failed"
    )
    assert raw_to not in str(mock_db.update_phone_preview_session_status.await_args)
    assert "ACSECRET" not in str(mock_db.update_phone_preview_session_status.await_args)


@pytest.mark.asyncio
async def test_call_expired_reserved_session_does_not_dispatch_provider(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("RECOVA_PREVIEW_TELEPHONY_ORGANIZATION_ID", "900")
    monkeypatch.setenv("RECOVA_PREVIEW_TELEPHONY_CONFIGURATION_ID", "901")
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)
    session = SimpleNamespace(
        id=123,
        status="expired",
        phone_number_masked="+82****5678",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
        workflow_run_id=None,
        provider_call_id=None,
        failure_reason="expired",
    )

    with (
        patch("api.services.phone_preview.service.db_client") as mock_db,
        patch(
            "api.services.phone_preview.service._get_preview_telephony_provider_by_id",
            new=AsyncMock(),
        ) as get_provider,
    ):
        mock_db.begin_phone_preview_call = AsyncMock(return_value=(session, False))

        with pytest.raises(HTTPException) as exc:
            await service.call(user=user, session_id=123)

    assert exc.value.status_code == 400
    assert exc.value.detail == "expired"
    get_provider.assert_not_awaited()


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
        phone_number_global_hash="global-hash",
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
async def test_call_rate_limits_destination_with_global_hash(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("RECOVA_PREVIEW_TELEPHONY_ORGANIZATION_ID", "900")
    monkeypatch.setenv("RECOVA_PREVIEW_TELEPHONY_CONFIGURATION_ID", "901")
    monkeypatch.setenv("RECOVA_PREVIEW_DAILY_PHONE_CALL_LIMIT", "5")
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    session = SimpleNamespace(
        id=123,
        organization_id=11,
        user_id=7,
        workflow_id=33,
        workflow_run_id=None,
        status="verified",
        phone_number_hash="scoped-hash",
        phone_number_global_hash="global-hash",
        phone_number_masked="+82****5678",
        destination_phone_encrypted=encrypt_phone("+821012345678"),
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
        mock_db.count_phone_preview_sessions_since = AsyncMock(side_effect=[1, 1, 6])
        mock_db.update_phone_preview_session_status = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await service.call(user=user, session_id=123)

    assert exc.value.status_code == 429
    assert exc.value.detail == "preview_phone_rate_limited"
    phone_limit_call = mock_db.count_phone_preview_sessions_since.await_args_list[2]
    assert phone_limit_call.kwargs["phone_number_global_hash"] == "global-hash"
    assert "phone_number_hash" not in phone_limit_call.kwargs
    get_provider.assert_not_awaited()
    mock_db.update_phone_preview_session_status.assert_awaited_once_with(
        123, status="failed", failure_reason="preview_phone_rate_limited"
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
        mock_db.get_workflow_run = AsyncMock(
            return_value=SimpleNamespace(is_completed=True)
        )
        mock_db.update_phone_preview_session_status = AsyncMock(
            return_value=completed_session
        )

        result = await service.status(user=user, session_id=123)

    assert result.status == "completed"
    mock_db.get_workflow_run.assert_awaited_once_with(501, organization_id=11)
    mock_db.update_phone_preview_session_status.assert_awaited_once_with(
        123, status="completed", completed=True
    )


@pytest.mark.asyncio
async def test_status_polls_aws_connect_preview_call_until_terminal():
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    session = SimpleNamespace(
        id=123,
        status="calling",
        provider="aws_connect",
        phone_number_masked="+82****5678",
        expires_at=expires_at,
        workflow_run_id=501,
        provider_call_id="contact-123",
        failure_reason=None,
    )
    completed_session = SimpleNamespace(**{**session.__dict__, "status": "completed"})
    workflow_run = SimpleNamespace(
        id=501,
        is_completed=False,
        initial_context={"telephony_preview": True, "preview_session_id": 123},
    )
    provider = SimpleNamespace(
        get_call_status=AsyncMock(
            return_value={
                "status": "completed",
                "disconnect_reason": "CONTACT_FLOW_DISCONNECT",
            }
        )
    )

    with (
        patch("api.services.phone_preview.service.db_client") as mock_db,
        patch(
            "api.services.telephony.factory.get_telephony_provider_for_run",
            new=AsyncMock(return_value=provider),
        ) as get_provider,
    ):
        mock_db.get_phone_preview_session = AsyncMock(return_value=session)
        mock_db.get_workflow_run = AsyncMock(return_value=workflow_run)
        mock_db.update_workflow_run = AsyncMock(return_value=workflow_run)
        mock_db.update_phone_preview_session_status = AsyncMock(
            return_value=completed_session
        )

        result = await service.status(user=user, session_id=123)

    assert result.status == "completed"
    get_provider.assert_awaited_once_with(workflow_run, 11)
    provider.get_call_status.assert_awaited_once_with("contact-123")
    mock_db.update_workflow_run.assert_awaited_once_with(
        run_id=501,
        is_completed=True,
        gathered_context={
            "provider_status": "completed",
            "provider_disconnect_reason": "CONTACT_FLOW_DISCONNECT",
        },
    )
    mock_db.update_phone_preview_session_status.assert_awaited_once_with(
        123, status="completed", failure_reason=None, completed=True
    )


@pytest.mark.asyncio
async def test_status_marks_aws_connect_poll_failure_failed():
    service = PhonePreviewService()
    user = SimpleNamespace(id=7, selected_organization_id=11)
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    session = SimpleNamespace(
        id=123,
        status="calling",
        provider="aws_connect",
        phone_number_masked="+82****5678",
        expires_at=expires_at,
        workflow_run_id=501,
        provider_call_id="contact-123",
        failure_reason=None,
    )
    failed_session = SimpleNamespace(
        **{
            **session.__dict__,
            "status": "failed",
            "failure_reason": "aws_connect_status_unavailable",
        }
    )
    workflow_run = SimpleNamespace(
        id=501,
        is_completed=False,
        initial_context={"telephony_preview": True, "preview_session_id": 123},
    )

    with (
        patch("api.services.phone_preview.service.db_client") as mock_db,
        patch(
            "api.services.telephony.factory.get_telephony_provider_for_run",
            new=AsyncMock(side_effect=ValueError("missing provider")),
        ),
    ):
        mock_db.get_phone_preview_session = AsyncMock(return_value=session)
        mock_db.get_workflow_run = AsyncMock(return_value=workflow_run)
        mock_db.update_workflow_run = AsyncMock(return_value=workflow_run)
        mock_db.update_phone_preview_session_status = AsyncMock(
            return_value=failed_session
        )

        result = await service.status(user=user, session_id=123)

    assert result.status == "failed"
    assert result.failure_reason == "aws_connect_status_unavailable"
    mock_db.update_workflow_run.assert_awaited_once_with(
        run_id=501,
        is_completed=True,
        gathered_context={
            "provider_status": "failed",
            "provider_error": "aws_connect_status_unavailable",
        },
    )
    mock_db.update_phone_preview_session_status.assert_awaited_once_with(
        123,
        status="failed",
        failure_reason="aws_connect_status_unavailable",
    )
