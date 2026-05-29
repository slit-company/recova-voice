from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from api.db.models import (
    OrganizationModel,
    PhonePreviewSessionModel,
    PhonePreviewVerificationModel,
    TelephonyPhoneNumberModel,
    UserModel,
    WorkflowModel,
)
from api.db.phone_preview_client import PhonePreviewClient
from api.services.phone_preview.config import get_preview_telephony_settings
from api.services.phone_preview.privacy import (
    global_phone_hash,
    phone_hash,
    sanitize_preview_workflow_run_logs,
    sanitize_preview_workflow_run_contexts,
)
from api.utils.phone_security import (
    build_stored_phone_number,
    generate_otp_code,
    hash_otp_code,
    hash_phone_number,
    mask_phone_number,
    normalize_kr_phone_number,
    verify_otp_code,
)
from api.utils.telephony_address import normalize_telephony_address


def test_kr_phone_normalization_supports_local_mobile_numbers():
    normalized = normalize_telephony_address("010-1234-5678", country_hint="KR")

    assert normalized.canonical == "+821012345678"
    assert normalized.address_type == "pstn"
    assert normalized.country_code == "KR"
    assert normalize_kr_phone_number("01012345678") == "+821012345678"


def test_phone_mask_and_hash_are_safe_for_preview_storage(monkeypatch):
    monkeypatch.setenv("PHONE_HASH_SECRET", "unit-test-phone-secret")
    monkeypatch.delenv("PHONE_RAW_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("PREVIEW_PHONE_ENCRYPTION_KEY", raising=False)

    stored = build_stored_phone_number("010-1234-5678", country_code="KR")

    assert stored.normalized == "+821012345678"
    assert stored.masked == "+82******5678"
    assert stored.lookup_hash == hash_phone_number("+821012345678")
    assert stored.lookup_hash != "+821012345678"
    assert stored.encrypted_raw is None
    assert mask_phone_number("+15551234567") == "+1******4567"


def test_otp_hash_verification_rejects_plaintext_and_wrong_codes():
    otp_code = generate_otp_code()
    otp_hash = hash_otp_code(otp_code)

    assert otp_code not in otp_hash
    assert verify_otp_code(otp_code, otp_hash)
    assert not verify_otp_code("000000" if otp_code != "000000" else "111111", otp_hash)
    assert not verify_otp_code("not-digits", otp_hash)


def test_preview_and_phone_models_include_security_columns():
    phone_columns = TelephonyPhoneNumberModel.__table__.columns
    preview_columns = PhonePreviewSessionModel.__table__.columns
    verification_columns = PhonePreviewVerificationModel.__table__.columns

    assert "address_masked" in phone_columns
    assert "address_hash" in phone_columns
    assert "address_encrypted_raw" in phone_columns

    assert "phone_number_masked" in preview_columns
    assert "phone_number_hash" in preview_columns
    assert "phone_number_global_hash" in preview_columns
    assert "destination_phone_encrypted" in preview_columns
    assert "verification_id" in preview_columns
    assert "expires_at" in preview_columns
    assert "completed_at" in preview_columns

    assert "code_hash" in verification_columns
    assert "code_salt" in verification_columns
    assert "expires_at" in verification_columns
    assert "attempts" in verification_columns
    assert "verified_at" in verification_columns


def test_phone_preview_client_exposes_retention_helpers():
    assert hasattr(PhonePreviewClient, "expire_phone_preview_records")
    assert hasattr(PhonePreviewClient, "purge_phone_preview_records_before")


def test_preview_zero_limits_are_preserved_for_operational_kill_switch(monkeypatch):
    monkeypatch.setenv("RECOVA_PREVIEW_DAILY_USER_CALL_LIMIT", "0")
    monkeypatch.setenv("RECOVA_PREVIEW_DAILY_ORG_CALL_LIMIT", "0")
    monkeypatch.setenv("RECOVA_PREVIEW_DAILY_PHONE_CALL_LIMIT", "0")
    monkeypatch.setenv("RECOVA_PREVIEW_OTP_DELIVERY_TIMEOUT_SECONDS", "0")

    settings = get_preview_telephony_settings()

    assert settings.daily_user_call_limit == 0
    assert settings.daily_org_call_limit == 0
    assert settings.daily_phone_call_limit == 0
    assert settings.otp_delivery_timeout_seconds == 0


def test_preview_global_phone_hash_is_cross_account_for_abuse_limits(monkeypatch):
    monkeypatch.setenv("RECOVA_PREVIEW_SECRET_KEY", "unit-test-preview-secret")
    e164 = "+821012345678"

    assert global_phone_hash(e164) == global_phone_hash(e164)
    assert global_phone_hash(e164) != e164
    assert phone_hash(e164, organization_id=1, user_id=1) != phone_hash(
        e164,
        organization_id=1,
        user_id=2,
    )
    assert global_phone_hash(e164) != phone_hash(e164, organization_id=1, user_id=1)


def test_preview_workflow_context_sanitizer_removes_provider_internals():
    initial_context, gathered_context = sanitize_preview_workflow_run_contexts(
        {
            "telephony_preview": True,
            "preview_session_id": 123,
            "provider": "twilio",
            "telephony_configuration_id": 901,
            "telephony_configuration_organization_id": 900,
            "preview_user_id": 7,
            "phone_number": "+82****5678",
        },
        {
            "provider": "twilio",
            "call_id": "CA123",
            "nested": {"provider_call_id": "CA123", "safe": "ok"},
        },
    )

    assert initial_context == {
        "telephony_preview": True,
        "preview_session_id": 123,
        "phone_number": "+82****5678",
    }
    assert gathered_context == {"nested": {"safe": "ok"}}


def test_preview_workflow_log_sanitizer_removes_provider_internals():
    logs = sanitize_preview_workflow_run_logs(
        {"telephony_preview": True, "preview_session_id": 123},
        {},
        {
            "telephony_status_callbacks": [
                {
                    "status": "ringing",
                    "timestamp": "2026-05-22T10:30:00+00:00",
                    "duration": "0",
                    "call_id": "CA123",
                    "CallSid": "CA123",
                    "account_sid": "ACSECRET",
                    "To": "+821012345678",
                    "nested": {"provider_call_id": "CA123", "safe": "ok"},
                }
            ]
        },
    )

    entry = logs["telephony_status_callbacks"][0]
    assert entry == {
        "status": "ringing",
        "timestamp": "2026-05-22T10:30:00+00:00",
        "duration": "0",
        "nested": {"safe": "ok"},
    }


@pytest.mark.asyncio
async def test_begin_phone_preview_call_expires_stale_verified_session(
    db_session,
    async_session,
):
    suffix = uuid4().hex
    org = OrganizationModel(provider_id=f"org-{suffix}")
    async_session.add(org)
    await async_session.flush()
    user = UserModel(provider_id=f"user-{suffix}", selected_organization_id=org.id)
    async_session.add(user)
    await async_session.flush()
    workflow = WorkflowModel(
        name="Preview workflow",
        user_id=user.id,
        organization_id=org.id,
        workflow_definition={},
        template_context_variables={},
        call_disposition_codes={},
        workflow_configurations={},
    )
    async_session.add(workflow)
    await async_session.flush()

    session = PhonePreviewSessionModel(
        organization_id=org.id,
        user_id=user.id,
        workflow_id=workflow.id,
        phone_number_hash="scoped-hash",
        phone_number_global_hash="global-hash",
        phone_number_masked="+82****5678",
        destination_phone_encrypted="v1:encrypted",
        status="verified",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
        max_duration_seconds=300,
    )
    async_session.add(session)
    await async_session.flush()

    row, should_start = await db_session.begin_phone_preview_call(
        session.id,
        organization_id=org.id,
        user_id=user.id,
    )

    assert should_start is False
    assert row.status == "expired"
    assert row.failure_reason == "expired"
    assert row.destination_phone_encrypted is None
