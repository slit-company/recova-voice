from api.db.models import (
    PhonePreviewSessionModel,
    PhonePreviewVerificationModel,
    TelephonyPhoneNumberModel,
)
from api.db.phone_preview_client import PhonePreviewClient
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
