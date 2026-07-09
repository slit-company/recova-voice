from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from api.services.telephony.jambonz_policy import (
    filter_assigned_recova_jambonz_numbers,
    is_recova_070_address,
    resolve_jambonz_outbound_caller,
)
from api.services.telephony.runtime_policy import (
    allowed_campaign_from_numbers,
    validate_campaign_caller_id,
)


def _phone_row(
    *,
    phone_number_id: int = 902,
    address_normalized: str = "+827012345678",
    is_active: bool = True,
    state: str | None = "assigned",
):
    metadata = {"recova_inventory_state": state} if state else {}
    return SimpleNamespace(
        id=phone_number_id,
        address_normalized=address_normalized,
        country_code="KR",
        is_active=is_active,
        extra_metadata=metadata,
    )


def test_recova_070_policy_accepts_kr_variants_and_rejects_non_070():
    assert is_recova_070_address("07012345678")
    assert is_recova_070_address("+827012345678")
    assert not is_recova_070_address("01012345678")
    assert not is_recova_070_address("+821012345678")


def test_filter_campaign_pool_keeps_only_assigned_active_recova_070_numbers():
    rows = [
        _phone_row(address_normalized="+827012345678"),
        _phone_row(address_normalized="+82705556666", is_active=False),
        _phone_row(address_normalized="+821012345678"),
        _phone_row(address_normalized="+82709998888", state="reserved"),
    ]

    assert filter_assigned_recova_jambonz_numbers(rows) == ["+827012345678"]


@pytest.mark.asyncio
async def test_resolve_jambonz_outbound_caller_requires_assigned_default(monkeypatch):
    mock_db = SimpleNamespace(
        get_default_caller_id=AsyncMock(return_value=_phone_row()),
        get_phone_number_for_config=AsyncMock(),
    )
    monkeypatch.setattr("api.services.telephony.jambonz_policy.db_client", mock_db)

    selection = await resolve_jambonz_outbound_caller(
        telephony_configuration_id=901,
        from_phone_number_id=None,
    )

    assert selection.phone_number_id == 902
    assert selection.from_number == "+827012345678"
    mock_db.get_default_caller_id.assert_awaited_once_with(901)
    mock_db.get_phone_number_for_config.assert_not_awaited()


@pytest.mark.asyncio
async def test_resolve_jambonz_outbound_caller_rejects_unassigned_explicit_number(monkeypatch):
    mock_db = SimpleNamespace(
        get_default_caller_id=AsyncMock(),
        get_phone_number_for_config=AsyncMock(
            return_value=_phone_row(state="reserved")
        ),
    )
    monkeypatch.setattr("api.services.telephony.jambonz_policy.db_client", mock_db)

    with pytest.raises(HTTPException) as exc:
        await resolve_jambonz_outbound_caller(
            telephony_configuration_id=901,
            from_phone_number_id=902,
        )

    assert exc.value.status_code == 400
    assert exc.value.detail == "jambonz_assigned_recova_070_caller_required"


@pytest.mark.asyncio
async def test_runtime_policy_filters_jambonz_campaign_pool_and_validates_selection(monkeypatch):
    rows = [_phone_row(address_normalized="+827012345678")]
    mock_policy_db = SimpleNamespace(
        list_phone_numbers_for_config=AsyncMock(return_value=rows)
    )
    mock_runtime_db = SimpleNamespace(
        list_phone_numbers_for_config=AsyncMock(return_value=rows)
    )
    monkeypatch.setattr("api.services.telephony.runtime_policy.db_client", mock_runtime_db)
    monkeypatch.setattr("api.services.telephony.jambonz_policy.db_client", mock_policy_db)

    allowed = await allowed_campaign_from_numbers(
        provider_name="jambonz",
        telephony_configuration_id=901,
        fallback_from_numbers=["+821012345678"],
    )
    assert allowed == ["+827012345678"]

    await validate_campaign_caller_id(
        provider_name="jambonz",
        telephony_configuration_id=901,
        from_number="07012345678",
    )

    mock_runtime_db.list_phone_numbers_for_config.assert_awaited_once_with(901)
    mock_policy_db.list_phone_numbers_for_config.assert_awaited_once_with(901)
