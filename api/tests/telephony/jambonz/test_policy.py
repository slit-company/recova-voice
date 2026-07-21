from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

import api.services.telephony.jambonz_policy as jambonz_policy_module
import api.services.telephony.runtime_policy as runtime_policy_module
from api.db.telephony_number_inventory_client import (
    INVENTORY_ID_METADATA_KEY,
    INVENTORY_STATUS_ASSIGNED,
    MANAGED_BY_METADATA_KEY,
    MANAGED_INVENTORY_CREDENTIAL,
    RECOVA_INVENTORY_STATE_KEY,
    TELEPHONY_PHONE_NUMBER_ID_METADATA_KEY,
    _strip_assigned_inventory_metadata,
    _with_assigned_inventory_metadata,
)
from api.services.telephony.jambonz_policy import (
    filter_assigned_recova_jambonz_numbers,
    is_assigned_recova_jambonz_070,
    is_current_jambonz_routable_phone_tuple,
    is_recova_070_address,
    resolve_jambonz_outbound_caller,
)
from api.services.telephony.runtime_policy import (
    allowed_campaign_from_numbers,
    validate_campaign_caller_id,
)
from api.services.telephony.registry import is_dispatch_purpose_allowed


def _phone_row(
    *,
    phone_number_id: int = 902,
    inventory_id: int | None = 501,
    organization_id: int = 11,
    telephony_configuration_id: int = 901,
    address_normalized: str = "+827012345678",
    is_active: bool = True,
    state: str | None = "assigned",
    managed_by: str | None = MANAGED_INVENTORY_CREDENTIAL,
    extra_metadata: dict | None = None,
    onnuri_staging_candidate_id: str | None = None,
):
    if extra_metadata is None:
        metadata = {}
        if state is not None:
            metadata["recova_inventory_state"] = state
        if managed_by is not None:
            metadata["managed_by"] = managed_by
        if inventory_id is not None:
            metadata["inventory_id"] = inventory_id
    else:
        metadata = extra_metadata
    return SimpleNamespace(
        id=phone_number_id,
        organization_id=organization_id,
        telephony_configuration_id=telephony_configuration_id,
        address_normalized=address_normalized,
        country_code="KR",
        is_active=is_active,
        extra_metadata=metadata,
        onnuri_staging_candidate_id=onnuri_staging_candidate_id,
    )


def _inventory_row(
    *,
    inventory_id: int = 501,
    organization_id: int = 11,
    onnuri_staging_candidate_id: str | None = None,
):
    return SimpleNamespace(
        id=inventory_id,
        organization_id=organization_id,
        status="assigned",
        onnuri_staging_candidate_id=onnuri_staging_candidate_id,
    )


def _policy_db(
    *,
    inventory=None,
    rows=None,
    default_row=None,
    config_row=None,
    current_onnuri_inventory=None,
):
    return SimpleNamespace(
        get_assigned_inventory_for_phone_number=AsyncMock(return_value=inventory),
        get_current_onnuri_staging_routable_inventory=AsyncMock(
            return_value=current_onnuri_inventory
        ),
        list_phone_numbers_for_config=AsyncMock(return_value=rows or []),
        get_default_caller_id=AsyncMock(return_value=default_row),
        get_phone_number_for_config=AsyncMock(return_value=config_row),
    )


def test_recova_070_policy_accepts_kr_variants_and_rejects_non_070():
    assert is_recova_070_address("07012345678")
    assert is_recova_070_address("+827012345678")
    assert not is_recova_070_address("01012345678")
    assert not is_recova_070_address("+821012345678")


def test_jambonz_waiting_dispatch_policy_allows_only_preview_smoke():
    assert is_dispatch_purpose_allowed("jambonz", "phone_preview_smoke")
    assert not is_dispatch_purpose_allowed("jambonz", "public")
    assert not is_dispatch_purpose_allowed("jambonz", "direct")
    assert not is_dispatch_purpose_allowed("jambonz", "campaign")

def test_assignment_metadata_helpers_stamp_full_tuple_and_strip_on_disable():
    stamped = _with_assigned_inventory_metadata(
        {"keep": "value"},
        inventory_id=501,
        telephony_phone_number_id=902,
    )

    assert stamped["keep"] == "value"
    assert stamped[RECOVA_INVENTORY_STATE_KEY] == INVENTORY_STATUS_ASSIGNED
    assert stamped[MANAGED_BY_METADATA_KEY] == MANAGED_INVENTORY_CREDENTIAL
    assert stamped[INVENTORY_ID_METADATA_KEY] == 501
    assert stamped[TELEPHONY_PHONE_NUMBER_ID_METADATA_KEY] == 902

    stripped = _strip_assigned_inventory_metadata(stamped)

    assert stripped == {"keep": "value"}


@pytest.mark.asyncio
async def test_filter_campaign_pool_keeps_only_authoritatively_assigned_active_recova_070_numbers(monkeypatch):
    rows = [
        _phone_row(address_normalized="+827012345678"),
        _phone_row(address_normalized="+82705556666", is_active=False),
        _phone_row(address_normalized="+821012345678"),
        _phone_row(address_normalized="+82709998888", state="reserved"),
    ]
    mock_db = _policy_db(inventory=_inventory_row())
    monkeypatch.setattr(jambonz_policy_module, "db_client", mock_db)

    assert await filter_assigned_recova_jambonz_numbers(rows) == ["+827012345678"]
    mock_db.get_assigned_inventory_for_phone_number.assert_awaited_once_with(
        inventory_id=501,
        organization_id=11,
        telephony_phone_number_id=902,
        provider="jambonz",
        telephony_configuration_id=901,
        address_normalized="+827012345678",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "extra_metadata",
    [
        {"recova_inventory_state": "assigned"},
        {
            "inventory_state": "assigned",
            "managed_by": MANAGED_INVENTORY_CREDENTIAL,
            "inventory_id": 501,
        },
        {
            "recova_inventory_state": "assigned",
            "managed_by": "customer_supplied",
            "inventory_id": 501,
        },
        {
            "recova_inventory_state": "assigned",
            "managed_by": MANAGED_INVENTORY_CREDENTIAL,
        },
        {
            "recova_inventory_state": "assigned",
            "managed_by": MANAGED_INVENTORY_CREDENTIAL,
            "inventory_id": "not-an-id",
        },
        {
            "recova_inventory_state": "assigned",
            "managed_by": MANAGED_INVENTORY_CREDENTIAL,
            "inventory_id": 501,
            "inventory_ids": [501, 502],
        },
    ],
)
async def test_assigned_policy_rejects_marker_alias_wrong_manager_and_bad_inventory_id(
    monkeypatch, extra_metadata
):
    mock_db = _policy_db(inventory=_inventory_row())
    monkeypatch.setattr(jambonz_policy_module, "db_client", mock_db)

    assert not await is_assigned_recova_jambonz_070(
        _phone_row(extra_metadata=extra_metadata)
    )
    mock_db.get_assigned_inventory_for_phone_number.assert_not_awaited()


@pytest.mark.asyncio
async def test_assigned_policy_rejects_when_inventory_lookup_is_not_authoritative(monkeypatch):
    row = _phone_row()
    mock_db = _policy_db(inventory=None)
    monkeypatch.setattr(jambonz_policy_module, "db_client", mock_db)

    assert not await is_assigned_recova_jambonz_070(row)
    mock_db.get_assigned_inventory_for_phone_number.assert_awaited_once()


@pytest.mark.asyncio
async def test_resolve_jambonz_outbound_caller_requires_assigned_default(monkeypatch):
    mock_db = _policy_db(
        inventory=_inventory_row(),
        default_row=_phone_row(),
        config_row=None,
    )
    monkeypatch.setattr(jambonz_policy_module, "db_client", mock_db)

    selection = await resolve_jambonz_outbound_caller(
        telephony_configuration_id=901,
        from_phone_number_id=None,
    )

    assert selection.phone_number_id == 902
    assert selection.from_number == "+827012345678"
    mock_db.get_default_caller_id.assert_awaited_once_with(901)
    mock_db.get_phone_number_for_config.assert_not_awaited()
    mock_db.get_assigned_inventory_for_phone_number.assert_awaited_once()


@pytest.mark.asyncio
async def test_resolve_jambonz_outbound_caller_rejects_unassigned_explicit_number(monkeypatch):
    mock_db = _policy_db(
        inventory=_inventory_row(),
        config_row=_phone_row(state="reserved"),
    )
    monkeypatch.setattr(jambonz_policy_module, "db_client", mock_db)

    with pytest.raises(HTTPException) as exc:
        await resolve_jambonz_outbound_caller(
            telephony_configuration_id=901,
            from_phone_number_id=902,
        )

    assert exc.value.status_code == 400
    assert exc.value.detail == "jambonz_assigned_recova_070_caller_required"
    mock_db.get_assigned_inventory_for_phone_number.assert_not_awaited()


@pytest.mark.asyncio
async def test_runtime_policy_filters_jambonz_campaign_pool_and_validates_selection(monkeypatch):
    rows = [_phone_row(address_normalized="+827012345678")]
    mock_policy_db = _policy_db(inventory=_inventory_row(), rows=rows)
    mock_runtime_db = SimpleNamespace(
        list_phone_numbers_for_config=AsyncMock(return_value=rows)
    )
    monkeypatch.setattr(runtime_policy_module, "db_client", mock_runtime_db)
    monkeypatch.setattr(jambonz_policy_module, "db_client", mock_policy_db)

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
    assert mock_policy_db.get_assigned_inventory_for_phone_number.await_count == 2

@pytest.mark.asyncio
async def test_classified_onnuri_inventory_fails_closed_without_current_proof(monkeypatch):
    inventory = SimpleNamespace(
        id=501,
        onnuri_staging_candidate_id="candidate-1",
        onnuri_preflight_proof_id="proof-1",
        onnuri_preflight_proof_hash="hash-1",
    )
    mock_db = _policy_db(inventory=inventory, current_onnuri_inventory=None)
    monkeypatch.setattr(jambonz_policy_module, "db_client", mock_db)

    assert not await is_assigned_recova_jambonz_070(_phone_row())
    mock_db.get_current_onnuri_staging_routable_inventory.assert_awaited_once_with(
        inventory_id=501,
        candidate_id="candidate-1",
        proof_id="proof-1",
        proof_hash="hash-1",
        organization_id=11,
        telephony_phone_number_id=902,
        provider="jambonz",
        telephony_configuration_id=901,
        address_normalized="+827012345678",
    )


@pytest.mark.asyncio
async def test_classified_onnuri_inventory_allows_only_current_proof(monkeypatch):
    inventory = SimpleNamespace(
        id=501,
        onnuri_staging_candidate_id="candidate-1",
        onnuri_preflight_proof_id="proof-2",
        onnuri_preflight_proof_hash="hash-2",
    )
    mock_db = _policy_db(
        inventory=inventory,
        current_onnuri_inventory=SimpleNamespace(id=501),
    )
    monkeypatch.setattr(jambonz_policy_module, "db_client", mock_db)

    assert await is_assigned_recova_jambonz_070(_phone_row())


@pytest.mark.asyncio
async def test_inventory_without_classification_attribute_fails_closed(monkeypatch):
    mock_db = _policy_db(inventory=SimpleNamespace(id=501))
    monkeypatch.setattr(jambonz_policy_module, "db_client", mock_db)

    assert not await is_assigned_recova_jambonz_070(_phone_row())
    mock_db.get_current_onnuri_staging_routable_inventory.assert_not_awaited()


@pytest.mark.asyncio
async def test_inbound_tuple_rejects_mismatched_normalized_did_before_lookup(monkeypatch):
    row = _phone_row(address_normalized="+82705555555")
    mock_db = _policy_db(config_row=row, inventory=_inventory_row())
    monkeypatch.setattr(jambonz_policy_module, "db_client", mock_db)

    assert not await is_current_jambonz_routable_phone_tuple(
        organization_id=11,
        telephony_configuration_id=901,
        telephony_phone_number_id=902,
        address="+827012345678",
    )
    mock_db.get_assigned_inventory_for_phone_number.assert_not_awaited()


@pytest.mark.asyncio
async def test_expired_or_revoked_classified_inventory_rejects_default_caller(
    monkeypatch,
):
    inventory = SimpleNamespace(
        id=501,
        onnuri_staging_candidate_id="candidate-1",
        onnuri_preflight_proof_id="proof-stale",
        onnuri_preflight_proof_hash="hash-stale",
    )
    mock_db = _policy_db(inventory=inventory, default_row=_phone_row())
    monkeypatch.setattr(jambonz_policy_module, "db_client", mock_db)

    with pytest.raises(HTTPException) as exc:
        await resolve_jambonz_outbound_caller(
            telephony_configuration_id=901,
            from_phone_number_id=None,
        )

    assert exc.value.detail == "jambonz_default_recova_070_caller_required"


@pytest.mark.asyncio
async def test_expired_or_revoked_classified_inventory_is_removed_from_campaign_pool(
    monkeypatch,
):
    rows = [_phone_row()]
    inventory = SimpleNamespace(
        id=501,
        onnuri_staging_candidate_id="candidate-1",
        onnuri_preflight_proof_id="proof-stale",
        onnuri_preflight_proof_hash="hash-stale",
    )
    mock_runtime_db = SimpleNamespace(
        list_phone_numbers_for_config=AsyncMock(return_value=rows)
    )
    mock_policy_db = _policy_db(inventory=inventory, rows=rows)
    monkeypatch.setattr(runtime_policy_module, "db_client", mock_runtime_db)
    monkeypatch.setattr(jambonz_policy_module, "db_client", mock_policy_db)

    assert await allowed_campaign_from_numbers(
        provider_name="jambonz",
        telephony_configuration_id=901,
        fallback_from_numbers=["+821012345678"],
    ) == []
