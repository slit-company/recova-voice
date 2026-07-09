from uuid import uuid4

import pytest

from api.db.models import (
    OrganizationModel,
    TelephonyConfigurationModel,
    TelephonyNumberInventoryModel,
    TelephonyPhoneNumberModel,
)
from api.db.telephony_number_inventory_client import (
    INVENTORY_ID_METADATA_KEY,
    INVENTORY_STATUS_ASSIGNED,
    INVENTORY_STATUS_AVAILABLE,
    INVENTORY_STATUS_QUARANTINED,
    INVENTORY_STATUS_RETIRED,
    MANAGED_BY_METADATA_KEY,
    MANAGED_INVENTORY_CREDENTIAL,
    RECOVA_INVENTORY_STATE_KEY,
)
from api.services.telephony.jambonz_policy import is_assigned_recova_jambonz_070


async def _create_org(session) -> OrganizationModel:
    org = OrganizationModel(provider_id=f"org-{uuid4()}")
    session.add(org)
    await session.flush()
    return org


async def _create_available_inventory(session, *, address: str = "+827012345678"):
    row = TelephonyNumberInventoryModel(
        provider="jambonz",
        address_normalized=address,
        address_masked="+82******5678",
        address_type="pstn",
        country_code="KR",
        status=INVENTORY_STATUS_AVAILABLE,
        extra_metadata={},
    )
    session.add(row)
    await session.flush()
    return row


async def _create_config(session, *, organization_id: int):
    config = TelephonyConfigurationModel(
        organization_id=organization_id,
        name=f"Managed Jambonz {uuid4()}",
        provider="jambonz",
        credentials={"managed_by": MANAGED_INVENTORY_CREDENTIAL},
        is_default_outbound=False,
    )
    session.add(config)
    await session.flush()
    return config


async def _create_legacy_assigned_pair(session, *, organization_id: int):
    config = await _create_config(session, organization_id=organization_id)
    phone = TelephonyPhoneNumberModel(
        organization_id=organization_id,
        telephony_configuration_id=config.id,
        address="+827011112222",
        address_normalized="+827011112222",
        address_masked="+82******2222",
        address_type="pstn",
        country_code="KR",
        is_active=True,
        is_default_caller_id=True,
        extra_metadata={},
    )
    session.add(phone)
    await session.flush()
    inventory = TelephonyNumberInventoryModel(
        provider="jambonz",
        organization_id=organization_id,
        telephony_configuration_id=config.id,
        telephony_phone_number_id=phone.id,
        address_normalized=phone.address_normalized,
        address_masked=phone.address_masked,
        address_type="pstn",
        country_code="KR",
        status=INVENTORY_STATUS_ASSIGNED,
        extra_metadata={},
    )
    session.add(inventory)
    await session.flush()
    return inventory, phone


@pytest.mark.asyncio
async def test_assignment_stamps_full_trust_tuple_and_policy_requires_inventory_link(db_session):
    async with db_session.async_session() as session:
        org = await _create_org(session)
        inventory = await _create_available_inventory(session)
        organization_id = org.id
        inventory_id = inventory.id

    assigned = await db_session.assign_telephony_number_inventory(
        inventory_id,
        organization_id=organization_id,
        actor_user_id=None,
        label="Recova 070",
        set_default_caller_id=True,
    )

    async with db_session.async_session() as session:
        phone = await session.get(TelephonyPhoneNumberModel, assigned.telephony_phone_number_id)
        inventory_row = await session.get(TelephonyNumberInventoryModel, inventory_id)

    assert phone is not None
    assert inventory_row is not None
    assert phone.extra_metadata[RECOVA_INVENTORY_STATE_KEY] == INVENTORY_STATUS_ASSIGNED
    assert phone.extra_metadata[MANAGED_BY_METADATA_KEY] == MANAGED_INVENTORY_CREDENTIAL
    assert phone.extra_metadata[INVENTORY_ID_METADATA_KEY] == inventory_id
    assert inventory_row.extra_metadata[RECOVA_INVENTORY_STATE_KEY] == INVENTORY_STATUS_ASSIGNED
    assert inventory_row.extra_metadata[MANAGED_BY_METADATA_KEY] == MANAGED_INVENTORY_CREDENTIAL
    assert inventory_row.extra_metadata[INVENTORY_ID_METADATA_KEY] == inventory_id
    assert await is_assigned_recova_jambonz_070(phone)


@pytest.mark.asyncio
async def test_live_validation_attestation_stamps_trusted_evidence_only_on_assigned_pair(
    db_session,
):
    async with db_session.async_session() as session:
        org = await _create_org(session)
        inventory = await _create_available_inventory(session, address="+827055556666")
        organization_id = org.id
        inventory_id = inventory.id

    assigned = await db_session.assign_telephony_number_inventory(
        inventory_id,
        organization_id=organization_id,
        actor_user_id=None,
        label="Validated Recova 070",
        set_default_caller_id=True,
    )
    phone_id = assigned.telephony_phone_number_id

    attested = await db_session.attest_telephony_number_inventory_live_validation(
        inventory_id,
        actor_user_id=None,
        live_validation_source="operator_attestation",
        live_validation_evidence_id="real-route-cdr-001",
        call_attempt_id="outbound:jambonz:real-route-001",
        note="staging proof",
    )

    async with db_session.async_session() as session:
        phone = await session.get(TelephonyPhoneNumberModel, phone_id)
        inventory_row = await session.get(TelephonyNumberInventoryModel, inventory_id)

    assert attested.id == inventory_id
    assert inventory_row.extra_metadata["live_trunk_validated"] is True
    assert inventory_row.extra_metadata["live_validation_source"] == "operator_attestation"
    assert inventory_row.extra_metadata["live_validation_evidence_id"] == "real-route-cdr-001"
    assert inventory_row.extra_metadata["contract_version"] == "jambonz_contract_v1"
    assert inventory_row.extra_metadata["is_contract_fixture"] is False
    assert inventory_row.extra_metadata["call_attempt_id"] == "outbound:jambonz:real-route-001"
    assert phone.extra_metadata["live_trunk_validated"] is True
    assert phone.extra_metadata[INVENTORY_ID_METADATA_KEY] == inventory_id
    assert await is_assigned_recova_jambonz_070(phone)


@pytest.mark.asyncio
async def test_backfill_is_idempotent_and_restores_policy_recognition(db_session):
    async with db_session.async_session() as session:
        org = await _create_org(session)
        inventory, phone = await _create_legacy_assigned_pair(
            session, organization_id=org.id
        )
        inventory_id = inventory.id
        phone_id = phone.id

    assert await db_session.backfill_assigned_inventory_metadata() == 1
    assert await db_session.backfill_assigned_inventory_metadata() == 0

    async with db_session.async_session() as session:
        phone = await session.get(TelephonyPhoneNumberModel, phone_id)
        inventory = await session.get(TelephonyNumberInventoryModel, inventory_id)

    assert phone.extra_metadata[RECOVA_INVENTORY_STATE_KEY] == INVENTORY_STATUS_ASSIGNED
    assert phone.extra_metadata[MANAGED_BY_METADATA_KEY] == MANAGED_INVENTORY_CREDENTIAL
    assert phone.extra_metadata[INVENTORY_ID_METADATA_KEY] == inventory_id
    assert inventory.extra_metadata[RECOVA_INVENTORY_STATE_KEY] == INVENTORY_STATUS_ASSIGNED
    assert inventory.extra_metadata[INVENTORY_ID_METADATA_KEY] == inventory_id
    assert await is_assigned_recova_jambonz_070(phone)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("transition", "expected_status"),
    [
        ("quarantine_telephony_number_inventory", INVENTORY_STATUS_QUARANTINED),
        ("retire_telephony_number_inventory", INVENTORY_STATUS_RETIRED),
    ],
)
async def test_quarantine_and_retire_clear_binding_and_remove_assigned_recognition(
    db_session, transition, expected_status
):
    async with db_session.async_session() as session:
        org = await _create_org(session)
        inventory = await _create_available_inventory(
            session,
            address=(
                "+827033334444"
                if expected_status == INVENTORY_STATUS_QUARANTINED
                else "+827044445555"
            ),
        )
        organization_id = org.id
        inventory_id = inventory.id

    assigned = await db_session.assign_telephony_number_inventory(
        inventory_id,
        organization_id=organization_id,
        actor_user_id=None,
        set_default_caller_id=True,
    )
    phone_id = assigned.telephony_phone_number_id

    await getattr(db_session, transition)(
        inventory_id,
        actor_user_id=None,
        reason="supplier gate failed",
    )

    async with db_session.async_session() as session:
        phone = await session.get(TelephonyPhoneNumberModel, phone_id)
        inventory = await session.get(TelephonyNumberInventoryModel, inventory_id)

    assert inventory.status == expected_status
    assert inventory.telephony_phone_number_id is None
    assert inventory.telephony_configuration_id is None
    assert RECOVA_INVENTORY_STATE_KEY not in inventory.extra_metadata
    assert INVENTORY_ID_METADATA_KEY not in inventory.extra_metadata
    assert phone.is_active is False
    assert phone.is_default_caller_id is False
    assert phone.inbound_workflow_id is None
    assert RECOVA_INVENTORY_STATE_KEY not in phone.extra_metadata
    assert INVENTORY_ID_METADATA_KEY not in phone.extra_metadata
    assert not await is_assigned_recova_jambonz_070(phone)
