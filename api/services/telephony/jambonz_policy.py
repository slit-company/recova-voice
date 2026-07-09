"""Runtime policy for Recova-owned Jambonz core calls.

Assigned Recova Jambonz 070 recognition is trust-boundary first: runtime code
must validate both phone-row metadata and the authoritative inventory row before
treating a number as live for inbound or outbound core use.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from fastapi import HTTPException

from api.db import db_client
from api.db.telephony_number_inventory_client import (
    INVENTORY_ID_METADATA_KEY,
    INVENTORY_STATUS_ASSIGNED,
    MANAGED_BY_METADATA_KEY,
    MANAGED_INVENTORY_CREDENTIAL,
    RECOVA_INVENTORY_STATE_KEY,
)
from api.utils.telephony_address import normalize_telephony_address

JAMBONZ_PROVIDER = "jambonz"
ASSIGNED_STATE = INVENTORY_STATUS_ASSIGNED


@dataclass(frozen=True)
class JambonzCallerSelection:
    phone_number_id: int
    from_number: str


def is_recova_070_address(address: str | None, country_hint: str | None = "KR") -> bool:
    if not address:
        return False
    try:
        normalized = normalize_telephony_address(address, country_hint=country_hint)
    except ValueError:
        return False
    return normalized.address_type == "pstn" and normalized.canonical.startswith("+8270")


def _coerce_inventory_id(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.isdecimal():
        parsed = int(value)
        return parsed if parsed > 0 else None
    return None


def _metadata_inventory_id(extra_metadata: dict | None) -> int | None:
    metadata = extra_metadata or {}
    if not isinstance(metadata, dict):
        return None

    inventory_id = _coerce_inventory_id(metadata.get(INVENTORY_ID_METADATA_KEY))
    if inventory_id is None:
        return None

    alias_values: list[Any] = []
    legacy_contract = metadata.get("jambonz_contract_v1")
    if isinstance(legacy_contract, dict):
        alias_values.append(legacy_contract.get(INVENTORY_ID_METADATA_KEY))
    alias_values.extend(
        metadata.get(key)
        for key in ("inventoryId", "inventory_ids")
        if key in metadata
    )

    for value in alias_values:
        values = value if isinstance(value, list) else [value]
        parsed_values = {
            parsed
            for parsed in (_coerce_inventory_id(candidate) for candidate in values)
            if parsed is not None
        }
        if len(parsed_values) > 1 or (
            len(parsed_values) == 1 and inventory_id not in parsed_values
        ):
            return None

    return inventory_id


def _canonical_assigned_inventory_id(extra_metadata: dict | None) -> int | None:
    metadata = extra_metadata or {}
    if not isinstance(metadata, dict):
        return None
    state = metadata.get(RECOVA_INVENTORY_STATE_KEY)
    if not isinstance(state, str) or state.lower() != ASSIGNED_STATE:
        return None
    if metadata.get(MANAGED_BY_METADATA_KEY) != MANAGED_INVENTORY_CREDENTIAL:
        return None
    return _metadata_inventory_id(metadata)


async def is_assigned_recova_jambonz_070(row) -> bool:
    """Return whether a phone-number row is valid for V1 core use."""
    if row is None or not getattr(row, "is_active", False):
        return False
    country_hint = getattr(row, "country_code", None) or "KR"
    address = getattr(row, "address_normalized", None)
    if not is_recova_070_address(address, country_hint):
        return False

    inventory_id = _canonical_assigned_inventory_id(
        getattr(row, "extra_metadata", None)
    )
    if inventory_id is None:
        return False

    organization_id = getattr(row, "organization_id", None)
    phone_number_id = getattr(row, "id", None)
    if organization_id is None or phone_number_id is None:
        return False

    inventory = await db_client.get_assigned_inventory_for_phone_number(
        inventory_id=inventory_id,
        organization_id=organization_id,
        telephony_phone_number_id=phone_number_id,
        provider=JAMBONZ_PROVIDER,
        telephony_configuration_id=getattr(row, "telephony_configuration_id", None),
        address_normalized=address,
    )
    return inventory is not None


async def assert_assigned_recova_jambonz_070(row, *, detail: str) -> None:
    if not await is_assigned_recova_jambonz_070(row):
        raise HTTPException(status_code=400, detail=detail)


async def resolve_jambonz_outbound_caller(
    *,
    telephony_configuration_id: int,
    from_phone_number_id: int | None,
) -> JambonzCallerSelection:
    """Resolve the only allowed caller ID for V1 Jambonz outbound calls.

    The default path is an assigned active Recova 070 marked as the config's
    default caller. Explicit caller selection is allowed only for an assigned
    active Recova 070 in the same config.
    """
    if from_phone_number_id is not None:
        row = await db_client.get_phone_number_for_config(
            from_phone_number_id, telephony_configuration_id
        )
        detail = "jambonz_assigned_recova_070_caller_required"
    else:
        row = await db_client.get_default_caller_id(telephony_configuration_id)
        detail = "jambonz_default_recova_070_caller_required"

    await assert_assigned_recova_jambonz_070(row, detail=detail)
    return JambonzCallerSelection(
        phone_number_id=row.id,
        from_number=row.address_normalized,
    )


async def require_jambonz_assigned_number_by_address(
    *,
    telephony_configuration_id: int,
    from_number: str,
):
    """Return the matching assigned phone row, or raise for policy violation."""
    normalized = normalize_telephony_address(from_number, country_hint="KR").canonical
    rows = await db_client.list_phone_numbers_for_config(telephony_configuration_id)
    for row in rows:
        if getattr(row, "address_normalized", None) == normalized:
            await assert_assigned_recova_jambonz_070(
                row, detail="jambonz_assigned_recova_070_caller_required"
            )
            return row
    raise HTTPException(status_code=400, detail="jambonz_assigned_recova_070_caller_required")


async def filter_assigned_recova_jambonz_numbers(rows: Iterable) -> list[str]:
    """Return normalized assigned Recova 070 numbers from phone-number rows."""
    assigned: list[str] = []
    for row in rows:
        if await is_assigned_recova_jambonz_070(row):
            assigned.append(row.address_normalized)
    return assigned
