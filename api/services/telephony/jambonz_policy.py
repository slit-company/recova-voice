"""Runtime policy for Recova-owned Jambonz core calls.

Lane B owns first-class inventory tables. Until those tables are present in this
worktree, Lane A enforces the V1 invariant at the shared phone-number row using
metadata that the inventory assignment path must stamp when creating assigned
Jambonz rows.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from fastapi import HTTPException

from api.db import db_client
from api.utils.telephony_address import normalize_telephony_address

JAMBONZ_PROVIDER = "jambonz"
ASSIGNED_STATE = "assigned"
_ASSIGNMENT_STATE_KEYS = (
    "recova_inventory_state",
    "inventory_state",
    "assignment_state",
)


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


def _metadata_assignment_state(extra_metadata: dict | None) -> str | None:
    metadata = extra_metadata or {}
    for key in _ASSIGNMENT_STATE_KEYS:
        value = metadata.get(key)
        if isinstance(value, str) and value.lower() == ASSIGNED_STATE:
            return ASSIGNED_STATE
    contract = metadata.get("jambonz_contract_v1")
    if isinstance(contract, dict):
        value = contract.get("assignment_state") or contract.get("inventory_state")
        if isinstance(value, str) and value.lower() == ASSIGNED_STATE:
            return ASSIGNED_STATE
    return None


def is_assigned_recova_jambonz_070(row) -> bool:
    """Return whether an existing phone-number row is valid for V1 core use."""
    if row is None or not getattr(row, "is_active", False):
        return False
    country_hint = getattr(row, "country_code", None) or "KR"
    if not is_recova_070_address(getattr(row, "address_normalized", None), country_hint):
        return False
    return _metadata_assignment_state(getattr(row, "extra_metadata", None)) == ASSIGNED_STATE


def assert_assigned_recova_jambonz_070(row, *, detail: str) -> None:
    if not is_assigned_recova_jambonz_070(row):
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

    assert_assigned_recova_jambonz_070(row, detail=detail)
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
            assert_assigned_recova_jambonz_070(
                row, detail="jambonz_assigned_recova_070_caller_required"
            )
            return row
    raise HTTPException(status_code=400, detail="jambonz_assigned_recova_070_caller_required")


def filter_assigned_recova_jambonz_numbers(rows: Iterable) -> list[str]:
    """Return normalized assigned Recova 070 numbers from phone-number rows."""
    return [
        row.address_normalized
        for row in rows
        if is_assigned_recova_jambonz_070(row)
    ]
