"""Shared telephony runtime policy hooks for generic callers."""

from __future__ import annotations

from fastapi import HTTPException

from api.db import db_client
from api.services.telephony.jambonz_policy import (
    JAMBONZ_PROVIDER,
    filter_assigned_recova_jambonz_numbers,
    require_jambonz_assigned_number_by_address,
)


async def allowed_campaign_from_numbers(
    *,
    provider_name: str,
    telephony_configuration_id: int | None,
    fallback_from_numbers: list[str],
) -> list[str]:
    """Return the caller-ID pool allowed for campaign dispatch."""
    if provider_name != JAMBONZ_PROVIDER:
        return fallback_from_numbers
    if telephony_configuration_id is None:
        return []
    rows = await db_client.list_phone_numbers_for_config(telephony_configuration_id)
    return filter_assigned_recova_jambonz_numbers(rows)


async def validate_campaign_caller_id(
    *,
    provider_name: str,
    telephony_configuration_id: int | None,
    from_number: str,
) -> None:
    """Validate a selected campaign caller ID against provider runtime policy."""
    if provider_name != JAMBONZ_PROVIDER:
        return
    if telephony_configuration_id is None:
        raise ValueError("jambonz_telephony_configuration_required")
    try:
        await require_jambonz_assigned_number_by_address(
            telephony_configuration_id=telephony_configuration_id,
            from_number=from_number,
        )
    except HTTPException as exc:
        raise ValueError(exc.detail) from exc
