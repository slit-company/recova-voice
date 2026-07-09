"""Service helpers for Recova-owned telephony number inventory."""

from __future__ import annotations

from typing import Any

from api.db import db_client
from api.db.telephony_number_inventory_client import TelephonyNumberInventoryError
from api.schemas.telephony_number_inventory import (
    CustomerAssignedNumberResponse,
    TelephonyNumberInventoryAuditResponse,
    TelephonyNumberInventoryResponse,
)


def inventory_to_response(row) -> TelephonyNumberInventoryResponse:
    return TelephonyNumberInventoryResponse.model_validate(row)


def audit_to_response(row) -> TelephonyNumberInventoryAuditResponse:
    return TelephonyNumberInventoryAuditResponse.model_validate(row)


def assigned_number_to_response(row, phone, workflow_name: str | None) -> CustomerAssignedNumberResponse:
    return CustomerAssignedNumberResponse(
        inventory_id=row.id,
        provider=row.provider,
        address_masked=row.address_masked,
        address_type=row.address_type,
        country_code=row.country_code,
        label=row.label if phone is None or phone.label is None else phone.label,
        status=row.status,
        telephony_configuration_id=row.telephony_configuration_id,
        telephony_phone_number_id=row.telephony_phone_number_id,
        inbound_workflow_id=phone.inbound_workflow_id if phone else None,
        inbound_workflow_name=workflow_name,
        is_active=bool(phone.is_active) if phone else False,
        is_default_caller_id=bool(phone.is_default_caller_id) if phone else False,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def import_inventory_numbers(
    items: list[dict[str, Any]], *, actor_user_id: int | None
):
    return await db_client.import_telephony_number_inventory(
        items,
        actor_user_id=actor_user_id,
    )


async def list_inventory_numbers(
    *,
    status: str | None,
    provider: str | None,
    organization_id: int | None,
    limit: int,
    offset: int,
):
    return await db_client.list_telephony_number_inventory(
        status=status,
        provider=provider,
        organization_id=organization_id,
        limit=limit,
        offset=offset,
    )


async def reserve_inventory_number(
    inventory_id: int,
    *,
    organization_id: int,
    actor_user_id: int | None,
    reservation_expires_at,
    note: str | None,
):
    return await db_client.reserve_telephony_number_inventory(
        inventory_id,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        reservation_expires_at=reservation_expires_at,
        note=note,
    )


async def assign_inventory_number(
    inventory_id: int,
    *,
    organization_id: int,
    actor_user_id: int | None,
    telephony_configuration_id: int | None,
    inbound_workflow_id: int | None,
    label: str | None,
    set_default_caller_id: bool,
    note: str | None,
):
    return await db_client.assign_telephony_number_inventory(
        inventory_id,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        telephony_configuration_id=telephony_configuration_id,
        inbound_workflow_id=inbound_workflow_id,
        label=label,
        set_default_caller_id=set_default_caller_id,
        note=note,
    )


async def quarantine_inventory_number(
    inventory_id: int,
    *,
    actor_user_id: int | None,
    reason: str,
):
    return await db_client.quarantine_telephony_number_inventory(
        inventory_id,
        actor_user_id=actor_user_id,
        reason=reason,
    )


async def retire_inventory_number(
    inventory_id: int,
    *,
    actor_user_id: int | None,
    reason: str,
):
    return await db_client.retire_telephony_number_inventory(
        inventory_id,
        actor_user_id=actor_user_id,
        reason=reason,
    )


async def list_inventory_audit(inventory_id: int):
    return await db_client.list_telephony_number_inventory_audit(inventory_id)


async def list_customer_assigned_numbers(*, organization_id: int):
    return await db_client.list_customer_assigned_telephony_numbers(organization_id)


async def bind_customer_assigned_number(
    inventory_id: int,
    *,
    organization_id: int,
    actor_user_id: int | None,
    workflow_id: int | None,
):
    return await db_client.bind_customer_assigned_telephony_number(
        inventory_id,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        workflow_id=workflow_id,
    )


__all__ = [
    "TelephonyNumberInventoryError",
    "assigned_number_to_response",
    "assign_inventory_number",
    "audit_to_response",
    "bind_customer_assigned_number",
    "import_inventory_numbers",
    "inventory_to_response",
    "list_customer_assigned_numbers",
    "list_inventory_audit",
    "list_inventory_numbers",
    "quarantine_inventory_number",
    "reserve_inventory_number",
    "retire_inventory_number",
]
