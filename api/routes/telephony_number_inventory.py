"""Operator and customer APIs for Recova-managed telephony numbers."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from api.db.models import UserModel
from api.schemas.telephony_number_inventory import (
    CustomerAssignedNumberBindRequest,
    CustomerAssignedNumberListResponse,
    CustomerAssignedNumberResponse,
    TelephonyNumberInventoryAssignRequest,
    TelephonyNumberInventoryAuditListResponse,
    TelephonyNumberInventoryImportRequest,
    TelephonyNumberInventoryImportResponse,
    TelephonyNumberInventoryListResponse,
    TelephonyNumberInventoryReserveRequest,
    TelephonyNumberInventoryResponse,
    TelephonyNumberInventorySkippedItem,
    TelephonyNumberInventoryStateChangeRequest,
    TelephonyNumberInventoryStatus,
)
from api.services.auth.depends import get_superuser
from api.services.feature_gates import require_self_serve_telephony
from api.services.telephony_number_inventory import (
    TelephonyNumberInventoryError,
    assigned_number_to_response,
    assign_inventory_number,
    audit_to_response,
    bind_customer_assigned_number,
    import_inventory_numbers,
    inventory_to_response,
    list_customer_assigned_numbers,
    list_inventory_audit,
    list_inventory_numbers,
    quarantine_inventory_number,
    reserve_inventory_number,
    retire_inventory_number,
)

operator_router = APIRouter(
    prefix="/telephony-number-inventory",
    tags=["telephony-number-inventory"],
)
customer_router = APIRouter(
    prefix="/organizations/telephony-numbers",
    tags=["telephony-number-inventory"],
)


def _raise_inventory_error(error: TelephonyNumberInventoryError) -> None:
    raise HTTPException(status_code=error.status_code, detail=error.detail)


@operator_router.post(
    "/import",
    response_model=TelephonyNumberInventoryImportResponse,
)
async def import_telephony_number_inventory(
    request: TelephonyNumberInventoryImportRequest,
    user: UserModel = Depends(get_superuser),
):
    items = [item.model_dump() for item in request.numbers]
    try:
        imported, skipped = await import_inventory_numbers(
            items,
            actor_user_id=user.id,
        )
    except TelephonyNumberInventoryError as error:
        _raise_inventory_error(error)
    return TelephonyNumberInventoryImportResponse(
        imported=[inventory_to_response(row) for row in imported],
        skipped=[TelephonyNumberInventorySkippedItem(**item) for item in skipped],
    )


@operator_router.get("", response_model=TelephonyNumberInventoryListResponse)
async def list_telephony_number_inventory(
    status: TelephonyNumberInventoryStatus | None = None,
    provider: str | None = Query(default=None, min_length=1, max_length=32),
    organization_id: int | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    user: UserModel = Depends(get_superuser),
):
    numbers, total_count = await list_inventory_numbers(
        status=status.value if status else None,
        provider=provider,
        organization_id=organization_id,
        limit=limit,
        offset=offset,
    )
    return TelephonyNumberInventoryListResponse(
        numbers=[inventory_to_response(row) for row in numbers],
        total_count=total_count,
        limit=limit,
        offset=offset,
    )


@operator_router.post(
    "/{inventory_id}/reserve",
    response_model=TelephonyNumberInventoryResponse,
)
async def reserve_telephony_number_inventory(
    inventory_id: int,
    request: TelephonyNumberInventoryReserveRequest,
    user: UserModel = Depends(get_superuser),
):
    try:
        row = await reserve_inventory_number(
            inventory_id,
            organization_id=request.organization_id,
            actor_user_id=user.id,
            reservation_expires_at=request.reservation_expires_at,
            note=request.note,
        )
    except TelephonyNumberInventoryError as error:
        _raise_inventory_error(error)
    return inventory_to_response(row)


@operator_router.post(
    "/{inventory_id}/assign",
    response_model=TelephonyNumberInventoryResponse,
)
async def assign_telephony_number_inventory(
    inventory_id: int,
    request: TelephonyNumberInventoryAssignRequest,
    user: UserModel = Depends(get_superuser),
):
    try:
        row = await assign_inventory_number(
            inventory_id,
            organization_id=request.organization_id,
            actor_user_id=user.id,
            telephony_configuration_id=request.telephony_configuration_id,
            inbound_workflow_id=request.inbound_workflow_id,
            label=request.label,
            set_default_caller_id=request.set_default_caller_id,
            note=request.note,
        )
    except TelephonyNumberInventoryError as error:
        _raise_inventory_error(error)
    return inventory_to_response(row)


@operator_router.post(
    "/{inventory_id}/quarantine",
    response_model=TelephonyNumberInventoryResponse,
)
async def quarantine_telephony_number_inventory(
    inventory_id: int,
    request: TelephonyNumberInventoryStateChangeRequest,
    user: UserModel = Depends(get_superuser),
):
    try:
        row = await quarantine_inventory_number(
            inventory_id,
            actor_user_id=user.id,
            reason=request.reason,
        )
    except TelephonyNumberInventoryError as error:
        _raise_inventory_error(error)
    return inventory_to_response(row)


@operator_router.post(
    "/{inventory_id}/retire",
    response_model=TelephonyNumberInventoryResponse,
)
async def retire_telephony_number_inventory(
    inventory_id: int,
    request: TelephonyNumberInventoryStateChangeRequest,
    user: UserModel = Depends(get_superuser),
):
    try:
        row = await retire_inventory_number(
            inventory_id,
            actor_user_id=user.id,
            reason=request.reason,
        )
    except TelephonyNumberInventoryError as error:
        _raise_inventory_error(error)
    return inventory_to_response(row)


@operator_router.get(
    "/{inventory_id}/audit",
    response_model=TelephonyNumberInventoryAuditListResponse,
)
async def list_telephony_number_inventory_audit(
    inventory_id: int,
    user: UserModel = Depends(get_superuser),
):
    try:
        rows = await list_inventory_audit(inventory_id)
    except TelephonyNumberInventoryError as error:
        _raise_inventory_error(error)
    return TelephonyNumberInventoryAuditListResponse(
        audit=[audit_to_response(row) for row in rows]
    )


@customer_router.get(
    "/assigned",
    response_model=CustomerAssignedNumberListResponse,
)
async def list_customer_assigned_telephony_numbers(
    user: UserModel = Depends(require_self_serve_telephony),
):
    if not user.selected_organization_id:
        raise HTTPException(status_code=400, detail="No organization selected")
    rows = await list_customer_assigned_numbers(
        organization_id=user.selected_organization_id,
    )
    return CustomerAssignedNumberListResponse(
        numbers=[assigned_number_to_response(row, phone, name) for row, phone, name in rows]
    )


@customer_router.post(
    "/assigned/{inventory_id}/bind",
    response_model=CustomerAssignedNumberResponse,
)
async def bind_customer_assigned_telephony_number(
    inventory_id: int,
    request: CustomerAssignedNumberBindRequest,
    user: UserModel = Depends(require_self_serve_telephony),
):
    if not user.selected_organization_id:
        raise HTTPException(status_code=400, detail="No organization selected")
    try:
        row, phone, workflow_name = await bind_customer_assigned_number(
            inventory_id,
            organization_id=user.selected_organization_id,
            actor_user_id=user.id,
            workflow_id=request.workflow_id,
        )
    except TelephonyNumberInventoryError as error:
        _raise_inventory_error(error)
    return assigned_number_to_response(row, phone, workflow_name)


@customer_router.delete(
    "/assigned/{inventory_id}/bind",
    response_model=CustomerAssignedNumberResponse,
)
async def unbind_customer_assigned_telephony_number(
    inventory_id: int,
    user: UserModel = Depends(require_self_serve_telephony),
):
    if not user.selected_organization_id:
        raise HTTPException(status_code=400, detail="No organization selected")
    try:
        row, phone, workflow_name = await bind_customer_assigned_number(
            inventory_id,
            organization_id=user.selected_organization_id,
            actor_user_id=user.id,
            workflow_id=None,
        )
    except TelephonyNumberInventoryError as error:
        _raise_inventory_error(error)
    return assigned_number_to_response(row, phone, workflow_name)
