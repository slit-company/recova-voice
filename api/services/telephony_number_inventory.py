"""Service helpers for Recova-owned telephony number inventory."""

from __future__ import annotations

from typing import Any

from api.db import db_client
from api.db.telephony_number_inventory_client import TelephonyNumberInventoryError
from api.schemas.telephony_number_inventory import (
    CustomerAssignedNumberResponse,
    TelephonyNumberInventoryAssignmentMetadata,
    TelephonyNumberInventoryAuditResponse,
    TelephonyNumberInventoryReadinessMetadata,
    TelephonyNumberInventoryResponse,
)

_MANAGED_INVENTORY_CREDENTIAL = "recova_number_inventory"
_LIVE_VALIDATION_TRUSTED_WRITER_METADATA_KEY = "live_validation_trusted_writer"
_LIVE_VALIDATION_TRUSTED_WRITER = "recova_operator_live_validation_v1"
_ASSIGNMENT_STATE_KEYS = (
    "recova_inventory_state",
    "inventory_state",
    "assignment_state",
)
_SAFE_METADATA_KEYS = {
    "assignment_state",
    "call_attempt_id",
    "contract_version",
    "import_batch_id",
    "inventory_id",
    "inventory_state",
    "is_contract_fixture",
    "live_trunk_validated",
    "live_validation_evidence_id",
    "live_validation_source",
    "managed_by",
    "operator_note",
    "phone_number_id",
    "telephony_configuration_id",
    "telephony_phone_number_id",
    "provider",
    "provider_config_id",
    "readiness_state",
    "recova_inventory_state",
    "supplier",
    "trunk_group",
    "validation_status",
}
_SENSITIVE_METADATA_KEY_PARTS = (
    "api_key",
    "auth",
    "credential",
    "encrypted",
    "hash",
    "password",
    "private",
    "raw",
    "secret",
    "signature",
    "token",
)



def _safe_metadata(
    metadata: dict[str, Any], *, allow_unknown_scalar: bool = False
) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    safe: dict[str, Any] = {}
    for key, value in metadata.items():
        if not isinstance(key, str):
            continue
        normalized_key = key.strip()
        if not normalized_key:
            continue
        lowered_key = normalized_key.lower()
        if any(part in lowered_key for part in _SENSITIVE_METADATA_KEY_PARTS):
            continue
        if lowered_key not in _SAFE_METADATA_KEYS and not allow_unknown_scalar:
            continue
        scalar = _safe_scalar(value)
        if scalar is not None:
            safe[normalized_key] = scalar
    return safe


def _safe_scalar(value: Any) -> str | int | float | bool | None:
    if value is None:
        return None
    if isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        trimmed = value.strip()
        return trimmed[:256] if trimmed else None
    return None


def _metadata_string(metadata: dict[str, Any], key: str) -> str | None:
    value = metadata.get(key)
    if value is None:
        return None
    return str(value)


def _metadata_int(metadata: dict[str, Any], key: str) -> int | None:
    value = metadata.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _metadata_bool(metadata: dict[str, Any], key: str) -> bool:
    value = metadata.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return False


def _normalize_readiness_claims(metadata: dict[str, Any]) -> dict[str, Any]:
    if not _metadata_bool(metadata, "live_trunk_validated"):
        return metadata
    if (
        _metadata_bool(metadata, "is_contract_fixture")
        or _metadata_string(metadata, _LIVE_VALIDATION_TRUSTED_WRITER_METADATA_KEY)
        != _LIVE_VALIDATION_TRUSTED_WRITER
        or not _metadata_string(metadata, "live_validation_source")
        or not _metadata_string(metadata, "live_validation_evidence_id")
    ):
        return {**metadata, "live_trunk_validated": False}
    return metadata


def _assignment_metadata(
    row, metadata: dict[str, Any]
) -> TelephonyNumberInventoryAssignmentMetadata:
    state = next(
        (
            _metadata_string(metadata, key)
            for key in _ASSIGNMENT_STATE_KEYS
            if _metadata_string(metadata, key)
        ),
        None,
    )
    inventory_id = _metadata_int(metadata, "inventory_id")
    managed_by = _metadata_string(metadata, "managed_by")
    return TelephonyNumberInventoryAssignmentMetadata(
        managed_by=managed_by,
        recova_inventory_state=state,
        inventory_id=inventory_id,
        binding_metadata_consistent=bool(
            getattr(row, "status", None) == "assigned"
            and managed_by == _MANAGED_INVENTORY_CREDENTIAL
            and state == "assigned"
            and inventory_id == getattr(row, "id", None)
            and getattr(row, "telephony_configuration_id", None) is not None
            and getattr(row, "telephony_phone_number_id", None) is not None
        ),
    )


def _readiness_metadata(
    metadata: dict[str, Any]
) -> TelephonyNumberInventoryReadinessMetadata:
    is_fixture = _metadata_bool(metadata, "is_contract_fixture")
    live_validation_source = _metadata_string(metadata, "live_validation_source")
    live_validation_evidence_id = _metadata_string(
        metadata, "live_validation_evidence_id"
    )
    live_trunk_validated = bool(
        _metadata_bool(metadata, "live_trunk_validated")
        and not is_fixture
        and live_validation_source
        and live_validation_evidence_id
    )
    return TelephonyNumberInventoryReadinessMetadata(
        contract_version=_metadata_string(metadata, "contract_version"),
        is_contract_fixture=is_fixture,
        live_trunk_validated=live_trunk_validated,
        live_validation_source=live_validation_source,
        live_validation_evidence_id=live_validation_evidence_id,
        provider_config_id=_metadata_string(metadata, "provider_config_id")
        or _metadata_string(metadata, "telephony_configuration_id"),
        phone_number_id=_metadata_int(metadata, "phone_number_id")
        or _metadata_int(metadata, "telephony_phone_number_id"),
        telephony_configuration_id=_metadata_int(metadata, "telephony_configuration_id"),
        telephony_phone_number_id=_metadata_int(metadata, "telephony_phone_number_id"),
        inventory_id=_metadata_int(metadata, "inventory_id"),
        call_attempt_id=_metadata_string(metadata, "call_attempt_id"),
    )

def inventory_to_response(row) -> TelephonyNumberInventoryResponse:
    response = TelephonyNumberInventoryResponse.model_validate(row)
    normalized_metadata = _normalize_readiness_claims(
        getattr(row, "extra_metadata", {}) or {}
    )
    safe_metadata = _safe_metadata(normalized_metadata)
    response.extra_metadata = safe_metadata
    response.assignment_metadata = _assignment_metadata(row, safe_metadata)
    response.readiness_metadata = _readiness_metadata(safe_metadata)
    return response


def audit_to_response(row) -> TelephonyNumberInventoryAuditResponse:
    response = TelephonyNumberInventoryAuditResponse.model_validate(row)
    response.details = _safe_metadata(
        getattr(row, "details", {}) or {}, allow_unknown_scalar=True
    )
    return response


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


async def attest_inventory_live_validation(
    inventory_id: int,
    *,
    actor_user_id: int | None,
    live_validation_source: str,
    live_validation_evidence_id: str,
    contract_version: str | None,
    call_attempt_id: str | None,
    note: str | None,
):
    return await db_client.attest_telephony_number_inventory_live_validation(
        inventory_id,
        actor_user_id=actor_user_id,
        live_validation_source=live_validation_source,
        live_validation_evidence_id=live_validation_evidence_id,
        contract_version=contract_version,
        call_attempt_id=call_attempt_id,
        note=note,
    )


__all__ = [
    "TelephonyNumberInventoryError",
    "assigned_number_to_response",
    "attest_inventory_live_validation",
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
