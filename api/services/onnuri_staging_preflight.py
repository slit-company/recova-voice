"""Service boundary for password-free Onnuri staging preflight lifecycle."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from api.db import db_client
from api.db.telephony_number_inventory_client import TelephonyNumberInventoryConflictError
from api.services.telephony.onnuri_preflight_policy import (
    OnnuriPreflightPolicyError,
    SMOKE_EVALUATOR_VERSION,
    canonicalize_proof_input,
)


def canonicalize_preflight_input(value: dict[str, Any]) -> tuple[dict[str, Any], str]:
    try:
        return canonicalize_proof_input(value)
    except OnnuriPreflightPolicyError as exc:
        raise TelephonyNumberInventoryConflictError(
            f"onnuri_preflight_{exc}"
        ) from exc


def _require_privileged_actor(actor_user_id: int | None) -> int:
    if actor_user_id is None:
        raise TelephonyNumberInventoryConflictError(
            "onnuri_staging_privileged_actor_required"
        )
    return actor_user_id


async def import_candidates(items: list[dict[str, Any]], *, actor_user_id: int | None):
    return await db_client.import_onnuri_staging_candidates(
        items, actor_user_id=_require_privileged_actor(actor_user_id)
    )


async def approve_proof(
    *,
    candidate_id: int,
    organization_id: int,
    predicate_class: str,
    canonical_input: dict[str, Any],
    expires_at: datetime,
    actor_user_id: int | None,
):
    actor_user_id = _require_privileged_actor(actor_user_id)
    canonical, _ = canonicalize_preflight_input(canonical_input)
    if predicate_class != canonical["soak_policy"]:
        raise TelephonyNumberInventoryConflictError(
            "onnuri_preflight_predicate_class_mismatch"
        )
    return await db_client.approve_onnuri_staging_preflight_proof(
        candidate_id=candidate_id,
        organization_id=organization_id,
        predicate_class=predicate_class,
        canonical_input=canonical,
        expires_at=expires_at,
        actor_user_id=actor_user_id,
        evaluator="recova_onnuri_staging_policy_v1",
        signer=f"superuser:{actor_user_id}",
    )


async def reserve_with_proof(
    inventory_id: int,
    *,
    proof_id: int,
    organization_id: int,
    actor_user_id: int | None,
    reservation_expires_at: datetime | None = None,
    note: str | None = None,
):
    return await db_client.reserve_onnuri_staging_inventory(
        inventory_id,
        proof_id=proof_id,
        organization_id=organization_id,
        actor_user_id=_require_privileged_actor(actor_user_id),
        reservation_expires_at=reservation_expires_at,
        note=note,
    )


async def assign_with_proof(
    inventory_id: int,
    *,
    proof_id: int,
    organization_id: int,
    actor_user_id: int | None,
    telephony_configuration_id: int | None = None,
    inbound_workflow_id: int | None = None,
    label: str | None = None,
    set_default_caller_id: bool = False,
    note: str | None = None,
):
    return await db_client.assign_telephony_number_inventory(
        inventory_id,
        organization_id=organization_id,
        actor_user_id=_require_privileged_actor(actor_user_id),
        telephony_configuration_id=telephony_configuration_id,
        inbound_workflow_id=inbound_workflow_id,
        label=label,
        set_default_caller_id=set_default_caller_id,
        note=note,
        onnuri_preflight_proof_id=proof_id,
    )


async def retire_candidate(
    candidate_id: int, *, actor_user_id: int | None, reason: str
):
    return await db_client.retire_onnuri_staging_candidate(
        candidate_id,
        actor_user_id=_require_privileged_actor(actor_user_id),
        reason=reason,
    )


async def revoke_proof(proof_id: int, *, actor_user_id: int | None, reason: str):
    return await db_client.revoke_onnuri_staging_preflight_proof(
        proof_id,
        actor_user_id=_require_privileged_actor(actor_user_id),
        reason=reason,
    )


async def acquire_application_smoke_lease(
    *,
    proof_id: int,
    inventory_id: int,
    organization_id: int,
    attempt_kind: str,
    duration_seconds: int,
    actor_user_id: int | None,
    application_attempt_id: str,
):
    return await db_client.acquire_onnuri_application_smoke_lease(
        proof_id=proof_id,
        inventory_id=inventory_id,
        organization_id=organization_id,
        attempt_kind=attempt_kind,
        duration_seconds=duration_seconds,
        actor_user_id=_require_privileged_actor(actor_user_id),
        application_attempt_id=application_attempt_id,
    )


async def consume_application_smoke_lease(
    lease_uuid: str,
    *,
    organization_id: int,
    application_attempt_id: str,
):
    return await db_client.consume_onnuri_application_smoke_lease(
        lease_uuid,
        organization_id=organization_id,
        application_attempt_id=application_attempt_id,
    )
async def mark_application_smoke_dispatched(
    application_attempt_id: str, *, organization_id: int
):
    return await db_client.mark_onnuri_smoke_dispatch_attempt_dispatched(
        application_attempt_id, organization_id=organization_id
    )


async def mark_application_smoke_failed(
    application_attempt_id: str, *, organization_id: int, reason: str
):
    return await db_client.mark_onnuri_smoke_dispatch_attempt_failed(
        application_attempt_id, organization_id=organization_id, reason=reason
    )
async def create_smoke_envelope(**kwargs):
    return await db_client.create_onnuri_smoke_envelope(**kwargs)


async def allocate_smoke_attempt(
    *,
    authenticated_operator_user_id: int | None,
    workflow_owner_user_id: int,
    direction: str,
    **kwargs,
):
    """Irreversibly allocate before any outbound signing work."""
    prohibited = {
        "dispatch_nonce_digest",
        "dispatch_token_digest",
        "dispatch_receipt_digest",
        "dispatch_expires_at",
        "encrypted_dispatch_recovery",
    }
    if prohibited.intersection(kwargs):
        raise TelephonyNumberInventoryConflictError(
            "onnuri_smoke_caller_capability_authority_prohibited"
        )
    return await db_client.allocate_onnuri_smoke_attempt(
        authenticated_operator_user_id=_require_privileged_actor(
            authenticated_operator_user_id
        ),
        workflow_owner_user_id=workflow_owner_user_id,
        direction=direction,
        **kwargs,
    )


async def issue_smoke_dispatch(attempt_uuid: str, **kwargs):
    return await db_client.issue_onnuri_smoke_dispatch(attempt_uuid, **kwargs)


async def consume_smoke_dispatch(attempt_uuid: str, **kwargs):
    return await db_client.consume_onnuri_smoke_dispatch(attempt_uuid, **kwargs)


async def bind_smoke_stock_call(attempt_uuid: str, **kwargs):
    return await db_client.bind_onnuri_smoke_stock_call(attempt_uuid, **kwargs)


async def record_outbound_answer_and_mint_media(**kwargs):
    return await db_client.record_onnuri_outbound_answer_and_mint_media(**kwargs)


async def commit_inbound_answer_intent_and_mint_media(**kwargs):
    return await db_client.commit_onnuri_inbound_answer_intent_and_mint_media(
        **kwargs
    )


async def consume_smoke_media(attempt_uuid: str, **kwargs):
    return await db_client.consume_onnuri_smoke_media(attempt_uuid, **kwargs)
async def mark_smoke_running(attempt_uuid: str, **kwargs):
    return await db_client.mark_onnuri_smoke_running(attempt_uuid, **kwargs)


async def create_registration_gate(**kwargs):
    return await db_client.create_onnuri_registration_gate(**kwargs)


async def update_registration_gate(gate_id: int, **kwargs):
    return await db_client.update_onnuri_registration_gate(gate_id, **kwargs)



async def set_smoke_terminal(attempt_uuid: str, **kwargs):
    return await db_client.set_onnuri_smoke_terminal(attempt_uuid, **kwargs)


async def get_smoke_redacted_status(envelope_uuid: str, **kwargs):
    return await db_client.get_onnuri_smoke_redacted_status(envelope_uuid, **kwargs)


def smoke_evaluator_version() -> str:
    return SMOKE_EVALUATOR_VERSION
