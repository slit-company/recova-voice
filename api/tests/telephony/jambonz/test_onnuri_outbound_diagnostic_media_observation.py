from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from api.db.models import (
    OnnuriOutboundDiagnosticAttemptModel,
    OnnuriOutboundDiagnosticEventModel,
    OnnuriOutboundDiagnosticLateEvidenceModel,
)
from api.db.telephony_number_inventory_client import TelephonyNumberInventoryConflictError
from api.schemas.onnuri_smoke import ONNURI_OUTBOUND_DIAGNOSTIC_FIXTURE_DIGEST
from api.tests.telephony.jambonz.test_onnuri_smoke_authority import _DIGEST, _seed_authority


async def _attempt(db_session, *, ordinal: int = 1) -> tuple[dict[str, object], OnnuriOutboundDiagnosticAttemptModel]:
    authority = await _seed_authority(db_session)
    async with db_session.async_session() as session:
        now = datetime.now(UTC)
        attempt = OnnuriOutboundDiagnosticAttemptModel(
            attempt_uuid=str(uuid4()), organization_id=authority["organization_id"],
            envelope_id=authority["envelope_id"], inventory_id=authority["inventory_id"],
            telephony_configuration_id=authority["configuration_id"],
            authenticated_operator_user_id=authority["operator_id"], ordinal=ordinal,
            idempotency_key=f"diagnostic-{uuid4()}", fixture_digest=ONNURI_OUTBOUND_DIAGNOSTIC_FIXTURE_DIGEST,
            destination_hmac_digest=_DIGEST, destination_hmac_key_version="test-v1", caller_digest=_DIGEST,
            operator_role="superuser", operator_credential_digest=_DIGEST, candidate_digest=_DIGEST,
            provider_digest=_DIGEST, route_digest=_DIGEST, nat_firewall_digest=_DIGEST,
            keyset_digest=_DIGEST, request_digest=_DIGEST,
            reconciliation_cutoff_at=now + timedelta(seconds=60), created_at=now,
        )
        session.add(attempt)
        await session.commit()
        await session.refresh(attempt)
    return authority, attempt


async def _transition(db_session, authority, attempt, operation: str, key: str):
    expected = (attempt.dispatch, attempt.signaling, attempt.answer, attempt.media, attempt.terminal)
    return await db_session.transition_onnuri_outbound_diagnostic(
        attempt_uuid=attempt.attempt_uuid, organization_id=authority["organization_id"], operation=operation,
        expected=expected, provenance_digest=_DIGEST, event_idempotency_key=key,
    )


@pytest.mark.asyncio
async def test_media_observation_exact_products_and_terminal_immutability(db_session):
    operations = {
        "record_media_zero_matching_packets": "answered_no_matching_rtp",
        "record_media_one_way_packets": "answered_rtp_one_way",
        "record_media_bidirectional_packets": "completed",
    }
    for operation, terminal in operations.items():
        authority, attempt = await _attempt(db_session)
        for index, transition in enumerate(("reserve_submission", "record_submission_sent", "record_ambiguous_submission", "reconcile_original_submission_accepted", "record_signaling_final_2xx", "record_answered", operation), start=1):
            attempt = await _transition(db_session, authority, attempt, transition, f"{operation}-{index}")
        assert attempt.terminal == terminal
        assert attempt.terminal_at is not None
        with pytest.raises(TelephonyNumberInventoryConflictError, match="transition_invalid"):
            await _transition(db_session, authority, attempt, "record_media_bidirectional_packets", f"{operation}-late")


@pytest.mark.asyncio
async def test_not_applicable_is_restricted_to_rejected_calls_and_late_evidence_is_append_only(db_session):
    authority, attempt = await _attempt(db_session)
    with pytest.raises(TelephonyNumberInventoryConflictError, match="transition_invalid"):
        await _transition(db_session, authority, attempt, "record_media_not_applicable", "invalid-not-applicable")
    for index, operation in enumerate(("reserve_submission", "record_submission_sent", "record_ambiguous_submission", "reconcile_original_submission_accepted", "record_signaling_final_3xx_6xx", "record_not_answered", "record_media_not_applicable"), start=1):
        attempt = await _transition(db_session, authority, attempt, operation, f"rejected-{index}")
    assert (attempt.media, attempt.terminal) == ("not_applicable", "carrier_rejected")
    before = (attempt.dispatch, attempt.signaling, attempt.answer, attempt.media, attempt.terminal)
    evidence = await db_session.record_onnuri_outbound_diagnostic_late_evidence(
        attempt_uuid=attempt.attempt_uuid, organization_id=authority["organization_id"], evidence_digest="b" * 64,
        evidence_kind="delayed-cdr",
    )
    assert evidence.evidence_kind == "delayed-cdr"
    async with db_session.async_session() as session:
        stored = await session.get(OnnuriOutboundDiagnosticAttemptModel, attempt.id)
        rows = (await session.execute(select(OnnuriOutboundDiagnosticLateEvidenceModel).where(OnnuriOutboundDiagnosticLateEvidenceModel.attempt_id == attempt.id))).scalars().all()
    assert (stored.dispatch, stored.signaling, stored.answer, stored.media, stored.terminal) == before
    assert [row.evidence_digest for row in rows] == ["b" * 64]
    with pytest.raises(TelephonyNumberInventoryConflictError, match="late_evidence_replay"):
        await db_session.record_onnuri_outbound_diagnostic_late_evidence(
            attempt_uuid=attempt.attempt_uuid, organization_id=authority["organization_id"], evidence_digest="b" * 64,
            evidence_kind="delayed-cdr",
        )


@pytest.mark.asyncio
async def test_ambiguity_reconciles_or_terminates_at_cutoff_and_events_are_idempotent(db_session):
    authority, attempt = await _attempt(db_session)
    for index, operation in enumerate(("reserve_submission", "record_submission_sent", "record_ambiguous_submission"), start=1):
        attempt = await _transition(db_session, authority, attempt, operation, f"ambiguous-{index}")
    reconciled = await _transition(db_session, authority, attempt, "reconcile_original_submission_accepted", "ambiguous-reconcile")
    assert reconciled.dispatch == "stock_accepted"
    authority, attempt = await _attempt(db_session)
    for index, operation in enumerate(("reserve_submission", "record_submission_sent", "record_ambiguous_submission", "terminate_ambiguous_submission_at_cutoff"), start=1):
        attempt = await _transition(db_session, authority, attempt, operation, f"cutoff-{index}")
    assert attempt.terminal == "ambiguous_submission"
    terminal_expected = ("ambiguous_submission", "unknown", "unknown", "unknown", "open")
    duplicate = await db_session.transition_onnuri_outbound_diagnostic(
        attempt_uuid=attempt.attempt_uuid, organization_id=authority["organization_id"],
        operation="terminate_ambiguous_submission_at_cutoff", expected=terminal_expected,
        provenance_digest=_DIGEST, event_idempotency_key="cutoff-4",
    )
    assert duplicate.id == attempt.id
    assert duplicate.terminal == "ambiguous_submission"
    for operation, expected, provenance_digest in (
        ("terminate_contained", terminal_expected, _DIGEST),
        ("terminate_ambiguous_submission_at_cutoff", terminal_expected, "b" * 64),
        ("terminate_ambiguous_submission_at_cutoff", ("submitted", "unknown", "unknown", "unknown", "open"), _DIGEST),
    ):
        with pytest.raises(TelephonyNumberInventoryConflictError, match="transition_replay"):
            await db_session.transition_onnuri_outbound_diagnostic(
                attempt_uuid=attempt.attempt_uuid, organization_id=authority["organization_id"],
                operation=operation, expected=expected, provenance_digest=provenance_digest,
                event_idempotency_key="cutoff-4",
            )
    async with db_session.async_session() as session:
        events = (await session.execute(select(OnnuriOutboundDiagnosticEventModel).where(OnnuriOutboundDiagnosticEventModel.attempt_id == attempt.id))).scalars().all()
    assert len(events) == 4


@pytest.mark.asyncio
async def test_direct_sql_rejects_unlisted_diagnostic_product(db_session):
    authority, attempt = await _attempt(db_session)
    async with db_session.async_session() as session:
        with pytest.raises(IntegrityError, match="ck_onnuri_outbound_diagnostic_product"):
            await session.execute(
                text(
                    "INSERT INTO onnuri_outbound_diagnostic_attempts "
                    "(attempt_uuid, organization_id, envelope_id, inventory_id, "
                    "telephony_configuration_id, authenticated_operator_user_id, ordinal, "
                    "idempotency_key, fixture_digest, destination_hmac_digest, "
                    "destination_hmac_key_version, caller_digest, operator_role, "
                    "operator_credential_digest, candidate_digest, provider_digest, "
                    "route_digest, nat_firewall_digest, keyset_digest, request_digest, "
                    "dispatch, signaling, answer, media, terminal, created_at, reconciliation_cutoff_at) "
                    "SELECT :attempt_uuid, organization_id, envelope_id, inventory_id, "
                    "telephony_configuration_id, authenticated_operator_user_id, 2, "
                    ":idempotency_key, fixture_digest, destination_hmac_digest, "
                    "destination_hmac_key_version, caller_digest, operator_role, "
                    "operator_credential_digest, candidate_digest, provider_digest, "
                    "route_digest, nat_firewall_digest, keyset_digest, request_digest, "
                    "'stock_accepted', 'final_2xx', 'answered', 'not_applicable', "
                    "'completed', created_at, reconciliation_cutoff_at "
                    "FROM onnuri_outbound_diagnostic_attempts WHERE id = :id"
                ),
                {
                    "attempt_uuid": str(uuid4()),
                    "idempotency_key": f"invalid-product-{uuid4()}",
                    "id": attempt.id,
                },
            )
        await session.rollback()
