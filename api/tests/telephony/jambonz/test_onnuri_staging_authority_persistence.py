from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

import pytest
from sqlalchemy import update
from sqlalchemy.exc import DBAPIError


from api.db.models import (
    OnnuriStagingCandidateModel,
    OnnuriStagingSmokeDispatchAttemptModel,
    OrganizationModel,
    TelephonyNumberInventoryModel,
    UserModel,
    organization_users_association,
)
from api.db.telephony_number_inventory_client import TelephonyNumberInventoryConflictError
from api.services.telephony.onnuri_preflight_policy import canonicalize_proof_input
from api.services.telephony.onnuri_preflight_policy import SMOKE_EVALUATOR_VERSION


def _exception_input() -> dict:
    starting = Decimal("10.00")
    return {
        "soak_policy": "exception_waiting",
        "authorization_scope": "through_application_smoke",
        "proxy_provenance": "user_approved_canary_assumption",
        "authorization_reference": "operator-approved-reference",
        "outbound_proxy": "61.78.32.184:5060/UDP",
        "source_cidr": "61.78.32.184/32",
        "currency": "KRW",
        "provider_evidence_ref": "provider-observation",
        "starting_balance_evidence_ref": "provider-observation",
        "observed_at": "2026-07-13T18:00:00Z",
        "scheduler_checkpoint_ref": "scheduler-checkpoint",
        "firewall_checkpoint_ref": "firewall-checkpoint",
        "sink_checkpoint_ref": "sink-checkpoint",
        "identity_checkpoint_ref": "identity-checkpoint",
        "owned_destinations_ref": "owned-destination-register",
        "starting_balance": format(starting, "f"),
        "warning_balance": format(starting * Decimal("0.20"), "f"),
        "stop_balance": "0",
        "max_discovery_smoke_spend": format(starting, "f"),
        "max_soak_spend": "0",
        "max_inbound_attempts": 2,
        "max_outbound_attempts": 2,
        "max_duration_seconds": 120,
        "max_concurrency": 1,
        "cps": 1,
        "retries": 0,
    }


async def _seed_preflight(db_session):
    async with db_session.async_session() as session:
        organization = OrganizationModel(provider_id=f"onnuri-org-{uuid4()}")
        superuser = UserModel(
            provider_id=f"onnuri-superuser-{uuid4()}", is_superuser=True
        )
        inventory = TelephonyNumberInventoryModel(
            provider="jambonz",
            address_normalized=f"+8270{str(uuid4().int)[:8]}",
            address_type="pstn",
            country_code="KR",
            status="available",
            extra_metadata={},
        )
        session.add_all([organization, superuser, inventory])
        await session.flush()
        await session.execute(
            organization_users_association.insert().values(
                user_id=superuser.id,
                organization_id=organization.id,
            )
        )
        candidate = OnnuriStagingCandidateModel(
            inventory_id=inventory.id,
            provider="jambonz",
            normalized_did=inventory.address_normalized,
            created_by_user_id=superuser.id,
        )
        session.add(candidate)
        await session.flush()
        inventory.onnuri_staging_candidate_id = candidate.id
        await session.flush()
        return organization.id, superuser.id, inventory.id, candidate.id


@pytest.mark.asyncio
async def test_direct_persistence_requires_superuser(db_session):
    organization_id, _, _, candidate_id = await _seed_preflight(db_session)
    canonical, _ = canonicalize_proof_input(_exception_input())

    with pytest.raises(TelephonyNumberInventoryConflictError):
        await db_session.approve_onnuri_staging_preflight_proof(
            candidate_id=candidate_id,
            organization_id=organization_id,
            predicate_class="exception_waiting",
            canonical_input=canonical,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            actor_user_id=None,
            evaluator="recova_onnuri_staging_policy_v1",
            signer="superuser:0",
        )


@pytest.mark.asyncio
async def test_consumption_creates_pending_attempt_and_rejects_incomplete_v2_linkage(
    db_session,
):
    organization_id, superuser_id, inventory_id, candidate_id = await _seed_preflight(
        db_session
    )
    canonical, _ = canonicalize_proof_input(_exception_input())
    proof = await db_session.approve_onnuri_staging_preflight_proof(
        candidate_id=candidate_id,
        organization_id=organization_id,
        predicate_class="exception_waiting",
        canonical_input=canonical,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        actor_user_id=superuser_id,
        evaluator="recova_onnuri_staging_policy_v1",
        signer=f"superuser:{superuser_id}",
    )
    await db_session.reserve_onnuri_staging_inventory(
        inventory_id,
        proof_id=proof.id,
        organization_id=organization_id,
        actor_user_id=superuser_id,
    )
    await db_session.assign_telephony_number_inventory(
        inventory_id,
        organization_id=organization_id,
        actor_user_id=superuser_id,
        onnuri_preflight_proof_id=proof.id,
    )
    lease = await db_session.acquire_onnuri_application_smoke_lease(
        proof_id=proof.id,
        inventory_id=inventory_id,
        organization_id=organization_id,
        attempt_kind="outbound",
        duration_seconds=60,
        actor_user_id=superuser_id,
        application_attempt_id="dispatch-attempt-1",
    )

    attempt = await db_session.consume_onnuri_application_smoke_lease(
        lease.lease_uuid,
        organization_id=organization_id,
        application_attempt_id="dispatch-attempt-1",
    )

    assert attempt.state == "pending"
    assert attempt.evaluator_version is None
    assert attempt.smoke_envelope_id is None
    assert attempt.smoke_attempt_id is None
    assert attempt.authenticated_operator_user_id is None
    assert attempt.workflow_owner_user_id is None
    assert attempt.evaluator_idempotency_key is None
    with pytest.raises(TelephonyNumberInventoryConflictError):
        await db_session.consume_onnuri_application_smoke_lease(
            lease.lease_uuid,
            organization_id=organization_id,
            application_attempt_id="dispatch-attempt-1",
        )

    async with db_session.async_session() as session:
        with pytest.raises(DBAPIError, match="tenant tuple mismatch"):
            await session.execute(
                update(OnnuriStagingSmokeDispatchAttemptModel)
                .where(OnnuriStagingSmokeDispatchAttemptModel.id == attempt.id)
                .values(evaluator_version=SMOKE_EVALUATOR_VERSION)
            )
            await session.commit()
        await session.rollback()
