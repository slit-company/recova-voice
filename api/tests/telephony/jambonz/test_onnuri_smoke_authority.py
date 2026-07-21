from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
from base64 import urlsafe_b64encode
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from api.db.models import (
    G008ExecutionSealModel,
    G008ExecutionStageModel,
    OnnuriSmokeAnswerAuthorizationModel,
    OnnuriSmokeAttemptModel,
    OnnuriSmokeCallbackEventModel,
    OnnuriSmokeCapabilityConsumptionModel,
    OnnuriRegistrationGateModel,
    OnnuriSmokeEnvelopeModel,
    OnnuriStagingCandidateModel,
    OrganizationModel,
    TelephonyConfigurationModel,
    TelephonyNumberInventoryModel,
    UserModel,
    WorkflowModel,
    organization_users_association,
)
from api.db.telephony_number_inventory_client import (
    ONNURI_SMOKE_AUTHORITY_V2,
    ONNURI_SMOKE_AUTHORITY_V3,
    TelephonyNumberInventoryConflictError,
    TelephonyNumberInventoryNotFoundError,
)
from api.services.telephony.onnuri_preflight_policy import (
    DISPATCH_CAPABILITY_DOMAIN,
    MEDIA_CAPABILITY_DOMAIN,
    canonicalize_proof_input,
)
from api.services.onnuri_smoke_capabilities import (
    AesGcmSmokeRecoverySealer,
    CapabilityBinding,
    CapabilityIssueRequest,
    CapabilityPolicy,
    PrivatePemSmokeCapabilityIssuer,
    SmokeCapabilityInvalidError,
    canonical_json_bytes,
    configure_smoke_authority_runtime_from_environment,
    opaque_signing_bytes,
    reset_smoke_authority_runtime_for_tests,
    signed_capability_bytes,
)
from api.services import onnuri_smoke_f12

_DIGEST = "a" * 64
_OTHER_DIGEST = "b" * 64
_DESTINATION_DIGEST = "c" * 64
_PROVIDER_PREFLIGHT_DIGEST = "d" * 64
_SUPPLIER_BOUNDS_DIGEST = "e" * 64
_TENANT_MAPPING_DIGEST = "f" * 64
_SECRET_MANIFEST_DIGEST = "1" * 64
_GATE_DECISION_DIGEST = "2" * 64
_V3_RECEIPTS = {
    "provider_balance_currency_receipt_digest": _PROVIDER_PREFLIGHT_DIGEST,
    "supplier_signaling_media_receipt_digest": _SUPPLIER_BOUNDS_DIGEST,
    "tenant_mapping_receipt_digest": _TENANT_MAPPING_DIGEST,
    "secret_version_manifest_receipt_digest": _SECRET_MANIFEST_DIGEST,
    "gate_decision_receipt_digest": _GATE_DECISION_DIGEST,
}
_SOURCE_ACCOUNT_ID = "offline-account"
_SOURCE_APPLICATION_ID = "offline-application"
_DISPATCH_RESPONSE = b'{"dispatch":"offline"}'
_DISPATCH_TOKEN_DIGEST = hashlib.sha256(_DISPATCH_RESPONSE).hexdigest()
_DISPATCH_CONSUME_RESPONSE = b'{"dispatch_receipt":"offline"}'
_MEDIA_RESPONSE = b'{"media":"offline"}'
_ISSUE_RECOVERY = "offline-dispatch-issue-ciphertext"
_CONSUME_RECOVERY = "offline-dispatch-consume-ciphertext"
_MEDIA_RECOVERY = "offline-media-ciphertext"

def test_facade_authority_migration_guard_fingerprints_reject_drift():
    migration = importlib.import_module(
        "api.alembic.versions.d6e7f8a9b0c1_add_onnuri_smoke_facade_authority"
    )
    predecessor = (
        "CREATE OR REPLACE FUNCTION public.onnuri_smoke_authority_row_guard() "
        "RETURNS trigger LANGUAGE plpgsql AS $function$ "
        "DECLARE old_fixed jsonb; new_fixed jsonb; BEGIN "
        "ELSIF TG_TABLE_NAME = 'onnuri_staging_smoke_attempts' THEN "
        "old_fixed := to_jsonb(OLD) - ARRAY["
        "'state','dispatch_receipt_digest','stock_call_id_digest',"
        "'bind_callback_nonce_digest','inbound_tuple_digest','stock_bound_at',"
        "'authority_kind','authority_wall_at','authority_deadline_at',"
        "'authority_budget_seconds','observed_carrier_answer_at','terminal_class',"
        "'terminal_reason','terminal_at','contained_at']; "
        "END IF; RETURN NEW; END $function$ "
    )
    # A replacement-pattern-only check would accept this truncated guard; the
    # migration-owned complete normalized SHA-256 contract must not.
    assert (
        hashlib.sha256(
            migration._normalized_definition(predecessor).encode("utf-8")
        ).hexdigest()
        != migration._PREDECESSOR_AUTHORITY_GUARD_SHA256
    )
    installed = predecessor.replace(
        "'authority_budget_seconds','observed_carrier_answer_at','terminal_class'",
        "'authority_budget_seconds','observed_carrier_answer_at','account_id',"
        "'application_id','run_id','terminal_class'",
    )
    assert (
        hashlib.sha256(
            migration._normalized_definition(installed).encode("utf-8")
        ).hexdigest()
        != migration._INSTALLED_AUTHORITY_GUARD_SHA256
    )


def _exception_input() -> dict[str, object]:
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
        "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
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


async def _seed_authority(
    db_session, *, evaluator_version: str = ONNURI_SMOKE_AUTHORITY_V3
) -> dict[str, object]:
    suffix = uuid4().hex
    async with db_session.async_session() as session:
        organization = OrganizationModel(provider_id=f"smoke-org-{suffix}")
        other_organization = OrganizationModel(provider_id=f"other-org-{suffix}")
        session.add_all([organization, other_organization])
        await session.flush()
        operator = UserModel(
            provider_id=f"smoke-operator-{suffix}",
            is_superuser=True,
            selected_organization_id=organization.id,
        )
        owner = UserModel(
            provider_id=f"smoke-owner-{suffix}",
            selected_organization_id=organization.id,
        )
        outsider = UserModel(
            provider_id=f"smoke-outsider-{suffix}",
            selected_organization_id=other_organization.id,
        )
        session.add_all([operator, owner, outsider])
        await session.flush()
        await session.execute(
            organization_users_association.insert(),
            [
                {"user_id": operator.id, "organization_id": organization.id},
                {"user_id": owner.id, "organization_id": organization.id},
                {"user_id": outsider.id, "organization_id": other_organization.id},
            ],
        )
        configuration = TelephonyConfigurationModel(
            organization_id=organization.id,
            name=f"Offline smoke {suffix}",
            provider="jambonz",
            credentials={
                "account_id": _SOURCE_ACCOUNT_ID,
                "application_id": _SOURCE_APPLICATION_ID,
            },
            is_default_outbound=False,
        )
        workflow = WorkflowModel(
            name=f"Offline smoke {suffix}",
            user_id=owner.id,
            organization_id=organization.id,
            workflow_definition={},
            template_context_variables={},
            call_disposition_codes={},
            workflow_configurations={},
        )
        normalized_did = f"+8270{str(uuid4().int)[:8]}"
        inventory = TelephonyNumberInventoryModel(
            provider="jambonz",
            address_normalized=normalized_did,
            address_type="pstn",
            country_code="KR",
            status="available",
            extra_metadata={},
        )
        session.add_all([configuration, workflow, inventory])
        await session.flush()
        candidate = OnnuriStagingCandidateModel(
            inventory_id=inventory.id,
            provider="jambonz",
            normalized_did=inventory.address_normalized,
            created_by_user_id=operator.id,
        )
        session.add(candidate)
        await session.flush()
        inventory.onnuri_staging_candidate_id = candidate.id
        await session.commit()
        ids = {
            "organization_id": organization.id,
            "other_organization_id": other_organization.id,
            "operator_id": operator.id,
            "owner_id": owner.id,
            "outsider_id": outsider.id,
            "configuration_id": configuration.id,
            "workflow_id": workflow.id,
            "inventory_id": inventory.id,
            "candidate_id": candidate.id,
            "normalized_did": normalized_did,
        }

    canonical, _ = canonicalize_proof_input(_exception_input())
    proof = await db_session.approve_onnuri_staging_preflight_proof(
        candidate_id=ids["candidate_id"],
        organization_id=ids["organization_id"],
        predicate_class="exception_waiting",
        canonical_input=canonical,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        actor_user_id=ids["operator_id"],
        evaluator="recova_onnuri_staging_policy_v1",
        signer=f"superuser:{ids['operator_id']}",
    )
    await db_session.reserve_onnuri_staging_inventory(
        ids["inventory_id"],
        proof_id=proof.id,
        organization_id=ids["organization_id"],
        actor_user_id=ids["operator_id"],
    )
    await db_session.assign_telephony_number_inventory(
        ids["inventory_id"],
        organization_id=ids["organization_id"],
        actor_user_id=ids["operator_id"],
        telephony_configuration_id=ids["configuration_id"],
        onnuri_preflight_proof_id=proof.id,
    )

    now = datetime.now(UTC)
    async with db_session.async_session() as session:
        envelope = OnnuriSmokeEnvelopeModel(
            evaluator_version=evaluator_version,
            proof_id=proof.id,
            organization_id=ids["organization_id"],
            inventory_id=ids["inventory_id"],
            telephony_configuration_id=ids["configuration_id"],
            workflow_id=ids["workflow_id"],
            destination_hmac_key_id="offline-destination-key",
            destination_hmac_key_version="1",
            destination_hmac_digest=_DESTINATION_DIGEST,
            dispatch_key_id="offline-dispatch-key",
            dispatch_algorithm_policy_id="ecdsa-p256-sha256",
            dispatch_domain=DISPATCH_CAPABILITY_DOMAIN,
            media_key_id="offline-media-key",
            media_algorithm_policy_id="ecdsa-p256-sha256",
            media_domain=MEDIA_CAPABILITY_DOMAIN,
            policy_digest=_DIGEST,
            candidate_digest=_DIGEST,
            phase_b_manifest_digest=_DIGEST,
            phase_c_iac_digest=_DIGEST,
            **(_V3_RECEIPTS if evaluator_version == ONNURI_SMOKE_AUTHORITY_V3 else {}),
            live_window_starts_at=now - timedelta(seconds=30),
            live_window_expires_at=now + timedelta(minutes=5),
            expires_at=now + timedelta(minutes=6),
            destroy_deadline=now + timedelta(minutes=7),
        )
        session.add(envelope)
        await session.commit()
        await session.refresh(envelope)
        ids.update(
            {
                "proof_id": proof.id,
                "envelope_id": envelope.id,
                "envelope_uuid": envelope.envelope_uuid,
                "live_window_expires_at": envelope.live_window_expires_at,
            }
        )
    return ids


def _inbound_tuple(ids: dict[str, object]) -> dict[str, str]:
    return {
        "source_account_id": _SOURCE_ACCOUNT_ID,
        "source_application_id": _SOURCE_APPLICATION_ID,
        "did_digest": hashlib.sha256(
            str(ids["normalized_did"]).encode("utf-8")
        ).hexdigest(),
        "caller_mobile_digest": _DESTINATION_DIGEST,
        "candidate_digest": _DIGEST,
        "account_id": "facade-account",
        "application_id": "facade-application",
        "run_id": "facade-run",
    }


def _allocation(ids: dict[str, object], *, direction: str, key: str, **overrides):
    values = {
        "envelope_uuid": ids["envelope_uuid"],
        "organization_id": ids["organization_id"],
        "proof_id": ids["proof_id"],
        "inventory_id": ids["inventory_id"],
        "telephony_configuration_id": ids["configuration_id"],
        "workflow_id": ids["workflow_id"],
        "direction": direction,
        "authenticated_operator_user_id": ids["operator_id"],
        "workflow_owner_user_id": ids["owner_id"],
        "idempotency_key": key,
        "request_digest": _DIGEST,
        "destination_hmac_digest": _DESTINATION_DIGEST,
    }
    values.update(overrides)
    return values


def _arming(ids: dict[str, object]) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "evaluator_version": ONNURI_SMOKE_AUTHORITY_V3,
        "proof_id": ids["proof_id"],
        "inventory_id": ids["inventory_id"],
        "organization_id": ids["organization_id"],
        "telephony_configuration_id": ids["configuration_id"],
        "workflow_id": ids["workflow_id"],
        "destination_hmac_key_id": "offline-destination-key",
        "destination_hmac_key_version": "1",
        "destination_hmac_digest": _DESTINATION_DIGEST,
        "dispatch_key_id": "offline-dispatch-key-v3",
        "dispatch_algorithm_policy_id": "gcp-kms-ecdsa-p256-sha256-v1",
        "media_key_id": "offline-media-key-v3",
        "media_algorithm_policy_id": "gcp-kms-ecdsa-p256-sha256-v1",
        "policy_digest": _DIGEST,
        "candidate_digest": _DIGEST,
        "phase_b_manifest_digest": _DIGEST,
        "phase_c_iac_digest": _DIGEST,
        "live_window_starts_at": now + timedelta(seconds=10),
        "live_window_expires_at": now + timedelta(minutes=5),
        "expires_at": now + timedelta(minutes=6),
        "destroy_deadline": now + timedelta(minutes=7),
        **_V3_RECEIPTS,
    }


def _dispatch_issue_builder(
    response: bytes = _DISPATCH_RESPONSE, *, nonce_digest: str = _DIGEST
):
    async def builder(context: dict[str, object]) -> dict[str, object]:
        if context["duplicate"]:
            assert context["encrypted_issue_recovery"] == _ISSUE_RECOVERY
            return {"response": response}
        assert context["domain"] == DISPATCH_CAPABILITY_DOMAIN
        assert context["key_id"] == "offline-dispatch-key"
        assert context["other_key_id"] == "offline-media-key"
        assert context["algorithm_policy_id"] == "ecdsa-p256-sha256"
        assert context["issued_at"] < context["expires_at"]
        assert (context["expires_at"] - context["issued_at"]).total_seconds() <= 60
        return {
            "response": response,
            "nonce_digest": nonce_digest,
            "token_digest": hashlib.sha256(response).hexdigest(),
            "receipt_digest": _DIGEST,
            "encrypted_issue_recovery": _ISSUE_RECOVERY,
            "issued_at": context["issued_at"],
            "expires_at": context["expires_at"],
            "domain": context["domain"],
            "key_id": context["key_id"],
            "algorithm_policy_id": context["algorithm_policy_id"],
        }

    return builder


def _dispatch_consume_builder(response: bytes = _DISPATCH_CONSUME_RESPONSE):
    async def builder(context: dict[str, object]) -> dict[str, object]:
        if context["duplicate"]:
            assert context["encrypted_consume_recovery"] == _CONSUME_RECOVERY
            return {"response": response}
        assert context["domain"] == DISPATCH_CAPABILITY_DOMAIN
        assert context["key_id"] == "offline-dispatch-key"
        assert context["other_key_id"] == "offline-media-key"
        assert context["algorithm_policy_id"] == "ecdsa-p256-sha256"
        assert context["consumed_at"] < context["expires_at"]
        return {
            "response": response,
            "encrypted_consume_recovery": _CONSUME_RECOVERY,
        }

    return builder


def _media_builder(response: bytes = _MEDIA_RESPONSE, *, nonce_digest: str = _DIGEST):
    async def builder(context: dict[str, object]) -> dict[str, object]:
        if context["duplicate"]:
            assert context["encrypted_response_recovery"] == _MEDIA_RECOVERY
            return {"response": response}
        assert context["domain"] == MEDIA_CAPABILITY_DOMAIN
        assert context["key_id"] == "offline-media-key"
        assert context["other_key_id"] == "offline-dispatch-key"
        assert context["algorithm_policy_id"] == "ecdsa-p256-sha256"
        assert context["issued_at"] == context["committed_at"]
        assert context["expires_at"] == context["deadline_at"]
        assert (
            context["deadline_at"] - context["authority_wall_at"]
        ).total_seconds() == 60
        return {
            "response": response,
            "encrypted_response_recovery": _MEDIA_RECOVERY,
            "nonce_digest": nonce_digest,
            "token_digest": _DIGEST,
            "receipt_digest": _DIGEST,
            "issued_at": context["issued_at"],
            "expires_at": context["expires_at"],
            "domain": context["domain"],
            "key_id": context["key_id"],
            "algorithm_policy_id": context["algorithm_policy_id"],
        }

    return builder


async def _issue_dispatch(
    db_session, attempt, *, organization_id: int, nonce_digest: str = _DIGEST
):
    return await db_session.issue_onnuri_smoke_dispatch(
        attempt.attempt_uuid,
        organization_id=organization_id,
        builder=_dispatch_issue_builder(nonce_digest=nonce_digest),
    )


@pytest.mark.asyncio
async def test_v3_prerequisite_receipts_are_complete_write_once_and_idempotent(
    db_session,
):
    ids = await _seed_authority(db_session)
    async with db_session.async_session() as session:
        envelope = await session.get(OnnuriSmokeEnvelopeModel, ids["envelope_id"])
        database_now = (await session.execute(text("SELECT now()"))).scalar_one()
        envelope.state = "contained"
        envelope.contained_at = database_now
        envelope.containment_reason = "arming-contract-test"
        await session.commit()

    values = _arming(ids)
    omitted = dict(values)
    omitted.pop("provider_balance_currency_receipt_digest")
    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="prerequisite_receipts"
    ):
        await db_session.create_onnuri_smoke_envelope(**omitted)

    malformed = dict(values)
    malformed["supplier_signaling_media_receipt_digest"] = "A" * 64
    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="prerequisite_receipts"
    ):
        await db_session.create_onnuri_smoke_envelope(**malformed)

    armed = await db_session.create_onnuri_smoke_envelope(**values)
    assert armed.sealed_at is not None
    duplicate = await db_session.create_onnuri_smoke_envelope(**values)
    assert duplicate.id == armed.id

    replay = dict(values)
    replay["gate_decision_receipt_digest"] = _OTHER_DIGEST
    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="active_envelope_mismatch"
    ):
        await db_session.create_onnuri_smoke_envelope(**replay)


@pytest.mark.asyncio
async def test_v2_and_cross_tenant_authorities_cannot_start_live_transitions(
    db_session,
):
    ids = await _seed_authority(
        db_session, evaluator_version=ONNURI_SMOKE_AUTHORITY_V2
    )
    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="v3_prerequisites"
    ):
        await db_session.allocate_onnuri_smoke_attempt(
            **_allocation(ids, direction="outbound", key="legacy-v2")
        )
    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="registration_gate_not_authorized"
    ):
        await db_session.create_onnuri_registration_gate(
            envelope_uuid=ids["envelope_uuid"],
            organization_id=ids["organization_id"],
            operation_kind="register",
            request_digest=_DIGEST,
        )
    with pytest.raises(TelephonyNumberInventoryNotFoundError):
        await db_session.create_onnuri_registration_gate(
            envelope_uuid=ids["envelope_uuid"],
            organization_id=ids["other_organization_id"],
            operation_kind="register",
            request_digest=_DIGEST,
        )
    async with db_session.async_session() as session:
        attempts = (
            await session.execute(
                select(OnnuriSmokeAttemptModel).where(
                    OnnuriSmokeAttemptModel.envelope_id == ids["envelope_id"]
                )
            )
        ).scalars().all()
        gates = (
            await session.execute(
                select(OnnuriRegistrationGateModel).where(
                    OnnuriRegistrationGateModel.envelope_id == ids["envelope_id"]
                )
            )
        ).scalars().all()
        assert attempts == []
        assert gates == []


@pytest.mark.asyncio
async def test_v3_prerequisite_receipts_cannot_be_mutated_after_database_seal(
    db_session,
):
    ids = await _seed_authority(db_session)
    async with db_session.async_session() as session:
        savepoint = await session.begin_nested()
        with pytest.raises(DBAPIError):
            await session.execute(
                text(
                    "UPDATE onnuri_staging_smoke_envelopes "
                    "SET gate_decision_receipt_digest = :digest WHERE id = :id"
                ),
                {"digest": _OTHER_DIGEST, "id": ids["envelope_id"]},
            )
            await session.flush()
        await savepoint.rollback()
        stored = await session.get(OnnuriSmokeEnvelopeModel, ids["envelope_id"])
        assert stored is not None
        assert stored.gate_decision_receipt_digest == _GATE_DECISION_DIGEST

@pytest.mark.asyncio
async def test_exact_binding_global_budget_and_irreversible_ordinals(db_session):
    ids = await _seed_authority(db_session)

    rejected_overrides = [
        {"organization_id": ids["other_organization_id"]},
        {"proof_id": -1},
        {"inventory_id": -1},
        {"telephony_configuration_id": -1},
        {"workflow_id": -1},
        {"authenticated_operator_user_id": ids["outsider_id"]},
        {"workflow_owner_user_id": ids["operator_id"]},
        {"destination_hmac_digest": _OTHER_DIGEST},
    ]
    for ordinal, overrides in enumerate(rejected_overrides):
        with pytest.raises(TelephonyNumberInventoryConflictError):
            await db_session.allocate_onnuri_smoke_attempt(
                **_allocation(
                    ids, direction="outbound", key=f"rejected-{ordinal}", **overrides
                )
            )

    outbound = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="outbound", key="attempt-1")
    )
    assert (outbound.ordinal, outbound.state) == (1, "allocated")
    outbound, dispatch_response = await _issue_dispatch(
        db_session, outbound, organization_id=ids["organization_id"]
    )
    assert outbound.state == "dispatch_issued"
    assert dispatch_response == _DISPATCH_RESPONSE
    with pytest.raises(TelephonyNumberInventoryConflictError, match="concurrent"):
        await db_session.allocate_onnuri_smoke_attempt(
            **_allocation(ids, direction="inbound", key="concurrent")
        )
    await db_session.set_onnuri_smoke_terminal(
        outbound.attempt_uuid,
        organization_id=ids["organization_id"],
        terminal_class="failed",
        terminal_reason="offline-test",
    )

    inbound = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="inbound", key="attempt-2")
    )
    assert inbound.ordinal == 2
    await db_session.set_onnuri_smoke_terminal(
        inbound.attempt_uuid,
        organization_id=ids["organization_id"],
        terminal_class="failed",
        terminal_reason="offline-test",
    )
    with pytest.raises(TelephonyNumberInventoryConflictError, match="acknowledgement"):
        await db_session.allocate_onnuri_smoke_attempt(
            **_allocation(ids, direction="inbound", key="attempt-3-unacknowledged")
        )
    third = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(
            ids,
            direction="inbound",
            key="attempt-3",
            manual_acknowledgement_digest=_DIGEST,
            manual_acknowledged_at=datetime.now(UTC) - timedelta(seconds=30),
        )
    )
    await db_session.set_onnuri_smoke_terminal(
        third.attempt_uuid,
        organization_id=ids["organization_id"],
        terminal_class="failed",
        terminal_reason="offline-test",
    )
    with pytest.raises(TelephonyNumberInventoryConflictError, match="exhausted"):
        await db_session.allocate_onnuri_smoke_attempt(
            **_allocation(ids, direction="outbound", key="attempt-4")
        )

    async with db_session.async_session() as session:
        ordinals = (
            (
                await session.execute(
                    select(OnnuriSmokeAttemptModel.ordinal)
                    .where(OnnuriSmokeAttemptModel.envelope_id == ids["envelope_id"])
                    .order_by(OnnuriSmokeAttemptModel.ordinal)
                )
            )
            .scalars()
            .all()
        )
    assert ordinals == [1, 2, 3]


@pytest.mark.asyncio
async def test_dispatch_bind_truthful_mint_duplicate_recovery_and_media_sole_consume(
    db_session,
):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="outbound", key="outbound")
    )

    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="inbound_tuple_invalid"
    ):
        await db_session.bind_onnuri_smoke_stock_call(
            attempt.attempt_uuid,
            idempotency_key=attempt.idempotency_key,
            request_digest=attempt.allocation_request_digest,
            organization_id=ids["organization_id"],
            stock_call_id_digest=_DIGEST,
            callback_nonce_digest=_DIGEST,
            **_inbound_tuple(ids),
        )
    with pytest.raises(TelephonyNumberInventoryConflictError):
        await db_session.bind_onnuri_smoke_stock_call(
            attempt.attempt_uuid,
            idempotency_key=attempt.idempotency_key,
            request_digest=attempt.allocation_request_digest,
            organization_id=ids["organization_id"],
            stock_call_id_digest=_DIGEST,
            callback_nonce_digest=_DIGEST,
        )
    attempt, dispatch_response = await _issue_dispatch(
        db_session, attempt, organization_id=ids["organization_id"]
    )
    duplicate_attempt, duplicate_dispatch_response = await _issue_dispatch(
        db_session, attempt, organization_id=ids["organization_id"]
    )
    assert duplicate_attempt.id == attempt.id
    assert duplicate_dispatch_response == dispatch_response == _DISPATCH_RESPONSE
    with pytest.raises(TelephonyNumberInventoryConflictError):
        await db_session.consume_onnuri_smoke_dispatch(
            attempt.attempt_uuid,
            organization_id=ids["organization_id"],
            nonce_digest=_OTHER_DIGEST,
            token_digest=_DISPATCH_TOKEN_DIGEST,
            request_digest=_DIGEST,
            receipt_digest=_DIGEST,
            builder=_dispatch_consume_builder(),
        )
    consumed_dispatch, consume_response = (
        await db_session.consume_onnuri_smoke_dispatch(
            attempt.attempt_uuid,
            organization_id=ids["organization_id"],
            nonce_digest=_DIGEST,
            token_digest=_DISPATCH_TOKEN_DIGEST,
            request_digest=_DIGEST,
            receipt_digest=_DIGEST,
            account_id="account-1",
            application_id="application-1",
            run_id="run-1",
            builder=_dispatch_consume_builder(),
        )
    )
    duplicate_consumed_dispatch, duplicate_consume_response = (
        await db_session.consume_onnuri_smoke_dispatch(
            attempt.attempt_uuid,
            organization_id=ids["organization_id"],
            nonce_digest=_DIGEST,
            token_digest=_DISPATCH_TOKEN_DIGEST,
            request_digest=_DIGEST,
            receipt_digest=_DIGEST,
            account_id="account-1",
            application_id="application-1",
            run_id="run-1",
            builder=_dispatch_consume_builder(),
        )
    )
    assert duplicate_consumed_dispatch.id == consumed_dispatch.id
    assert (
        consumed_dispatch.account_id,
        consumed_dispatch.application_id,
        consumed_dispatch.run_id,
    ) == ("account-1", "application-1", "run-1")
    assert duplicate_consume_response == consume_response == _DISPATCH_CONSUME_RESPONSE
    bound = await db_session.bind_onnuri_smoke_stock_call(
        attempt.attempt_uuid,
        idempotency_key=attempt.idempotency_key,
        request_digest=attempt.allocation_request_digest,
        organization_id=ids["organization_id"],
        stock_call_id_digest=_DIGEST,
        callback_nonce_digest=_DIGEST,
        account_id="account-1",
        application_id="application-1",
        run_id="run-1",
    )
    duplicate_bound = await db_session.bind_onnuri_smoke_stock_call(
        attempt.attempt_uuid,
        idempotency_key=attempt.idempotency_key,
        request_digest=attempt.allocation_request_digest,
        organization_id=ids["organization_id"],
        stock_call_id_digest=_DIGEST,
        callback_nonce_digest=_DIGEST,
        account_id="account-1",
        application_id="application-1",
        run_id="run-1",
    )
    assert duplicate_bound.id == bound.id
    assert bound.stock_bound_at is not None
    assert duplicate_bound.stock_bound_at == bound.stock_bound_at
    with pytest.raises(TelephonyNumberInventoryNotFoundError):
        await db_session.bind_onnuri_smoke_stock_call(
            attempt.attempt_uuid,
            idempotency_key=attempt.idempotency_key,
            request_digest=attempt.allocation_request_digest,
            organization_id=-1,
            stock_call_id_digest=_DIGEST,
            callback_nonce_digest=_DIGEST,
            account_id="account-1",
            application_id="application-1",
            run_id="run-1",
        )
    with pytest.raises(TelephonyNumberInventoryConflictError, match="replay"):
        await db_session.bind_onnuri_smoke_stock_call(
            attempt.attempt_uuid,
            idempotency_key=attempt.idempotency_key,
            request_digest=attempt.allocation_request_digest,
            organization_id=ids["organization_id"],
            stock_call_id_digest=_OTHER_DIGEST,
            callback_nonce_digest=_DIGEST,
            account_id="account-1",
            application_id="application-1",
            run_id="run-1",
        )
    async with db_session.async_session() as session:
        media_before_answer = (
            (
                await session.execute(
                    select(OnnuriSmokeCapabilityConsumptionModel).where(
                        OnnuriSmokeCapabilityConsumptionModel.attempt_id == attempt.id,
                        OnnuriSmokeCapabilityConsumptionModel.kind == "media",
                    )
                )
            )
            .scalars()
            .all()
        )
        persisted_bound = await session.get(OnnuriSmokeAttemptModel, attempt.id)
        assert persisted_bound is not None
        assert persisted_bound.stock_bound_at == bound.stock_bound_at
    assert media_before_answer == []

    authority_wall = datetime.now(UTC) - timedelta(seconds=30)
    mint = {
        "attempt_uuid": attempt.attempt_uuid,
        "organization_id": ids["organization_id"],
        "idempotency_key": attempt.idempotency_key,
        "callback_nonce_digest": _DIGEST,
        "request_digest": attempt.allocation_request_digest,
        "stock_call_id_digest": _DIGEST,
        "authority_wall_at": authority_wall,
        "deadline_at": authority_wall + timedelta(seconds=60),
        "builder": _media_builder(),
        "account_id": "account-1",
        "application_id": "application-1",
        "run_id": "run-1",
    }
    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="inbound_tuple_invalid"
    ):
        await db_session.record_onnuri_outbound_answer_and_mint_media(
            **(_inbound_tuple(ids) | mint)
        )
    authorization, media_response = (
        await db_session.record_onnuri_outbound_answer_and_mint_media(**mint)
    )
    duplicate, duplicate_media_response = (
        await db_session.record_onnuri_outbound_answer_and_mint_media(**mint)
    )
    assert duplicate.id == authorization.id
    assert duplicate_media_response == media_response == _MEDIA_RESPONSE
    assert duplicate.encrypted_response_recovery == _MEDIA_RECOVERY
    assert duplicate.deadline_at == authorization.deadline_at
    assert authorization.authority_kind == "outbound_observed_answer"
    assert authorization.observed_carrier_answer_at == authority_wall
    assert authorization.budget_seconds == 60
    assert authorization.deadline_at == authority_wall + timedelta(seconds=60)
    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="answer_authority_invalid"
    ):
        await db_session.record_onnuri_outbound_answer_and_mint_media(
            **(mint | {"request_digest": _OTHER_DIGEST})
        )

    with pytest.raises(TelephonyNumberInventoryConflictError):
        await db_session.consume_onnuri_smoke_media(
            attempt.attempt_uuid,
            organization_id=ids["organization_id"],
            nonce_digest=_DIGEST,
            token_digest=_OTHER_DIGEST,
            stock_call_id_digest=_DIGEST,
            request_digest=_DIGEST,
            receipt_digest=_DIGEST,
        )
    consumed = await db_session.consume_onnuri_smoke_media(
        attempt.attempt_uuid,
        organization_id=ids["organization_id"],
        nonce_digest=_DIGEST,
        token_digest=_DIGEST,
        stock_call_id_digest=_DIGEST,
        request_digest=_DIGEST,
        receipt_digest=_DIGEST,
    )
    assert consumed.state == "running"
    with pytest.raises(TelephonyNumberInventoryConflictError):
        await db_session.consume_onnuri_smoke_media(
            attempt.attempt_uuid,
            organization_id=ids["organization_id"],
            nonce_digest=_DIGEST,
            token_digest=_DIGEST,
            stock_call_id_digest=_DIGEST,
            request_digest=_DIGEST,
            receipt_digest=_DIGEST,
        )
    async with db_session.async_session() as session:
        erased = await session.get(
            OnnuriSmokeAnswerAuthorizationModel, authorization.id
        )
    assert erased.encrypted_response_recovery is None
    assert erased.recovery_erased_at is not None


@pytest.mark.asyncio
async def test_dispatch_builder_failure_burns_issuance_before_retry(db_session):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="outbound", key="dispatch-builder-failure")
    )
    issue_calls = 0

    async def failing_builder(context):
        nonlocal issue_calls
        issue_calls += 1
        assert context["duplicate"] is False
        raise RuntimeError("offline-dispatch-builder-failure")

    with pytest.raises(RuntimeError, match="dispatch-builder-failure"):
        await db_session.issue_onnuri_smoke_dispatch(
            attempt.attempt_uuid,
            organization_id=ids["organization_id"],
            builder=failing_builder,
        )

    retry_calls = 0

    async def retry_builder(context):
        nonlocal retry_calls
        retry_calls += 1
        return await _dispatch_issue_builder()(context)

    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="issue_not_authorized"
    ):
        await db_session.issue_onnuri_smoke_dispatch(
            attempt.attempt_uuid,
            organization_id=ids["organization_id"],
            builder=retry_builder,
        )

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt.id)
        capabilities = (
            (
                await session.execute(
                    select(OnnuriSmokeCapabilityConsumptionModel).where(
                        OnnuriSmokeCapabilityConsumptionModel.attempt_id == attempt.id,
                        OnnuriSmokeCapabilityConsumptionModel.kind == "dispatch",
                    )
                )
            )
            .scalars()
            .all()
        )
    assert issue_calls == 1
    assert retry_calls == 0
    assert persisted.state == "dispatch_issuing"
    assert capabilities == []


@pytest.mark.asyncio
async def test_media_builder_failure_burns_issuance_before_retry(db_session):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="inbound", key="media-builder-failure")
    )
    inbound_tuple = _inbound_tuple(ids)
    await db_session.bind_onnuri_smoke_stock_call(
        attempt.attempt_uuid,
        idempotency_key=attempt.idempotency_key,
        request_digest=attempt.allocation_request_digest,
        organization_id=ids["organization_id"],
        stock_call_id_digest=_DIGEST,
        callback_nonce_digest=_DIGEST,
        **inbound_tuple,
    )
    authority_wall = datetime.now(UTC) - timedelta(seconds=30)
    mint = {
        "attempt_uuid": attempt.attempt_uuid,
        "organization_id": ids["organization_id"],
        "idempotency_key": attempt.idempotency_key,
        "callback_nonce_digest": _DIGEST,
        "request_digest": attempt.allocation_request_digest,
        "stock_call_id_digest": _DIGEST,
        "authority_wall_at": authority_wall,
        "deadline_at": authority_wall + timedelta(seconds=60),
        "approved_pause_milliseconds": 0,
        **inbound_tuple,
    }
    issue_calls = 0

    async def failing_builder(context):
        nonlocal issue_calls
        issue_calls += 1
        assert context["duplicate"] is False
        raise RuntimeError("offline-media-builder-failure")

    with pytest.raises(RuntimeError, match="media-builder-failure"):
        await db_session.commit_onnuri_inbound_answer_intent_and_mint_media(
            builder=failing_builder,
            **mint,
        )

    retry_calls = 0

    async def retry_builder(context):
        nonlocal retry_calls
        retry_calls += 1
        return await _media_builder()(context)

    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="answer_authority_invalid"
    ):
        await db_session.commit_onnuri_inbound_answer_intent_and_mint_media(
            builder=retry_builder,
            **mint,
        )

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt.id)
        authorizations = (
            (
                await session.execute(
                    select(OnnuriSmokeAnswerAuthorizationModel).where(
                        OnnuriSmokeAnswerAuthorizationModel.attempt_id == attempt.id
                    )
                )
            )
            .scalars()
            .all()
        )
        capabilities = (
            (
                await session.execute(
                    select(OnnuriSmokeCapabilityConsumptionModel).where(
                        OnnuriSmokeCapabilityConsumptionModel.attempt_id == attempt.id,
                        OnnuriSmokeCapabilityConsumptionModel.kind == "media",
                    )
                )
            )
            .scalars()
            .all()
        )
    assert issue_calls == 1
    assert retry_calls == 0
    assert persisted.state == "media_issuing"
    assert authorizations == []
    assert capabilities == []


@pytest.mark.asyncio
async def test_dispatch_finalization_observes_concurrent_containment(db_session):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="outbound", key="dispatch-contained-during-issue")
    )
    builder_calls = 0

    async def containing_builder(context):
        nonlocal builder_calls
        builder_calls += 1
        await db_session.set_onnuri_smoke_terminal(
            attempt.attempt_uuid,
            organization_id=ids["organization_id"],
            terminal_class="authority_failure",
            terminal_reason="contained-during-dispatch-issue",
            contain=True,
        )
        return await _dispatch_issue_builder()(context)

    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="issue_not_authorized"
    ):
        await db_session.issue_onnuri_smoke_dispatch(
            attempt.attempt_uuid,
            organization_id=ids["organization_id"],
            builder=containing_builder,
        )

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt.id)
        capabilities = (
            (
                await session.execute(
                    select(OnnuriSmokeCapabilityConsumptionModel).where(
                        OnnuriSmokeCapabilityConsumptionModel.attempt_id == attempt.id,
                        OnnuriSmokeCapabilityConsumptionModel.kind == "dispatch",
                    )
                )
            )
            .scalars()
            .all()
        )
    assert builder_calls == 1
    assert persisted.state == "contained"
    assert capabilities == []


@pytest.mark.asyncio
async def test_media_finalization_observes_concurrent_containment(db_session):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="inbound", key="media-contained-during-issue")
    )
    inbound_tuple = _inbound_tuple(ids)
    await db_session.bind_onnuri_smoke_stock_call(
        attempt.attempt_uuid,
        idempotency_key=attempt.idempotency_key,
        request_digest=attempt.allocation_request_digest,
        organization_id=ids["organization_id"],
        stock_call_id_digest=_DIGEST,
        callback_nonce_digest=_DIGEST,
        **inbound_tuple,
    )
    authority_wall = datetime.now(UTC) - timedelta(seconds=30)
    builder_calls = 0

    async def containing_builder(context):
        nonlocal builder_calls
        builder_calls += 1
        await db_session.set_onnuri_smoke_terminal(
            attempt.attempt_uuid,
            organization_id=ids["organization_id"],
            terminal_class="authority_failure",
            terminal_reason="contained-during-media-issue",
            contain=True,
        )
        return await _media_builder()(context)

    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="answer_authority_invalid"
    ):
        await db_session.commit_onnuri_inbound_answer_intent_and_mint_media(
            attempt_uuid=attempt.attempt_uuid,
            organization_id=ids["organization_id"],
            idempotency_key=attempt.idempotency_key,
            callback_nonce_digest=_DIGEST,
            request_digest=attempt.allocation_request_digest,
            stock_call_id_digest=_DIGEST,
            authority_wall_at=authority_wall,
            deadline_at=authority_wall + timedelta(seconds=60),
            approved_pause_milliseconds=0,
            builder=containing_builder,
            **inbound_tuple,
        )

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt.id)
        authorizations = (
            (
                await session.execute(
                    select(OnnuriSmokeAnswerAuthorizationModel).where(
                        OnnuriSmokeAnswerAuthorizationModel.attempt_id == attempt.id
                    )
                )
            )
            .scalars()
            .all()
        )
        capabilities = (
            (
                await session.execute(
                    select(OnnuriSmokeCapabilityConsumptionModel).where(
                        OnnuriSmokeCapabilityConsumptionModel.attempt_id == attempt.id,
                        OnnuriSmokeCapabilityConsumptionModel.kind == "media",
                    )
                )
            )
            .scalars()
            .all()
        )
    assert builder_calls == 1
    assert persisted.state == "contained"
    assert authorizations == []
    assert capabilities == []
@pytest.mark.asyncio
async def test_envelope_mutex_serializes_allocation_issue_and_containment(
    db_session,
):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="outbound", key="mutex-issue")
    )
    started = asyncio.Event()
    release = asyncio.Event()

    async def delayed_builder(context):
        started.set()
        await release.wait()
        return await _dispatch_issue_builder()(context)

    issue_task = asyncio.create_task(
        db_session.issue_onnuri_smoke_dispatch(
            attempt.attempt_uuid,
            organization_id=ids["organization_id"],
            builder=delayed_builder,
        )
    )
    await asyncio.wait_for(started.wait(), timeout=2)
    with pytest.raises(TelephonyNumberInventoryConflictError, match="concurrent_attempt"):
        await asyncio.wait_for(
            db_session.allocate_onnuri_smoke_attempt(
                **_allocation(ids, direction="inbound", key="mutex-allocation")
            ),
            timeout=2,
        )
    contained = await asyncio.wait_for(
        db_session.set_onnuri_smoke_terminal(
            attempt.attempt_uuid,
            organization_id=ids["organization_id"],
            terminal_class="operator_containment",
            terminal_reason="mutex-regression",
            contain=True,
        ),
        timeout=2,
    )
    release.set()
    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="issue_not_authorized"
    ):
        await asyncio.wait_for(issue_task, timeout=2)
    assert contained.state == "contained"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("idempotency_key", "mismatched-idempotency"),
        ("request_digest", _OTHER_DIGEST),
    ],
)
async def test_bind_rejects_mismatched_attempt_authority_without_transition(
    db_session, field: str, value: str
):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="inbound", key=f"bind-authority-{field}")
    )
    bind = {
        "idempotency_key": attempt.idempotency_key,
        "request_digest": attempt.allocation_request_digest,
        "organization_id": ids["organization_id"],
        "stock_call_id_digest": _DIGEST,
        "callback_nonce_digest": _DIGEST,
        **_inbound_tuple(ids),
    }
    bind[field] = value

    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="bind_not_authorized"
    ):
        await db_session.bind_onnuri_smoke_stock_call(
            attempt.attempt_uuid,
            **bind,
        )

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt.id)
        authorizations = (
            (
                await session.execute(
                    select(OnnuriSmokeAnswerAuthorizationModel).where(
                        OnnuriSmokeAnswerAuthorizationModel.attempt_id == attempt.id
                    )
                )
            )
            .scalars()
            .all()
        )
    assert persisted.state == "allocated"
    assert persisted.inbound_tuple_digest is None
    assert authorizations == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("idempotency_key", "mismatched-idempotency"),
        ("request_digest", _OTHER_DIGEST),
    ],
)
async def test_mint_rejects_mismatched_attempt_authority_without_transition(
    db_session, field: str, value: str
):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="inbound", key=f"mint-authority-{field}")
    )
    inbound_tuple = _inbound_tuple(ids)
    await db_session.bind_onnuri_smoke_stock_call(
        attempt.attempt_uuid,
        idempotency_key=attempt.idempotency_key,
        request_digest=attempt.allocation_request_digest,
        organization_id=ids["organization_id"],
        stock_call_id_digest=_DIGEST,
        callback_nonce_digest=_DIGEST,
        **inbound_tuple,
    )
    authority_wall = datetime.now(UTC) - timedelta(seconds=30)
    builder_calls = 0

    async def forbidden_builder(context):
        nonlocal builder_calls
        builder_calls += 1
        return await _media_builder()(context)

    mint = {
        "attempt_uuid": attempt.attempt_uuid,
        "organization_id": ids["organization_id"],
        "idempotency_key": attempt.idempotency_key,
        "callback_nonce_digest": _DIGEST,
        "request_digest": attempt.allocation_request_digest,
        "stock_call_id_digest": _DIGEST,
        "authority_wall_at": authority_wall,
        "deadline_at": authority_wall + timedelta(seconds=60),
        "approved_pause_milliseconds": 0,
        "builder": forbidden_builder,
        **inbound_tuple,
    }
    mint[field] = value

    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="answer_authority_invalid"
    ):
        await db_session.commit_onnuri_inbound_answer_intent_and_mint_media(
            **mint,
        )

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt.id)
        authorizations = (
            (
                await session.execute(
                    select(OnnuriSmokeAnswerAuthorizationModel).where(
                        OnnuriSmokeAnswerAuthorizationModel.attempt_id == attempt.id
                    )
                )
            )
            .scalars()
            .all()
        )
        media = (
            (
                await session.execute(
                    select(OnnuriSmokeCapabilityConsumptionModel).where(
                        OnnuriSmokeCapabilityConsumptionModel.attempt_id == attempt.id,
                        OnnuriSmokeCapabilityConsumptionModel.kind == "media",
                    )
                )
            )
            .scalars()
            .all()
        )
    assert builder_calls == 0
    assert persisted.state == "stock_bound"
    assert authorizations == []
    assert media == []


@pytest.mark.asyncio
async def test_inbound_tuple_rejects_wrong_attempt_without_transition(db_session):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="inbound", key="wrong-attempt-tuple")
    )
    wrong_attempt_uuid = str(uuid4())
    inbound_tuple = _inbound_tuple(ids)

    with pytest.raises(TelephonyNumberInventoryNotFoundError):
        await db_session.bind_onnuri_smoke_stock_call(
            wrong_attempt_uuid,
            idempotency_key=attempt.idempotency_key,
            request_digest=attempt.allocation_request_digest,
            organization_id=ids["organization_id"],
            stock_call_id_digest=_DIGEST,
            callback_nonce_digest=_DIGEST,
            **inbound_tuple,
        )

    authority_wall = datetime.now(UTC) - timedelta(seconds=30)
    with pytest.raises(TelephonyNumberInventoryNotFoundError):
        await db_session.commit_onnuri_inbound_answer_intent_and_mint_media(
            attempt_uuid=wrong_attempt_uuid,
            organization_id=ids["organization_id"],
            idempotency_key="wrong-attempt-tuple",
            callback_nonce_digest=_DIGEST,
            request_digest=_DIGEST,
            stock_call_id_digest=_DIGEST,
            authority_wall_at=authority_wall,
            deadline_at=authority_wall + timedelta(seconds=60),
            approved_pause_milliseconds=0,
            builder=_media_builder(),
            **inbound_tuple,
        )

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt.id)
        authorizations = (
            (
                await session.execute(
                    select(OnnuriSmokeAnswerAuthorizationModel).where(
                        OnnuriSmokeAnswerAuthorizationModel.attempt_id == attempt.id
                    )
                )
            )
            .scalars()
            .all()
        )
        media = (
            (
                await session.execute(
                    select(OnnuriSmokeCapabilityConsumptionModel).where(
                        OnnuriSmokeCapabilityConsumptionModel.attempt_id == attempt.id,
                        OnnuriSmokeCapabilityConsumptionModel.kind == "media",
                    )
                )
            )
            .scalars()
            .all()
        )
    assert persisted.state == "allocated"
    assert persisted.inbound_tuple_digest is None
    assert authorizations == []
    assert media == []


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["bind", "mint"])
async def test_inbound_tuple_rejects_retired_candidate_without_transition(
    db_session, stage: str
):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(
            ids,
            direction="inbound",
            key=f"retired-candidate-{stage}",
        )
    )
    inbound_tuple = _inbound_tuple(ids)
    if stage == "mint":
        await db_session.bind_onnuri_smoke_stock_call(
            attempt.attempt_uuid,
            idempotency_key=attempt.idempotency_key,
            request_digest=attempt.allocation_request_digest,
            organization_id=ids["organization_id"],
            stock_call_id_digest=_DIGEST,
            callback_nonce_digest=_DIGEST,
            **inbound_tuple,
        )

    async with db_session.async_session() as session:
        await session.execute(
            text("SET LOCAL recova.onnuri_candidate_lifecycle = 'retire'")
        )
        candidate = await session.get(
            OnnuriStagingCandidateModel,
            ids["candidate_id"],
            with_for_update=True,
        )
        candidate.state = "retired"
        candidate.retired_at = datetime.now(UTC)
        candidate.retired_by_user_id = ids["operator_id"]
        candidate.retired_reason = "partial-retirement-test"
        await session.commit()

    if stage == "bind":
        with pytest.raises(
            TelephonyNumberInventoryConflictError, match="inbound_tuple_invalid"
        ):
            await db_session.bind_onnuri_smoke_stock_call(
                attempt.attempt_uuid,
                idempotency_key=attempt.idempotency_key,
                request_digest=attempt.allocation_request_digest,
                organization_id=ids["organization_id"],
                stock_call_id_digest=_DIGEST,
                callback_nonce_digest=_DIGEST,
                **inbound_tuple,
            )
        expected_state = "allocated"
    else:
        authority_wall = datetime.now(UTC) - timedelta(seconds=30)
        with pytest.raises(
            TelephonyNumberInventoryConflictError, match="inbound_tuple_invalid"
        ):
            await db_session.commit_onnuri_inbound_answer_intent_and_mint_media(
                attempt_uuid=attempt.attempt_uuid,
                organization_id=ids["organization_id"],
                idempotency_key=attempt.idempotency_key,
                callback_nonce_digest=_DIGEST,
                request_digest=attempt.allocation_request_digest,
                stock_call_id_digest=_DIGEST,
                authority_wall_at=authority_wall,
                deadline_at=authority_wall + timedelta(seconds=60),
                approved_pause_milliseconds=0,
                builder=_media_builder(),
                **inbound_tuple,
            )
        expected_state = "stock_bound"

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt.id)
        authorizations = (
            (
                await session.execute(
                    select(OnnuriSmokeAnswerAuthorizationModel).where(
                        OnnuriSmokeAnswerAuthorizationModel.attempt_id == attempt.id
                    )
                )
            )
            .scalars()
            .all()
        )
        media = (
            (
                await session.execute(
                    select(OnnuriSmokeCapabilityConsumptionModel).where(
                        OnnuriSmokeCapabilityConsumptionModel.attempt_id == attempt.id,
                        OnnuriSmokeCapabilityConsumptionModel.kind == "media",
                    )
                )
            )
            .scalars()
            .all()
        )
    assert persisted.state == expected_state
    assert authorizations == []
    assert media == []


@pytest.mark.asyncio
async def test_inbound_tuple_rejects_cross_tenant_bind_and_mint_without_transition(
    db_session,
):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="inbound", key="cross-tenant-tuple")
    )
    inbound_tuple = _inbound_tuple(ids)

    with pytest.raises(TelephonyNumberInventoryNotFoundError):
        await db_session.bind_onnuri_smoke_stock_call(
            attempt.attempt_uuid,
            idempotency_key=attempt.idempotency_key,
            request_digest=attempt.allocation_request_digest,
            organization_id=ids["other_organization_id"],
            stock_call_id_digest=_DIGEST,
            callback_nonce_digest=_DIGEST,
            **inbound_tuple,
        )

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt.id)
    assert persisted.state == "allocated"
    assert persisted.inbound_tuple_digest is None

    await db_session.bind_onnuri_smoke_stock_call(
        attempt.attempt_uuid,
        idempotency_key=attempt.idempotency_key,
        request_digest=attempt.allocation_request_digest,
        organization_id=ids["organization_id"],
        stock_call_id_digest=_DIGEST,
        callback_nonce_digest=_DIGEST,
        **inbound_tuple,
    )
    authority_wall = datetime.now(UTC) - timedelta(seconds=30)
    with pytest.raises(TelephonyNumberInventoryNotFoundError):
        await db_session.commit_onnuri_inbound_answer_intent_and_mint_media(
            attempt_uuid=attempt.attempt_uuid,
            organization_id=ids["other_organization_id"],
            idempotency_key="cross-tenant-tuple",
            callback_nonce_digest=_DIGEST,
            request_digest=_DIGEST,
            stock_call_id_digest=_DIGEST,
            authority_wall_at=authority_wall,
            deadline_at=authority_wall + timedelta(seconds=60),
            approved_pause_milliseconds=0,
            builder=_media_builder(),
            **inbound_tuple,
        )

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt.id)
        authorizations = (
            (
                await session.execute(
                    select(OnnuriSmokeAnswerAuthorizationModel).where(
                        OnnuriSmokeAnswerAuthorizationModel.attempt_id == attempt.id
                    )
                )
            )
            .scalars()
            .all()
        )
    assert persisted.state == "stock_bound"
    assert authorizations == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field",
    [
        "source_account_id",
        "source_application_id",
        "did_digest",
        "caller_mobile_digest",
        "candidate_digest",
    ],
)
async def test_inbound_tuple_mismatch_rejects_bind_without_authority(
    db_session, field: str
):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="inbound", key=f"bind-mismatch-{field}")
    )
    inbound_tuple = _inbound_tuple(ids)
    inbound_tuple[field] = (
        "mismatched-authority" if field.startswith("source_") else _OTHER_DIGEST
    )

    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="inbound_tuple_invalid"
    ):
        await db_session.bind_onnuri_smoke_stock_call(
            attempt.attempt_uuid,
            idempotency_key=attempt.idempotency_key,
            request_digest=attempt.allocation_request_digest,
            organization_id=ids["organization_id"],
            stock_call_id_digest=_DIGEST,
            callback_nonce_digest=_DIGEST,
            **inbound_tuple,
        )

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt.id)
        authorizations = (
            (
                await session.execute(
                    select(OnnuriSmokeAnswerAuthorizationModel).where(
                        OnnuriSmokeAnswerAuthorizationModel.attempt_id == attempt.id
                    )
                )
            )
            .scalars()
            .all()
        )
        media = (
            (
                await session.execute(
                    select(OnnuriSmokeCapabilityConsumptionModel).where(
                        OnnuriSmokeCapabilityConsumptionModel.attempt_id == attempt.id,
                        OnnuriSmokeCapabilityConsumptionModel.kind == "media",
                    )
                )
            )
            .scalars()
            .all()
        )
    assert persisted.state == "allocated"
    assert persisted.stock_bound_at is None
    assert authorizations == []
    assert media == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field",
    [
        "source_account_id",
        "source_application_id",
        "did_digest",
        "caller_mobile_digest",
        "candidate_digest",
    ],
)
async def test_inbound_tuple_mismatch_rejects_mint_after_valid_bind(
    db_session, field: str
):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="inbound", key=f"mint-mismatch-{field}")
    )
    inbound_tuple = _inbound_tuple(ids)
    await db_session.bind_onnuri_smoke_stock_call(
        attempt.attempt_uuid,
        idempotency_key=attempt.idempotency_key,
        request_digest=attempt.allocation_request_digest,
        organization_id=ids["organization_id"],
        stock_call_id_digest=_DIGEST,
        callback_nonce_digest=_DIGEST,
        **inbound_tuple,
    )
    inbound_tuple[field] = (
        "mismatched-authority" if field.startswith("source_") else _OTHER_DIGEST
    )
    authority_wall = datetime.now(UTC) - timedelta(seconds=30)

    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="inbound_tuple_invalid"
    ):
        await db_session.commit_onnuri_inbound_answer_intent_and_mint_media(
            attempt_uuid=attempt.attempt_uuid,
            organization_id=ids["organization_id"],
            idempotency_key=attempt.idempotency_key,
            callback_nonce_digest=_DIGEST,
            request_digest=attempt.allocation_request_digest,
            stock_call_id_digest=_DIGEST,
            authority_wall_at=authority_wall,
            deadline_at=authority_wall + timedelta(seconds=60),
            approved_pause_milliseconds=0,
            builder=_media_builder(),
            **inbound_tuple,
        )

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt.id)
        authorizations = (
            (
                await session.execute(
                    select(OnnuriSmokeAnswerAuthorizationModel).where(
                        OnnuriSmokeAnswerAuthorizationModel.attempt_id == attempt.id
                    )
                )
            )
            .scalars()
            .all()
        )
        media = (
            (
                await session.execute(
                    select(OnnuriSmokeCapabilityConsumptionModel).where(
                        OnnuriSmokeCapabilityConsumptionModel.attempt_id == attempt.id,
                        OnnuriSmokeCapabilityConsumptionModel.kind == "media",
                    )
                )
            )
            .scalars()
            .all()
        )
    assert persisted.state == "stock_bound"
    assert authorizations == []
    assert media == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("credential_field", "tuple_field"),
    [
        ("account_id", "source_account_id"),
        ("application_id", "source_application_id"),
    ],
)
async def test_inbound_duplicate_bind_rejects_rotated_authority_tuple(
    db_session, credential_field: str, tuple_field: str
):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(
            ids,
            direction="inbound",
            key=f"bind-tuple-replay-{credential_field}",
        )
    )
    inbound_tuple = _inbound_tuple(ids)
    bound = await db_session.bind_onnuri_smoke_stock_call(
        attempt.attempt_uuid,
        idempotency_key=attempt.idempotency_key,
        request_digest=attempt.allocation_request_digest,
        organization_id=ids["organization_id"],
        stock_call_id_digest=_DIGEST,
        callback_nonce_digest=_DIGEST,
        **inbound_tuple,
    )
    original_tuple_digest = bound.inbound_tuple_digest
    assert original_tuple_digest

    rotated_value = f"rotated-{credential_field}"
    async with db_session.async_session() as session:
        configuration = await session.get(
            TelephonyConfigurationModel, ids["configuration_id"]
        )
        configuration.credentials = {
            **configuration.credentials,
            credential_field: rotated_value,
        }
        await session.commit()

    with pytest.raises(TelephonyNumberInventoryConflictError, match="bind_replay"):
        await db_session.bind_onnuri_smoke_stock_call(
            attempt.attempt_uuid,
            idempotency_key=attempt.idempotency_key,
            request_digest=attempt.allocation_request_digest,
            organization_id=ids["organization_id"],
            stock_call_id_digest=_DIGEST,
            callback_nonce_digest=_DIGEST,
            **(inbound_tuple | {tuple_field: rotated_value}),
        )

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt.id)
        authorizations = (
            (
                await session.execute(
                    select(OnnuriSmokeAnswerAuthorizationModel).where(
                        OnnuriSmokeAnswerAuthorizationModel.attempt_id == attempt.id
                    )
                )
            )
            .scalars()
            .all()
        )
    assert persisted.state == "stock_bound"
    assert persisted.inbound_tuple_digest == original_tuple_digest
    assert authorizations == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("credential_field", "tuple_field"),
    [
        ("account_id", "source_account_id"),
        ("application_id", "source_application_id"),
    ],
)
async def test_inbound_duplicate_mint_rejects_rotated_authority_tuple(
    db_session, credential_field: str, tuple_field: str
):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(
            ids,
            direction="inbound",
            key=f"mint-tuple-replay-{credential_field}",
        )
    )
    inbound_tuple = _inbound_tuple(ids)
    await db_session.bind_onnuri_smoke_stock_call(
        attempt.attempt_uuid,
        idempotency_key=attempt.idempotency_key,
        request_digest=attempt.allocation_request_digest,
        organization_id=ids["organization_id"],
        stock_call_id_digest=_DIGEST,
        callback_nonce_digest=_DIGEST,
        **inbound_tuple,
    )
    authority_wall = datetime.now(UTC) - timedelta(seconds=30)
    mint = {
        "attempt_uuid": attempt.attempt_uuid,
        "organization_id": ids["organization_id"],
        "idempotency_key": attempt.idempotency_key,
        "callback_nonce_digest": _DIGEST,
        "request_digest": attempt.allocation_request_digest,
        "stock_call_id_digest": _DIGEST,
        "authority_wall_at": authority_wall,
        "deadline_at": authority_wall + timedelta(seconds=60),
        "approved_pause_milliseconds": 0,
        "builder": _media_builder(),
        **inbound_tuple,
    }
    authorization, media_response = (
        await db_session.commit_onnuri_inbound_answer_intent_and_mint_media(**mint)
    )

    rotated_value = f"rotated-{credential_field}"
    async with db_session.async_session() as session:
        configuration = await session.get(
            TelephonyConfigurationModel, ids["configuration_id"]
        )
        configuration.credentials = {
            **configuration.credentials,
            credential_field: rotated_value,
        }
        await session.commit()

    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="inbound_tuple_invalid"
    ):
        await db_session.commit_onnuri_inbound_answer_intent_and_mint_media(
            **(mint | {tuple_field: rotated_value})
        )

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt.id)
        authorizations = (
            (
                await session.execute(
                    select(OnnuriSmokeAnswerAuthorizationModel).where(
                        OnnuriSmokeAnswerAuthorizationModel.attempt_id == attempt.id
                    )
                )
            )
            .scalars()
            .all()
        )
        media = (
            (
                await session.execute(
                    select(OnnuriSmokeCapabilityConsumptionModel).where(
                        OnnuriSmokeCapabilityConsumptionModel.attempt_id == attempt.id,
                        OnnuriSmokeCapabilityConsumptionModel.kind == "media",
                    )
                )
            )
            .scalars()
            .all()
        )
    assert persisted.state == "inbound_answer_committed_media_issued"
    assert [item.id for item in authorizations] == [authorization.id]
    assert len(media) == 1
    assert media_response == _MEDIA_RESPONSE


@pytest.mark.asyncio
async def test_inbound_preanswer_deadline_replay_expiry_and_containment(db_session):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="inbound", key="inbound")
    )
    bound = await db_session.bind_onnuri_smoke_stock_call(
        attempt.attempt_uuid,
        idempotency_key=attempt.idempotency_key,
        request_digest=attempt.allocation_request_digest,
        organization_id=ids["organization_id"],
        stock_call_id_digest=_DIGEST,
        callback_nonce_digest=_DIGEST,
        **_inbound_tuple(ids),
    )
    duplicate_bound = await db_session.bind_onnuri_smoke_stock_call(
        attempt.attempt_uuid,
        idempotency_key=attempt.idempotency_key,
        request_digest=attempt.allocation_request_digest,
        organization_id=ids["organization_id"],
        stock_call_id_digest=_DIGEST,
        callback_nonce_digest=_DIGEST,
        **_inbound_tuple(ids),
    )
    assert duplicate_bound.id == bound.id
    assert duplicate_bound.stock_bound_at == bound.stock_bound_at
    stale_wall = datetime.now(UTC) - timedelta(seconds=2)
    stale = {
        "attempt_uuid": attempt.attempt_uuid,
        "organization_id": ids["organization_id"],
        "idempotency_key": attempt.idempotency_key,
        "callback_nonce_digest": _DIGEST,
        "request_digest": attempt.allocation_request_digest,
        "stock_call_id_digest": _DIGEST,
        "authority_wall_at": stale_wall,
        "deadline_at": stale_wall + timedelta(seconds=1),
        "approved_pause_milliseconds": 0,
        "builder": _media_builder(),
        **_inbound_tuple(ids),
    }
    with pytest.raises(TelephonyNumberInventoryConflictError, match="invalid"):
        await db_session.commit_onnuri_inbound_answer_intent_and_mint_media(**stale)

    authority_wall = datetime.now(UTC) - timedelta(seconds=30)
    mint = stale | {
        "authority_wall_at": authority_wall,
        "deadline_at": authority_wall + timedelta(seconds=60),
    }
    authorization, media_response = (
        await db_session.commit_onnuri_inbound_answer_intent_and_mint_media(**mint)
    )
    assert media_response == _MEDIA_RESPONSE
    assert authorization.authority_kind == "inbound_preanswer_commit"
    assert authorization.observed_carrier_answer_at is None
    authorization_id = authorization.id
    attempt_uuid = attempt.attempt_uuid

    duplicate_authorization, duplicate_media_response = (
        await db_session.commit_onnuri_inbound_answer_intent_and_mint_media(**mint)
    )
    assert duplicate_authorization.id == authorization_id
    assert duplicate_media_response == media_response
    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="answer_authority_invalid"
    ):
        await db_session.commit_onnuri_inbound_answer_intent_and_mint_media(
            **(mint | {"request_digest": _OTHER_DIGEST})
        )

    contained = await db_session.set_onnuri_smoke_terminal(
        attempt_uuid,
        organization_id=ids["organization_id"],
        terminal_class="authority_failure",
        terminal_reason="offline-containment",
        contain=True,
    )
    assert contained.state == "contained"
    async with db_session.async_session() as session:
        envelope = await session.get(OnnuriSmokeEnvelopeModel, ids["envelope_id"])
    assert envelope.state == "contained"
    with pytest.raises(TelephonyNumberInventoryConflictError):
        await db_session.allocate_onnuri_smoke_attempt(
            **_allocation(ids, direction="outbound", key="after-containment")
        )


@pytest.mark.asyncio
async def test_issued_capability_policy_is_database_immutable(db_session):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="outbound", key="immutable-capability")
    )
    attempt, _ = await _issue_dispatch(
        db_session, attempt, organization_id=ids["organization_id"]
    )

    async with db_session.async_session() as session:
        capability = (
            await session.execute(
                select(OnnuriSmokeCapabilityConsumptionModel).where(
                    OnnuriSmokeCapabilityConsumptionModel.attempt_id == attempt.id,
                    OnnuriSmokeCapabilityConsumptionModel.kind == "dispatch",
                )
            )
        ).scalar_one()
        capability.domain = MEDIA_CAPABILITY_DOMAIN
        with pytest.raises(DBAPIError, match="immutable"):
            await session.flush()


@pytest.mark.asyncio
async def test_stock_bound_timestamp_is_database_write_once(db_session):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="outbound", key="immutable-bind-time")
    )
    attempt, _ = await _issue_dispatch(
        db_session, attempt, organization_id=ids["organization_id"]
    )
    attempt, _ = await db_session.consume_onnuri_smoke_dispatch(
        attempt.attempt_uuid,
        organization_id=ids["organization_id"],
        nonce_digest=_DIGEST,
        token_digest=_DISPATCH_TOKEN_DIGEST,
        request_digest=_DIGEST,
        receipt_digest=_DIGEST,
        account_id="account-1",
        application_id="application-1",
        run_id="run-1",
        builder=_dispatch_consume_builder(),
    )
    bound = await db_session.bind_onnuri_smoke_stock_call(
        attempt.attempt_uuid,
        idempotency_key=attempt.idempotency_key,
        request_digest=attempt.allocation_request_digest,
        organization_id=ids["organization_id"],
        stock_call_id_digest=_DIGEST,
        callback_nonce_digest=_DIGEST,
        account_id="account-1",
        application_id="application-1",
        run_id="run-1",
    )
    bound_id = bound.id
    bound_at = bound.stock_bound_at

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, bound_id)
        persisted.stock_bound_at = bound_at + timedelta(seconds=1)
        with pytest.raises(DBAPIError, match="write-once"):
            await session.flush()


@pytest.mark.asyncio
@pytest.mark.parametrize("replacement", [_OTHER_DIGEST, None])
async def test_bind_callback_nonce_digest_is_database_write_once(
    db_session, replacement: str | None
):
    ids = await _seed_authority(db_session)
    replacement_tag = "null" if replacement is None else "changed"
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(
            ids,
            direction="inbound",
            key=f"immutable-bind-callback-{replacement_tag}",
        )
    )
    bound = await db_session.bind_onnuri_smoke_stock_call(
        attempt.attempt_uuid,
        idempotency_key=attempt.idempotency_key,
        request_digest=attempt.allocation_request_digest,
        organization_id=ids["organization_id"],
        stock_call_id_digest=_DIGEST,
        callback_nonce_digest=_DIGEST,
        **_inbound_tuple(ids),
    )

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, bound.id)
        persisted.bind_callback_nonce_digest = replacement
        with pytest.raises(DBAPIError, match="write-once"):
            await session.flush()


@pytest.mark.asyncio
@pytest.mark.parametrize("replacement", [_OTHER_DIGEST, None])
async def test_inbound_tuple_digest_is_database_write_once(
    db_session, replacement: str | None
):
    ids = await _seed_authority(db_session)
    replacement_tag = "null" if replacement is None else "changed"
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(
            ids,
            direction="inbound",
            key=f"immutable-inbound-tuple-{replacement_tag}",
        )
    )
    bound = await db_session.bind_onnuri_smoke_stock_call(
        attempt.attempt_uuid,
        idempotency_key=attempt.idempotency_key,
        request_digest=attempt.allocation_request_digest,
        organization_id=ids["organization_id"],
        stock_call_id_digest=_DIGEST,
        callback_nonce_digest=_DIGEST,
        **_inbound_tuple(ids),
    )

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, bound.id)
        persisted.inbound_tuple_digest = replacement
        with pytest.raises(DBAPIError, match="write-once"):
            await session.flush()


@pytest.mark.asyncio
async def test_database_rejects_issuance_rewind_and_envelope_revival(db_session):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="outbound", key="database-state-rewind")
    )
    attempt_id = attempt.id
    attempt_uuid = attempt.attempt_uuid

    async def failing_builder(context):
        assert context["duplicate"] is False
        raise RuntimeError("offline-rewind-builder-failure")

    with pytest.raises(RuntimeError, match="rewind-builder-failure"):
        await db_session.issue_onnuri_smoke_dispatch(
            attempt_uuid,
            organization_id=ids["organization_id"],
            builder=failing_builder,
        )

    async with db_session.async_session() as session:
        savepoint = await session.begin_nested()
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt_id)
        persisted.state = "allocated"
        with pytest.raises(DBAPIError, match="forward-only"):
            await session.flush()
        await savepoint.rollback()

    contained = await db_session.set_onnuri_smoke_terminal(
        attempt_uuid,
        organization_id=ids["organization_id"],
        terminal_class="authority_failure",
        terminal_reason="database-revival-test",
        contain=True,
    )
    assert contained.state == "contained"

    async with db_session.async_session() as session:
        savepoint = await session.begin_nested()
        envelope = await session.get(OnnuriSmokeEnvelopeModel, ids["envelope_id"])
        envelope.state = "armed"
        envelope.contained_at = None
        envelope.containment_reason = None
        with pytest.raises(DBAPIError, match="forward-only"):
            await session.flush()
        await savepoint.rollback()


@pytest.mark.asyncio
async def test_database_rejects_consumption_and_answer_evidence_rewrites(db_session):
    ids = await _seed_authority(db_session)
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="outbound", key="database-evidence-rewrite")
    )
    attempt, _ = await _issue_dispatch(
        db_session, attempt, organization_id=ids["organization_id"]
    )
    attempt, _ = await db_session.consume_onnuri_smoke_dispatch(
        attempt.attempt_uuid,
        organization_id=ids["organization_id"],
        nonce_digest=_DIGEST,
        token_digest=_DISPATCH_TOKEN_DIGEST,
        request_digest=attempt.allocation_request_digest,
        receipt_digest=_DIGEST,
        account_id="account-1",
        application_id="application-1",
        run_id="run-1",
        builder=_dispatch_consume_builder(),
    )
    await db_session.bind_onnuri_smoke_stock_call(
        attempt.attempt_uuid,
        idempotency_key=attempt.idempotency_key,
        request_digest=attempt.allocation_request_digest,
        organization_id=ids["organization_id"],
        stock_call_id_digest=_DIGEST,
        callback_nonce_digest=_DIGEST,
        account_id="account-1",
        application_id="application-1",
        run_id="run-1",
    )
    authority_wall = datetime.now(UTC) - timedelta(seconds=30)
    authorization, _ = await db_session.record_onnuri_outbound_answer_and_mint_media(
        attempt_uuid=attempt.attempt_uuid,
        organization_id=ids["organization_id"],
        idempotency_key=attempt.idempotency_key,
        callback_nonce_digest=_DIGEST,
        request_digest=attempt.allocation_request_digest,
        stock_call_id_digest=_DIGEST,
        authority_wall_at=authority_wall,
        deadline_at=authority_wall + timedelta(seconds=60),
        builder=_media_builder(),
        account_id="account-1",
        application_id="application-1",
        run_id="run-1",
    )
    running = await db_session.consume_onnuri_smoke_media(
        attempt.attempt_uuid,
        organization_id=ids["organization_id"],
        nonce_digest=_DIGEST,
        token_digest=_DIGEST,
        stock_call_id_digest=_DIGEST,
        request_digest=attempt.allocation_request_digest,
        receipt_digest=_DIGEST,
    )
    assert running.state == "running"
    attempt_id = running.id
    authorization_id = authorization.id

    async with db_session.async_session() as session:
        savepoint = await session.begin_nested()
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt_id)
        persisted.state = "outbound_answer_recorded_media_issued"
        with pytest.raises(DBAPIError, match="forward-only"):
            await session.flush()
        await savepoint.rollback()

    async with db_session.async_session() as session:
        savepoint = await session.begin_nested()
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt_id)
        persisted.observed_carrier_answer_at = None
        with pytest.raises(DBAPIError, match="write-once"):
            await session.flush()
        await savepoint.rollback()

    async with db_session.async_session() as session:
        savepoint = await session.begin_nested()
        capability = (
            await session.execute(
                select(OnnuriSmokeCapabilityConsumptionModel).where(
                    OnnuriSmokeCapabilityConsumptionModel.attempt_id == attempt_id,
                    OnnuriSmokeCapabilityConsumptionModel.kind == "media",
                )
            )
        ).scalar_one()
        capability.consumed_at = None
        with pytest.raises(DBAPIError, match="consumption is write-once"):
            await session.flush()
        await savepoint.rollback()

    async with db_session.async_session() as session:
        savepoint = await session.begin_nested()
        persisted_authorization = await session.get(
            OnnuriSmokeAnswerAuthorizationModel, authorization_id
        )
        persisted_authorization.observed_carrier_answer_at = None
        with pytest.raises(DBAPIError, match="immutable"):
            await session.flush()
        await savepoint.rollback()


async def _stock_bound_attempt(
    db_session, *, key: str, stock_call_id_digest: str = _DIGEST
):
    ids = await _seed_authority(db_session)
    capability_digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    attempt = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="outbound", key=key)
    )
    attempt, _ = await _issue_dispatch(
        db_session,
        attempt,
        organization_id=ids["organization_id"],
        nonce_digest=capability_digest,
    )
    attempt, _ = await db_session.consume_onnuri_smoke_dispatch(
        attempt.attempt_uuid,
        organization_id=ids["organization_id"],
        nonce_digest=capability_digest,
        token_digest=_DISPATCH_TOKEN_DIGEST,
        request_digest=_DIGEST,
        receipt_digest=_DIGEST,
        account_id="facade-account",
        application_id="facade-application",
        run_id="facade-run",
        builder=_dispatch_consume_builder(),
    )
    attempt = await db_session.bind_onnuri_smoke_stock_call(
        attempt.attempt_uuid,
        organization_id=ids["organization_id"],
        idempotency_key=attempt.idempotency_key,
        request_digest=attempt.allocation_request_digest,
        stock_call_id_digest=stock_call_id_digest,
        callback_nonce_digest=_DIGEST,
        account_id="facade-account",
        application_id="facade-application",
        run_id="facade-run",
    )
    return ids, attempt
@pytest.mark.asyncio
async def test_database_guard_rejects_stock_bound_running_bypass(db_session):
    ids, attempt = await _stock_bound_attempt(
        db_session, key="facade-running-bypass"
    )
    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt.id)
        assert persisted is not None
        persisted.state = "running"
        with pytest.raises(DBAPIError, match="forward-only"):
            await session.flush()
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("account_id", "swapped-account"),
        ("application_id", "swapped-application"),
        ("run_id", "swapped-run"),
    ),
)
async def test_facade_context_swaps_are_rejected_at_bind_and_media_mint(
    db_session, field, value
):
    ids, attempt = await _stock_bound_attempt(
        db_session, key=f"facade-context-swap-{field}"
    )
    context = {
        "account_id": "facade-account",
        "application_id": "facade-application",
        "run_id": "facade-run",
    }
    context[field] = value
    with pytest.raises(TelephonyNumberInventoryConflictError, match="bind_replay"):
        await db_session.bind_onnuri_smoke_stock_call(
            attempt.attempt_uuid,
            organization_id=ids["organization_id"],
            idempotency_key=attempt.idempotency_key,
            request_digest=attempt.allocation_request_digest,
            stock_call_id_digest=attempt.stock_call_id_digest,
            callback_nonce_digest=_DIGEST,
            **context,
        )
    authority_wall = datetime.now(UTC) - timedelta(seconds=30)
    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="context_mismatch"
    ):
        await db_session.record_onnuri_outbound_answer_and_mint_media(
            attempt_uuid=attempt.attempt_uuid,
            organization_id=ids["organization_id"],
            idempotency_key=attempt.idempotency_key,
            callback_nonce_digest=_DIGEST,
            request_digest=attempt.allocation_request_digest,
            stock_call_id_digest=attempt.stock_call_id_digest,
            authority_wall_at=authority_wall,
            deadline_at=authority_wall + timedelta(seconds=60),
            builder=_media_builder(),
            **context,
        )


async def _running_attempt(
    db_session, *, key: str, stock_call_id_digest: str = _DIGEST
):
    ids, attempt = await _stock_bound_attempt(
        db_session, key=key, stock_call_id_digest=stock_call_id_digest
    )
    media_digest = hashlib.sha256(f"{key}:media".encode("utf-8")).hexdigest()
    authority_wall = datetime.now(UTC) - timedelta(seconds=30)
    await db_session.record_onnuri_outbound_answer_and_mint_media(
        attempt_uuid=attempt.attempt_uuid,
        organization_id=ids["organization_id"],
        idempotency_key=attempt.idempotency_key,
        callback_nonce_digest=_DIGEST,
        request_digest=attempt.allocation_request_digest,
        stock_call_id_digest=stock_call_id_digest,
        authority_wall_at=authority_wall,
        deadline_at=authority_wall + timedelta(seconds=60),
        builder=_media_builder(nonce_digest=media_digest),
        account_id="facade-account",
        application_id="facade-application",
        run_id="facade-run",
    )
    attempt = await db_session.consume_onnuri_smoke_media(
        attempt.attempt_uuid,
        organization_id=ids["organization_id"],
        nonce_digest=media_digest,
        token_digest=_DIGEST,
        stock_call_id_digest=stock_call_id_digest,
        request_digest=attempt.allocation_request_digest,
        receipt_digest=_DIGEST,
    )
    return ids, attempt


def _facade_context(attempt, ids, **overrides):
    context = {
        "organization_id": ids["organization_id"],
        "account_id": "facade-account",
        "application_id": "facade-application",
        "run_id": "facade-run",
        "attempt_uuid": attempt.attempt_uuid,
        "stock_call_id_digest": attempt.stock_call_id_digest,
    }
    context.update(overrides)
    return context


async def _facade_snapshot(db_session, attempt_id: int, envelope_id: int):
    async with db_session.async_session() as session:
        attempt = await session.get(OnnuriSmokeAttemptModel, attempt_id)
        envelope = await session.get(OnnuriSmokeEnvelopeModel, envelope_id)
        event_count = (
            await session.execute(
                select(OnnuriSmokeCallbackEventModel).where(
                    OnnuriSmokeCallbackEventModel.attempt_id == attempt_id
                )
            )
        ).scalars().all()
    assert attempt is not None
    assert envelope is not None
    return (
        attempt.state,
        attempt.terminal_class,
        attempt.terminal_reason,
        attempt.contained_at,
        attempt.terminal_at,
        envelope.state,
        envelope.containment_reason,
        len(event_count),
    )
async def _refresh_facade_authority_fingerprints(db_session):
    async with db_session.async_session() as session:
        await session.execute(
            text("""
                DO $$
                DECLARE object_name text;
                DECLARE definition text;
                BEGIN
                  FOREACH object_name IN ARRAY ARRAY[
                    'onnuri_smoke_authority_row_guard',
                    'onnuri_smoke_facade_context_guard'
                  ] LOOP
                    SELECT regexp_replace(
                      pg_get_functiondef(p.oid), E'[[:space:]]+', ' ', 'g'
                    ) INTO definition
                    FROM pg_proc p
                    JOIN pg_namespace n ON n.oid = p.pronamespace
                    WHERE p.proname = object_name
                      AND n.nspname = current_schema()
                      AND p.pronargs = 0;
                    EXECUTE format(
                      'COMMENT ON FUNCTION %I.%I() IS %L',
                      current_schema(), object_name,
                      'onnuri-smoke-definition:' || definition
                    );
                  END LOOP;
                  FOR object_name, definition IN
                    SELECT c.conname,
                           regexp_replace(
                             pg_get_constraintdef(c.oid),
                             E'[[:space:]]+', ' ', 'g'
                           )
                    FROM pg_constraint c
                    JOIN pg_class r ON r.oid = c.conrelid
                    JOIN pg_namespace n ON n.oid = r.relnamespace
                    WHERE n.nspname = current_schema()
                      AND (
                        c.conname IN (
                          'ck_onnuri_smoke_attempt_bound_context',
                          'uq_onnuri_smoke_callback_nonce',
                          'ck_onnuri_smoke_callback_event_type',
                          'ck_onnuri_smoke_callback_duration'
                        )
                        OR (
                          r.relname = 'onnuri_staging_smoke_callback_events'
                          AND c.contype = 'f'
                        )
                      )
                  LOOP
                    EXECUTE format(
                      'COMMENT ON CONSTRAINT %I ON %I.%I IS %L',
                      object_name,
                      current_schema(),
                      CASE
                        WHEN object_name = 'ck_onnuri_smoke_attempt_bound_context'
                          THEN 'onnuri_staging_smoke_attempts'
                        ELSE 'onnuri_staging_smoke_callback_events'
                      END,
                      'onnuri-smoke-definition:' || definition
                    );
                  END LOOP;
                END $$;
            """)
        )
        await session.commit()


@pytest.mark.asyncio
async def test_facade_authority_readiness_rejects_catalog_contract_drift(db_session):
    async with db_session.async_session() as session:
        authority_guard = (
            await session.execute(
                text(
                    "SELECT pg_get_functiondef(p.oid) FROM pg_proc p "
                    "JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE p.proname = 'onnuri_smoke_authority_row_guard' "
                    "AND n.nspname = current_schema() AND p.pronargs = 0"
                )
            )
        ).scalar_one()
        facade_guard = (
            await session.execute(
                text(
                    "SELECT pg_get_functiondef(p.oid) FROM pg_proc p "
                    "JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE p.proname = 'onnuri_smoke_facade_context_guard' "
                    "AND n.nspname = current_schema() AND p.pronargs = 0"
                )
            )
        ).scalar_one()

        await session.execute(text("CREATE SCHEMA onnuri_readiness_decoy"))
        await session.execute(
            text(
                "CREATE FUNCTION onnuri_readiness_decoy.onnuri_smoke_facade_context_guard() "
                "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"
            )
        )
        await session.execute(
            text(
                "DROP TRIGGER trg_onnuri_smoke_attempt_facade_context "
                "ON onnuri_staging_smoke_attempts"
            )
        )
        await session.execute(
            text(
                "CREATE TRIGGER trg_onnuri_smoke_attempt_facade_context "
                "BEFORE UPDATE ON onnuri_staging_smoke_attempts FOR EACH ROW "
                "EXECUTE FUNCTION onnuri_readiness_decoy.onnuri_smoke_facade_context_guard()"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "DROP TRIGGER trg_onnuri_smoke_attempt_facade_context "
                    "ON onnuri_staging_smoke_attempts"
                )
            )
            await session.execute(
                text(
                    "CREATE TRIGGER trg_onnuri_smoke_attempt_facade_context "
                    "BEFORE UPDATE ON onnuri_staging_smoke_attempts FOR EACH ROW "
                    "EXECUTE FUNCTION onnuri_smoke_facade_context_guard()"
                )
            )
            await session.execute(text("DROP SCHEMA onnuri_readiness_decoy CASCADE"))
            await session.commit()

    async with db_session.async_session() as session:
        await session.execute(
            text(
                "CREATE OR REPLACE FUNCTION onnuri_smoke_facade_context_guard() "
                "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"
            )
        )
        await session.execute(
            text(
                "COMMENT ON FUNCTION onnuri_smoke_facade_context_guard() "
                "IS 'onnuri-smoke-definition:recertified-no-op'"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(text(facade_guard))
            await session.commit()

    for trigger_sql in (
        "BEFORE UPDATE OF state ON onnuri_staging_smoke_attempts FOR EACH ROW "
        "EXECUTE FUNCTION onnuri_smoke_facade_context_guard()",
        "BEFORE UPDATE ON onnuri_staging_smoke_attempts FOR EACH ROW "
        "WHEN (OLD.state IS NOT NULL) "
        "EXECUTE FUNCTION onnuri_smoke_facade_context_guard()",
    ):
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "DROP TRIGGER trg_onnuri_smoke_attempt_facade_context "
                    "ON onnuri_staging_smoke_attempts"
                )
            )
            await session.execute(
                text(
                    "CREATE TRIGGER trg_onnuri_smoke_attempt_facade_context "
                    + trigger_sql
                )
            )
            await session.commit()
        try:
            assert await db_session.onnuri_smoke_authority_ready() is False
        finally:
            async with db_session.async_session() as session:
                await session.execute(
                    text(
                        "DROP TRIGGER trg_onnuri_smoke_attempt_facade_context "
                        "ON onnuri_staging_smoke_attempts"
                    )
                )
                await session.execute(
                    text(
                        "CREATE TRIGGER trg_onnuri_smoke_attempt_facade_context "
                        "BEFORE UPDATE ON onnuri_staging_smoke_attempts FOR EACH ROW "
                        "EXECUTE FUNCTION onnuri_smoke_facade_context_guard()"
                    )
                )
                await session.commit()
    async with db_session.async_session() as session:
        await session.execute(
            text(
                "CREATE TRIGGER trg_zz_onnuri_smoke_unexpected_rewrite "
                "BEFORE UPDATE ON onnuri_staging_smoke_attempts FOR EACH ROW "
                "EXECUTE FUNCTION onnuri_smoke_authority_row_guard()"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "DROP TRIGGER trg_zz_onnuri_smoke_unexpected_rewrite "
                    "ON onnuri_staging_smoke_attempts"
                )
            )
            await session.commit()
    async with db_session.async_session() as session:
        await session.execute(
            text(
                "CREATE FUNCTION onnuri_smoke_readiness_argument_guard() "
                "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"
            )
        )
        await session.execute(
            text(
                "DROP TRIGGER trg_onnuri_smoke_attempt_facade_context "
                "ON onnuri_staging_smoke_attempts"
            )
        )
        await session.execute(
            text(
                "CREATE TRIGGER trg_onnuri_smoke_attempt_facade_context "
                "BEFORE UPDATE ON onnuri_staging_smoke_attempts FOR EACH ROW "
                "EXECUTE FUNCTION onnuri_smoke_readiness_argument_guard('drift')"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "DROP TRIGGER trg_onnuri_smoke_attempt_facade_context "
                    "ON onnuri_staging_smoke_attempts"
                )
            )
            await session.execute(
                text(
                    "CREATE TRIGGER trg_onnuri_smoke_attempt_facade_context "
                    "BEFORE UPDATE ON onnuri_staging_smoke_attempts FOR EACH ROW "
                    "EXECUTE FUNCTION onnuri_smoke_facade_context_guard()"
                )
            )
            await session.execute(
                text("DROP FUNCTION onnuri_smoke_readiness_argument_guard()")
            )
            await session.commit()

    async with db_session.async_session() as session:
        await session.execute(
            text(
                "CREATE OR REPLACE FUNCTION onnuri_smoke_authority_row_guard() "
                "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(text(authority_guard))
            await session.commit()

    async with db_session.async_session() as session:
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_callback_events "
                "RENAME CONSTRAINT uq_onnuri_smoke_callback_nonce "
                "TO uq_onnuri_smoke_callback_nonce_real"
            )
        )
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_attempts "
                "ADD CONSTRAINT uq_onnuri_smoke_callback_nonce UNIQUE (id)"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_attempts "
                    "DROP CONSTRAINT uq_onnuri_smoke_callback_nonce"
                )
            )
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_callback_events "
                    "RENAME CONSTRAINT uq_onnuri_smoke_callback_nonce_real "
                    "TO uq_onnuri_smoke_callback_nonce"
                )
            )
            await session.commit()

    async with db_session.async_session() as session:
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_callback_events "
                "DROP CONSTRAINT ck_onnuri_smoke_callback_event_type"
            )
        )
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_callback_events "
                "ADD CONSTRAINT ck_onnuri_smoke_callback_event_type CHECK (TRUE)"
            )
        )
        await session.execute(
            text(
                "CREATE TABLE onnuri_smoke_readiness_constraint_decoy ("
                "event_type VARCHAR(16) NOT NULL, "
                "CONSTRAINT ck_onnuri_smoke_callback_event_type "
                "CHECK (event_type IN ('status','cdr')))"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_callback_events "
                    "DROP CONSTRAINT ck_onnuri_smoke_callback_event_type"
                )
            )
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_callback_events "
                    "ADD CONSTRAINT ck_onnuri_smoke_callback_event_type "
                    "CHECK (event_type IN ('status','cdr'))"
                )
            )
            await session.execute(
                text("DROP TABLE onnuri_smoke_readiness_constraint_decoy")
            )
            await session.commit()
        await _refresh_facade_authority_fingerprints(db_session)

    async with db_session.async_session() as session:
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_callback_events "
                "DROP CONSTRAINT uq_onnuri_smoke_callback_nonce"
            )
        )
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_callback_events "
                "ADD CONSTRAINT uq_onnuri_smoke_callback_nonce "
                "UNIQUE (attempt_id, event_nonce_digest, event_type)"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_callback_events "
                    "DROP CONSTRAINT uq_onnuri_smoke_callback_nonce"
                )
            )
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_callback_events "
                    "ADD CONSTRAINT uq_onnuri_smoke_callback_nonce "
                    "UNIQUE (attempt_id, event_nonce_digest)"
                )
            )
            await session.commit()
        await _refresh_facade_authority_fingerprints(db_session)

    async with db_session.async_session() as session:
        foreign_key_identifier = (
            await session.execute(
                text(
                    "SELECT quote_ident(conname) FROM pg_constraint c "
                    "JOIN pg_class r ON r.oid = c.conrelid "
                    "JOIN pg_namespace n ON n.oid = r.relnamespace "
                    "WHERE r.relname = 'onnuri_staging_smoke_callback_events' "
                    "AND n.nspname = current_schema() AND c.contype = 'f'"
                )
            )
        ).scalar_one()
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_callback_events "
                f"DROP CONSTRAINT {foreign_key_identifier}"
            )
        )
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_callback_events "
                "ADD CONSTRAINT onnuri_smoke_callback_wrong_fk "
                "FOREIGN KEY (id) REFERENCES onnuri_staging_smoke_attempts(id) "
                "ON DELETE RESTRICT NOT VALID"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_callback_events "
                    "DROP CONSTRAINT onnuri_smoke_callback_wrong_fk"
                )
            )
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_callback_events "
                    f"ADD CONSTRAINT {foreign_key_identifier} "
                    "FOREIGN KEY (attempt_id) REFERENCES onnuri_staging_smoke_attempts(id) "
                    "ON DELETE RESTRICT"
                )
            )
            await session.commit()
        await _refresh_facade_authority_fingerprints(db_session)

    for drift_sql, restore_sql in (
        (
            "ALTER COLUMN event_type DROP NOT NULL",
            "ALTER COLUMN event_type SET NOT NULL",
        ),
        (
            "ALTER COLUMN redacted_cause_category TYPE text",
            "ALTER COLUMN redacted_cause_category TYPE varchar(64)",
        ),
        (
            "ALTER COLUMN accepted_at DROP DEFAULT",
            "ALTER COLUMN accepted_at SET DEFAULT now()",
        ),
        (
            "ALTER COLUMN account_id SET DEFAULT 'unexpected'",
            "ALTER COLUMN account_id DROP DEFAULT",
        ),
    ):
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_callback_events "
                    + drift_sql
                    if "account_id" not in drift_sql
                    else "ALTER TABLE onnuri_staging_smoke_attempts " + drift_sql
                )
            )
            await session.commit()
        try:
            assert await db_session.onnuri_smoke_authority_ready() is False
        finally:
            async with db_session.async_session() as session:
                await session.execute(
                    text(
                        "ALTER TABLE onnuri_staging_smoke_callback_events "
                        + restore_sql
                        if "account_id" not in restore_sql
                        else "ALTER TABLE onnuri_staging_smoke_attempts " + restore_sql
                    )
                )
                await session.commit()
    async with db_session.async_session() as session:
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_callback_events "
                "DROP CONSTRAINT onnuri_staging_smoke_callback_events_pkey"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_callback_events "
                    "ADD PRIMARY KEY (id)"
                )
            )
            await session.commit()
    async with db_session.async_session() as session:
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_callback_events "
                "DROP CONSTRAINT onnuri_staging_smoke_callback_events_pkey"
            )
        )
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_callback_events "
                "ADD CONSTRAINT onnuri_staging_smoke_callback_events_pkey "
                "PRIMARY KEY (id) DEFERRABLE INITIALLY DEFERRED"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_callback_events "
                    "DROP CONSTRAINT onnuri_staging_smoke_callback_events_pkey"
                )
            )
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_callback_events "
                    "ADD PRIMARY KEY (id)"
                )
            )
            await session.commit()

    async with db_session.async_session() as session:
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_callback_events "
                "ALTER COLUMN id DROP DEFAULT"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_callback_events "
                    "ALTER COLUMN id SET DEFAULT "
                    "nextval('onnuri_staging_smoke_callback_events_id_seq'::regclass)"
                )
            )
            await session.commit()

    await _refresh_facade_authority_fingerprints(db_session)
    assert await db_session.onnuri_smoke_authority_ready() is True


@pytest.mark.asyncio
async def test_facade_authority_readiness_rejects_duplicate_callback_attempt_fks(
    db_session,
):
    async with db_session.async_session() as session:
        foreign_key_identifier = (
            await session.execute(
                text(
                    "SELECT quote_ident(conname) FROM pg_constraint c "
                    "JOIN pg_class r ON r.oid = c.conrelid "
                    "JOIN pg_namespace n ON n.oid = r.relnamespace "
                    "WHERE r.relname = 'onnuri_staging_smoke_callback_events' "
                    "AND n.nspname = current_schema() AND c.contype = 'f'"
                )
            )
        ).scalar_one()
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_callback_events "
                f"DROP CONSTRAINT {foreign_key_identifier}"
            )
        )
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_callback_events "
                "ADD CONSTRAINT onnuri_smoke_callback_wrong_fk "
                "FOREIGN KEY (attempt_id) REFERENCES onnuri_staging_smoke_attempts(id) "
                "ON DELETE CASCADE NOT VALID"
            )
        )
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_callback_events "
                f"ADD CONSTRAINT {foreign_key_identifier} "
                "FOREIGN KEY (attempt_id) REFERENCES onnuri_staging_smoke_attempts(id) "
                "ON DELETE RESTRICT"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_callback_events "
                    f"DROP CONSTRAINT {foreign_key_identifier}"
                )
            )
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_callback_events "
                    "DROP CONSTRAINT onnuri_smoke_callback_wrong_fk"
                )
            )
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_callback_events "
                    f"ADD CONSTRAINT {foreign_key_identifier} "
                    "FOREIGN KEY (attempt_id) REFERENCES onnuri_staging_smoke_attempts(id) "
                    "ON DELETE RESTRICT"
                )
            )
            await session.commit()
            assert (await session.execute(text("SELECT 1"))).scalar_one() == 1

@pytest.mark.asyncio
async def test_facade_authority_readiness_and_bound_attempt_lookup_are_exact(db_session):
    assert await db_session.onnuri_smoke_authority_ready() is True
    ids, attempt = await _stock_bound_attempt(db_session, key="facade-lookup")

    found = await db_session.lookup_onnuri_smoke_bound_attempt(
        organization_id=ids["organization_id"],
        account_id="facade-account",
        stock_call_id_digest=_DIGEST,
    )
    assert found.id == attempt.id
    for overrides in (
        {"organization_id": ids["other_organization_id"]},
        {"account_id": "wrong-account"},
        {"stock_call_id_digest": _OTHER_DIGEST},
    ):
        with pytest.raises(TelephonyNumberInventoryNotFoundError):
            await db_session.lookup_onnuri_smoke_bound_attempt(
                organization_id=overrides.get(
                    "organization_id", ids["organization_id"]
                ),
                account_id=overrides.get("account_id", "facade-account"),
                stock_call_id_digest=overrides.get(
                    "stock_call_id_digest", _DIGEST
                ),
            )

@pytest.mark.asyncio
async def test_facade_authority_readiness_rejects_disabled_guards_and_incomplete_schema(
    db_session,
):
    async with db_session.async_session() as session:
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_attempts "
                "DISABLE TRIGGER trg_onnuri_smoke_attempt_facade_context"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_attempts "
                    "ENABLE TRIGGER trg_onnuri_smoke_attempt_facade_context"
                )
            )
            await session.commit()
    async with db_session.async_session() as session:
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_attempts DISABLE TRIGGER "
                "trg_onnuri_staging_smoke_attempts_authority_immutable"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_attempts ENABLE TRIGGER "
                    "trg_onnuri_staging_smoke_attempts_authority_immutable"
                )
            )
            await session.commit()
    async with db_session.async_session() as session:
        await session.execute(
            text(
                "CREATE FUNCTION onnuri_smoke_readiness_wrong_guard() "
                "RETURNS trigger LANGUAGE plpgsql AS $$ "
                "BEGIN RETURN NEW; END $$"
            )
        )
        await session.execute(
            text(
                "DROP TRIGGER trg_onnuri_smoke_attempt_facade_context "
                "ON onnuri_staging_smoke_attempts"
            )
        )
        await session.execute(
            text(
                "CREATE TRIGGER trg_onnuri_smoke_attempt_facade_context "
                "BEFORE UPDATE ON onnuri_staging_smoke_attempts FOR EACH ROW "
                "EXECUTE FUNCTION onnuri_smoke_readiness_wrong_guard()"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "DROP TRIGGER trg_onnuri_smoke_attempt_facade_context "
                    "ON onnuri_staging_smoke_attempts"
                )
            )
            await session.execute(
                text(
                    "CREATE TRIGGER trg_onnuri_smoke_attempt_facade_context "
                    "BEFORE UPDATE ON onnuri_staging_smoke_attempts FOR EACH ROW "
                    "EXECUTE FUNCTION onnuri_smoke_facade_context_guard()"
                )
            )
            await session.execute(
                text("DROP FUNCTION onnuri_smoke_readiness_wrong_guard()")
            )
            await session.commit()

    async with db_session.async_session() as session:
        await session.execute(
            text(
                "ALTER TABLE onnuri_staging_smoke_callback_events "
                "DROP COLUMN redacted_cause_category"
            )
        )
        await session.commit()
    try:
        assert await db_session.onnuri_smoke_authority_ready() is False
    finally:
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "ALTER TABLE onnuri_staging_smoke_callback_events "
                    "ADD COLUMN redacted_cause_category VARCHAR(64)"
                )
            )
            await session.commit()

@pytest.mark.asyncio
async def test_facade_callback_persists_redacted_events_and_refuses_without_mutation(
    db_session,
):
    ids, attempt = await _running_attempt(db_session, key="facade-callback")
    event_args = _facade_context(
        attempt,
        ids,
        event_nonce_digest="nonce-1",
        idempotency_key="callback-idempotency-1",
        request_digest=_DIGEST,
        event_type="status",
        normalized_status="running",
        occurred_at=datetime.now(UTC),
        duration_seconds=12,
        redacted_cause_category="carrier_progress",
    )
    event = await db_session.accept_onnuri_smoke_callback(**event_args)
    duplicate = await db_session.accept_onnuri_smoke_callback(**event_args)
    assert duplicate.id == event.id
    assert (
        event.event_nonce_digest,
        event.idempotency_key,
        event.request_digest,
        event.redacted_cause_category,
    ) == ("nonce-1", "callback-idempotency-1", _DIGEST, "carrier_progress")
    assert not hasattr(event, "stock_call_id")
    assert str(ids["normalized_did"]) not in repr(event.__dict__)
    assert "raw-stock-call-id" not in repr(event.__dict__)

    async def assert_refused(**overrides):
        before = await _facade_snapshot(db_session, attempt.id, ids["envelope_id"])
        with pytest.raises(
            (TelephonyNumberInventoryConflictError, TelephonyNumberInventoryNotFoundError)
        ):
            await db_session.accept_onnuri_smoke_callback(
                **(event_args | overrides)
            )
        assert await _facade_snapshot(db_session, attempt.id, ids["envelope_id"]) == before

    await assert_refused(
        event_nonce_digest="nonce-1", request_digest=_OTHER_DIGEST
    )
    await assert_refused(event_nonce_digest="nonce-account", account_id="wrong-account")
    await assert_refused(
        event_nonce_digest="nonce-tenant",
        organization_id=ids["other_organization_id"],
    )
    await assert_refused(event_nonce_digest="nonce-context", application_id="wrong-app")
    await assert_refused(event_nonce_digest="nonce-run", run_id="wrong-run")
    await assert_refused(event_nonce_digest="nonce-stock", stock_call_id_digest=_OTHER_DIGEST)
    await assert_refused(event_nonce_digest="nonce-attempt", attempt_uuid=str(uuid4()))
    await assert_refused(event_nonce_digest="nonce-backward", normalized_status="stock_bound")
    await assert_refused(event_nonce_digest="nonce-equal", normalized_status="running")
    await assert_refused(event_nonce_digest="nonce-illegal", normalized_status="unknown")


@pytest.mark.asyncio
async def test_facade_callbacks_transition_forward_and_terminal_is_immutable(db_session):
    ids, attempt = await _running_attempt(db_session, key="facade-forward")
    for ordinal, status in enumerate(
        ("running", "completed"), start=1
    ):
        await db_session.accept_onnuri_smoke_callback(
            **_facade_context(
                attempt,
                ids,
                event_nonce_digest=f"forward-nonce-{ordinal}",
                idempotency_key=f"forward-idempotency-{ordinal}",
                request_digest=_DIGEST,
                event_type="cdr",
                normalized_status=status,
                occurred_at=datetime.now(UTC) + timedelta(seconds=ordinal),
                redacted_cause_category="carrier_complete",
            )
        )

    before = await _facade_snapshot(db_session, attempt.id, ids["envelope_id"])
    with pytest.raises(TelephonyNumberInventoryConflictError, match="transition_invalid"):
        await db_session.accept_onnuri_smoke_callback(
            **_facade_context(
                attempt,
                ids,
                event_nonce_digest="terminal-refusal",
                idempotency_key="terminal-refusal",
                request_digest=_DIGEST,
                event_type="status",
                normalized_status="running",
                occurred_at=datetime.now(UTC),
            )
        )
    assert await _facade_snapshot(db_session, attempt.id, ids["envelope_id"]) == before


@pytest.mark.asyncio
async def test_facade_containment_binds_exactly_and_updates_attempt_and_envelope_atomically(
    db_session,
):
    ids, attempt = await _stock_bound_attempt(db_session, key="facade-containment")
    containment = _facade_context(attempt, ids, category="operator_containment")
    contained = await db_session.request_onnuri_smoke_containment(**containment)
    duplicate = await db_session.request_onnuri_smoke_containment(**containment)
    assert duplicate.id == contained.id
    assert (contained.state, contained.terminal_class, contained.terminal_reason) == (
        "contained",
        "contained",
        "operator_containment",
    )
    async with db_session.async_session() as session:
        persisted_attempt = await session.get(OnnuriSmokeAttemptModel, attempt.id)
        envelope = await session.get(OnnuriSmokeEnvelopeModel, ids["envelope_id"])
    assert persisted_attempt is not None
    assert envelope is not None
    assert persisted_attempt.contained_at == envelope.contained_at
    assert (envelope.state, envelope.containment_reason) == (
        "contained",
        "operator_containment",
    )

    for overrides in (
        {"category": "different-category"},
        {"organization_id": ids["other_organization_id"]},
        {"account_id": "wrong-account"},
        {"application_id": "wrong-app"},
        {"run_id": "wrong-run"},
        {"stock_call_id_digest": _OTHER_DIGEST},
    ):
        before = await _facade_snapshot(db_session, attempt.id, ids["envelope_id"])
        with pytest.raises(
            (TelephonyNumberInventoryConflictError, TelephonyNumberInventoryNotFoundError)
        ):
            await db_session.request_onnuri_smoke_containment(
                **(containment | overrides)
            )
        assert await _facade_snapshot(db_session, attempt.id, ids["envelope_id"]) == before

    terminal_ids, terminal_attempt = await _running_attempt(
        db_session,
        key="facade-containment-terminal",
        stock_call_id_digest=_OTHER_DIGEST,
    )
    await db_session.accept_onnuri_smoke_callback(
        **_facade_context(
            terminal_attempt,
            terminal_ids,
            event_nonce_digest="terminal-running",
            idempotency_key="terminal-running",
            request_digest=_DIGEST,
            event_type="status",
            normalized_status="running",
            occurred_at=datetime.now(UTC),
        )
    )
    await db_session.accept_onnuri_smoke_callback(
        **_facade_context(
            terminal_attempt,
            terminal_ids,
            event_nonce_digest="terminal-event",
            idempotency_key="terminal-event",
            request_digest=_DIGEST,
            event_type="status",
            normalized_status="completed",
            occurred_at=datetime.now(UTC) + timedelta(seconds=1),
        )
    )
    before = await _facade_snapshot(
        db_session, terminal_attempt.id, terminal_ids["envelope_id"]
    )
    with pytest.raises(TelephonyNumberInventoryConflictError, match="containment_terminal"):
        await db_session.request_onnuri_smoke_containment(
            **_facade_context(terminal_attempt, terminal_ids, category="late")
        )
    assert (
        await _facade_snapshot(
            db_session, terminal_attempt.id, terminal_ids["envelope_id"]
        )
        == before
    )


@pytest.mark.asyncio
async def test_facade_dispatch_context_is_write_once_and_duplicate_mismatch_is_refused(
    db_session,
):
    ids, attempt = await _stock_bound_attempt(db_session, key="facade-context")
    attempt_id = attempt.id
    attempt_uuid = attempt.attempt_uuid
    allocation_request_digest = attempt.allocation_request_digest
    for field in ("account_id", "application_id", "run_id"):
        async with db_session.async_session() as session:
            persisted = await session.get(OnnuriSmokeAttemptModel, attempt_id)
            assert persisted is not None
            savepoint = await session.begin_nested()
            setattr(persisted, field, f"rotated-{field}")
            with pytest.raises(DBAPIError, match="context is immutable"):
                await session.flush()
            await savepoint.rollback()

    with pytest.raises(TelephonyNumberInventoryConflictError, match="not_authorized"):
        await db_session.consume_onnuri_smoke_dispatch(
            attempt_uuid,
            organization_id=ids["organization_id"],
            nonce_digest=_DIGEST,
            token_digest=_DISPATCH_TOKEN_DIGEST,
            request_digest=allocation_request_digest,
            receipt_digest=_DIGEST,
            account_id="facade-account",
            application_id="facade-application",
            run_id="rotated-run",
            builder=_dispatch_consume_builder(),
        )
    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriSmokeAttemptModel, attempt_id)
    assert persisted is not None
    assert (
        persisted.account_id,
        persisted.application_id,
        persisted.run_id,
    ) == ("facade-account", "facade-application", "facade-run")


async def _registration_gate_snapshot(db_session, envelope_id: int):
    async with db_session.async_session() as session:
        return [
            (
                gate.id,
                gate.operation_kind,
                gate.unregisters_gate_id,
                gate.state,
                gate.request_digest,
                gate.transaction_count,
                gate.retransmission_count,
                gate.terminal_at,
            )
            for gate in (
                await session.execute(
                    select(OnnuriRegistrationGateModel)
                    .where(OnnuriRegistrationGateModel.envelope_id == envelope_id)
                    .order_by(OnnuriRegistrationGateModel.id)
                )
            ).scalars()
        ]


@pytest.mark.asyncio
async def test_registration_legacy_create_is_disabled_for_v3_without_state(
    db_session,
):
    ids = await _seed_authority(db_session)
    before = await _registration_gate_snapshot(db_session, ids["envelope_id"])

    for _ in range(2):
        with pytest.raises(
            TelephonyNumberInventoryConflictError,
            match="onnuri_registration_legacy_path_disabled",
        ):
            await db_session.create_onnuri_registration_gate(
                envelope_uuid=ids["envelope_uuid"],
                organization_id=ids["organization_id"],
                operation_kind="register",
                request_digest=_DIGEST,
            )

    assert await _registration_gate_snapshot(db_session, ids["envelope_id"]) == before


@pytest.mark.asyncio
async def test_registration_legacy_rejections_leave_v3_authority_unchanged(db_session):
    ids = await _seed_authority(db_session)
    other_ids = await _seed_authority(db_session)
    before = await _registration_gate_snapshot(db_session, ids["envelope_id"])

    with pytest.raises(
        TelephonyNumberInventoryConflictError,
        match="onnuri_registration_legacy_path_disabled",
    ):
        await db_session.create_onnuri_registration_gate(
            envelope_uuid=ids["envelope_uuid"],
            organization_id=ids["organization_id"],
            operation_kind="unregister",
            request_digest=_DIGEST,
            unregisters_gate_id=1,
        )

    with pytest.raises(
        TelephonyNumberInventoryNotFoundError,
        match="onnuri_smoke_envelope_not_found",
    ):
        await db_session.create_onnuri_registration_gate(
            envelope_uuid=ids["envelope_uuid"],
            organization_id=other_ids["organization_id"],
            operation_kind="register",
            request_digest=_DIGEST,
        )

    assert await _registration_gate_snapshot(db_session, ids["envelope_id"]) == before
    assert await _registration_gate_snapshot(
        db_session, other_ids["envelope_id"]
    ) == []


def _registration_values(
    ids: dict[str, object],
    *,
    operation_kind: str = "register",
    prior_register_gate_id: int | None = None,
    prior_register_operation_uuid: str | None = None,
) -> dict[str, object]:
    return {
        "envelope_uuid": ids["envelope_uuid"],
        "organization_id": ids["organization_id"],
        "operation_kind": operation_kind,
        "request_digest": "3" * 64,
        "candidate_digest": _DIGEST,
        "gate_envelope_digest": hashlib.sha256(
            str(ids["envelope_uuid"]).encode("utf-8")
        ).hexdigest(),
        "nonce_digest": "4" * 64,
        "prior_register_gate_id": prior_register_gate_id,
        "prior_register_operation_uuid": prior_register_operation_uuid,
    }


async def _begin_registration(db_session, ids, **overrides):
    from api.tests.telephony.jambonz.test_g008_registration_stage_bridge import (
        _claim_inbound,
        _finish_generic,
        _seal_payload,
        _start,
    )

    values = _registration_values(ids)
    values.update(overrides)
    operation_kind = str(values["operation_kind"])
    if operation_kind == "register":
        seal = _seal_payload(ids)
        seal["execution_nonce_digest"] = hashlib.sha256(
            f"registration-execution:{seal['execution_seal_uuid']}".encode("utf-8")
        ).hexdigest()
        created = await db_session.create_execution_seal(seal)
        await _start(db_session, seal, 1)
        stage = created["stages"][0]
    else:
        async with db_session.async_session() as session:
            prior_gate = await session.get(
                OnnuriRegistrationGateModel, values["prior_register_gate_id"]
            )
            prior_stage = (
                await session.get(
                    G008ExecutionStageModel, prior_gate.execution_stage_id
                )
                if prior_gate is not None
                else None
            )
            persisted_seal = (
                await session.get(
                    G008ExecutionSealModel, prior_stage.execution_seal_id
                )
                if prior_stage is not None
                else None
            )
            stages = (
                (
                    await session.execute(
                        select(G008ExecutionStageModel)
                        .where(
                            G008ExecutionStageModel.execution_seal_id
                            == persisted_seal.id
                        )
                        .order_by(G008ExecutionStageModel.ordinal)
                    )
                )
                .scalars()
                .all()
                if persisted_seal is not None
                else []
            )
        if persisted_seal is None or len(stages) != 4:
            raise AssertionError("registration test execution seal linkage is incomplete")
        seal = {
            "organization_id": persisted_seal.organization_id,
            "execution_seal_uuid": persisted_seal.execution_seal_uuid,
            "execution_nonce_digest": persisted_seal.execution_nonce_digest,
            "candidate_digest": persisted_seal.candidate_digest,
            "gate_envelope_digest": persisted_seal.gate_envelope_digest,
            "reserved_inbound_did_digest": persisted_seal.reserved_inbound_did_digest,
            "reserved_inbound_caller_digest": (
                persisted_seal.reserved_inbound_caller_digest
            ),
        }
        if prior_stage.state == "succeeded":
            for ordinal in (2, 3):
                await _start(db_session, seal, ordinal)
                if ordinal == 3:
                    await _claim_inbound(db_session, seal)
                await _finish_generic(db_session, ids, seal, ordinal)
        elif prior_stage.state not in {"failed", "contained"}:
            raise AssertionError("register stage must be terminal before unregister")
        await _start(db_session, seal, 4)
        stage = {"stage_uuid": stages[3].stage_uuid}

    values.update(
        execution_seal_uuid=seal["execution_seal_uuid"],
        execution_nonce_digest=seal["execution_nonce_digest"],
        execution_stage_uuid=stage["stage_uuid"],
        execution_stage=operation_kind,
        execution_stage_ordinal=1 if operation_kind == "register" else 4,
    )
    context = await db_session.begin_onnuri_registration_operation(**values)
    excluded = {
        "envelope_uuid",
        "execution_seal_uuid",
        "execution_nonce_digest",
        "execution_stage_uuid",
        "execution_stage",
        "execution_stage_ordinal",
    }
    consume = {key: value for key, value in values.items() if key not in excluded}
    consume.update(
        registration_gate_id=context["gate"].id,
        operation_uuid=context["gate"].operation_uuid,
    )
    return context["gate"], consume


def _registration_execution_attestation(
    receipt: dict[str, object],
) -> dict[str, object]:
    now = datetime.now(UTC)
    completed_at = now.replace(microsecond=now.microsecond // 1000 * 1000)
    completed_at_text = completed_at.isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )
    started_at_text = (completed_at - timedelta(seconds=1)).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")
    operation_uuid = str(receipt["operation_uuid"])
    outcome = str(receipt["outcome"])
    response_count = int(receipt["response_count"])
    wire_request_count = int(receipt["wire_request_count"])
    has_challenge = response_count == 2 or (
        outcome == "contained" and response_count == 1
    )
    has_final_response = outcome in {"succeeded", "failed"}
    claims = {
        "accepted_expires_seconds": receipt["accepted_expires_seconds"],
        "authorization_nonce_digest": receipt["nonce_digest"],
        "candidate_digest": receipt["candidate_digest"],
        "challenge_response_wire_digest": (
            hashlib.sha256(
                f"{operation_uuid}:challenge-response".encode()
            ).hexdigest()
            if has_challenge
            else None
        ),
        "challenge_status": 401 if has_challenge else None,
        "completed_at": completed_at_text,
        "deregistered": receipt["deregistered"],
        "final_response_wire_digest": (
            hashlib.sha256(
                f"{operation_uuid}:final-response".encode()
            ).hexdigest()
            if has_final_response
            else None
        ),
        "final_status": (
            200
            if outcome == "succeeded"
            else 500
            if outcome == "failed"
            else None
        ),
        "gate_envelope_digest": receipt["gate_envelope_digest"],
        "initial_request_wire_digest": (
            hashlib.sha256(
                f"{operation_uuid}:initial-request".encode()
            ).hexdigest()
            if wire_request_count > 0
            else None
        ),
        "operation_kind": receipt["operation_kind"],
        "operation_uuid": receipt["operation_uuid"],
        "organization_id": receipt["organization_id"],
        "outcome": receipt["outcome"],
        "prior_register_gate_id": receipt["prior_register_gate_id"],
        "prior_register_operation_uuid": receipt["prior_register_operation_uuid"],
        "registration_gate_id": receipt["registration_gate_id"],
        "request_digest": receipt["request_digest"],
        "response_count": receipt["response_count"],
        "retry_count": receipt["retry_count"],
        "retry_request_wire_digest": (
            hashlib.sha256(
                f"{operation_uuid}:retry-request".encode()
            ).hexdigest()
            if wire_request_count == 2
            else None
        ),
        "sip_transaction_binding_digest": (
            hashlib.sha256(
                f"{operation_uuid}:sip-transaction".encode()
            ).hexdigest()
            if wire_request_count > 0
            else None
        ),
        "started_at": started_at_text,
        "transaction_count": receipt["transaction_count"],
        "transport": "udp",
        "upstream_endpoint_digest": hashlib.sha256(
            b"test-registration-upstream"
        ).hexdigest(),
        "verification_domain": "recova.onnuri.smoke.registration.execution.v1",
        "wire_request_count": receipt["wire_request_count"],
    }
    key_id = "test-execution-evidence-v1"
    unsigned = {
        "algorithm": "ES256",
        "claims": claims,
        "key_id": key_id,
        "verification_domain": "recova.onnuri.smoke.registration.execution.v1",
    }
    private_key = ec.derive_private_key(1, ec.SECP256R1())
    der_signature = private_key.sign(
        canonical_json_bytes(unsigned), ec.ECDSA(hashes.SHA256())
    )
    r, s = decode_dss_signature(der_signature)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    canonical = canonical_json_bytes(
        {
            **unsigned,
            "signature": urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
        }
    )
    public_key_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "execution_attestation_canonical": canonical,
        "execution_attestation_signature": signature,
        "execution_attestation_digest": hashlib.sha256(canonical).hexdigest(),
        "execution_attestation_signature_digest": hashlib.sha256(
            signature
        ).hexdigest(),
        "execution_attestation_key_digest": hashlib.sha256(
            public_key_der
        ).hexdigest(),
        "execution_attestation_key_id": key_id,
        "execution_attested_at": completed_at,
    }


def _registration_finalize_values(consume: dict[str, object], **overrides):
    operation_kind = str(consume["operation_kind"])
    values = {
        "organization_id": consume["organization_id"],
        "operation_uuid": consume["operation_uuid"],
        "registration_gate_id": consume["registration_gate_id"],
        "operation_kind": operation_kind,
        "nonce_digest": consume["nonce_digest"],
        "candidate_digest": consume["candidate_digest"],
        "gate_envelope_digest": consume["gate_envelope_digest"],
        "request_digest": consume["request_digest"],
        "prior_register_gate_id": consume["prior_register_gate_id"],
        "prior_register_operation_uuid": consume["prior_register_operation_uuid"],
        "outcome": "succeeded",
        "transaction_count": 1,
        "retry_count": 0,
        "response_count": 1,
        "wire_request_count": 1,
        "deregistered": operation_kind == "unregister",
        "accepted_expires_seconds": 0 if operation_kind == "unregister" else 3600,
    }
    values.update(overrides)
    values.update(_registration_execution_attestation(values))
    return values


@pytest.mark.asyncio
async def test_registration_consume_is_atomic_one_shot_and_initial_finalization_is_exact(db_session):
    ids = await _seed_authority(db_session)
    gate, consume = await _begin_registration(db_session, ids)

    assert await _registration_gate_snapshot(db_session, ids["envelope_id"]) == [
        (
            gate.id,
            "register",
            None,
            "pending",
            gate.request_digest,
            0,
            0,
            None,
        )
    ]

    started = await db_session.consume_onnuri_registration_operation(**consume)

    assert started.id == gate.id
    challenged = await _registration_gate_snapshot(db_session, ids["envelope_id"])
    assert challenged == [
        (
            gate.id,
            "register",
            None,
            "challenged",
            gate.request_digest,
            1,
            0,
            None,
        )
    ]
    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriRegistrationGateModel, gate.id)
    assert persisted is not None
    assert persisted.unregister_required is True
    assert persisted.unregister_satisfied_at is None
    with pytest.raises(
        TelephonyNumberInventoryConflictError,
        match="registration_gate_not_authorized",
    ):
        await db_session.consume_onnuri_registration_operation(**consume)
    assert await _registration_gate_snapshot(db_session, ids["envelope_id"]) == challenged
    finalize_values = _registration_finalize_values(consume)
    finalized, recovered = await db_session.finalize_onnuri_registration_operation(
        **finalize_values
    )
    assert finalized.id == gate.id
    assert recovered is False
    attestation = json.loads(finalize_values["execution_attestation_canonical"])
    assert attestation["verification_domain"] == (
        "recova.onnuri.smoke.registration.execution.v1"
    )
    assert attestation["claims"]["verification_domain"] == (
        "recova.onnuri.smoke.registration.execution.v1"
    )
    terminal = await _registration_gate_snapshot(db_session, ids["envelope_id"])
    duplicate_finalization, recovered = await db_session.finalize_onnuri_registration_operation(
        **finalize_values
    )
    assert duplicate_finalization.id == gate.id
    assert recovered is True
    assert await _registration_gate_snapshot(db_session, ids["envelope_id"]) == terminal


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("organization_id", "other_organization_id"),
        ("registration_gate_id", 999_999_999),
        ("operation_uuid", "55555555-5555-4555-8555-555555555555"),
        ("operation_kind", "unregister"),
        ("request_digest", "5" * 64),
        ("candidate_digest", "6" * 64),
        ("gate_envelope_digest", "7" * 64),
        ("nonce_digest", "8" * 64),
    ],
)
async def test_registration_consume_identity_mismatches_never_transition(
    db_session, field: str, replacement: object
):
    ids = await _seed_authority(db_session)
    _, consume = await _begin_registration(db_session, ids)
    before = await _registration_gate_snapshot(db_session, ids["envelope_id"])
    mutated = dict(consume)
    mutated[field] = (
        ids[replacement] if field == "organization_id" else replacement
    )

    with pytest.raises(
        (TelephonyNumberInventoryConflictError, TelephonyNumberInventoryNotFoundError)
    ):
        await db_session.consume_onnuri_registration_operation(**mutated)

    assert await _registration_gate_snapshot(db_session, ids["envelope_id"]) == before


@pytest.mark.asyncio
async def test_registration_consume_rejects_noncurrent_and_terminal_gates_without_transition(
    db_session,
):
    ids = await _seed_authority(db_session)
    _, consume = await _begin_registration(db_session, ids)
    before = await _registration_gate_snapshot(db_session, ids["envelope_id"])
    async with db_session.async_session() as session:
        envelope = await session.get(OnnuriSmokeEnvelopeModel, ids["envelope_id"])
        database_now = (await session.execute(text("SELECT now()"))).scalar_one()
        envelope.state = "contained"
        envelope.contained_at = database_now
        envelope.containment_reason = "registration-consume-currentness-test"
        await session.commit()

    with pytest.raises(
        TelephonyNumberInventoryConflictError,
        match="registration_gate_not_authorized",
    ):
        await db_session.consume_onnuri_registration_operation(**consume)
    assert await _registration_gate_snapshot(db_session, ids["envelope_id"]) == before

    terminal_ids = await _seed_authority(db_session)
    _, terminal_consume = await _begin_registration(db_session, terminal_ids)
    await db_session.consume_onnuri_registration_operation(**terminal_consume)
    await db_session.finalize_onnuri_registration_operation(
        **_registration_finalize_values(terminal_consume)
    )
    terminal = await _registration_gate_snapshot(
        db_session, terminal_ids["envelope_id"]
    )
    with pytest.raises(
        TelephonyNumberInventoryConflictError,
        match="registration_gate_not_authorized",
    ):
        await db_session.consume_onnuri_registration_operation(**terminal_consume)
    assert (
        await _registration_gate_snapshot(db_session, terminal_ids["envelope_id"])
        == terminal
    )


@pytest.mark.asyncio
async def test_registration_finalize_requires_consume_and_terminal_recovery_is_exact(
    db_session,
):
    ids = await _seed_authority(db_session)
    _, consume = await _begin_registration(db_session, ids)
    finalize = _registration_finalize_values(consume)
    pending = await _registration_gate_snapshot(db_session, ids["envelope_id"])

    with pytest.raises(
        TelephonyNumberInventoryConflictError,
        match="registration_gate_not_authorized",
    ):
        await db_session.finalize_onnuri_registration_operation(**finalize)
    assert await _registration_gate_snapshot(db_session, ids["envelope_id"]) == pending

    await db_session.consume_onnuri_registration_operation(**consume)
    consumed = await _registration_gate_snapshot(db_session, ids["envelope_id"])
    with pytest.raises(
        TelephonyNumberInventoryConflictError,
        match="registration_receipt_mismatch",
    ):
        await db_session.finalize_onnuri_registration_operation(
            **{**finalize, "registration_gate_id": consume["registration_gate_id"] + 1}
        )
    assert await _registration_gate_snapshot(db_session, ids["envelope_id"]) == consumed
    completed, recovered = await db_session.finalize_onnuri_registration_operation(
        **finalize
    )
    assert completed.state == "completed"
    assert recovered is False
    terminal = await _registration_gate_snapshot(db_session, ids["envelope_id"])

    duplicate, recovered = await db_session.finalize_onnuri_registration_operation(
        **finalize
    )
    assert duplicate.id == completed.id
    assert recovered is True
    assert await _registration_gate_snapshot(db_session, ids["envelope_id"]) == terminal
    with pytest.raises(
        TelephonyNumberInventoryConflictError,
        match="registration_receipt_mismatch",
    ):
        await db_session.finalize_onnuri_registration_operation(
            **{**finalize, "registration_gate_id": consume["registration_gate_id"] + 1}
        )
    assert await _registration_gate_snapshot(db_session, ids["envelope_id"]) == terminal

    with pytest.raises(
        TelephonyNumberInventoryConflictError,
        match="registration_terminal_replay_rejected",
    ):
        await db_session.finalize_onnuri_registration_operation(
            **_registration_finalize_values(consume, accepted_expires_seconds=1800)
        )
    assert await _registration_gate_snapshot(db_session, ids["envelope_id"]) == terminal


@pytest.mark.asyncio
async def test_unregister_consume_requires_exact_completed_register_linkage(db_session):
    ids = await _seed_authority(db_session)
    register, register_consume = await _begin_registration(db_session, ids)
    await db_session.consume_onnuri_registration_operation(**register_consume)
    await db_session.finalize_onnuri_registration_operation(
        **_registration_finalize_values(register_consume)
    )

    unregister, consume = await _begin_registration(
        db_session,
        ids,
        operation_kind="unregister",
        prior_register_gate_id=register.id,
        prior_register_operation_uuid=register.operation_uuid,
    )
    before = await _registration_gate_snapshot(db_session, ids["envelope_id"])

    for mutation in (
        {"prior_register_gate_id": register.id + 1},
        {
            "prior_register_operation_uuid": (
                "66666666-6666-4666-8666-666666666666"
            )
        },
    ):
        with pytest.raises(
            TelephonyNumberInventoryConflictError,
            match="registration_gate_not_authorized",
        ):
            await db_session.consume_onnuri_registration_operation(
                **{**consume, **mutation}
            )
        assert (
            await _registration_gate_snapshot(db_session, ids["envelope_id"])
            == before
        )

    consumed = await db_session.consume_onnuri_registration_operation(**consume)
    assert consumed.id == unregister.id
    assert consumed.state == "challenged"
    assert consumed.transaction_count == 1
    assert consumed.retransmission_count == 0


@pytest.mark.asyncio
async def test_registration_terminal_transition_requires_execution_attestation(
    db_session,
):
    ids = await _seed_authority(db_session)
    gate, consume = await _begin_registration(db_session, ids)
    await db_session.consume_onnuri_registration_operation(**consume)

    with pytest.raises(DBAPIError):
        async with db_session.async_session() as session:
            await session.execute(
                text(
                    "UPDATE onnuri_registration_gates "
                    "SET state = 'completed', terminal_at = now() "
                    "WHERE id = :gate_id"
                ),
                {"gate_id": gate.id},
            )
            await session.commit()

    async with db_session.async_session() as session:
        persisted = await session.get(OnnuriRegistrationGateModel, gate.id)
    assert persisted is not None
    assert persisted.state == "challenged"
    assert persisted.execution_attestation_digest is None
    assert persisted.execution_attestation_key_id is None
    assert persisted.execution_attested_at is None


@pytest.mark.asyncio
async def test_registration_attestation_digest_is_globally_one_shot(db_session):
    first_ids = await _seed_authority(db_session)
    second_ids = await _seed_authority(db_session)
    _, first_consume = await _begin_registration(db_session, first_ids)
    _, second_consume = await _begin_registration(db_session, second_ids)
    await db_session.consume_onnuri_registration_operation(**first_consume)
    await db_session.consume_onnuri_registration_operation(**second_consume)
    first_finalize = _registration_finalize_values(first_consume)
    await db_session.finalize_onnuri_registration_operation(**first_finalize)
    replayed_attestation = {
        key: first_finalize[key]
        for key in (
            "execution_attestation_canonical",
            "execution_attestation_signature",
            "execution_attestation_digest",
            "execution_attestation_signature_digest",
            "execution_attestation_key_digest",
            "execution_attestation_key_id",
            "execution_attested_at",
        )
    }
    second_finalize = _registration_finalize_values(second_consume)
    second_finalize.update(replayed_attestation)

    with pytest.raises(
        TelephonyNumberInventoryConflictError,
        match="registration_attestation_replay_rejected",
    ):
        await db_session.finalize_onnuri_registration_operation(**second_finalize)


@pytest.mark.asyncio
async def test_registration_conflicting_terminal_receipts_have_one_winner(db_session):
    ids = await _seed_authority(db_session)
    _, consume = await _begin_registration(db_session, ids)
    await db_session.consume_onnuri_registration_operation(**consume)
    success = _registration_finalize_values(consume)
    contained = _registration_finalize_values(
        consume,
        outcome="contained",
        response_count=0,
        deregistered=False,
        accepted_expires_seconds=None,
    )

    finalized, recovered = await db_session.finalize_onnuri_registration_operation(
        **success
    )
    assert finalized.state == "completed"
    assert recovered is False

    with pytest.raises(
        TelephonyNumberInventoryConflictError,
        match="onnuri_registration_terminal_replay_rejected",
    ):
        await db_session.finalize_onnuri_registration_operation(**contained)


@pytest.mark.asyncio
@pytest.mark.parametrize("register_outcome", ["succeeded", "failed", "contained"])
async def test_compensating_unregister_survives_every_consumed_register_outcome(
    db_session, register_outcome: str
):
    ids = await _seed_authority(db_session)
    register, register_consume = await _begin_registration(db_session, ids)
    await db_session.consume_onnuri_registration_operation(**register_consume)
    register_finalize = _registration_finalize_values(
        register_consume,
        **(
            {
                "outcome": register_outcome,
                "response_count": 0,
                "deregistered": False,
                "accepted_expires_seconds": None,
            }
            if register_outcome != "succeeded"
            else {}
        ),
    )
    await db_session.finalize_onnuri_registration_operation(**register_finalize)
    async with db_session.async_session() as session:
        persisted_register = await session.get(OnnuriRegistrationGateModel, register.id)
    assert persisted_register is not None
    assert persisted_register.unregister_required is True
    assert persisted_register.unregister_satisfied_at is None


    unregister, unregister_consume = await _begin_registration(
        db_session,
        ids,
        operation_kind="unregister",
        prior_register_gate_id=register.id,
        prior_register_operation_uuid=register.operation_uuid,
    )
    await db_session.consume_onnuri_registration_operation(**unregister_consume)
    unregister_finalize = _registration_finalize_values(unregister_consume)
    for mutation in (
        {"prior_register_gate_id": register.id + 1},
        {
            "prior_register_operation_uuid": (
                "77777777-7777-4777-8777-777777777777"
            )
        },
    ):
        with pytest.raises(
            TelephonyNumberInventoryConflictError,
            match="registration_receipt_mismatch",
        ):
            await db_session.finalize_onnuri_registration_operation(
                **{**unregister_finalize, **mutation}
            )
    finalized, recovered = await db_session.finalize_onnuri_registration_operation(
        **unregister_finalize
    )

    assert finalized.id == unregister.id
    assert finalized.state == "completed"
    assert finalized.execution_attestation_digest is not None
    assert finalized.accepted_expires_at is not None
    assert recovered is False
    async with db_session.async_session() as session:
        satisfied_register = await session.get(OnnuriRegistrationGateModel, register.id)
    assert satisfied_register is not None
    assert satisfied_register.unregister_required is True
    assert satisfied_register.unregister_satisfied_at is not None

    duplicate, recovered = await db_session.finalize_onnuri_registration_operation(
        **unregister_finalize
    )
    assert duplicate.id == unregister.id
    assert recovered is True

    async with db_session.async_session() as session:
        envelope = await session.get(OnnuriSmokeEnvelopeModel, ids["envelope_id"])
        database_now = (await session.execute(text("SELECT now()"))).scalar_one()
        envelope.state = "contained"
        envelope.contained_at = database_now
        envelope.containment_reason = "registration-compensation-complete"
        await session.commit()


@pytest.mark.asyncio
async def test_failed_compensating_unregister_is_terminal_and_has_no_retry(db_session):
    ids = await _seed_authority(db_session)
    register, register_consume = await _begin_registration(db_session, ids)
    await db_session.consume_onnuri_registration_operation(**register_consume)
    await db_session.finalize_onnuri_registration_operation(
        **_registration_finalize_values(register_consume)
    )
    _, unregister_consume = await _begin_registration(
        db_session,
        ids,
        operation_kind="unregister",
        prior_register_gate_id=register.id,
        prior_register_operation_uuid=register.operation_uuid,
    )
    await db_session.consume_onnuri_registration_operation(**unregister_consume)
    await db_session.finalize_onnuri_registration_operation(
        **_registration_finalize_values(
            unregister_consume,
            outcome="failed",
            deregistered=False,
            accepted_expires_seconds=None,
        )
    )
    async with db_session.async_session() as session:
        outstanding_register = await session.get(OnnuriRegistrationGateModel, register.id)
    assert outstanding_register is not None
    assert outstanding_register.unregister_required is True
    assert outstanding_register.unregister_satisfied_at is None

    with pytest.raises(
        TelephonyNumberInventoryConflictError,
        match="g008_stage_not_startable",
    ):
        await _begin_registration(
            db_session,
            ids,
            operation_kind="unregister",
            prior_register_gate_id=register.id,
            prior_register_operation_uuid=register.operation_uuid,
        )

    with pytest.raises(DBAPIError):
        async with db_session.async_session() as session:
            envelope = await session.get(
                OnnuriSmokeEnvelopeModel, ids["envelope_id"]
            )
            database_now = (
                await session.execute(text("SELECT now()"))
            ).scalar_one()
            envelope.state = "contained"
            envelope.contained_at = database_now
            envelope.containment_reason = "failed-unregister-must-remain-open"
            await session.commit()


def _write_es256_pair(tmp_path, name: str):
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_path = tmp_path / f"{name}-private.pem"
    public_path = tmp_path / f"{name}-public.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def _runtime_environment(tmp_path, monkeypatch):
    dispatch_private, dispatch_public = _write_es256_pair(tmp_path, "dispatch")
    media_private, media_public = _write_es256_pair(tmp_path, "media")
    execution_private, execution_public = _write_es256_pair(tmp_path, "execution")
    recovery = tmp_path / "recovery.key"
    recovery.write_bytes(b"r" * 32)
    values = {
        "ONNURI_SMOKE_DISPATCH_PRIVATE_KEY_FILE": dispatch_private,
        "ONNURI_SMOKE_DISPATCH_PUBLIC_KEY_FILE": dispatch_public,
        "ONNURI_SMOKE_DISPATCH_KEY_ID": "dispatch-key",
        "ONNURI_SMOKE_MEDIA_PRIVATE_KEY_FILE": media_private,
        "ONNURI_SMOKE_MEDIA_PUBLIC_KEY_FILE": media_public,
        "ONNURI_SMOKE_MEDIA_KEY_ID": "media-key",
        "ONNURI_SMOKE_EXECUTION_EVIDENCE_PRIVATE_KEY_FILE": execution_private,
        "ONNURI_SMOKE_EXECUTION_EVIDENCE_PUBLIC_KEY_FILE": execution_public,
        "ONNURI_SMOKE_EXECUTION_EVIDENCE_KEY_ID": "execution-evidence-key",
        "ONNURI_SMOKE_RECOVERY_KEY_FILE": recovery,
    }
    for name, value in values.items():
        monkeypatch.setenv(name, str(value))


@pytest.mark.asyncio
async def test_concrete_smoke_runtime_readiness_and_authenticated_recovery(
    tmp_path, monkeypatch
):
    reset_smoke_authority_runtime_for_tests()

    async def database_ready():
        return True

    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "onnuri_smoke_authority_ready",
        database_ready,
    )
    try:
        assert await onnuri_smoke_f12.authority_ready() is False
        monkeypatch.setattr(
            onnuri_smoke_f12,
            "_load_g008_authority_signing_key",
            lambda _trusted_keyset_digest: object(),
        )
        _runtime_environment(tmp_path, monkeypatch)
        runtime = configure_smoke_authority_runtime_from_environment()
        assert runtime.configuration_ready() is True
        assert await onnuri_smoke_f12.authority_ready() is True

        expires_at = datetime.now(UTC) + timedelta(seconds=30)
        sealed = await runtime.recovery_sealer.seal(
            plaintext=b"recovery-record", expires_at=expires_at
        )
        assert await runtime.recovery_sealer.unseal(ciphertext=sealed) == b"recovery-record"
        replacement = "A" if sealed[0] != "A" else "B"
        with pytest.raises(SmokeCapabilityInvalidError):
            await runtime.recovery_sealer.unseal(ciphertext=replacement + sealed[1:])
    finally:
        reset_smoke_authority_runtime_for_tests()


@pytest.mark.asyncio
async def test_concrete_issuer_requires_separate_keys_candidate_and_gate_binding(
    tmp_path,
):
    dispatch_private, dispatch_public = _write_es256_pair(tmp_path, "dispatch")
    media_private, media_public = _write_es256_pair(tmp_path, "media")
    issuer = PrivatePemSmokeCapabilityIssuer(
        dispatch_private_key_file=str(dispatch_private),
        dispatch_public_key_file=str(dispatch_public),
        dispatch_key_id="dispatch-key",
        media_private_key_file=str(media_private),
        media_public_key_file=str(media_public),
        media_key_id="media-key",
    )
    now = datetime.now(UTC)
    binding = CapabilityBinding(
        organization_id=7,
        account_id="account",
        application_id="application",
        run_id="run",
        attempt_id="attempt",
        direction="outbound",
        idempotency_key="idempotency",
        request_digest=_DIGEST,
        candidate_digest=_OTHER_DIGEST,
        gate_envelope_digest=_DESTINATION_DIGEST,
    )
    policy = CapabilityPolicy(
        kind="dispatch",
        verification_domain=DISPATCH_CAPABILITY_DOMAIN,
        key_id="dispatch-key",
        other_key_id="media-key",
    )
    with pytest.raises(SmokeCapabilityInvalidError):
        CapabilityIssueRequest(
            binding=binding,
            policy=policy,
            issued_at=now,
            expires_at=now + timedelta(seconds=30),
            gate_envelope_digest=_OTHER_DIGEST,
        )
    missing_candidate = CapabilityIssueRequest(
        binding=CapabilityBinding(
            organization_id=binding.organization_id,
            account_id=binding.account_id,
            application_id=binding.application_id,
            run_id=binding.run_id,
            attempt_id=binding.attempt_id,
            direction=binding.direction,
            idempotency_key=binding.idempotency_key,
            request_digest=binding.request_digest,
            candidate_digest="not-a-digest",
            gate_envelope_digest=binding.gate_envelope_digest,
        ),
        policy=policy,
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
        gate_envelope_digest=binding.gate_envelope_digest,
    )
    with pytest.raises(SmokeCapabilityInvalidError):
        await issuer.issue_dispatch(missing_candidate)

    request = CapabilityIssueRequest(
        binding=binding,
        policy=policy,
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
        gate_envelope_digest=binding.gate_envelope_digest,
    )
    issued = await issuer.issue_dispatch(request)
    opaque, signing_bytes = signed_capability_bytes(issued, request)
    verified = await issuer.verify(
        "dispatch", opaque, signing_bytes, issued.signature, binding
    )
    assert verified.token_digest == hashlib.sha256(opaque).hexdigest()
    with pytest.raises(SmokeCapabilityInvalidError):
        await issuer.verify(
            "dispatch",
            opaque,
            opaque_signing_bytes(opaque, kind="dispatch") + b"x",
            issued.signature,
            binding,
        )

    expired_request = CapabilityIssueRequest(
        binding=binding,
        policy=policy,
        issued_at=now - timedelta(seconds=31),
        expires_at=now - timedelta(seconds=1),
        gate_envelope_digest=_DESTINATION_DIGEST,
    )
    expired = await issuer.issue_dispatch(expired_request)
    expired_opaque, expired_signing_bytes = signed_capability_bytes(
        expired, expired_request
    )
    with pytest.raises(SmokeCapabilityInvalidError):
        await issuer.verify(
            "dispatch",
            expired_opaque,
            expired_signing_bytes,
            expired.signature,
            binding,
        )

    with pytest.raises(RuntimeError, match="issuer_separation_invalid"):
        PrivatePemSmokeCapabilityIssuer(
            dispatch_private_key_file=str(dispatch_private),
            dispatch_public_key_file=str(dispatch_public),
            dispatch_key_id="shared-key",
            media_private_key_file=str(media_private),
            media_public_key_file=str(media_public),
            media_key_id="shared-key",
        )


def test_concrete_issuer_rejects_public_key_disagreement(tmp_path):
    dispatch_private, _dispatch_public = _write_es256_pair(tmp_path, "dispatch")
    _other_private, other_public = _write_es256_pair(tmp_path, "other-dispatch")
    media_private, media_public = _write_es256_pair(tmp_path, "media")
    with pytest.raises(RuntimeError, match="public_key_mismatch"):
        PrivatePemSmokeCapabilityIssuer(
            dispatch_private_key_file=str(dispatch_private),
            dispatch_public_key_file=str(other_public),
            dispatch_key_id="dispatch-key",
            media_private_key_file=str(media_private),
            media_public_key_file=str(media_public),
            media_key_id="media-key",
        )


def test_recovery_sealer_has_no_implicit_key_default(tmp_path):
    with pytest.raises(RuntimeError, match="recovery_key_file_invalid"):
        AesGcmSmokeRecoverySealer(key_file=str(tmp_path / "missing.key"))
