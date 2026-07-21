from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from api.db.models import (
    G008ExecutionSealModel,
    G008ExecutionNonceConsumptionModel,
    G008ExecutionStageModel,
    OnnuriRegistrationGateModel,
    OnnuriSmokeAttemptModel,
    OnnuriSmokeCallbackEventModel,
)
from api.db.telephony_number_inventory_client import (
    TelephonyNumberInventoryConflictError,
    TelephonyNumberInventoryNotFoundError,
)
from api.tests.telephony.jambonz.test_onnuri_smoke_authority import (
    _DESTINATION_DIGEST,
    _DIGEST,
    _seed_authority,
)

_STAGES = ["register", "outbound_call", "inbound_call", "unregister"]
_TEST_EVIDENCE_KEY_DIGEST = hashlib.sha256(
    b"test-execution-evidence-spki"
).hexdigest()
_TEST_EVIDENCE_KEY_ID = "test-execution-evidence-v1"

_TEST_BIND_RECEIPT_KEY_DIGEST = hashlib.sha256(
    b"test-inbound-bind-receipt-spki"
).hexdigest()
_TEST_BIND_RECEIPT_KEY_ID = "test-inbound-bind-receipt-v1"


async def _build_test_bind_receipt(
    ingredients: dict[str, object],
) -> dict[str, object]:
    canonical_claims = ingredients["canonical_claims"]
    unsigned_envelope = {
        "schema_version": "recova-g008-inbound-bind-receipt-v1",
        "algorithm": "ES256",
        "verification_domain": "recova.onnuri.smoke.g008.inbound-bind.v1",
        "key_id": _TEST_BIND_RECEIPT_KEY_ID,
        "claims": canonical_claims,
    }
    unsigned = json.dumps(
        unsigned_envelope, sort_keys=True, separators=(",", ":")
    ).encode()
    signature = hashlib.sha256(b"test-signature:" + unsigned).hexdigest()
    recovery_ciphertext = json.dumps(
        {**unsigned_envelope, "signature": signature},
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "receipt_schema": "recova-g008-inbound-bind-receipt-v1",
        "receipt_domain": "recova.onnuri.smoke.g008.inbound-bind.v1",
        "receipt_algorithm": "ES256",
        "receipt_key_id": _TEST_BIND_RECEIPT_KEY_ID,
        "receipt_spki_digest": _TEST_BIND_RECEIPT_KEY_DIGEST,
        "receipt_signature_digest": hashlib.sha256(signature.encode()).hexdigest(),
        "receipt_unsigned_digest": hashlib.sha256(unsigned).hexdigest(),
        "canonical_claims": canonical_claims,
        "recovery_ciphertext": recovery_ciphertext,
        "recovery_ciphertext_digest": hashlib.sha256(
            recovery_ciphertext.encode()
        ).hexdigest(),
    }


async def _build_test_evidence(
    ingredients: dict[str, object],
) -> dict[str, object]:
    canonical = json.dumps(
        ingredients, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    signature = hashlib.sha512(b"signature:" + canonical).digest()
    return {
        "evidence_digest": hashlib.sha256(canonical).hexdigest(),
        "evidence_signature_digest": hashlib.sha256(signature).hexdigest(),
        "evidence_key_digest": _TEST_EVIDENCE_KEY_DIGEST,
        "evidence_key_id": _TEST_EVIDENCE_KEY_ID,
        "canonical_evidence": canonical,
        "evidence_signature": signature,
    }


async def _unexpected_evidence_builder(
    ingredients: dict[str, object],
) -> dict[str, object]:
    del ingredients
    raise AssertionError("registration stage rejection must precede evidence signing")

def _seal_payload(ids: dict[str, object]) -> dict[str, object]:
    now = datetime.now(UTC)
    execution_seal_uuid = str(uuid4())
    return {
        "organization_id": ids["organization_id"],
        "execution_seal_uuid": execution_seal_uuid,
        "execution_nonce_digest": hashlib.sha256(
            f"nonce:{execution_seal_uuid}".encode()
        ).hexdigest(),
        "candidate_digest": _DIGEST,
        "gate_envelope_digest": hashlib.sha256(
            str(ids["envelope_uuid"]).encode("utf-8")
        ).hexdigest(),
        "schema_version": "recova-g008-execution-seal-v1",
        "destination_hmac_digest": _DESTINATION_DIGEST,
        "reserved_inbound_did_digest": hashlib.sha256(
            f"did:{execution_seal_uuid}".encode()
        ).hexdigest(),
        "reserved_inbound_caller_digest": hashlib.sha256(
            f"caller:{execution_seal_uuid}".encode()
        ).hexdigest(),
        "policy_digest": "8" * 64,
        "stages": _STAGES,
        "live_window_starts_at": now - timedelta(seconds=2),
        "live_window_expires_at": now + timedelta(minutes=10),
        "retry_count": 0,
        "concurrency_count": 1,
        "call_deadline_seconds": 60,
        "sealed_at": now - timedelta(seconds=3),
    }


def _binding(seal: dict[str, object]) -> dict[str, object]:
    return {
        key: seal[key]
        for key in (
            "organization_id",
            "execution_seal_uuid",
            "execution_nonce_digest",
            "candidate_digest",
            "gate_envelope_digest",
        )
    }


async def _create_seal(db_session, ids: dict[str, object]) -> tuple[dict[str, object], dict[str, object]]:
    seal = _seal_payload(ids)
    created = await db_session.create_execution_seal(seal)
    return seal, created

async def _ensure_nonce_consumed(db_session, seal: dict[str, object]) -> None:
    async with db_session.async_session() as session:
        consumed = (
            await session.execute(
                select(G008ExecutionNonceConsumptionModel.id).where(
                    G008ExecutionNonceConsumptionModel.execution_seal_uuid
                    == seal["execution_seal_uuid"]
                )
            )
        ).scalar_one_or_none()
    if consumed is None:
        await db_session.consume_execution_nonce(
            {
                **_binding(seal),
                "trusted_keyset_digest": "00645f3af8230c742951c12f17a713afde209de12182cd6e3722ac59445507aa",
            }
        )



async def _start(db_session, seal: dict[str, object], ordinal: int) -> None:
    await _ensure_nonce_consumed(db_session, seal)
    async with db_session.async_session() as session:
        database_now = (await session.execute(select(func.clock_timestamp()))).scalar_one()
    await db_session.start_execution_stage(
        {
            **_binding(seal),
            "stage": _STAGES[ordinal - 1],
            "ordinal": ordinal,
            "started_at": database_now - timedelta(seconds=1),
        }
    )


async def _claim_inbound(db_session, seal: dict[str, object]) -> None:
    await db_session.claim_reserved_inbound_and_bind(
        {
            "organization_id": seal["organization_id"],
            "account_uuid": str(uuid4()),
            "application_uuid": str(uuid4()),
            "stock_call_uuid": str(uuid4()),
            "did_digest": seal["reserved_inbound_did_digest"],
            "caller_digest": seal["reserved_inbound_caller_digest"],
        },
        receipt_builder=_build_test_bind_receipt,
    )


async def _bind_outbound(
    db_session, ids: dict[str, object], seal: dict[str, object]
) -> None:
    await asyncio.sleep(0.01)
    attempt_uuid = str(uuid4())
    async with db_session.async_session() as session:
        now = (await session.execute(select(func.clock_timestamp()))).scalar_one()
        terminal_at = now
        attempt = OnnuriSmokeAttemptModel(
            attempt_uuid=attempt_uuid,
            envelope_id=ids["envelope_id"],
            proof_id=ids["proof_id"],
            organization_id=ids["organization_id"],
            inventory_id=ids["inventory_id"],
            telephony_configuration_id=ids["configuration_id"],
            workflow_id=ids["workflow_id"],
            ordinal=1,
            direction="outbound",
            state="terminal",
            authenticated_operator_user_id=ids["operator_id"],
            workflow_owner_user_id=ids["owner_id"],
            idempotency_key=str(uuid4()),
            allocation_request_digest=hashlib.sha256(
                attempt_uuid.encode()
            ).hexdigest(),
            dispatch_receipt_digest=hashlib.sha256(
                f"dispatch:{attempt_uuid}".encode()
            ).hexdigest(),
            stock_call_id_digest=hashlib.sha256(
                f"stock:{attempt_uuid}".encode()
            ).hexdigest(),
            authority_kind="outbound",
            authority_wall_at=now,
            authority_deadline_at=now + timedelta(seconds=60),
            authority_budget_seconds=60,
            allocated_at=now,
            terminal_class="call_completed",
            terminal_at=terminal_at,
            account_id="offline-account",
            application_id="offline-application",
            run_id=str(uuid4()),
        )
        session.add(attempt)
        await session.flush()
        session.add(
            OnnuriSmokeCallbackEventModel(
                attempt_id=attempt.id,
                event_nonce_digest=hashlib.sha256(
                    f"callback:{attempt_uuid}".encode()
                ).hexdigest(),
                idempotency_key=str(uuid4()),
                request_digest=hashlib.sha256(
                    f"callback-request:{attempt_uuid}".encode()
                ).hexdigest(),
                event_type="status",
                normalized_status="completed",
                occurred_at=terminal_at,
                accepted_at=terminal_at,
            )
        )
        await session.commit()
    await db_session.bind_g008_outbound_observation(
        {
            "organization_id": ids["organization_id"],
            "attempt_uuid": attempt_uuid,
        }
    )


async def _finish_generic(
    db_session, ids: dict[str, object], seal: dict[str, object], ordinal: int
) -> None:
    if ordinal == 2:
        await _bind_outbound(db_session, ids, seal)
    await db_session.finalize_execution_stage(
        {
            **_binding(seal),
            "stage": _STAGES[ordinal - 1],
            "ordinal": ordinal,
            "stage_state": "succeeded",
            "terminal_class": "call_completed" if ordinal == 2 else "inbound_bound",
        },
        evidence_builder=_build_test_evidence,
    )


def _begin_values(
    ids: dict[str, object],
    seal: dict[str, object],
    stage_row: dict[str, object],
    *,
    operation_kind: str,
    prior: OnnuriRegistrationGateModel | None = None,
) -> dict[str, object]:
    return {
        "envelope_uuid": ids["envelope_uuid"],
        "organization_id": ids["organization_id"],
        "operation_kind": operation_kind,
        "request_digest": "3" * 64,
        "candidate_digest": seal["candidate_digest"],
        "gate_envelope_digest": seal["gate_envelope_digest"],
        "nonce_digest": seal["execution_nonce_digest"],
        "execution_seal_uuid": seal["execution_seal_uuid"],
        "execution_nonce_digest": seal["execution_nonce_digest"],
        "execution_stage_uuid": stage_row["stage_uuid"],
        "execution_stage": operation_kind,
        "execution_stage_ordinal": 1 if operation_kind == "register" else 4,
        "prior_register_gate_id": prior.id if prior is not None else None,
        "prior_register_operation_uuid": prior.operation_uuid if prior is not None else None,
    }


def _consume_values(begin: dict[str, object], gate: OnnuriRegistrationGateModel) -> dict[str, object]:
    excluded = {
        "envelope_uuid",
        "execution_seal_uuid",
        "execution_nonce_digest",
        "execution_stage_uuid",
        "execution_stage",
        "execution_stage_ordinal",
    }
    values = {key: value for key, value in begin.items() if key not in excluded}
    values.update(registration_gate_id=gate.id, operation_uuid=gate.operation_uuid)
    return values


def _finalize_values(consume: dict[str, object], *, suffix: str = "a") -> dict[str, object]:
    unregister = consume["operation_kind"] == "unregister"
    canonical = json.dumps(
        {
            "operation_uuid": consume["operation_uuid"],
            "operation_kind": consume["operation_kind"],
            "attestation_variant": suffix,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    signature = hashlib.sha512(b"registration-attestation:" + canonical).digest()
    return {
        **consume,
        "outcome": "succeeded",
        "transaction_count": 1,
        "retry_count": 0,
        "response_count": 1,
        "wire_request_count": 1,
        "deregistered": unregister,
        "accepted_expires_seconds": 0 if unregister else 3600,
        "execution_attestation_canonical": canonical,
        "execution_attestation_signature": signature,
        "execution_attestation_digest": hashlib.sha256(canonical).hexdigest(),
        "execution_attestation_signature_digest": hashlib.sha256(
            signature
        ).hexdigest(),
        "execution_attestation_key_digest": "c" * 64,
        "execution_attestation_key_id": "registration-attestation-v1",
        "execution_attested_at": datetime.now(UTC),
    }


async def _snapshot(db_session, seal_uuid: str) -> tuple[object, list[tuple[object, ...]], list[tuple[object, ...]]]:
    async with db_session.async_session() as session:
        seal = (
            await session.execute(
                select(G008ExecutionSealModel).where(
                    G008ExecutionSealModel.execution_seal_uuid == seal_uuid
                )
            )
        ).scalar_one()
        stages = (
            await session.execute(
                select(G008ExecutionStageModel)
                .where(G008ExecutionStageModel.execution_seal_id == seal.id)
                .order_by(G008ExecutionStageModel.ordinal)
            )
        ).scalars().all()
        gates = (
            await session.execute(
                select(OnnuriRegistrationGateModel)
                .where(OnnuriRegistrationGateModel.execution_stage_id.in_([row.id for row in stages]))
                .order_by(OnnuriRegistrationGateModel.id)
            )
        ).scalars().all()
        return (
            (seal.state, seal.failed_at, seal.contained_at),
            [
                (
                    row.ordinal,
                    row.state,
                    row.terminal_class,
                    row.evidence_digest,
                    row.evidence_signature_digest,
                    row.evidence_key_digest,
                    row.finalized_at,
                )
                for row in stages
            ],
            [
                (
                    gate.id,
                    gate.state,
                    gate.execution_stage_id,
                    gate.execution_attestation_digest,
                    gate.execution_attestation_signature_digest,
                    gate.execution_attestation_key_digest,
                    gate.unregister_satisfied_at,
                )
                for gate in gates
            ],
        )


async def _register(db_session):
    ids = await _seed_authority(db_session)
    seal, created = await _create_seal(db_session, ids)
    await _start(db_session, seal, 1)
    begin = _begin_values(ids, seal, created["stages"][0], operation_kind="register")
    context = await db_session.begin_onnuri_registration_operation(**begin)
    gate = context["gate"]
    consume = _consume_values(begin, gate)
    await db_session.consume_onnuri_registration_operation(**consume)
    finalize = _finalize_values(consume)
    completed, recovered = await db_session.finalize_onnuri_registration_operation(**finalize)
    assert recovered is False
    return ids, seal, created, completed, finalize


async def _contain_seal_with_unresolved_register(db_session, seal: dict[str, object]) -> None:
    """Populate the valid legacy contained seal shape without changing its receipt."""
    canonical = b"contained-register-cleanup"
    signature = hashlib.sha512(canonical).digest()
    async with db_session.async_session() as session:
        persisted = (
            await session.execute(
                select(G008ExecutionSealModel)
                .where(G008ExecutionSealModel.execution_seal_uuid == seal["execution_seal_uuid"])
                .with_for_update()
            )
        ).scalar_one()
        now = (await session.execute(select(func.clock_timestamp()))).scalar_one()
        persisted.state = "contained"
        persisted.containment_class = "legacy_contained_register"
        persisted.containment_evidence_digest = hashlib.sha256(canonical).hexdigest()
        persisted.containment_evidence_signature_digest = hashlib.sha256(signature).hexdigest()
        persisted.containment_evidence_key_digest = _TEST_EVIDENCE_KEY_DIGEST
        persisted.containment_evidence_key_id = _TEST_EVIDENCE_KEY_ID
        persisted.containment_evidence_canonical = canonical
        persisted.containment_evidence_signature = signature
        persisted.contained_at = now
        await session.commit()


@pytest.mark.asyncio
async def test_contained_seal_unregister_cleanup_keeps_seal_contained_and_records_receipt(db_session):
    ids, seal, created, register, _ = await _register(db_session)
    await _contain_seal_with_unresolved_register(db_session, seal)

    await _start(db_session, seal, 4)
    begin = _begin_values(
        ids, seal, created["stages"][3], operation_kind="unregister", prior=register
    )
    context = await db_session.begin_onnuri_registration_operation(**begin)
    consume = _consume_values(begin, context["gate"])
    await db_session.consume_onnuri_registration_operation(**consume)
    finalized, recovered = await db_session.finalize_onnuri_registration_operation(
        **_finalize_values(consume, suffix="contained-cleanup")
    )

    assert recovered is False
    async with db_session.async_session() as session:
        persisted_seal = (
            await session.execute(
                select(G008ExecutionSealModel).where(
                    G008ExecutionSealModel.execution_seal_uuid
                    == seal["execution_seal_uuid"]
                )
            )
        ).scalar_one()
        persisted_register = await session.get(OnnuriRegistrationGateModel, register.id)
        persisted_stage = await session.get(
            G008ExecutionStageModel, finalized.execution_stage_id
        )
    assert persisted_seal is not None and persisted_register is not None
    assert persisted_stage is not None
    assert persisted_seal.state == "contained"
    assert persisted_register.unregister_satisfied_at == persisted_stage.finalized_at
    assert (persisted_stage.ordinal, persisted_stage.state, persisted_stage.terminal_class) == (
        4,
        "succeeded",
        "unregistered",
    )


@pytest.mark.asyncio
async def test_contained_seal_unregister_cleanup_refuses_wrong_linkage_without_mutation(db_session):
    ids, seal, created, register, _ = await _register(db_session)
    await _contain_seal_with_unresolved_register(db_session, seal)
    await _start(db_session, seal, 4)
    begin = _begin_values(
        ids, seal, created["stages"][3], operation_kind="unregister", prior=register
    )
    before = await _snapshot(db_session, str(seal["execution_seal_uuid"]))

    with pytest.raises(TelephonyNumberInventoryConflictError):
        await db_session.begin_onnuri_registration_operation(
            **{
                **begin,
                "prior_register_operation_uuid": "99999999-9999-4999-8999-999999999999",
            }
        )

    assert await _snapshot(db_session, str(seal["execution_seal_uuid"])) == before


@pytest.mark.asyncio
async def test_contained_seal_unregister_cleanup_finalize_rollback_preserves_seal_and_obligation(
    db_session, monkeypatch: pytest.MonkeyPatch
):
    ids, seal, created, register, _ = await _register(db_session)
    await _contain_seal_with_unresolved_register(db_session, seal)
    await _start(db_session, seal, 4)
    begin = _begin_values(
        ids, seal, created["stages"][3], operation_kind="unregister", prior=register
    )
    gate = (await db_session.begin_onnuri_registration_operation(**begin))["gate"]
    consume = _consume_values(begin, gate)
    await db_session.consume_onnuri_registration_operation(**consume)
    before = await _snapshot(db_session, str(seal["execution_seal_uuid"]))

    async with db_session.async_session() as session:
        fault_savepoint = await session.begin_nested()

        async def fail_after_cleanup_receipt() -> None:
            await session.flush()
            gate_state = await session.scalar(
                select(OnnuriRegistrationGateModel.state).where(
                    OnnuriRegistrationGateModel.id == gate.id
                )
            )
            stage_state = await session.scalar(
                select(G008ExecutionStageModel.state).where(
                    G008ExecutionStageModel.id == gate.execution_stage_id,
                )
            )
            assert gate_state == "completed"
            assert stage_state == "succeeded"
            await fault_savepoint.rollback()
            session.expire_all()
            raise RuntimeError("injected contained-cleanup commit fault")

        monkeypatch.setattr(session, "commit", fail_after_cleanup_receipt)
        with pytest.raises(RuntimeError, match="injected contained-cleanup commit fault"):
            await db_session.finalize_onnuri_registration_operation(
                **_finalize_values(consume, suffix="contained-cleanup-rollback")
            )

    assert await _snapshot(db_session, str(seal["execution_seal_uuid"])) == before


@pytest.mark.asyncio
async def test_register_finalize_atomically_terminalizes_gate_and_stage_one(db_session):
    _ids, seal, _created, gate, finalize = await _register(db_session)

    async with db_session.async_session() as session:
        persisted_gate = await session.get(OnnuriRegistrationGateModel, gate.id)
        persisted_stage = await session.get(G008ExecutionStageModel, gate.execution_stage_id)
    assert persisted_gate is not None and persisted_stage is not None
    assert persisted_gate.state == "completed"
    assert persisted_stage.ordinal == 1
    assert (persisted_stage.stage, persisted_stage.state, persisted_stage.terminal_class) == (
        "register",
        "succeeded",
        "registered",
    )
    assert persisted_gate.terminal_at == persisted_stage.finalized_at
    assert persisted_gate.execution_attestation_digest == persisted_stage.evidence_digest
    assert persisted_gate.execution_attestation_signature_digest == persisted_stage.evidence_signature_digest
    assert persisted_gate.execution_attestation_key_digest == persisted_stage.evidence_key_digest
    assert persisted_stage.evidence_digest == finalize["execution_attestation_digest"]
    status = await db_session.get_execution_stage_status(
        **{**_binding(seal), "stage": "register", "ordinal": 1}
    )
    assert status is not None
    assert status["registration_gate_id"] == gate.id
    assert status["registration_operation_uuid"] == gate.operation_uuid


@pytest.mark.asyncio
async def test_unregister_finalize_atomically_terminalizes_stage_four_and_exact_prior(db_session):
    ids, seal, created, register, _ = await _register(db_session)
    for ordinal in (2, 3):
        await _start(db_session, seal, ordinal)
        if ordinal == 3:
            await _claim_inbound(db_session, seal)
        await _finish_generic(db_session, ids, seal, ordinal)
    await _start(db_session, seal, 4)
    begin = _begin_values(
        ids, seal, created["stages"][3], operation_kind="unregister", prior=register
    )
    context = await db_session.begin_onnuri_registration_operation(**begin)
    unregister = context["gate"]
    consume = _consume_values(begin, unregister)
    await db_session.consume_onnuri_registration_operation(**consume)
    finalized, recovered = await db_session.finalize_onnuri_registration_operation(
        **_finalize_values(consume, suffix="d")
    )
    assert recovered is False

    async with db_session.async_session() as session:
        persisted_prior = await session.get(OnnuriRegistrationGateModel, register.id)
        persisted_unregister = await session.get(OnnuriRegistrationGateModel, finalized.id)
        stage = await session.get(G008ExecutionStageModel, finalized.execution_stage_id)
    assert persisted_prior is not None and persisted_unregister is not None and stage is not None
    assert persisted_unregister.unregisters_gate_id == persisted_prior.id
    assert (stage.ordinal, stage.stage, stage.state, stage.terminal_class) == (
        4,
        "unregister",
        "succeeded",
        "unregistered",
    )
    assert persisted_unregister.terminal_at == stage.finalized_at
    assert persisted_prior.unregister_required is True
    assert persisted_prior.unregister_satisfied_at == stage.finalized_at
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("prior_register_gate_id", 999_999_999),
        (
            "prior_register_operation_uuid",
            "99999999-9999-4999-8999-999999999999",
        ),
    ],
)
async def test_unregister_wrong_prior_link_leaves_stage_and_obligation_unchanged(
    db_session, field: str, replacement: object
):
    ids, seal, created, register, _ = await _register(db_session)
    for ordinal in (2, 3):
        await _start(db_session, seal, ordinal)
        if ordinal == 3:
            await _claim_inbound(db_session, seal)
        await _finish_generic(db_session, ids, seal, ordinal)
    await _start(db_session, seal, 4)
    begin = _begin_values(
        ids, seal, created["stages"][3], operation_kind="unregister", prior=register
    )
    before = await _snapshot(db_session, str(seal["execution_seal_uuid"]))

    with pytest.raises(TelephonyNumberInventoryConflictError):
        await db_session.begin_onnuri_registration_operation(
            **{**begin, field: replacement}
        )

    assert await _snapshot(db_session, str(seal["execution_seal_uuid"])) == before
    async with db_session.async_session() as session:
        persisted_prior = await session.get(OnnuriRegistrationGateModel, register.id)
    assert persisted_prior is not None
    assert persisted_prior.unregister_satisfied_at is None



@pytest.mark.asyncio
@pytest.mark.parametrize("ordinal", [1, 4])
async def test_generic_stage_finalizer_rejects_registration_ordinals_without_transition(
    db_session, ordinal: int
):
    if ordinal == 1:
        ids = await _seed_authority(db_session)
        seal, _created = await _create_seal(db_session, ids)
        await _start(db_session, seal, 1)
    else:
        ids, seal, _created, _register_gate, _finalize = await _register(db_session)
        for prior_ordinal in (2, 3):
            await _start(db_session, seal, prior_ordinal)
            if prior_ordinal == 3:
                await _claim_inbound(db_session, seal)
            await _finish_generic(db_session, ids, seal, prior_ordinal)
        await _start(db_session, seal, 4)
    before = await _snapshot(db_session, str(seal["execution_seal_uuid"]))
    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="requires_attestation"
    ):
        await db_session.finalize_execution_stage(
            {
                **_binding(seal),
                "stage": _STAGES[ordinal - 1],
                "ordinal": ordinal,
                "stage_state": "succeeded",
                "terminal_class": "registered" if ordinal == 1 else "unregistered",
            },
            evidence_builder=_unexpected_evidence_builder,
        )
    assert await _snapshot(db_session, str(seal["execution_seal_uuid"])) == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("organization_id", "other_tenant"),
        ("execution_seal_uuid", "99999999-9999-4999-8999-999999999999"),
        ("candidate_digest", "9" * 64),
        ("gate_envelope_digest", "8" * 64),
        ("execution_nonce_digest", "7" * 64),
        ("execution_stage_uuid", "88888888-8888-4888-8888-888888888888"),
        ("execution_stage", "unregister"),
        ("execution_stage_ordinal", 4),
    ],
)
async def test_wrong_registration_execution_binding_never_transitions(
    db_session, field: str, replacement: object
):
    ids = await _seed_authority(db_session)
    seal, created = await _create_seal(db_session, ids)
    await _start(db_session, seal, 1)
    begin = _begin_values(ids, seal, created["stages"][0], operation_kind="register")
    if field == "organization_id":
        other_ids = await _seed_authority(db_session)
        replacement = other_ids["organization_id"]
    before = await _snapshot(db_session, str(seal["execution_seal_uuid"]))
    with pytest.raises(
        (TelephonyNumberInventoryConflictError, TelephonyNumberInventoryNotFoundError)
    ):
        await db_session.begin_onnuri_registration_operation(
            **{**begin, field: replacement}
        )
    assert await _snapshot(db_session, str(seal["execution_seal_uuid"])) == before


@pytest.mark.asyncio
async def test_exact_finalize_and_status_recover_but_altered_replay_is_rejected(db_session):
    _ids, seal, _created, gate, finalize = await _register(db_session)
    before = await _snapshot(db_session, str(seal["execution_seal_uuid"]))
    duplicate, recovered = await db_session.finalize_onnuri_registration_operation(**finalize)
    assert duplicate.id == gate.id
    assert recovered is True
    status = await db_session.get_execution_stage_status(
        **{**_binding(seal), "stage": "register", "ordinal": 1}
    )
    assert status is not None and status["state"] == "succeeded"
    assert await _snapshot(db_session, str(seal["execution_seal_uuid"])) == before

    altered = _finalize_values(
        _consume_values(
            _begin_values(
                _ids,
                seal,
                _created["stages"][0],
                operation_kind="register",
            ),
            gate,
        ),
        suffix="altered",
    )
    cross_execution_canonical = json.dumps(
        {
            "execution_seal_uuid": str(uuid4()),
            "operation_kind": "register",
            "attestation_variant": "cross-execution",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    cross_execution_signature = hashlib.sha512(
        b"registration-attestation:" + cross_execution_canonical
    ).digest()
    cross_execution = {
        **altered,
        "execution_attestation_canonical": cross_execution_canonical,
        "execution_attestation_signature": cross_execution_signature,
        "execution_attestation_digest": hashlib.sha256(
            cross_execution_canonical
        ).hexdigest(),
        "execution_attestation_signature_digest": hashlib.sha256(
            cross_execution_signature
        ).hexdigest(),
    }
    for replay in (altered, cross_execution):
        with pytest.raises(
            TelephonyNumberInventoryConflictError, match="terminal_replay"
        ):
            await db_session.finalize_onnuri_registration_operation(**replay)
        assert await _snapshot(
            db_session, str(seal["execution_seal_uuid"])
        ) == before


@pytest.mark.asyncio
async def test_finalize_commit_fault_rolls_back_gate_and_stage_mutations(
    db_session, monkeypatch: pytest.MonkeyPatch
):
    ids = await _seed_authority(db_session)
    seal, created = await _create_seal(db_session, ids)
    await _start(db_session, seal, 1)
    begin = _begin_values(ids, seal, created["stages"][0], operation_kind="register")
    gate = (await db_session.begin_onnuri_registration_operation(**begin))["gate"]
    consume = _consume_values(begin, gate)
    await db_session.consume_onnuri_registration_operation(**consume)
    before = await _snapshot(db_session, str(seal["execution_seal_uuid"]))

    async with db_session.async_session() as session:
        original_commit = session.commit
        fault_savepoint = await session.begin_nested()

        async def fail_after_mutations() -> None:
            assert any(
                isinstance(row, OnnuriRegistrationGateModel) and row.state == "completed"
                for row in session.dirty
            )
            assert any(
                isinstance(row, G008ExecutionStageModel) and row.state == "succeeded"
                for row in session.dirty
            )
            await session.flush()
            await fault_savepoint.rollback()
            raise RuntimeError("injected commit fault")

        monkeypatch.setattr(session, "commit", fail_after_mutations)
        with pytest.raises(RuntimeError, match="injected commit fault"):
            await db_session.finalize_onnuri_registration_operation(
                **_finalize_values(consume)
            )
        monkeypatch.setattr(session, "commit", original_commit)

    assert await _snapshot(db_session, str(seal["execution_seal_uuid"])) == before


@pytest.mark.asyncio
async def test_status_missing_or_any_binding_mismatch_fails_closed(db_session):
    ids = await _seed_authority(db_session)
    seal, _created = await _create_seal(db_session, ids)
    await _start(db_session, seal, 1)
    assert await db_session.get_execution_stage_status(
        **{**_binding(seal), "stage": "register", "ordinal": 1}
    ) is not None
    before = await _snapshot(db_session, str(seal["execution_seal_uuid"]))
    for field, value in (
        ("organization_id", int(ids["organization_id"]) + 1),
        ("execution_seal_uuid", "99999999-9999-4999-8999-999999999999"),
        ("execution_nonce_digest", "9" * 64),
        ("candidate_digest", "8" * 64),
        ("gate_envelope_digest", "7" * 64),
    ):
        assert await db_session.get_execution_stage_status(
            **{
                **_binding(seal),
                "stage": "register",
                "ordinal": 1,
                field: value,
            }
        ) is None
    with pytest.raises(TelephonyNumberInventoryConflictError):
        await db_session.get_execution_stage_status(
            **{**_binding(seal), "stage": "unregister", "ordinal": 1}
        )
    assert await _snapshot(db_session, str(seal["execution_seal_uuid"])) == before

@pytest.mark.asyncio
async def test_legacy_registration_create_rejects_g008_v3_envelope(db_session):
    ids = await _seed_authority(db_session)

    with pytest.raises(
        TelephonyNumberInventoryConflictError,
        match="legacy_path_disabled",
    ):
        await db_session.create_onnuri_registration_gate(
            envelope_uuid=str(ids["envelope_uuid"]),
            organization_id=int(ids["organization_id"]),
            operation_kind="register",
            request_digest="c" * 64,
        )


@pytest.mark.asyncio
async def test_legacy_registration_update_rejects_g008_v3_envelope(db_session):
    ids = await _seed_authority(db_session)
    seal, created = await _create_seal(db_session, ids)
    await _start(db_session, seal, 1)
    begin = _begin_values(
        ids,
        seal,
        created["stages"][0],
        operation_kind="register",
    )
    gate = (await db_session.begin_onnuri_registration_operation(**begin))["gate"]
    gate_id = gate.id

    with pytest.raises(
        TelephonyNumberInventoryConflictError,
        match="legacy_path_disabled",
    ):
        await db_session.update_onnuri_registration_gate(
            gate_id,
            organization_id=int(ids["organization_id"]),
            state="challenged",
            transaction_count=1,
            retransmission_count=0,
        )
