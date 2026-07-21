from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker

from api.db.models import (
    G008ExecutionSealModel,
    G008ExecutionNonceConsumptionModel,
    G008InboundBindingModel,
    G008ExecutionStageModel,
    G008OutboundBindingModel,
    OnnuriRegistrationGateModel,
    OnnuriSmokeAttemptModel,
    OnnuriSmokeCallbackEventModel,
)
from api.db.telephony_number_inventory_client import (
    TelephonyNumberInventoryConflictError,
    _registration_binding_digest,
)
from api.tests.telephony.jambonz.test_onnuri_smoke_authority import (
    _DESTINATION_DIGEST,
    _DIGEST,
    _seed_authority,
)


D = "a" * 64
OTHER = "b" * 64
STAGES = ["register", "outbound_call", "inbound_call", "unregister"]
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

async def _organization(db_session, suffix: str) -> dict[str, object]:
    del suffix
    return await _seed_authority(db_session)


@pytest.fixture
async def committed_db_session(db_session, test_engine):
    original_session_factory = db_session.async_session
    db_session.async_session = async_sessionmaker(
        bind=test_engine,
        expire_on_commit=False,
        autoflush=False,
    )
    try:
        yield db_session
    finally:
        db_session.async_session = original_session_factory


def _seal_payload(
    authority: dict[str, object],
    *,
    nonce: str | None = None,
    did: str | None = None,
    caller: str | None = None,
    starts_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> dict[str, object]:
    now = datetime.now(UTC)
    starts_at = starts_at or now - timedelta(seconds=2)
    execution_seal_uuid = str(uuid4())
    return {
        "organization_id": authority["organization_id"],
        "execution_seal_uuid": execution_seal_uuid,
        "execution_nonce_digest": nonce
        or hashlib.sha256(f"nonce:{execution_seal_uuid}".encode()).hexdigest(),
        "candidate_digest": _DIGEST,
        "gate_envelope_digest": hashlib.sha256(
            str(authority["envelope_uuid"]).encode("utf-8")
        ).hexdigest(),
        "schema_version": "recova-g008-execution-seal-v1",
        "destination_hmac_digest": _DESTINATION_DIGEST,
        "reserved_inbound_did_digest": did
        or hashlib.sha256(f"did:{execution_seal_uuid}".encode()).hexdigest(),
        "reserved_inbound_caller_digest": caller
        or hashlib.sha256(f"caller:{execution_seal_uuid}".encode()).hexdigest(),
        "policy_digest": "2" * 64,
        "stages": STAGES,
        "live_window_starts_at": starts_at,
        "live_window_expires_at": expires_at or now + timedelta(minutes=10),
        "retry_count": 0,
        "concurrency_count": 1,
        "call_deadline_seconds": 60,
        "sealed_at": starts_at - timedelta(seconds=1),
    }


def _common(payload: dict[str, object]) -> dict[str, object]:
    return {
        key: payload[key]
        for key in (
            "organization_id",
            "execution_seal_uuid",
            "execution_nonce_digest",
            "candidate_digest",
            "gate_envelope_digest",
        )
    }



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
                **_common(seal),
                "trusted_keyset_digest": "00645f3af8230c742951c12f17a713afde209de12182cd6e3722ac59445507aa",
            }
        )

async def _start(db_session, seal: dict[str, object], ordinal: int) -> dict[str, object]:
    await _ensure_nonce_consumed(db_session, seal)
    async with db_session.async_session() as session:
        database_now = (await session.execute(select(func.clock_timestamp()))).scalar_one()
    return await db_session.start_execution_stage(
        {
            **_common(seal),
            "stage": STAGES[ordinal - 1],
            "ordinal": ordinal,
            "started_at": database_now - timedelta(seconds=1),
        }
    )


async def _create_outbound_attempt(
    db_session,
    authority: dict[str, object],
    *,
    with_callback: bool = True,
    deadline_seconds: int = 60,
) -> str:
    await asyncio.sleep(0.01)
    attempt_uuid = str(uuid4())
    async with db_session.async_session() as session:
        now = (await session.execute(select(func.clock_timestamp()))).scalar_one()
        terminal_at = now - timedelta(seconds=1)
        attempt = OnnuriSmokeAttemptModel(
            attempt_uuid=attempt_uuid,
            envelope_id=authority["envelope_id"],
            proof_id=authority["proof_id"],
            organization_id=authority["organization_id"],
            inventory_id=authority["inventory_id"],
            telephony_configuration_id=authority["configuration_id"],
            workflow_id=authority["workflow_id"],
            ordinal=1,
            direction="outbound",
            state="terminal",
            authenticated_operator_user_id=authority["operator_id"],
            workflow_owner_user_id=authority["owner_id"],
            idempotency_key=str(uuid4()),
            allocation_request_digest=hashlib.sha256(attempt_uuid.encode()).hexdigest(),
            dispatch_receipt_digest=hashlib.sha256(
                f"dispatch:{attempt_uuid}".encode()
            ).hexdigest(),
            stock_call_id_digest=hashlib.sha256(
                f"stock:{attempt_uuid}".encode()
            ).hexdigest(),
            authority_kind="outbound",
            authority_wall_at=now,
            authority_deadline_at=now + timedelta(seconds=deadline_seconds),
            authority_budget_seconds=deadline_seconds,
            allocated_at=now,
            terminal_class="call_completed",
            terminal_at=terminal_at,
            account_id="offline-account",
            application_id="offline-application",
            run_id=str(uuid4()),
        )
        session.add(attempt)
        await session.flush()
        if with_callback:
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
    return attempt_uuid


async def _bind_outbound(
    db_session,
    authority: dict[str, object],
    seal: dict[str, object],
    *,
    with_callback: bool = True,
    deadline_seconds: int = 60,
) -> None:
    del seal
    attempt_uuid = await _create_outbound_attempt(
        db_session,
        authority,
        with_callback=with_callback,
        deadline_seconds=deadline_seconds,
    )
    await db_session.bind_g008_outbound_observation(
        {
            "organization_id": authority["organization_id"],
            "attempt_uuid": attempt_uuid,
        }
    )


async def _finish(
    db_session,
    authority: dict[str, object],
    seal: dict[str, object],
    ordinal: int,
    *,
    registration_outcome: str = "succeeded",
) -> None:
    if ordinal in {2, 3}:
        if ordinal == 2:
            await _bind_outbound(db_session, authority, seal)
        await db_session.finalize_execution_stage(
            {
                **_common(seal),
                "stage": STAGES[ordinal - 1],
                "ordinal": ordinal,
                "stage_state": "succeeded",
                "terminal_class": (
                    "call_completed" if ordinal == 2 else "inbound_bound"
                ),
            },
            evidence_builder=_build_test_evidence,
        )
        return

    status = await db_session.get_execution_stage_status(
        **_common(seal),
        stage=STAGES[ordinal - 1],
        ordinal=ordinal,
    )
    assert status is not None
    prior = None
    if ordinal == 4:
        async with db_session.async_session() as session:
            prior = (
                await session.execute(
                    select(OnnuriRegistrationGateModel)
                    .join(
                        G008ExecutionStageModel,
                        G008ExecutionStageModel.id
                        == OnnuriRegistrationGateModel.execution_stage_id,
                    )
                    .join(
                        G008ExecutionSealModel,
                        G008ExecutionSealModel.id
                        == G008ExecutionStageModel.execution_seal_id,
                    )
                    .where(
                        G008ExecutionSealModel.execution_seal_uuid
                        == seal["execution_seal_uuid"],
                        G008ExecutionStageModel.ordinal == 1,
                    )
                )
            ).scalar_one()

    begin = {
        "envelope_uuid": authority["envelope_uuid"],
        "organization_id": authority["organization_id"],
        "operation_kind": STAGES[ordinal - 1],
        "request_digest": hashlib.sha256(
            f"{seal['execution_seal_uuid']}:{ordinal}:request".encode()
        ).hexdigest(),
        "candidate_digest": seal["candidate_digest"],
        "gate_envelope_digest": seal["gate_envelope_digest"],
        "nonce_digest": seal["execution_nonce_digest"],
        "execution_seal_uuid": seal["execution_seal_uuid"],
        "execution_nonce_digest": seal["execution_nonce_digest"],
        "execution_stage_uuid": status["stage_uuid"],
        "execution_stage": STAGES[ordinal - 1],
        "execution_stage_ordinal": ordinal,
        "prior_register_gate_id": prior.id if prior is not None else None,
        "prior_register_operation_uuid": (
            prior.operation_uuid if prior is not None else None
        ),
    }
    context = await db_session.begin_onnuri_registration_operation(**begin)
    gate = context["gate"]
    consume = {
        key: value
        for key, value in begin.items()
        if key
        not in {
            "envelope_uuid",
            "execution_seal_uuid",
            "execution_nonce_digest",
            "execution_stage_uuid",
            "execution_stage",
            "execution_stage_ordinal",
        }
    }
    consume.update(registration_gate_id=gate.id, operation_uuid=gate.operation_uuid)
    await db_session.consume_onnuri_registration_operation(**consume)
    canonical_attestation = json.dumps(
        {
            "execution_seal_uuid": seal["execution_seal_uuid"],
            "operation_uuid": gate.operation_uuid,
            "operation_kind": STAGES[ordinal - 1],
            "ordinal": ordinal,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    attestation_signature = hashlib.sha512(
        b"registration-attestation:" + canonical_attestation
    ).digest()
    async with db_session.async_session() as session:
        execution_attested_at = (
            await session.execute(select(func.clock_timestamp()))
        ).scalar_one()
    _completed, recovered = await db_session.finalize_onnuri_registration_operation(
        **consume,
        outcome=registration_outcome,
        transaction_count=1,
        retry_count=0,
        response_count=1,
        wire_request_count=1,
        deregistered=ordinal == 4 and registration_outcome == "succeeded",
        accepted_expires_seconds=(
            0
            if ordinal == 4 and registration_outcome == "succeeded"
            else 3600
            if registration_outcome == "succeeded"
            else None
        ),
        execution_attestation_canonical=canonical_attestation,
        execution_attestation_signature=attestation_signature,
        execution_attestation_digest=hashlib.sha256(
            canonical_attestation
        ).hexdigest(),
        execution_attestation_signature_digest=hashlib.sha256(
            attestation_signature
        ).hexdigest(),
        execution_attestation_key_digest="9" * 64,
        execution_attestation_key_id="registration-attestation-v1",
        execution_attested_at=execution_attested_at,
    )
    assert recovered is False


async def _prepare_expiring_unregister_gate(
    db_session,
    authority: dict[str, object],
    seal: dict[str, object],
    *,
    state: str,
) -> tuple[OnnuriRegistrationGateModel, OnnuriRegistrationGateModel, dict[str, object]]:
    for ordinal in (1, 2):
        await _start(db_session, seal, ordinal)
        await _finish(db_session, authority, seal, ordinal)
    await _start(db_session, seal, 3)
    await db_session.claim_reserved_inbound_and_bind(
        _claim(seal),
        receipt_builder=_build_test_bind_receipt,
    )
    await _finish(db_session, authority, seal, 3)
    await _start(db_session, seal, 4)

    async with db_session.async_session() as session:
        database_now = (
            await session.execute(select(func.clock_timestamp()))
        ).scalar_one()
        prior = (
            await session.execute(
                select(OnnuriRegistrationGateModel)
                .join(
                    G008ExecutionStageModel,
                    G008ExecutionStageModel.id
                    == OnnuriRegistrationGateModel.execution_stage_id,
                )
                .join(G008ExecutionSealModel)
                .where(
                    G008ExecutionSealModel.execution_seal_uuid
                    == seal["execution_seal_uuid"],
                    G008ExecutionStageModel.ordinal == 1,
                )
            )
        ).scalar_one()
        stage = (
            await session.execute(
                select(G008ExecutionStageModel)
                .join(G008ExecutionSealModel)
                .where(
                    G008ExecutionSealModel.execution_seal_uuid
                    == seal["execution_seal_uuid"],
                    G008ExecutionStageModel.ordinal == 4,
                )
            )
        ).scalar_one()
        request_digest = hashlib.sha256(
            f"{seal['execution_seal_uuid']}:lock-deadline:request".encode()
        ).hexdigest()
        binding_digest = _registration_binding_digest(
            organization_id=authority["organization_id"],
            envelope_uuid=authority["envelope_uuid"],
            operation_kind="unregister",
            request_digest=request_digest,
            candidate_digest=seal["candidate_digest"],
            gate_envelope_digest=seal["gate_envelope_digest"],
            nonce_digest=seal["execution_nonce_digest"],
            prior_register_gate_id=prior.id,
            prior_register_operation_uuid=prior.operation_uuid,
        )
        gate = OnnuriRegistrationGateModel(
            envelope_id=authority["envelope_id"],
            operation_kind="unregister",
            unregisters_gate_id=prior.id,
            execution_stage_id=stage.id,
            state=state,
            request_digest=binding_digest,
            transaction_count=1 if state == "challenged" else 0,
            retransmission_count=0,
            created_at=database_now - timedelta(seconds=59),
        )
        session.add(gate)
        await session.commit()
        await session.refresh(gate)
        values = {
            "organization_id": authority["organization_id"],
            "operation_uuid": gate.operation_uuid,
            "registration_gate_id": gate.id,
            "operation_kind": "unregister",
            "request_digest": request_digest,
            "candidate_digest": seal["candidate_digest"],
            "gate_envelope_digest": seal["gate_envelope_digest"],
            "nonce_digest": seal["execution_nonce_digest"],
            "prior_register_gate_id": prior.id,
            "prior_register_operation_uuid": prior.operation_uuid,
            "execution_seal_uuid": seal["execution_seal_uuid"],
            "execution_nonce_digest": seal["execution_nonce_digest"],
            "execution_stage_uuid": stage.stage_uuid,
            "execution_stage": "unregister",
            "execution_stage_ordinal": 4,
            "envelope_uuid": authority["envelope_uuid"],
        }
        return prior, gate, values

async def _advance_to_inbound(
    db_session, authority: dict[str, object], seal: dict[str, object]
) -> None:
    for ordinal in (1, 2):
        await _start(db_session, seal, ordinal)
        await _finish(db_session, authority, seal, ordinal)
    await _start(db_session, seal, 3)


def _claim(
    seal: dict[str, object],
    *,
    stock_call_uuid: str | None = None,
    **changes,
) -> dict[str, object]:
    values = {
        "organization_id": seal["organization_id"],
        "account_uuid": str(uuid4()),
        "application_uuid": str(uuid4()),
        "stock_call_uuid": stock_call_uuid or str(uuid4()),
        "did_digest": seal["reserved_inbound_did_digest"],
        "caller_digest": seal["reserved_inbound_caller_digest"],
    }
    values.update(changes)
    return values


@pytest.mark.asyncio
async def test_stage_order_exact_start_replay_recovers_and_altered_replay_is_rejected(
    db_session,
):
    authority = await _organization(db_session, "order")
    seal = _seal_payload(authority)
    created = await db_session.create_execution_seal(seal)
    assert [(row["ordinal"], row["stage"]) for row in created["stages"]] == [
        (1, "register"),
        (2, "outbound_call"),
        (3, "inbound_call"),
        (4, "unregister"),
    ]

    with pytest.raises(TelephonyNumberInventoryConflictError, match="wrong_order"):
        await _start(db_session, seal, 2)
    start_payload = {
        **_common(seal),
        "stage": "register",
        "ordinal": 1,
        "started_at": datetime.now(UTC) - timedelta(milliseconds=1),
    }
    started = await db_session.start_execution_stage(start_payload)
    recovered = await db_session.start_execution_stage(start_payload)
    assert recovered["stages"][0]["recovered"] is True
    started_stage = dict(started["stages"][0])
    recovered_stage = dict(recovered["stages"][0])
    started_stage.pop("recovered", None)
    recovered_stage.pop("recovered", None)
    assert recovered_stage == started_stage

    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="binding_mismatch"
    ):
        await db_session.start_execution_stage(
            {**start_payload, "candidate_digest": OTHER}
        )

    async with db_session.async_session() as session:
        rows = (
            await session.execute(
                select(G008ExecutionStageModel)
                .join(G008ExecutionSealModel)
                .where(
                    G008ExecutionSealModel.execution_seal_uuid
                    == seal["execution_seal_uuid"]
                )
                .order_by(G008ExecutionStageModel.ordinal)
            )
        ).scalars().all()
        assert [row.state for row in rows] == ["started", "pending", "pending", "pending"]
        assert rows[0].started_at == started_stage["started_at"]
        assert all(row.finalized_at is None for row in rows)


@pytest.mark.asyncio
async def test_stage_deadline_is_database_clock_bound_and_rejects_status_and_finalize(
    db_session,
):
    authority = await _organization(db_session, "stage-deadline")
    seal = _seal_payload(authority)
    await db_session.create_execution_seal(seal)
    await _start(db_session, seal, 1)

    async with db_session.async_session() as session:
        persisted = (
            await session.execute(
                select(G008ExecutionStageModel)
                .join(G008ExecutionSealModel)
                .where(
                    G008ExecutionSealModel.execution_seal_uuid
                    == seal["execution_seal_uuid"],
                    G008ExecutionStageModel.ordinal == 1,
                )
            )
        ).scalar_one()
        assert persisted.started_at is not None
        assert persisted.stage_deadline_at == persisted.started_at + timedelta(seconds=60)
        seal_id = persisted.execution_seal_id
        expired_start = datetime.now(UTC) - timedelta(seconds=61)
        expired_deadline = expired_start + timedelta(seconds=60)
        await session.execute(
            text("ALTER TABLE g008_execution_stages DISABLE TRIGGER USER")
        )
        await session.execute(
            text(
                "UPDATE g008_execution_stages "
                "SET started_at = :started_at, stage_deadline_at = :deadline "
                "WHERE id = :stage_id"
            ),
            {
                "started_at": expired_start,
                "deadline": expired_deadline,
                "stage_id": persisted.id,
            },
        )
        await session.execute(
            text("ALTER TABLE g008_execution_stages ENABLE TRIGGER USER")
        )
        await session.commit()


    async with db_session.async_session() as session:
        stage = (
            await session.execute(
                select(G008ExecutionStageModel).where(
                    G008ExecutionStageModel.execution_seal_id == seal_id,
                    G008ExecutionStageModel.ordinal == 1,
                )
            )
        ).scalar_one()
        assert stage.state == "started"
        assert stage.finalized_at is None


@pytest.mark.asyncio
async def test_duplicate_nonce_and_cross_tenant_binding_are_rejected(db_session):
    first_authority = await _organization(db_session, "nonce-a")
    second_authority = await _organization(db_session, "nonce-b")
    first = _seal_payload(first_authority)
    await db_session.create_execution_seal(first)
    duplicate = _seal_payload(
        second_authority, nonce=first["execution_nonce_digest"]
    )
    with pytest.raises(TelephonyNumberInventoryConflictError, match="seal_conflict"):
        await db_session.create_execution_seal(duplicate)

    cross_tenant = {
        **_common(first),
        "organization_id": second_authority["organization_id"],
        "stage": "register",
        "ordinal": 1,
        "started_at": datetime.now(UTC),
    }
    with pytest.raises(TelephonyNumberInventoryConflictError, match="binding_mismatch"):
        await db_session.start_execution_stage(cross_tenant)

    async with db_session.async_session() as session:
        row = (
            await session.execute(
                select(G008ExecutionSealModel).where(
                    G008ExecutionSealModel.execution_seal_uuid == first["execution_seal_uuid"]
                )
            )
        ).scalar_one()
        assert row.state == "sealed"


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["did_digest", "caller_digest"])
async def test_inbound_wrong_reservation_digest_leaves_stage_unbound(db_session, field):
    authority = await _organization(db_session, field)
    seal = _seal_payload(authority)
    await db_session.create_execution_seal(seal)
    await _advance_to_inbound(db_session, authority, seal)

    with pytest.raises(TelephonyNumberInventoryConflictError, match="not_claimable"):
        await db_session.claim_reserved_inbound_and_bind(
            _claim(seal, **{field: OTHER}),
            receipt_builder=_build_test_bind_receipt,
        )

    async with db_session.async_session() as session:
        stage = (
            await session.execute(
                select(G008ExecutionStageModel)
                .join(G008ExecutionSealModel)
                .where(
                    G008ExecutionSealModel.execution_seal_uuid == seal["execution_seal_uuid"],
                    G008ExecutionStageModel.ordinal == 3,
                )
            )
        ).scalar_one()
        assert stage.state == "started"
        assert stage.stock_call_id_digest is None


@pytest.mark.asyncio
async def test_inbound_claim_is_one_time_and_stock_digest_is_globally_unique(db_session):
    first_authority = await _organization(db_session, "claim-a")
    second_authority = await _organization(db_session, "claim-b")
    first = _seal_payload(first_authority)
    second = _seal_payload(second_authority)
    await db_session.create_execution_seal(first)
    await db_session.create_execution_seal(second)
    await _advance_to_inbound(db_session, first_authority, first)
    await _advance_to_inbound(db_session, second_authority, second)

    stock_call_uuid = str(uuid4())
    claim = _claim(first, stock_call_uuid=stock_call_uuid)
    assert set(claim) == {
        "organization_id",
        "account_uuid",
        "application_uuid",
        "stock_call_uuid",
        "did_digest",
        "caller_digest",
    }
    receipt = await db_session.claim_reserved_inbound_and_bind(
        claim,
        receipt_builder=_build_test_bind_receipt,
    )
    assert receipt["stock_call_id_digest"] == hashlib.sha256(
        stock_call_uuid.encode()
    ).hexdigest()
    assert receipt["authority_deadline_at"] == receipt["issued_at"] + timedelta(
        seconds=60
    )
    for field in (
        "run_uuid",
        "attempt_uuid",
        "idempotency_uuid",
        "bind_receipt_uuid",
    ):
        assert field not in claim
        assert str(UUID(receipt[field])) == receipt[field]
        assert receipt[field] == receipt["canonical_claims"][field]
    assert "request_digest" not in claim
    expected_request_digest = hashlib.sha256(
        json.dumps(claim, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert receipt["request_digest"] == expected_request_digest
    assert receipt["canonical_claims"]["request_digest"] == expected_request_digest
    assert (
        receipt["canonical_claims"]["execution_seal_uuid"]
        == first["execution_seal_uuid"]
    )
    assert receipt["receipt_key_id"] == _TEST_BIND_RECEIPT_KEY_ID
    assert receipt["receipt_spki_digest"] == _TEST_BIND_RECEIPT_KEY_DIGEST

    duplicate = await db_session.claim_reserved_inbound_and_bind(
        claim,
        receipt_builder=_build_test_bind_receipt,
    )
    assert duplicate == receipt

    with pytest.raises(TelephonyNumberInventoryConflictError, match="binding_conflict"):
        await db_session.claim_reserved_inbound_and_bind(
            _claim(first),
            receipt_builder=_build_test_bind_receipt,
        )
    with pytest.raises(TelephonyNumberInventoryConflictError, match="not_claimable"):
        await db_session.claim_reserved_inbound_and_bind(
            _claim(second, stock_call_uuid=stock_call_uuid),
            receipt_builder=_build_test_bind_receipt,
        )


@pytest.mark.asyncio
async def test_expired_inbound_claim_leaves_no_transition(db_session):
    authority = await _organization(db_session, "expired")
    now = datetime.now(UTC)
    seal = _seal_payload(
        authority,
        starts_at=now - timedelta(seconds=2),
        expires_at=now + timedelta(seconds=10),
    )
    await db_session.create_execution_seal(seal)
    await _advance_to_inbound(db_session, authority, seal)
    await asyncio.sleep(10.1)
    with pytest.raises(TelephonyNumberInventoryConflictError, match="not_claimable"):
        await db_session.claim_reserved_inbound_and_bind(
            _claim(seal),
            receipt_builder=_build_test_bind_receipt,
        )

    async with db_session.async_session() as session:
        stage = (
            await session.execute(
                select(G008ExecutionStageModel)
                .join(G008ExecutionSealModel)
                .where(
                    G008ExecutionSealModel.execution_seal_uuid == seal["execution_seal_uuid"],
                    G008ExecutionStageModel.ordinal == 3,
                )
            )
        ).scalar_one()
        assert stage.stock_call_id_digest is None


@pytest.mark.asyncio
async def test_final_evidence_is_single_write_and_containment_is_terminal(db_session):
    authority = await _organization(db_session, "final")
    async with db_session.async_session() as session:
        database_now = (
            await session.execute(select(func.clock_timestamp()))
        ).scalar_one()
    seal = _seal_payload(
        authority,
        starts_at=database_now - timedelta(seconds=2),
        expires_at=database_now + timedelta(minutes=10),
    )
    await db_session.create_execution_seal(seal)
    for ordinal in (1, 2):
        await _start(db_session, seal, ordinal)
        await _finish(db_session, authority, seal, ordinal)
    await _start(db_session, seal, 3)
    await db_session.claim_reserved_inbound_and_bind(
        _claim(seal),
        receipt_builder=_build_test_bind_receipt,
    )
    await _finish(db_session, authority, seal, 3)
    await _start(db_session, seal, 4)
    await _finish(db_session, authority, seal, 4)

    evidence_builds = 0

    async def build_evidence(ingredients: dict[str, object]) -> dict[str, object]:
        nonlocal evidence_builds
        evidence_builds += 1
        return await _build_test_evidence(ingredients)

    completed = await db_session.finalize_execution_evidence(
        _common(seal),
        evidence_builder=build_evidence,
    )
    assert completed["state"] == "completed"
    assert completed["final_evidence_key_digest"] == _TEST_EVIDENCE_KEY_DIGEST
    assert completed["final_evidence_key_id"] == _TEST_EVIDENCE_KEY_ID
    duplicate = await db_session.finalize_execution_evidence(
        _common(seal),
        evidence_builder=build_evidence,
    )
    assert duplicate == completed
    assert evidence_builds == 1

    contained_authority = await _organization(db_session, "contained")
    async with db_session.async_session() as session:
        database_now = (
            await session.execute(select(func.clock_timestamp()))
        ).scalar_one()
    contained_seal = _seal_payload(
        contained_authority,
        starts_at=database_now - timedelta(seconds=2),
        expires_at=database_now + timedelta(minutes=10),
    )
    await db_session.create_execution_seal(contained_seal)
    await _start(db_session, contained_seal, 1)
    await _finish(db_session, contained_authority, contained_seal, 1)
    await _start(db_session, contained_seal, 2)
    contained = await db_session.contain_execution(
        {
            **_common(contained_seal),
            "containment_class": "fail_closed",
        },
        evidence_builder=_build_test_evidence,
    )
    assert contained["state"] == "cleanup_required"
    assert contained["stages"][1]["evidence_key_digest"] == _TEST_EVIDENCE_KEY_DIGEST
    assert contained["stages"][1]["evidence_key_id"] == _TEST_EVIDENCE_KEY_ID
    with pytest.raises(TelephonyNumberInventoryConflictError, match="terminal_replay_rejected"):
        await db_session.contain_execution(
            {
                **_common(contained_seal),
                "containment_class": "rewrite",
            },
            evidence_builder=_build_test_evidence,
        )


@pytest.mark.asyncio
async def test_outbound_success_requires_authority_owned_terminal_observation(db_session):
    authority = await _organization(db_session, "outbound-false-success")
    seal = _seal_payload(authority)
    await db_session.create_execution_seal(seal)
    await _start(db_session, seal, 1)
    await _finish(db_session, authority, seal, 1)
    await _start(db_session, seal, 2)
    with pytest.raises(
        TelephonyNumberInventoryConflictError, match="outbound_stage_unobserved"
    ):
        await db_session.finalize_execution_stage(
            {
                **_common(seal),
                "stage": "outbound_call",
                "ordinal": 2,
                "stage_state": "succeeded",
                "terminal_class": "call_completed",
            },
            evidence_builder=_build_test_evidence,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal_mode", ["failed", "contained"])
async def test_consumed_register_keeps_unregister_reachable(
    db_session, terminal_mode: str
):
    authority = await _organization(db_session, f"cleanup-{terminal_mode}")
    nonce = ("4" if terminal_mode == "failed" else "5") * 64
    seal = _seal_payload(authority, nonce=nonce)
    await db_session.create_execution_seal(seal)
    await _start(db_session, seal, 1)
    await _finish(db_session, authority, seal, 1)
    await _start(db_session, seal, 2)
    if terminal_mode == "failed":
        result = await db_session.finalize_execution_stage(
            {
                **_common(seal),
                "stage": "outbound_call",
                "ordinal": 2,
                "stage_state": "failed",
                "terminal_class": "provider_failure",
            },
            evidence_builder=_build_test_evidence,
        )
    else:
        result = await db_session.contain_execution(
            {**_common(seal), "containment_class": "host_containment"},
            evidence_builder=_build_test_evidence,
        )
    assert result["state"] == "cleanup_required"
    if terminal_mode == "failed":
        async with db_session.async_session() as session:
            expired = (
                await session.execute(
                    select(G008ExecutionStageModel)
                    .join(G008ExecutionSealModel)
                    .where(
                        G008ExecutionSealModel.execution_seal_uuid
                        == seal["execution_seal_uuid"],
                        G008ExecutionStageModel.ordinal == 2,
                    )
                )
            ).scalar_one()
            assert expired.stage_deadline_at == expired.started_at + timedelta(seconds=60)
    started = await _start(db_session, seal, 4)
    assert started["stages"][3]["state"] == "started"
    assert started["stages"][3]["stage_deadline_at"] > started["stages"][3]["started_at"]
    if terminal_mode == "contained":
        await _finish(db_session, authority, seal, 4)
        status = await db_session.get_execution_stage_status(
            **_common(seal), stage="unregister", ordinal=4
        )
        assert status is not None
        assert status["state"] == "succeeded"
        assert status["seal_state"] == "failed"


@pytest.mark.asyncio
async def test_inbound_issuing_survives_signer_crash_and_exact_resume(db_session):
    authority = await _organization(db_session, "inbound-resume")
    seal = _seal_payload(authority)
    await db_session.create_execution_seal(seal)
    await _advance_to_inbound(db_session, authority, seal)
    claim = _claim(seal)

    async def crash(_ingredients):
        raise RuntimeError("simulated signer crash")

    with pytest.raises(RuntimeError, match="simulated signer crash"):
        await db_session.claim_reserved_inbound_and_bind(
            claim, receipt_builder=crash
        )
    resumed = await db_session.claim_reserved_inbound_and_bind(
        claim, receipt_builder=_build_test_bind_receipt
    )
    assert resumed["state"] == "bound"
    assert resumed["bound_at"] >= resumed["issued_at"]
    async with db_session.async_session() as session:
        binding = (
            await session.execute(
                select(G008InboundBindingModel).where(
                    G008InboundBindingModel.stock_call_id_digest
                    == resumed["stock_call_id_digest"]
                )
            )
        ).scalar_one()
        assert binding.issuance_attempt_count == 2


@pytest.mark.asyncio
async def test_terminal_evidence_artifact_is_exact_and_redacted(db_session):
    authority = await _organization(db_session, "evidence-artifact")
    seal = _seal_payload(authority)
    await db_session.create_execution_seal(seal)
    await _start(db_session, seal, 1)
    await _finish(db_session, authority, seal, 1)
    await _start(db_session, seal, 2)
    finalized = await db_session.finalize_execution_stage(
        {
            **_common(seal),
            "stage": "outbound_call",
            "ordinal": 2,
            "stage_state": "failed",
            "terminal_class": "provider_failure",
        },
        evidence_builder=_build_test_evidence,
    )
    assert "canonical_evidence" not in finalized
    assert "evidence_signature" not in finalized
    async with db_session.async_session() as session:
        stage = (
            await session.execute(
                select(G008ExecutionStageModel)
                .join(G008ExecutionSealModel)
                .where(
                    G008ExecutionSealModel.execution_seal_uuid
                    == seal["execution_seal_uuid"],
                    G008ExecutionStageModel.ordinal == 2,
                )
            )
        ).scalar_one()
        assert hashlib.sha256(stage.evidence_canonical).hexdigest() == stage.evidence_digest
        assert len(stage.evidence_signature) == 64
        assert (
            hashlib.sha256(stage.evidence_signature).hexdigest()
            == stage.evidence_signature_digest
        )
        terminal_claims = json.loads(stage.evidence_canonical)
        assert terminal_claims["stage_state"] == "failed"
        assert terminal_claims["terminal_class"] == "provider_failure"


@pytest.mark.asyncio
async def test_concurrent_exact_inbound_issuing_resumes_single_binding(db_session):
    authority = await _organization(db_session, "inbound-concurrent-resume")
    seal = _seal_payload(authority)
    await db_session.create_execution_seal(seal)
    await _advance_to_inbound(db_session, authority, seal)
    claim = _claim(seal)
    signing_started = asyncio.Event()
    release_signer = asyncio.Event()

    async def delayed_builder(ingredients):
        signing_started.set()
        await release_signer.wait()
        return await _build_test_bind_receipt(ingredients)

    first = asyncio.create_task(
        db_session.claim_reserved_inbound_and_bind(
            claim, receipt_builder=delayed_builder
        )
    )
    await signing_started.wait()
    second = await db_session.claim_reserved_inbound_and_bind(
        claim, receipt_builder=_build_test_bind_receipt
    )
    release_signer.set()
    first_result = await first
    assert first_result == second
    assert second["state"] == "bound"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "gate_state"),
    [
        ("succeeded", "completed"),
        ("failed", "failed"),
        ("contained", "contained"),
    ],
)
async def test_registration_gate_trigger_accepts_exact_terminal_stage_mapping(
    db_session,
    outcome,
    gate_state,
):
    authority = await _organization(db_session, f"registration-terminal-{outcome}")
    seal = _seal_payload(authority)
    await db_session.create_execution_seal(seal)
    await _start(db_session, seal, 1)
    await _finish(
        db_session,
        authority,
        seal,
        1,
        registration_outcome=outcome,
    )

    async with db_session.async_session() as session:
        gate, stage = (
            await session.execute(
                select(OnnuriRegistrationGateModel, G008ExecutionStageModel)
                .join(
                    G008ExecutionStageModel,
                    G008ExecutionStageModel.id
                    == OnnuriRegistrationGateModel.execution_stage_id,
                )
                .join(G008ExecutionSealModel)
                .where(
                    G008ExecutionSealModel.execution_seal_uuid
                    == seal["execution_seal_uuid"],
                    G008ExecutionStageModel.ordinal == 1,
                )
            )
        ).one()
        assert gate.state == gate_state
        assert stage.state == outcome
        assert gate.failure_class == stage.state
        assert gate.terminal_at == stage.finalized_at
        assert gate.execution_attestation_digest == stage.evidence_digest
        assert (
            gate.execution_attestation_signature_digest
            == stage.evidence_signature_digest
        )
        assert gate.execution_attestation_key_digest == stage.evidence_key_digest
        assert gate.execution_attestation_key_id == stage.evidence_key_id
        with pytest.raises(DBAPIError, match="requires exact execution stage"):
            await session.execute(
                update(OnnuriRegistrationGateModel)
                .where(OnnuriRegistrationGateModel.id == gate.id)
                .values(execution_attestation_digest=OTHER)
            )
        await session.rollback()

@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("invalid_state", "invalid_transactions", "invalid_retransmissions"),
    [
        ("pending", 1, 0),
        ("pending", 0, 1),
        ("challenged", 0, 0),
        ("challenged", 1, 1),
    ],
)
async def test_registration_gate_trigger_rejects_direct_invalid_counts_and_linkage(
    committed_db_session,
    invalid_state,
    invalid_transactions,
    invalid_retransmissions,
):
    authority = await _organization(
        committed_db_session, "registration-trigger-adversarial"
    )
    seal = _seal_payload(authority)
    await committed_db_session.create_execution_seal(seal)
    await _start(committed_db_session, seal, 1)

    async with committed_db_session.async_session() as session:
        stages = (
            await session.execute(
                select(G008ExecutionStageModel)
                .join(G008ExecutionSealModel)
                .where(
                    G008ExecutionSealModel.execution_seal_uuid
                    == seal["execution_seal_uuid"]
                )
                .order_by(G008ExecutionStageModel.ordinal)
            )
        ).scalars().all()
        session.add(
            OnnuriRegistrationGateModel(
                envelope_id=authority["envelope_id"],
                execution_stage_id=stages[0].id,
                operation_kind="register",
                state=invalid_state,
                request_digest=D,
                transaction_count=invalid_transactions,
                retransmission_count=invalid_retransmissions,
            )
        )
        with pytest.raises(DBAPIError, match="exact transaction and retry counts"):
            await session.flush()
        await session.rollback()

    async with committed_db_session.async_session() as session:
        stages = (
            await session.execute(
                select(G008ExecutionStageModel)
                .join(G008ExecutionSealModel)
                .where(
                    G008ExecutionSealModel.execution_seal_uuid
                    == seal["execution_seal_uuid"]
                )
                .order_by(G008ExecutionStageModel.ordinal)
            )
        ).scalars().all()
        session.add(
            OnnuriRegistrationGateModel(
                envelope_id=authority["envelope_id"],
                execution_stage_id=stages[1].id,
                operation_kind="register",
                state="pending",
                request_digest=D,
                transaction_count=0,
                retransmission_count=0,
            )
        )
        with pytest.raises(DBAPIError, match="requires exact execution stage"):
            await session.flush()
        await session.rollback()

    async with committed_db_session.async_session() as session:
        stage = (
            await session.execute(
                select(G008ExecutionStageModel)
                .join(G008ExecutionSealModel)
                .where(
                    G008ExecutionSealModel.execution_seal_uuid
                    == seal["execution_seal_uuid"],
                    G008ExecutionStageModel.ordinal == 1,
                )
            )
        ).scalar_one()
        valid = OnnuriRegistrationGateModel(
            envelope_id=authority["envelope_id"],
            execution_stage_id=stage.id,
            operation_kind="register",
            state="pending",
            request_digest=D,
            transaction_count=0,
            retransmission_count=0,
        )
        session.add(valid)
        await session.flush()
        gate_id = valid.id
        await session.commit()

    async with committed_db_session.async_session() as session:
        stage_two_id = (
            await session.execute(
                select(G008ExecutionStageModel.id)
                .join(G008ExecutionSealModel)
                .where(
                    G008ExecutionSealModel.execution_seal_uuid
                    == seal["execution_seal_uuid"],
                    G008ExecutionStageModel.ordinal == 2,
                )
            )
        ).scalar_one()
        with pytest.raises(DBAPIError, match="requires exact execution stage"):
            await session.execute(
                update(OnnuriRegistrationGateModel)
                .where(OnnuriRegistrationGateModel.id == gate_id)
                .values(execution_stage_id=stage_two_id)
            )
        await session.rollback()

    async with committed_db_session.async_session() as session:
        with pytest.raises(DBAPIError, match="exact transaction and retry counts"):
            await session.execute(
                update(OnnuriRegistrationGateModel)
                .where(OnnuriRegistrationGateModel.id == gate_id)
                .values(state="challenged", transaction_count=0)
            )
        await session.rollback()

@pytest.mark.asyncio
async def test_outbound_binding_trigger_requires_exact_completed_callback_provenance(
    committed_db_session,
):
    authority = await _organization(committed_db_session, "outbound-trigger")
    seal = _seal_payload(authority)
    await committed_db_session.create_execution_seal(seal)
    await _start(committed_db_session, seal, 1)
    await _finish(committed_db_session, authority, seal, 1)
    await _start(committed_db_session, seal, 2)
    attempt_uuid = await _create_outbound_attempt(
        committed_db_session,
        authority,
        with_callback=False,
    )

    async with committed_db_session.async_session() as session:
        attempt = (
            await session.execute(
                select(OnnuriSmokeAttemptModel).where(
                    OnnuriSmokeAttemptModel.attempt_uuid == attempt_uuid
                )
            )
        ).scalar_one()
        stage = (
            await session.execute(
                select(G008ExecutionStageModel)
                .join(G008ExecutionSealModel)
                .where(
                    G008ExecutionSealModel.execution_seal_uuid
                    == seal["execution_seal_uuid"],
                    G008ExecutionStageModel.ordinal == 2,
                )
            )
        ).scalar_one()
        database_now = (
            await session.execute(select(func.clock_timestamp()))
        ).scalar_one()
        binding_values = {
            "organization_id": authority["organization_id"],
            "execution_stage_id": stage.id,
            "smoke_attempt_id": attempt.id,
            "account_uuid": attempt.account_id,
            "application_uuid": attempt.application_id,
            "stock_call_id_digest": attempt.stock_call_id_digest,
            "authority_deadline_at": attempt.authority_deadline_at,
            "terminal_class": attempt.terminal_class,
            "terminal_at": attempt.terminal_at,
            "bound_at": max(database_now, attempt.terminal_at),
        }
        attempt_id = attempt.id
        terminal_at = attempt.terminal_at

    async with committed_db_session.async_session() as session:
        session.add(G008OutboundBindingModel(**binding_values))
        with pytest.raises(DBAPIError, match="callback provenance missing"):
            await session.flush()
        await session.rollback()

    async with committed_db_session.async_session() as session:
        session.add(
            OnnuriSmokeCallbackEventModel(
                attempt_id=attempt_id,
                event_nonce_digest=hashlib.sha256(
                    f"mismatched-callback:{attempt_uuid}".encode()
                ).hexdigest(),
                idempotency_key=str(uuid4()),
                request_digest=hashlib.sha256(
                    f"mismatched-request:{attempt_uuid}".encode()
                ).hexdigest(),
                event_type="status",
                normalized_status="completed",
                occurred_at=terminal_at,
                accepted_at=terminal_at + timedelta(microseconds=1),
            )
        )
        await session.commit()

    async with committed_db_session.async_session() as session:
        session.add(G008OutboundBindingModel(**binding_values))
        with pytest.raises(DBAPIError, match="callback provenance missing"):
            await session.flush()
        await session.rollback()

    async with committed_db_session.async_session() as session:
        session.add(
            OnnuriSmokeCallbackEventModel(
                attempt_id=attempt_id,
                event_nonce_digest=hashlib.sha256(
                    f"exact-callback:{attempt_uuid}".encode()
                ).hexdigest(),
                idempotency_key=str(uuid4()),
                request_digest=hashlib.sha256(
                    f"exact-request:{attempt_uuid}".encode()
                ).hexdigest(),
                event_type="status",
                normalized_status="completed",
                occurred_at=terminal_at,
                accepted_at=terminal_at,
            )
        )
        await session.commit()

    async with committed_db_session.async_session() as session:
        binding = G008OutboundBindingModel(**binding_values)
        session.add(binding)
        await session.flush()
        assert binding.id is not None
        await session.commit()


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["begin", "consume", "finalize"])
async def test_unregister_rechecks_deadline_after_linked_prior_gate_lock(
    committed_db_session,
    operation,
):
    authority = await _organization(
        committed_db_session, f"registration-{operation}-lock-deadline"
    )
    seal = _seal_payload(authority, nonce=hashlib.sha256(uuid4().bytes).hexdigest())
    await committed_db_session.create_execution_seal(seal)
    prior, gate, values = await _prepare_expiring_unregister_gate(
        committed_db_session,
        authority,
        seal,
        state="challenged" if operation == "finalize" else "pending",
    )

    if operation == "begin":
        invoke_values = {
            key: value
            for key, value in values.items()
            if key not in {"operation_uuid", "registration_gate_id"}
        }
        invoke = committed_db_session.begin_onnuri_registration_operation(
            **invoke_values
        )
    elif operation == "consume":
        invoke_values = {
            key: value
            for key, value in values.items()
            if key
            not in {
                "envelope_uuid",
                "execution_seal_uuid",
                "execution_nonce_digest",
                "execution_stage_uuid",
                "execution_stage",
                "execution_stage_ordinal",
            }
        }
        invoke = committed_db_session.consume_onnuri_registration_operation(
            **invoke_values
        )
    else:
        invoke_values = {
            key: value
            for key, value in values.items()
            if key
            not in {
                "envelope_uuid",
                "execution_seal_uuid",
                "execution_nonce_digest",
                "execution_stage_uuid",
                "execution_stage",
                "execution_stage_ordinal",
            }
        }
        canonical = json.dumps(
            {
                "execution_seal_uuid": seal["execution_seal_uuid"],
                "operation_uuid": gate.operation_uuid,
                "operation_kind": "unregister",
                "ordinal": 4,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        signature = hashlib.sha512(b"registration-lock-test:" + canonical).digest()
        invoke = committed_db_session.finalize_onnuri_registration_operation(
            **invoke_values,
            outcome="succeeded",
            transaction_count=1,
            retry_count=0,
            response_count=1,
            wire_request_count=1,
            deregistered=True,
            accepted_expires_seconds=0,
            execution_attestation_canonical=canonical,
            execution_attestation_signature=signature,
            execution_attestation_digest=hashlib.sha256(canonical).hexdigest(),
            execution_attestation_signature_digest=hashlib.sha256(
                signature
            ).hexdigest(),
            execution_attestation_key_digest="9" * 64,
            execution_attestation_key_id="registration-lock-test-v1",
            execution_attested_at=datetime.now(UTC),
        )

    async with committed_db_session.async_session() as lock_session:
        locked_prior = (
            await lock_session.execute(
                select(OnnuriRegistrationGateModel)
                .where(OnnuriRegistrationGateModel.id == prior.id)
                .with_for_update()
            )
        ).scalar_one()
        stage = (
            await lock_session.execute(
                select(G008ExecutionStageModel).where(
                    G008ExecutionStageModel.id == gate.execution_stage_id
                )
            )
        ).scalar_one()
        deadline = stage.stage_deadline_at
        before_deadline = (
            await lock_session.execute(select(func.clock_timestamp()))
        ).scalar_one()
        assert before_deadline < deadline
        task = asyncio.create_task(invoke)
        await asyncio.sleep(0.05)
        assert not task.done()
        await asyncio.sleep(
            max(0.0, (deadline - before_deadline).total_seconds()) + 0.05
        )
        after_deadline = (
            await lock_session.execute(select(func.clock_timestamp()))
        ).scalar_one()
        assert after_deadline >= deadline
        assert locked_prior.id == prior.id
        await lock_session.commit()

    with pytest.raises(
        TelephonyNumberInventoryConflictError,
        match="onnuri_registration_gate_not_authorized",
    ):
        await asyncio.wait_for(task, timeout=2)

    async with committed_db_session.async_session() as session:
        unchanged_gate = await session.get(OnnuriRegistrationGateModel, gate.id)
        unchanged_prior = await session.get(OnnuriRegistrationGateModel, prior.id)
        stage = (
            await session.execute(
                select(G008ExecutionStageModel)
                .join(G008ExecutionSealModel)
                .where(
                    G008ExecutionSealModel.execution_seal_uuid
                    == seal["execution_seal_uuid"],
                    G008ExecutionStageModel.ordinal == 4,
                )
            )
        ).scalar_one()
        expected_state = "challenged" if operation == "finalize" else "pending"
        assert unchanged_gate.state == expected_state
        assert unchanged_gate.transaction_count == (
            1 if operation == "finalize" else 0
        )
        assert unchanged_gate.terminal_at is None
        assert unchanged_gate.execution_attestation_digest is None
        assert unchanged_prior.state == "completed"
        assert unchanged_prior.unregister_satisfied_at is None
        assert stage.state == "started"
        assert stage.finalized_at is None

@pytest.mark.asyncio
async def test_outbound_binding_rechecks_clock_after_callback_authority_lock(
    committed_db_session,
):
    authority = await _organization(committed_db_session, "outbound-lock-deadline")
    seal = _seal_payload(authority)
    await committed_db_session.create_execution_seal(seal)
    await _start(committed_db_session, seal, 1)
    await _finish(committed_db_session, authority, seal, 1)
    await _start(committed_db_session, seal, 2)
    attempt_uuid = await _create_outbound_attempt(
        committed_db_session,
        authority,
        deadline_seconds=1,
    )

    async with committed_db_session.async_session() as lock_session:
        attempt = (
            await lock_session.execute(
                select(OnnuriSmokeAttemptModel).where(
                    OnnuriSmokeAttemptModel.attempt_uuid == attempt_uuid
                )
            )
        ).scalar_one()
        callback = (
            await lock_session.execute(
                select(OnnuriSmokeCallbackEventModel)
                .where(OnnuriSmokeCallbackEventModel.attempt_id == attempt.id)
                .with_for_update()
            )
        ).scalar_one()
        assert callback.accepted_at == attempt.terminal_at

        binding_task = asyncio.create_task(
            committed_db_session.bind_g008_outbound_observation(
                {
                    "organization_id": authority["organization_id"],
                    "attempt_uuid": attempt_uuid,
                }
            )
        )
        await asyncio.sleep(0.1)
        assert not binding_task.done()

        database_now = (
            await lock_session.execute(select(func.clock_timestamp()))
        ).scalar_one()
        await asyncio.sleep(
            max(0.0, (attempt.authority_deadline_at - database_now).total_seconds())
            + 0.05
        )
        expired_now = (
            await lock_session.execute(select(func.clock_timestamp()))
        ).scalar_one()
        assert expired_now >= attempt.authority_deadline_at
        await lock_session.commit()

    with pytest.raises(
        TelephonyNumberInventoryConflictError,
        match="terminal_observation_expired",
    ):
        await asyncio.wait_for(binding_task, timeout=2)

    async with committed_db_session.async_session() as session:
        binding = (
            await session.execute(
                select(G008OutboundBindingModel).where(
                    G008OutboundBindingModel.smoke_attempt_id == attempt.id
                )
            )
        ).scalar_one_or_none()
        stage = (
            await session.execute(
                select(G008ExecutionStageModel)
                .join(G008ExecutionSealModel)
                .where(
                    G008ExecutionSealModel.execution_seal_uuid
                    == seal["execution_seal_uuid"],
                    G008ExecutionStageModel.ordinal == 2,
                )
            )
        ).scalar_one()
        assert binding is None
        assert stage.state == "started"
        assert stage.terminal_class is None
        assert stage.finalized_at is None


@pytest.mark.asyncio
async def test_resumed_inbound_rechecks_deadline_after_delayed_signer(
    db_session,
):
    authority = await _organization(db_session, "inbound-resume-expired")
    seal = _seal_payload(authority)
    await db_session.create_execution_seal(seal)
    await _advance_to_inbound(db_session, authority, seal)
    claim = _claim(seal)

    async def crash(_ingredients):
        raise RuntimeError("simulated signer crash")

    with pytest.raises(RuntimeError, match="simulated signer crash"):
        await db_session.claim_reserved_inbound_and_bind(
            claim, receipt_builder=crash
        )

    signing_started = asyncio.Event()
    async def delayed_past_deadline(ingredients):
        signing_started.set()
        await asyncio.sleep(60.1)
        return await _build_test_bind_receipt(ingredients)

    with pytest.raises(
        TelephonyNumberInventoryConflictError,
        match="inbound_binding_expired",
    ):
        await db_session.claim_reserved_inbound_and_bind(
            claim, receipt_builder=delayed_past_deadline
        )
    assert signing_started.is_set()
