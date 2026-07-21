from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from api.db.models import (
    OnnuriOutboundDiagnosticAttemptModel,
    OnnuriOutboundDiagnosticCapabilityModel,
    OnnuriSmokeAttemptModel,
)
from api.db.telephony_number_inventory_client import (
    TelephonyNumberInventoryConflictError,
)
from api.schemas.onnuri_smoke import ONNURI_OUTBOUND_DIAGNOSTIC_CONTRACT
from api.tests.telephony.jambonz.test_onnuri_smoke_authority import (
    _DIGEST,
    _allocation,
    _seed_authority,
)


async def _route_capability(db_session, ids: dict[str, object], *, key: str):
    authorization = await db_session.allocate_onnuri_smoke_attempt(
        **_allocation(ids, direction="outbound", key=key)
    )
    issued_at = datetime.now(UTC)
    values = {
        "nonce_digest": hashlib.sha256(f"nonce:{key}".encode()).hexdigest(),
        "organization_id": ids["organization_id"],
        "authorization_attempt_uuid": authorization.attempt_uuid,
        "idempotency_key": key,
        "request_digest": _DIGEST,
        "candidate_digest": _DIGEST,
        "gate_envelope_digest": hashlib.sha256(
            str(ids["envelope_uuid"]).encode()
        ).hexdigest(),
        "route_profile_digest": "b" * 64,
        "route_digest": "c" * 64,
        "provider_digest": "d" * 64,
        "keyset_digest": "e" * 64,
        "token_digest": hashlib.sha256(f"token:{key}".encode()).hexdigest(),
        "signature_digest": hashlib.sha256(f"signature:{key}".encode()).hexdigest(),
        "encrypted_capability_recovery": f"issue-recovery:{key}",
        "issued_at": issued_at,
        "expires_at": issued_at + timedelta(seconds=59),
    }
    await db_session.persist_onnuri_outbound_diagnostic_capability(**values)
    return authorization, values


def _consume_values(authorization, values: dict[str, object]) -> dict[str, object]:
    fields = {
        "nonce_digest",
        "token_digest",
        "signature_digest",
        "organization_id",
        "idempotency_key",
        "request_digest",
        "candidate_digest",
        "gate_envelope_digest",
        "route_profile_digest",
        "route_digest",
        "provider_digest",
        "keyset_digest",
    }
    return {
        **{field: values[field] for field in fields},
        "authorization_attempt_uuid": authorization.attempt_uuid,
        "key_id": "route-test-key",
        "other_key_id": "media-test-key",
        "domain": "recova.onnuri.smoke.route-chain.v1",
        "algorithm_policy_id": "gcp-kms-ecdsa-p256-sha256-v1",
    }


@pytest.mark.asyncio
async def test_direct_route_consume_commits_once_recovers_exact_duplicate_and_preserves_legacy_attempts(
    db_session,
) -> None:
    ids = await _seed_authority(db_session)
    authorization, values = await _route_capability(
        db_session, ids, key=f"route-commit-{uuid4()}"
    )
    calls: list[dict[str, object]] = []
    response = b'{"route":"committed"}'

    async def builder(context: dict[str, object]) -> dict[str, object]:
        calls.append(context)
        if context["duplicate"]:
            assert context["encrypted_consume_recovery"] == "consume-recovery"
            return {"response": response}
        return {
            "response": response,
            "encrypted_consume_recovery": "consume-recovery",
        }

    async with db_session.async_session() as session:
        legacy_before = await session.scalar(select(func.count()).select_from(OnnuriSmokeAttemptModel))

    first, first_response = await db_session.consume_onnuri_outbound_route_capability(
        **_consume_values(authorization, values), builder=builder
    )
    duplicate, duplicate_response = await db_session.consume_onnuri_outbound_route_capability(
        **_consume_values(authorization, values), builder=builder
    )

    assert first.id == duplicate.id
    assert first_response == duplicate_response == response
    assert [call["duplicate"] for call in calls] == [False, True]
    async with db_session.async_session() as session:
        capability = await session.scalar(
            select(OnnuriOutboundDiagnosticCapabilityModel).where(
                OnnuriOutboundDiagnosticCapabilityModel.nonce_digest == values["nonce_digest"]
            )
        )
        diagnostic_count = await session.scalar(
            select(func.count()).select_from(OnnuriOutboundDiagnosticAttemptModel)
        )
        legacy_after = await session.scalar(select(func.count()).select_from(OnnuriSmokeAttemptModel))
    assert capability is not None
    assert capability.diagnostic_attempt_id == first.id
    assert capability.consumed_at is not None
    assert capability.consume_response_digest == hashlib.sha256(response).hexdigest()
    assert diagnostic_count == 1
    assert legacy_after == legacy_before


@pytest.mark.asyncio
async def test_direct_route_consume_builder_rollback_and_signature_mutation_create_no_diagnostic_rows(
    db_session,
) -> None:
    ids = await _seed_authority(db_session)
    authorization, values = await _route_capability(
        db_session, ids, key=f"route-rollback-{uuid4()}"
    )
    authorization_attempt_uuid = authorization.attempt_uuid
    authorization_envelope_id = authorization.envelope_id
    async with db_session.async_session() as session:
        diagnostic_before = await session.scalar(
            select(func.count()).select_from(OnnuriOutboundDiagnosticAttemptModel).where(
                OnnuriOutboundDiagnosticAttemptModel.envelope_id == authorization_envelope_id,
                OnnuriOutboundDiagnosticAttemptModel.idempotency_key == values["idempotency_key"],
            )
        )
    invoked = 0

    async def failing_builder(_context: dict[str, object]) -> dict[str, object]:
        nonlocal invoked
        invoked += 1
        raise RuntimeError("builder failure")
    consume_values = _consume_values(authorization, values)
    mutated = dict(consume_values)
    mutated["signature_digest"] = "f" * 64

    with pytest.raises(RuntimeError, match="builder failure"):
        await db_session.consume_onnuri_outbound_route_capability(
            **consume_values, builder=failing_builder
        )
    assert invoked == 1


    async with db_session.async_session() as session:
        capability = await session.scalar(
            select(OnnuriOutboundDiagnosticCapabilityModel).where(
                OnnuriOutboundDiagnosticCapabilityModel.nonce_digest == values["nonce_digest"]
            )
        )
        diagnostic_count = await session.scalar(
            select(func.count()).select_from(OnnuriOutboundDiagnosticAttemptModel).where(
                OnnuriOutboundDiagnosticAttemptModel.envelope_id == authorization_envelope_id,
                OnnuriOutboundDiagnosticAttemptModel.idempotency_key == values["idempotency_key"],
            )
        )
    if capability is not None:
        assert capability.consumed_at is None
        assert capability.diagnostic_attempt_id is None
    assert diagnostic_count == diagnostic_before


def test_diagnostic_fixture_is_bounded_and_default_disabled() -> None:
    fixture = ONNURI_OUTBOUND_DIAGNOSTIC_CONTRACT

    assert fixture["fixture_domain"] == "recova.onnuri.outbound-diagnostic.v1"
    assert fixture["limits"] == {
        "max_attempts": 3,
        "max_concurrency": 1,
        "max_duration_seconds": 60,
        "automatic_retries": 0,
    }
    assert "retry" not in " ".join(
        edge["operation"] for edge in fixture["edges"]
    ).lower()
