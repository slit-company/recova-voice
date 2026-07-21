from __future__ import annotations

import base64
import asyncio
import os
import json
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from api.db.telephony_number_inventory_client import (
    TelephonyNumberInventoryConflictError,
    TelephonyNumberInventoryNotFoundError,
)
from api.routes.onnuri_smoke_internal import router
from api.services import onnuri_smoke_f12
from api.services.onnuri_smoke_capabilities import (
    CapabilityBinding,
    CapabilityIssueRequest,
    CapabilityPolicy,
    IssuedCapability,
    SignedExecutionEvidence,
    VerifiedCapability,
    canonical_json_bytes,
    signed_capability_bytes,
)
from api.services.telephony.onnuri_preflight_policy import (
    DISPATCH_CAPABILITY_DOMAIN,
    MEDIA_CAPABILITY_DOMAIN,
)
from api.services.telephony.providers.jambonz.facade.auth import canonical_signing_bytes
from api.services.telephony.providers.jambonz.facade.clients import (
    F12AuthorityHttpClient,
)
from api.services.telephony.providers.jambonz.facade.models import (
    BoundCallContext,
    CallbackReceipt,
    CallStatus,
    ContainmentRequest,
    DispatchConsumeReceipt,
    FailureCategory,
    MediaAuthorityReceipt,
    StockCallBindReceipt,
    RouteChainCapability,
    StockCallBindRequest,
)
from api.schemas.onnuri_smoke import (
    FacadeBoundCallStatusResponse,
    ExecutionContainRequest,
    ExecutionEvidenceFinalizeRequest,
    ClaimReservedInboundAndBindRequest,
    ClaimReservedInboundAndBindResponse,
    ExecutionSealRequest,
    ExecutionStageFinalizeRequest,
    ExecutionStageStartRequest,
    RegistrationBeginRequest,
    RegistrationFinalizeRequest,
    SmokeReceipt,
)

_SECRET = "endpoint-secret"
_IDENTITY = "jambonz-facade"
_ISSUER = "recova-edge-ca"
_DIGEST = "a" * 64
_IDEMPOTENCY_KEY = "idem-00000000001"
_DISPATCH_KEY_ID = "dispatch-key"
_MEDIA_KEY_ID = "media-key"
_CANDIDATE_DIGEST = "b" * 64
_GATE_ENVELOPE_DIGEST = "c" * 64
_REGISTRATION_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
_REGISTRATION_ATTESTATION_KEY_ID = "registration-attestation-v1"
_UPSTREAM_ENDPOINT_DIGEST = "f" * 64
_EXECUTION_DOMAIN = "recova.onnuri.smoke.registration.execution.v1"


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> TestClient:
    monkeypatch.setenv(
        "ONNURI_SMOKE_F12_CREDENTIAL_SHA256",
        hashlib.sha256(_SECRET.encode()).hexdigest(),
    )
    monkeypatch.setenv("ONNURI_SMOKE_F12_TRUSTED_MTLS_ISSUER", _ISSUER)
    monkeypatch.setenv("ONNURI_SMOKE_F12_ALLOWED_MTLS_IDENTITIES", _IDENTITY)
    monkeypatch.setenv(
        "ONNURI_SMOKE_F12_IDENTITY_ORGANIZATION_SCOPES",
        json.dumps({_IDENTITY: [7]}),
    )

    public_key_file = tmp_path / "dispatch-public.pem"
    public_key_file.write_bytes(
        _REGISTRATION_PRIVATE_KEY.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setenv("ONNURI_SMOKE_DISPATCH_KEY_ID", _DISPATCH_KEY_ID)
    monkeypatch.setenv(
        "ONNURI_SMOKE_DISPATCH_PUBLIC_KEY_FILE", str(public_key_file)
    )
    monkeypatch.setenv(
        "ONNURI_SMOKE_REGISTRATION_ATTESTATION_KEY_ID",
        _REGISTRATION_ATTESTATION_KEY_ID,
    )
    monkeypatch.setenv(
        "ONNURI_SMOKE_REGISTRATION_ATTESTATION_PUBLIC_KEY_FILE",
        str(public_key_file),
    )
    monkeypatch.setenv(
        "ONNURI_SMOKE_REGISTRATION_UPSTREAM_ENDPOINT_SHA256",
        _UPSTREAM_ENDPOINT_DIGEST,
    )
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    return TestClient(app)


@pytest.mark.parametrize(
    ("attestation_key_id", "attestation_key_digest"),
    [
        (_DISPATCH_KEY_ID, "d" * 64),
        (_REGISTRATION_ATTESTATION_KEY_ID, "a" * 64),
    ],
)
def test_startup_rejects_registration_key_id_or_spki_reuse(
    attestation_key_id: str, attestation_key_digest: str
) -> None:
    runtime = SimpleNamespace(
        issuer=SimpleNamespace(
            key_ids=lambda: frozenset({_DISPATCH_KEY_ID, _MEDIA_KEY_ID}),
            public_key_digests=lambda: frozenset({"a" * 64, "b" * 64}),
        ),
        execution_evidence_signer=SimpleNamespace(
            key_ids=lambda: frozenset({_EXECUTION_EVIDENCE_KEY_ID}),
            public_key_digests=lambda: frozenset({"c" * 64}),
        ),
    )

    with pytest.raises(
        RuntimeError, match="onnuri_smoke_authority_key_separation_invalid"
    ):
        onnuri_smoke_f12._validate_authority_key_separation(
            attestation_key_id=attestation_key_id,
            attestation_key_digest=attestation_key_digest,
            runtime=runtime,
        )


def _headers() -> dict[str, str]:
    return {
        "X-Recova-Verified-MTLS-Identity": _IDENTITY,
        "X-Recova-Verified-MTLS-Issuer": _ISSUER,
        "X-Recova-Onnuri-Endpoint-Credential": _SECRET,
    }


def _dispatch_payload() -> dict[str, object]:
    return {
        "organization_id": 7,
        "account_id": "account-a",
        "application_id": "application-a",
        "run_id": "run-a",
        "attempt_uuid": "attempt-a",
        "idempotency_key": _IDEMPOTENCY_KEY,
        "opaque_capability": "offline-opaque-capability",
        "request_digest": _DIGEST,
    }


def _bind_request(
    *,
    organization_id: int = 7,
    account_id: str = "account-a",
    stock_call_id: str = "stock-call-a",
) -> StockCallBindRequest:
    return StockCallBindRequest(
        context=BoundCallContext(
            organization_id=organization_id,
            account_id=account_id,
            application_id="application-a",
            run_id="run-a",
            attempt_id="attempt-a",
            direction="outbound",
            stock_call_id=stock_call_id,
            authority_deadline=datetime(2026, 7, 14, 12, 1, tzinfo=UTC),
            candidate_digest=_CANDIDATE_DIGEST,
            gate_envelope_digest=_GATE_ENVELOPE_DIGEST,
        ),
        stock_call_id=stock_call_id,
        idempotency_key=_IDEMPOTENCY_KEY,
        request_digest=_DIGEST,
        dispatch_receipt_id="attempt-a:dispatch-consume",
    )


def _inbound_bind_request() -> StockCallBindRequest:
    payload = _bind_request().model_dump(mode="json")
    payload["context"]["direction"] = "inbound"
    payload.update(
        {
            "dispatch_receipt_id": None,
            "source_account_id": "account-a",
            "source_application_id": "application-a",
            "did_digest": "b" * 64,
            "caller_mobile_digest": "c" * 64,
            "candidate_digest": "d" * 64,
        }
    )
    return StockCallBindRequest.model_validate(payload)


@pytest.mark.parametrize(
    "missing_field",
    [
        "source_account_id",
        "source_application_id",
        "did_digest",
        "caller_mobile_digest",
        "candidate_digest",
    ],
)
def test_bind_contract_requires_complete_direction_authority(
    missing_field: str,
) -> None:
    inbound = _inbound_bind_request().model_dump(mode="json")
    inbound[missing_field] = None
    with pytest.raises(ValueError, match="inbound bind authority is incomplete"):
        StockCallBindRequest.model_validate(inbound)

    outbound = _bind_request().model_dump(mode="json")
    outbound[missing_field] = (
        "unexpected-authority" if missing_field.startswith("source_") else "e" * 64
    )
    with pytest.raises(ValueError, match="outbound bind authority is incomplete"):
        StockCallBindRequest.model_validate(outbound)


def test_bind_contract_requires_direction_receipt_and_matching_sources() -> None:
    outbound = _bind_request().model_dump(mode="json")
    outbound["dispatch_receipt_id"] = None
    with pytest.raises(ValueError, match="outbound bind authority is incomplete"):
        StockCallBindRequest.model_validate(outbound)

    inbound = _inbound_bind_request().model_dump(mode="json")
    inbound["dispatch_receipt_id"] = "unexpected-dispatch-receipt"
    with pytest.raises(ValueError, match="inbound bind authority is incomplete"):
        StockCallBindRequest.model_validate(inbound)

    inbound = _inbound_bind_request().model_dump(mode="json")
    inbound["source_account_id"] = "mismatched-authority"
    with pytest.raises(ValueError, match="source account"):
        StockCallBindRequest.model_validate(inbound)

    inbound = _inbound_bind_request().model_dump(mode="json")
    inbound["source_application_id"] = "mismatched-authority"
    with pytest.raises(ValueError, match="source application"):
        StockCallBindRequest.model_validate(inbound)


def _assert_unauthorized_without_leak(response, *presented_values: str) -> None:
    assert response.status_code == 401
    assert response.json() == {"detail": "onnuri_smoke_f12_unauthorized"}
    for value in (*presented_values, _SECRET, _IDENTITY, _ISSUER):
        assert value not in response.text


@pytest.mark.parametrize(
    "missing",
    [
        "X-Recova-Verified-MTLS-Identity",
        "X-Recova-Verified-MTLS-Issuer",
        "X-Recova-Onnuri-Endpoint-Credential",
    ],
)
def test_auth_rejects_missing_headers(client: TestClient, missing: str) -> None:
    headers = _headers()
    headers.pop(missing)
    response = client.post(
        "/api/v1/internal/onnuri-smoke/consume-dispatch",
        headers=headers,
        json=_dispatch_payload(),
    )
    _assert_unauthorized_without_leak(response)


@pytest.mark.parametrize(
    ("header", "unapproved"),
    [
        ("X-Recova-Verified-MTLS-Identity", "unapproved-facade"),
        ("X-Recova-Verified-MTLS-Issuer", "untrusted-edge-ca"),
        ("X-Recova-Onnuri-Endpoint-Credential", "wrong-endpoint-credential"),
    ],
)
def test_auth_rejects_unapproved_identity_issuer_and_credential_without_leak(
    client: TestClient, header: str, unapproved: str
) -> None:
    response = client.post(
        "/api/v1/internal/onnuri-smoke/consume-dispatch",
        headers=_headers() | {header: unapproved},
        json=_dispatch_payload(),
    )
    _assert_unauthorized_without_leak(response, unapproved)


@pytest.mark.parametrize(
    "duplicated",
    [
        "X-Recova-Verified-MTLS-Identity",
        "X-Recova-Verified-MTLS-Issuer",
        "X-Recova-Onnuri-Endpoint-Credential",
    ],
)
def test_auth_rejects_duplicate_trust_headers(
    client: TestClient, duplicated: str
) -> None:
    duplicate_headers = list(_headers().items()) + [
        (duplicated, _headers()[duplicated])
    ]
    response = client.post(
        "/api/v1/internal/onnuri-smoke/consume-dispatch",
        headers=duplicate_headers,
        json=_dispatch_payload(),
    )
    _assert_unauthorized_without_leak(response, _headers()[duplicated])


@pytest.mark.parametrize(
    "forbidden",
    [
        ("Authorization", "Bearer customer-session"),
        ("Cookie", "session=customer-session"),
        ("X-API-Key", "customer-api-key"),
    ],
)
def test_customer_and_api_key_auth_are_rejected(
    client: TestClient, forbidden: tuple[str, str]
) -> None:
    response = client.post(
        "/api/v1/internal/onnuri-smoke/consume-dispatch",
        headers=_headers() | {forbidden[0]: forbidden[1]},
        json=_dispatch_payload(),
    )
    _assert_unauthorized_without_leak(response, forbidden[1])



def test_f12_identity_rejects_cross_tenant_before_service(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation = AsyncMock()
    monkeypatch.setattr(onnuri_smoke_f12, "create_execution_seal", operation)
    payload = _execution_seal_payload()
    payload["organization_id"] = 8

    response = client.post(
        "/api/v1/internal/onnuri-smoke/execution/seal",
        headers=_headers(),
        json=payload,
    )

    assert response.status_code == 403
    assert response.json() == {
        "detail": "onnuri_smoke_f12_tenant_scope_rejected"
    }
    operation.assert_not_awaited()


@pytest.mark.parametrize(
    "scope_claim",
    [
        "not-json",
        "[]",
        json.dumps({_IDENTITY: []}),
        json.dumps({_IDENTITY: [0]}),
        json.dumps({_IDENTITY: ["7"]}),
    ],
)
def test_f12_identity_rejects_malformed_scope_claims(
    monkeypatch: pytest.MonkeyPatch, scope_claim: str
) -> None:
    monkeypatch.setenv(
        "ONNURI_SMOKE_F12_CREDENTIAL_SHA256",
        hashlib.sha256(_SECRET.encode()).hexdigest(),
    )
    monkeypatch.setenv("ONNURI_SMOKE_F12_TRUSTED_MTLS_ISSUER", _ISSUER)
    monkeypatch.setenv("ONNURI_SMOKE_F12_ALLOWED_MTLS_IDENTITIES", _IDENTITY)
    monkeypatch.setenv(
        "ONNURI_SMOKE_F12_IDENTITY_ORGANIZATION_SCOPES", scope_claim
    )

    with pytest.raises(onnuri_smoke_f12.F12ServiceError) as raised:
        onnuri_smoke_f12.authenticate(
            identity=_IDENTITY, issuer=_ISSUER, credential=_SECRET
        )

    assert raised.value.status_code == 401


@pytest.mark.parametrize("ready_value", [True, False])
def test_authenticated_readiness_returns_authority_database_state(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, ready_value: bool
) -> None:
    operation = AsyncMock(return_value=ready_value)
    monkeypatch.setattr(onnuri_smoke_f12, "authority_ready", operation)

    response = client.post("/api/v1/internal/onnuri-smoke/ready", headers=_headers())

    assert response.status_code == 200
    assert response.json() == {"ready": ready_value}
    operation.assert_awaited_once()


@pytest.mark.parametrize(
    ("account_id", "result", "expected_status"),
    [
        (
            "account-a",
            FacadeBoundCallStatusResponse(
                context=_bind_request().context.model_copy(update={"stock_call_id": None}),
                status=CallStatus.RUNNING,
                idempotency_key=_IDEMPOTENCY_KEY,
                request_digest=_DIGEST,
                candidate_digest="b" * 64,
                allocated_at=datetime(2026, 7, 14, 12, tzinfo=UTC),
            ),
            200,
        ),
        (
            "wrong-account",
            onnuri_smoke_f12.F12ServiceError(
                "onnuri_smoke_f12_partition_rejected", 404
            ),
            404,
        ),
        (
            "account-a",
            onnuri_smoke_f12.F12ServiceError(
                "onnuri_smoke_f12_attempt_not_found", 404
            ),
            404,
        ),
    ],
)
def test_bound_status_is_account_bound_and_redacts_failures(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    account_id: str,
    result: FacadeBoundCallStatusResponse | Exception,
    expected_status: int,
) -> None:
    operation = AsyncMock(
        side_effect=result if isinstance(result, Exception) else None,
        return_value=None if isinstance(result, Exception) else result,
    )
    monkeypatch.setattr(onnuri_smoke_f12, "get_bound_call_status", operation)
    payload = {
        "organization_id": 7,
        "account_id": account_id,
        "stock_call_id_digest": hashlib.sha256(b"raw-stock-call-id").hexdigest(),
    }

    response = client.post(
        "/api/v1/internal/onnuri-smoke/bound-call-status",
        headers=_headers(),
        json=payload,
    )

    assert response.status_code == expected_status
    if expected_status == 200:
        assert response.json() == result.model_dump(mode="json")
        operation.assert_awaited_once_with(**payload)
    else:
        assert response.json()["detail"].startswith("onnuri_smoke_f12_")
        for raw in (
            "raw-stock-call-id",
            "wrong-account",
            "01012345678",
            "sip:secret@example.invalid",
            "opaque-token",
            _SECRET,
        ):
            assert raw not in response.text


@pytest.mark.parametrize(
    ("result", "expected_status"),
    [
        (
            CallbackReceipt(
                organization_id=7,
                event_nonce="event-digest",
                idempotency_key=_IDEMPOTENCY_KEY,
                request_digest=_DIGEST,
                accepted_at=datetime(2026, 7, 14, 12, tzinfo=UTC),
                status=CallStatus.RUNNING,
            ),
            200,
        ),
        (
            CallbackReceipt(
                organization_id=7,
                event_nonce="event-digest",
                idempotency_key=_IDEMPOTENCY_KEY,
                request_digest=_DIGEST,
                accepted_at=datetime(2026, 7, 14, 12, tzinfo=UTC),
                status=CallStatus.RUNNING,
            ),
            200,
        ),
        (onnuri_smoke_f12.F12ServiceError("onnuri_smoke_f12_replay_rejected", 409), 409),
        (onnuri_smoke_f12.F12ServiceError("onnuri_smoke_f12_operation_rejected", 409), 409),
    ],
    ids=["accepted", "exact-duplicate", "mismatch", "illegal-transition"],
)
def test_normalized_event_accepts_exact_duplicates_and_rejects_mismatch_or_transition(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    result: CallbackReceipt | Exception,
    expected_status: int,
) -> None:
    operation = AsyncMock(
        side_effect=result if isinstance(result, Exception) else None,
        return_value=None if isinstance(result, Exception) else result,
    )
    monkeypatch.setattr(onnuri_smoke_f12, "accept_call_event", operation)
    context = _bind_request(stock_call_id="raw-stock-call-id").context
    payload = {
        "context": context.model_dump(mode="json"),
        "event_nonce_digest": "b" * 64,
        "idempotency_key": _IDEMPOTENCY_KEY,
        "request_digest": _DIGEST,
        "event_type": "status",
        "normalized_status": "running",
        "occurred_at": datetime(2026, 7, 14, 12, tzinfo=UTC).isoformat(),
    }

    response = client.post(
        "/api/v1/internal/onnuri-smoke/normalized-event",
        headers=_headers(),
        json=payload,
    )

    assert response.status_code == expected_status
    if expected_status == 200:
        assert response.json() == result.model_dump(mode="json")
    else:
        assert response.json()["detail"].startswith("onnuri_smoke_f12_")
        for raw in (
            "raw-stock-call-id",
            "01012345678",
            "sip:secret@example.invalid",
            "opaque-token",
            _SECRET,
        ):
            assert raw not in response.text


@pytest.mark.parametrize(
    ("result", "expected_status"),
    [
        (SmokeReceipt(attempt_uuid="attempt-a", state="contained"), 200),
        (SmokeReceipt(attempt_uuid="attempt-a", state="contained"), 200),
        (onnuri_smoke_f12.F12ServiceError("onnuri_smoke_f12_replay_rejected", 409), 409),
    ],
    ids=["contained", "exact-duplicate", "mismatch"],
)
def test_containment_accepts_exact_duplicates_and_rejects_mismatch_without_mutation(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    result: SmokeReceipt | Exception,
    expected_status: int,
) -> None:
    operation = AsyncMock(
        side_effect=result if isinstance(result, Exception) else None,
        return_value=None if isinstance(result, Exception) else result,
    )
    monkeypatch.setattr(onnuri_smoke_f12, "request_call_containment", operation)
    request = ContainmentRequest(
        organization_id=7,
        context=_bind_request(stock_call_id="raw-stock-call-id").context,
        stock_call_id="raw-stock-call-id",
        category=FailureCategory.CONTAINMENT_REQUIRED,
    )

    response = client.post(
        "/api/v1/internal/onnuri-smoke/containment",
        headers=_headers(),
        json={"context": request.context.model_dump(mode="json"), "category": request.category},
    )

    assert response.status_code == expected_status
    if expected_status == 200:
        assert response.json() == result.model_dump(mode="json")
    else:
        assert response.json()["detail"] == "onnuri_smoke_f12_replay_rejected"
        for raw in (
            "raw-stock-call-id",
            "01012345678",
            "sip:secret@example.invalid",
            "opaque-token",
            _SECRET,
        ):
            assert raw not in response.text


def test_route_delegates_exact_validated_payload(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    receipt = DispatchConsumeReceipt(
        context=BoundCallContext(
            organization_id=7,
            account_id="account-a",
            application_id="application-a",
            run_id="run-a",
            attempt_id="attempt-a",
            direction="outbound",
            authority_deadline=now + timedelta(seconds=60),
            candidate_digest=_CANDIDATE_DIGEST,
            gate_envelope_digest=_GATE_ENVELOPE_DIGEST,
        ),
        idempotency_key=_IDEMPOTENCY_KEY,
        request_digest=_DIGEST,
        receipt_id="attempt-a:dispatch-consume",
        consumed_at=now,
        dispatch_key_id=_DISPATCH_KEY_ID,
        verification_domain=DISPATCH_CAPABILITY_DOMAIN,
        signature="signed-dispatch-receipt",
    )
    operation = AsyncMock(return_value=receipt)
    monkeypatch.setattr(onnuri_smoke_f12, "consume_dispatch", operation)

    response = client.post(
        "/api/v1/internal/onnuri-smoke/consume-dispatch",
        headers=_headers(),
        json=_dispatch_payload(),
    )

    assert response.status_code == 200
    operation.assert_awaited_once()
    delegated = operation.await_args.kwargs
    assert delegated == {
        "organization_id": 7,
        "account_id": "account-a",
        "application_id": "application-a",
        "run_id": "run-a",
        "attempt_uuid": "attempt-a",
        "idempotency_key": _IDEMPOTENCY_KEY,
        "opaque_capability": SecretStr("offline-opaque-capability"),
        "request_digest": _DIGEST,
    }
    assert (
        delegated["opaque_capability"].get_secret_value() == "offline-opaque-capability"
    )
    expected = receipt.model_dump(mode="json", exclude={"signature"})
    expected["signature"] = "signed-dispatch-receipt"
    assert response.json() == expected
    round_tripped = DispatchConsumeReceipt.model_validate(response.json())
    assert round_tripped.model_dump(mode="json") == receipt.model_dump(mode="json")
    assert round_tripped.context.organization_id == (
        _dispatch_payload()["organization_id"]
    )
    assert (
        round_tripped.signature.get_secret_value()
        == receipt.signature.get_secret_value()
    )


def test_media_route_round_trips_exact_opaque_capability(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    deadline = now + timedelta(seconds=60)
    receipt = MediaAuthorityReceipt(
        context=BoundCallContext(
            organization_id=7,
            account_id="account-a",
            application_id="application-a",
            run_id="run-a",
            attempt_id="attempt-a",
            direction="outbound",
            stock_call_id="call-a",
            authority_deadline=deadline,
            candidate_digest=_CANDIDATE_DIGEST,
            gate_envelope_digest=_GATE_ENVELOPE_DIGEST,
        ),
        stock_call_id="call-a",
        idempotency_key=_IDEMPOTENCY_KEY,
        request_digest=_DIGEST,
        authority_receipt_id="attempt-a:media-authority",
        committed_at=now,
        authority_deadline=deadline,
        media_key_id=_MEDIA_KEY_ID,
        opaque_media_capability="exact-opaque-media-capability",
    )
    operation = AsyncMock(return_value=receipt)
    monkeypatch.setattr(onnuri_smoke_f12, "record_answer_and_mint_media", operation)
    payload = {
        "organization_id": 7,
        "account_id": "account-a",
        "application_id": "application-a",
        "run_id": "run-a",
        "attempt_uuid": "attempt-a",
        "stock_call_id": "call-a",
        "idempotency_key": _IDEMPOTENCY_KEY,
        "request_digest": _DIGEST,
        "event_nonce": "event-a",
        "candidate_digest": "b" * 64,
        "gate_envelope_digest": _GATE_ENVELOPE_DIGEST,
        "observed_wall_time": now.isoformat(),
        "proposed_deadline": deadline.isoformat(),
        "observed_answer": True,
    }

    response = client.post(
        "/api/v1/internal/onnuri-smoke/record-answer-and-mint-media",
        headers=_headers(),
        json=payload,
    )

    assert response.status_code == 200
    expected = receipt.model_dump(mode="json", exclude={"opaque_media_capability"})
    expected["opaque_media_capability"] = "exact-opaque-media-capability"
    assert response.json() == expected
    assert MediaAuthorityReceipt.model_validate(response.json()) == receipt
    delegated = operation.await_args.kwargs
    assert delegated["organization_id"] == 7
    assert delegated["observed_wall_time"] == now
    assert delegated["proposed_deadline"] == deadline


def test_secret_bearing_media_failure_is_redacted_without_error_chain_leak(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "media-capability-must-not-escape"
    operation = AsyncMock(
        side_effect=onnuri_smoke_f12.F12ServiceError(
            code="onnuri_smoke_f12_operation_rejected",
            status_code=409,
        )
    )
    monkeypatch.setattr(onnuri_smoke_f12, "record_answer_and_mint_media", operation)
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    payload = {
        "organization_id": 7,
        "account_id": "account-a",
        "application_id": "application-a",
        "run_id": "run-a",
        "attempt_uuid": "attempt-a",
        "stock_call_id": "call-a",
        "idempotency_key": _IDEMPOTENCY_KEY,
        "request_digest": _DIGEST,
        "event_nonce": secret,
        "candidate_digest": "b" * 64,
        "gate_envelope_digest": _GATE_ENVELOPE_DIGEST,
        "observed_wall_time": now.isoformat(),
        "proposed_deadline": (now + timedelta(seconds=60)).isoformat(),
        "observed_answer": True,
    }

    response = client.post(
        "/api/v1/internal/onnuri-smoke/record-answer-and-mint-media",
        headers=_headers(),
        json=payload,
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "onnuri_smoke_f12_operation_rejected"}
    assert secret not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("inbound", [False, True])
async def test_bind_duplicate_returns_same_committed_receipt(
    monkeypatch: pytest.MonkeyPatch,
    inbound: bool,
) -> None:
    bound_at = datetime(2026, 7, 14, 12, 0, 5, tzinfo=UTC)
    committed = SimpleNamespace(
        attempt_uuid="attempt-a",
        organization_id=7,
        direction="inbound" if inbound else "outbound",
        idempotency_key=_IDEMPOTENCY_KEY,
        allocation_request_digest=_DIGEST,
        state="stock_bound",
        stock_bound_at=bound_at,
    )
    authority_call = AsyncMock(return_value=committed)
    monkeypatch.setattr(
        onnuri_smoke_f12.authority, "bind_smoke_stock_call", authority_call
    )
    request = _inbound_bind_request() if inbound else _bind_request()

    first = await onnuri_smoke_f12.bind_stock_call(request)
    duplicate = await onnuri_smoke_f12.bind_stock_call(request)

    assert (
        first
        == duplicate
        == StockCallBindReceipt(
            context=request.context,
            stock_call_id=request.stock_call_id,
            idempotency_key=request.idempotency_key,
            request_digest=request.request_digest,
            bind_receipt_id="attempt-a:stock-bind",
            bound_at=bound_at,
            media_capability_issued=False,
        )
    )
    assert first.model_dump_json() == duplicate.model_dump_json()
    expected_authority = {
        "organization_id": 7,
        "idempotency_key": _IDEMPOTENCY_KEY,
        "request_digest": _DIGEST,
        "stock_call_id_digest": hashlib.sha256(b"stock-call-a").hexdigest(),
        "callback_nonce_digest": hashlib.sha256(
            canonical_json_bytes(request.model_dump(mode="json", exclude_none=True))
        ).hexdigest(),
        "account_id": request.context.account_id,
        "application_id": request.context.application_id,
        "run_id": request.context.run_id,
    }
    if inbound:
        expected_authority.update(
            {
                "source_account_id": "account-a",
                "source_application_id": "application-a",
                "did_digest": "b" * 64,
                "caller_mobile_digest": "c" * 64,
                "candidate_digest": "d" * 64,
            }
        )
    authority_call.assert_awaited_with("attempt-a", **expected_authority)


def test_bind_route_returns_exact_facade_wire_shape_and_redacts_failures(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _bind_request()
    receipt = StockCallBindReceipt(
        context=request.context,
        stock_call_id=request.stock_call_id,
        idempotency_key=request.idempotency_key,
        request_digest=request.request_digest,
        bind_receipt_id="attempt-a:stock-bind",
        bound_at=datetime(2026, 7, 14, 12, 0, 5, tzinfo=UTC),
        media_capability_issued=False,
    )
    operation = AsyncMock(return_value=receipt)
    monkeypatch.setattr(onnuri_smoke_f12, "bind_stock_call", operation)

    response = client.post(
        "/api/v1/internal/onnuri-smoke/bind-stock-call",
        headers=_headers(),
        json=request.model_dump(mode="json"),
    )

    assert response.status_code == 200
    assert response.json() == receipt.model_dump(mode="json")
    operation.assert_awaited_once_with(request)

    raw_stock_call_id = "raw-stock-call-id-must-not-escape"
    rejected = AsyncMock(
        side_effect=onnuri_smoke_f12.F12ServiceError(
            "onnuri_smoke_f12_replay_rejected", 409
        )
    )
    monkeypatch.setattr(onnuri_smoke_f12, "bind_stock_call", rejected)
    rejected_response = client.post(
        "/api/v1/internal/onnuri-smoke/bind-stock-call",
        headers=_headers(),
        json=_bind_request(stock_call_id=raw_stock_call_id).model_dump(mode="json"),
    )
    assert rejected_response.status_code == 409
    assert rejected_response.json() == {"detail": "onnuri_smoke_f12_replay_rejected"}
    assert raw_stock_call_id not in rejected_response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("bind_request", "error", "code"),
    [
        (
            _bind_request(account_id="swapped-account"),
            TelephonyNumberInventoryConflictError("onnuri_smoke_bind_replay"),
            "onnuri_smoke_f12_replay_rejected",
        ),
        (
            _bind_request(organization_id=999),
            TelephonyNumberInventoryNotFoundError("onnuri_smoke_attempt_not_found"),
            "onnuri_smoke_f12_partition_rejected",
        ),
    ],
)
async def test_bind_tenant_and_context_swaps_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    bind_request: StockCallBindRequest,
    error: Exception,
    code: str,
) -> None:
    monkeypatch.setattr(
        onnuri_smoke_f12.authority,
        "bind_smoke_stock_call",
        AsyncMock(side_effect=error),
    )

    with pytest.raises(onnuri_smoke_f12.F12ServiceError) as raised:
        await onnuri_smoke_f12.bind_stock_call(bind_request)

    assert raised.value.code == code
    assert bind_request.stock_call_id not in raised.value.code


@pytest.mark.asyncio
@pytest.mark.parametrize("inbound", [False, True])
async def test_f12_http_client_posts_exact_typed_bind_contract(inbound: bool) -> None:
    request = _inbound_bind_request() if inbound else _bind_request()
    receipt = StockCallBindReceipt(
        context=request.context,
        stock_call_id=request.stock_call_id,
        idempotency_key=request.idempotency_key,
        request_digest=request.request_digest,
        bind_receipt_id="attempt-a:stock-bind",
        bound_at=datetime(2026, 7, 14, 12, 0, 5, tzinfo=UTC),
        media_capability_issued=False,
    )
    transport = SimpleNamespace(post_typed=AsyncMock(return_value=receipt))
    authority_client = F12AuthorityHttpClient(transport)

    assert await authority_client.bind_stock_call(request) == receipt
    transport.post_typed.assert_awaited_once_with(
        operation_path="/api/v1/internal/onnuri-smoke/bind-stock-call",
        request=request,
        response_model=StockCallBindReceipt,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "code"),
    [
        (
            TelephonyNumberInventoryConflictError("onnuri_smoke_bind_replay"),
            "onnuri_smoke_f12_replay_rejected",
        ),
        (
            TelephonyNumberInventoryConflictError("onnuri_smoke_media_not_authorized"),
            "onnuri_smoke_f12_operation_rejected",
        ),
        (
            TelephonyNumberInventoryNotFoundError("onnuri_smoke_attempt_not_found"),
            "onnuri_smoke_f12_partition_rejected",
        ),
    ],
)
async def test_mismatch_replay_and_cross_org_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch, error: Exception, code: str
) -> None:
    monkeypatch.setattr(
        onnuri_smoke_f12.authority,
        "consume_smoke_media",
        AsyncMock(side_effect=error),
    )
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    issuer = _RecordingIssuer()
    values = _media_values(now, organization_id=999)
    opaque = _issued_media_capability(values, now=now)
    with pytest.raises(onnuri_smoke_f12.F12ServiceError) as raised:
        await onnuri_smoke_f12.consume_media(
            issuer=issuer,
            opaque_capability=opaque.decode("utf-8"),
            **values,
        )
    assert issuer.verify_calls == 1
    assert raised.value.code == code
    assert "attempt-a" not in raised.value.code


def test_status_is_redacted_and_internal_route_is_absent_from_openapi(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    status = {
        "envelope_uuid": "envelope-a",
        "state": "armed",
        "current": True,
        "remaining_attempts": 2,
        "max_duration_seconds": 60,
        "attempts": [
            {
                "attempt_uuid": "attempt-a",
                "ordinal": 1,
                "direction": "outbound",
                "state": "running",
                "terminal_class": None,
            }
        ],
    }
    operation = AsyncMock(return_value=status)
    monkeypatch.setattr(onnuri_smoke_f12, "redacted_status", operation)

    response = client.get(
        "/api/v1/internal/onnuri-smoke/status/envelope-a?organization_id=7",
        headers=_headers(),
    )

    assert response.status_code == 200
    assert response.json() == status
    serialized = response.text
    for forbidden in ("phone", "token", "digest", "inventory_id", "proof_id"):
        assert forbidden not in serialized
    assert not any(
        "onnuri-smoke" in path for path in client.get("/openapi.json").json()["paths"]
    )


def test_production_configuration_requires_all_trust_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("ONNURI_SMOKE_F12_CREDENTIAL_SHA256", raising=False)
    monkeypatch.delenv("ONNURI_SMOKE_F12_TRUSTED_MTLS_ISSUER", raising=False)
    monkeypatch.delenv("ONNURI_SMOKE_F12_ALLOWED_MTLS_IDENTITIES", raising=False)
    with pytest.raises(RuntimeError):
        onnuri_smoke_f12.validate_startup_configuration()


@pytest.mark.asyncio
async def test_media_duplicate_recovers_committed_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    deadline = now + timedelta(seconds=60)
    issuer = _RecordingIssuer()
    sealer = _MemorySealer()
    values = {
        **_media_values(now),
        "observed_answer": True,
        "proposed_deadline": deadline,
    }
    receipt = MediaAuthorityReceipt(
        context=BoundCallContext(
            organization_id=values["organization_id"],
            account_id=values["account_id"],
            application_id=values["application_id"],
            run_id=values["run_id"],
            attempt_id=values["attempt_uuid"],
            direction="outbound",
            stock_call_id=values["stock_call_id"],
            authority_deadline=deadline,
            candidate_digest=values["candidate_digest"],
            gate_envelope_digest=values["gate_envelope_digest"],
        ),
        stock_call_id=values["stock_call_id"],
        idempotency_key=values["idempotency_key"],
        request_digest=values["request_digest"],
        authority_receipt_id="attempt-a:media-authority",
        committed_at=now,
        authority_deadline=deadline,
        media_verification_domain=MEDIA_CAPABILITY_DOMAIN,
        media_key_id=_MEDIA_KEY_ID,
        opaque_media_capability="signed-media-capability",
    )
    persisted = onnuri_smoke_f12._media_receipt_bytes(receipt)
    sealer.values["persisted-media"] = persisted

    async def operation(*, builder, **kwargs):
        assert kwargs == {
            "attempt_uuid": "attempt-a",
            "organization_id": 7,
            "idempotency_key": _IDEMPOTENCY_KEY,
            "callback_nonce_digest": onnuri_smoke_f12.sha256_hex("event-a"),
            "request_digest": _DIGEST,
            "stock_call_id_digest": onnuri_smoke_f12.sha256_hex("call-a"),
            "authority_wall_at": now,
            "deadline_at": deadline,
            "approved_pause_milliseconds": 0,
            "account_id": values["account_id"],
            "application_id": values["application_id"],
            "run_id": values["run_id"],
        }
        response = await builder(
            {
                "duplicate": True,
                "attempt_uuid": "attempt-a",
                "idempotency_key": _IDEMPOTENCY_KEY,
                "request_digest": _DIGEST,
                "candidate_digest": "b" * 64,
                "gate_envelope_digest": _GATE_ENVELOPE_DIGEST,
                "deadline_at": deadline,
                "encrypted_response_recovery": "persisted-media",
            }
        )
        return SimpleNamespace(), response["response"]

    monkeypatch.setattr(
        onnuri_smoke_f12.authority,
        "record_outbound_answer_and_mint_media",
        operation,
    )

    recovered = await onnuri_smoke_f12.record_answer_and_mint_media(
        issuer=issuer,
        recovery_sealer=sealer,
        **values,
    )

    assert onnuri_smoke_f12._media_receipt_bytes(recovered) == persisted
    assert issuer.issue_requests == []
    assert recovered.media_verification_domain == "recova.onnuri.smoke.media.v1"
    assert recovered.authority_deadline - recovered.committed_at == timedelta(
        seconds=60
    )


@pytest.mark.asyncio
async def test_inbound_media_mint_forwards_complete_authority_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    deadline = now + timedelta(seconds=60)
    values = {
        **_media_values(now),
        "direction": "inbound",
        "proposed_deadline": deadline,
        "source_account_id": "account-a",
        "source_application_id": "application-a",
        "did_digest": "c" * 64,
        "caller_mobile_digest": "d" * 64,
        "candidate_digest": "b" * 64,
    }
    receipt = MediaAuthorityReceipt(
        context=BoundCallContext(
            organization_id=values["organization_id"],
            account_id=values["account_id"],
            application_id=values["application_id"],
            run_id=values["run_id"],
            attempt_id=values["attempt_uuid"],
            direction="inbound",
            stock_call_id=values["stock_call_id"],
            authority_deadline=deadline,
            candidate_digest=values["candidate_digest"],
            gate_envelope_digest=values["gate_envelope_digest"],
        ),
        stock_call_id=values["stock_call_id"],
        idempotency_key=values["idempotency_key"],
        request_digest=values["request_digest"],
        authority_receipt_id="attempt-a:media-authority",
        committed_at=now,
        authority_deadline=deadline,
        media_verification_domain=MEDIA_CAPABILITY_DOMAIN,
        media_key_id=_MEDIA_KEY_ID,
        opaque_media_capability="signed-media-capability",
    )

    async def operation(*, builder, **kwargs):
        assert callable(builder)
        assert kwargs == {
            "attempt_uuid": "attempt-a",
            "organization_id": 7,
            "idempotency_key": _IDEMPOTENCY_KEY,
            "callback_nonce_digest": onnuri_smoke_f12.sha256_hex("event-a"),
            "request_digest": _DIGEST,
            "stock_call_id_digest": onnuri_smoke_f12.sha256_hex("call-a"),
            "authority_wall_at": now,
            "deadline_at": deadline,
            "approved_pause_milliseconds": 0,
            "source_account_id": "account-a",
            "source_application_id": "application-a",
            "did_digest": "c" * 64,
            "caller_mobile_digest": "d" * 64,
            "candidate_digest": "b" * 64,
            "account_id": values["account_id"],
            "application_id": values["application_id"],
            "run_id": values["run_id"],
        }
        return SimpleNamespace(), onnuri_smoke_f12._media_receipt_bytes(receipt)

    monkeypatch.setattr(
        onnuri_smoke_f12.authority,
        "commit_inbound_answer_intent_and_mint_media",
        operation,
    )

    forwarded = await onnuri_smoke_f12.commit_inbound_answer_intent_and_mint_media(
        issuer=_RecordingIssuer(),
        recovery_sealer=_MemorySealer(),
        **values,
    )

    assert forwarded == receipt


class _MemorySealer:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}
        self.unseal_calls = 0

    async def seal(self, *, plaintext: bytes, expires_at: datetime) -> str:
        ciphertext = f"sealed-{len(self.values)}"
        self.values[ciphertext] = plaintext
        return ciphertext

    async def unseal(self, *, ciphertext: str) -> bytes:
        self.unseal_calls += 1
        return self.values[ciphertext]


class _RecordingIssuer:
    def __init__(self) -> None:
        self.issue_requests: list[CapabilityIssueRequest] = []
        self.receipt_messages: list[tuple[bytes, CapabilityPolicy]] = []
        self.verify_calls = 0

    async def issue_dispatch(self, request: CapabilityIssueRequest) -> IssuedCapability:
        self.issue_requests.append(request)
        return IssuedCapability(
            policy=request.policy,
            issued_at=request.issued_at,
            expires_at=request.expires_at,
            nonce="nonce-a",
            signature="capability-signature",
        )

    async def issue_media(self, request: CapabilityIssueRequest) -> IssuedCapability:
        self.issue_requests.append(request)
        return IssuedCapability(
            policy=request.policy,
            issued_at=request.issued_at,
            expires_at=request.expires_at,
            nonce="nonce-media",
            signature="media-signature",
        )

    async def verify(self, kind, opaque, *_args, **_kwargs) -> VerifiedCapability:
        self.verify_calls += 1
        if kind == "dispatch":
            parsed = onnuri_smoke_f12.parse_dispatch_capability(opaque)
            nonce = parsed.nonce
            signature = parsed.signature.get_secret_value()
        else:
            parsed = onnuri_smoke_f12.parse_media_capability(opaque)
            nonce = parsed["nonce"]
            signature = parsed["signature"]
        return VerifiedCapability(
            nonce_digest=onnuri_smoke_f12.sha256_hex(nonce),
            token_digest=onnuri_smoke_f12.sha256_hex(opaque),
            receipt_digest=onnuri_smoke_f12.sha256_hex(signature),
        )

    async def sign_dispatch_receipt(
        self, *, signing_bytes: bytes, policy: CapabilityPolicy
    ) -> str:
        self.receipt_messages.append((signing_bytes, policy))
        return "signed-dispatch-receipt"


def _binding_values(now: datetime) -> dict[str, object]:
    return {
        "organization_id": 7,
        "account_id": "account-a",
        "application_id": "application-a",
        "run_id": "run-a",
        "attempt_uuid": "attempt-a",
        "idempotency_key": _IDEMPOTENCY_KEY,
        "request_digest": _DIGEST,
        "candidate_digest": "b" * 64,
        "gate_envelope_digest": _GATE_ENVELOPE_DIGEST,
        "stock_call_id": "call-a",
        "event_nonce": "event-a",
        "observed_wall_time": now,
    }


def _media_values(now: datetime, *, organization_id: int = 7) -> dict[str, object]:
    return {
        **_binding_values(now),
        "organization_id": organization_id,
        "direction": "outbound",
    }


def _issued_media_capability(values: dict[str, object], *, now: datetime) -> bytes:
    deadline = now + timedelta(seconds=60)
    binding = CapabilityBinding(
        organization_id=values["organization_id"],
        account_id=values["account_id"],
        application_id=values["application_id"],
        run_id=values["run_id"],
        attempt_id=values["attempt_uuid"],
        direction=values["direction"],
        idempotency_key=values["idempotency_key"],
        request_digest=values["request_digest"],
        stock_call_id=values["stock_call_id"],
        callback_event_nonce=values["event_nonce"],
        candidate_digest=values["candidate_digest"],
        gate_envelope_digest=values["gate_envelope_digest"],
        observed_event_wall_time=values["observed_wall_time"],
    )
    policy = CapabilityPolicy(
        kind="media",
        verification_domain=MEDIA_CAPABILITY_DOMAIN,
        key_id=_MEDIA_KEY_ID,
        other_key_id=_DISPATCH_KEY_ID,
    )
    request = CapabilityIssueRequest(
        binding, policy, now, deadline, values["gate_envelope_digest"]
    )
    issued = IssuedCapability(
        policy=policy,
        issued_at=now,
        expires_at=deadline,
        nonce="nonce-media",
        signature="signed-media-capability",
    )
    opaque, _ = signed_capability_bytes(issued, request)
    return opaque


@pytest.mark.asyncio
async def test_dispatch_issuer_receives_locked_policy_and_exact_database_times(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    expires_at = now + timedelta(seconds=37)
    issuer = _RecordingIssuer()
    sealer = _MemorySealer()

    async def issue_operation(*args, builder, **kwargs):
        response = await builder(
            {
                "duplicate": False,
                "issued_at": now,
                "expires_at": expires_at,
                "attempt_uuid": "attempt-a",
                "request_digest": _DIGEST,
                "idempotency_key": _IDEMPOTENCY_KEY,
                "candidate_digest": "b" * 64,
                "gate_envelope_digest": "c" * 64,
                "domain": DISPATCH_CAPABILITY_DOMAIN,
                "key_id": _DISPATCH_KEY_ID,
                "other_key_id": _MEDIA_KEY_ID,
                "algorithm_policy_id": "gcp-kms-ecdsa-p256-sha256-v1",
            }
        )
        return SimpleNamespace(), response["response"]

    monkeypatch.setattr(
        onnuri_smoke_f12.authority, "issue_smoke_dispatch", issue_operation
    )
    values = _binding_values(now)
    attempt_uuid = values.pop("attempt_uuid")
    opaque = await onnuri_smoke_f12.issue_dispatch(
        attempt_uuid,
        issuer=issuer,
        recovery_sealer=sealer,
        **values,
    )

    request = issuer.issue_requests[0]
    assert request.issued_at == now
    assert request.expires_at == expires_at
    assert 0 < (request.expires_at - request.issued_at).total_seconds() <= 60
    assert request.policy.verification_domain == "recova.onnuri.smoke.dispatch.v1"
    assert request.policy.key_id == _DISPATCH_KEY_ID
    assert request.policy.other_key_id == _MEDIA_KEY_ID
    parsed = onnuri_smoke_f12.parse_dispatch_capability(opaque)
    assert parsed.verification_domain == "recova.onnuri.smoke.dispatch.v1"
    assert parsed.algorithm == "ES256"
    assert parsed.expires_at == expires_at
    assert parsed.claims["candidate_digest"] == _CANDIDATE_DIGEST
    assert parsed.claims["gate_envelope_digest"] == _GATE_ENVELOPE_DIGEST
    assert request.gate_envelope_digest == request.binding.gate_envelope_digest



@pytest.mark.asyncio
async def test_dispatch_consume_signs_exact_canonical_receipt_after_database_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    expires_at = now + timedelta(seconds=45)
    issuer = _RecordingIssuer()
    sealer = _MemorySealer()
    binding = CapabilityBinding(
        organization_id=7,
        account_id="account-a",
        application_id="application-a",
        run_id="run-a",
        attempt_id="attempt-a",
        direction="outbound",
        idempotency_key=_IDEMPOTENCY_KEY,
        request_digest=_DIGEST,
        stock_call_id="call-a",
        callback_event_nonce="event-a",
        candidate_digest="b" * 64,
        gate_envelope_digest=_GATE_ENVELOPE_DIGEST,
        observed_event_wall_time=now,
    )
    policy = CapabilityPolicy(
        kind="dispatch",
        verification_domain=DISPATCH_CAPABILITY_DOMAIN,
        key_id=_DISPATCH_KEY_ID,
        other_key_id=_MEDIA_KEY_ID,
    )
    request = CapabilityIssueRequest(
        binding, policy, now, expires_at, _GATE_ENVELOPE_DIGEST
    )
    opaque, _ = signed_capability_bytes(await issuer.issue_dispatch(request), request)

    async def consume_operation(*args, builder, **kwargs):
        assert kwargs["account_id"] == "account-a"
        assert kwargs["application_id"] == "application-a"
        assert kwargs["run_id"] == "run-a"
        response = await builder(
            {
                "duplicate": False,
                "consumed_at": now + timedelta(seconds=3),
                "attempt_uuid": "attempt-a",
                "idempotency_key": _IDEMPOTENCY_KEY,
                "request_digest": _DIGEST,
                "key_id": _DISPATCH_KEY_ID,
                "other_key_id": _MEDIA_KEY_ID,
                "domain": DISPATCH_CAPABILITY_DOMAIN,
                "algorithm_policy_id": "gcp-kms-ecdsa-p256-sha256-v1",
                "expires_at": expires_at,
            }
        )
        return SimpleNamespace(), response["response"]

    monkeypatch.setattr(
        onnuri_smoke_f12.authority, "consume_smoke_dispatch", consume_operation
    )
    receipt = await onnuri_smoke_f12.consume_dispatch(
        issuer=issuer,
        recovery_sealer=sealer,
        opaque_capability=opaque.decode(),
        **_binding_values(now),
    )

    assert receipt.consumed_at == now + timedelta(seconds=3)
    assert receipt.context.authority_deadline == expires_at
    assert receipt.verification_domain == "recova.onnuri.smoke.dispatch.v1"
    assert receipt.dispatch_key_id == _DISPATCH_KEY_ID
    assert receipt.signature.get_secret_value() == "signed-dispatch-receipt"
    unsigned_receipt = receipt.model_copy(update={"signature": "unsigned"})
    assert issuer.receipt_messages == [
        (
            canonical_signing_bytes(unsigned_receipt, exclude={"signature"}),
            policy,
        )
    ]

@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("candidate_digest", "gate_envelope_digest"),
    [
        ("d" * 64, _GATE_ENVELOPE_DIGEST),
        (_CANDIDATE_DIGEST, "d" * 64),
        ("d" * 64, "e" * 64),
    ],
    ids=["candidate-only-mismatch", "gate-only-mismatch", "cross-envelope-candidate-replay"],
)
async def test_dispatch_consume_rejects_digest_replay_before_database_consumption(
    monkeypatch: pytest.MonkeyPatch,
    candidate_digest: str,
    gate_envelope_digest: str,
) -> None:
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    expires_at = now + timedelta(seconds=45)
    issuer = _RecordingIssuer()
    binding = CapabilityBinding(
        organization_id=7,
        account_id="account-a",
        application_id="application-a",
        run_id="run-a",
        attempt_id="attempt-a",
        direction="outbound",
        idempotency_key=_IDEMPOTENCY_KEY,
        request_digest=_DIGEST,
        candidate_digest=_CANDIDATE_DIGEST,
        gate_envelope_digest=_GATE_ENVELOPE_DIGEST,
        stock_call_id="call-a",
        callback_event_nonce="event-a",
        observed_event_wall_time=now,
    )
    policy = CapabilityPolicy(
        kind="dispatch",
        verification_domain=DISPATCH_CAPABILITY_DOMAIN,
        key_id=_DISPATCH_KEY_ID,
        other_key_id=_MEDIA_KEY_ID,
    )
    request = CapabilityIssueRequest(
        binding, policy, now, expires_at, _GATE_ENVELOPE_DIGEST
    )
    opaque, _ = signed_capability_bytes(await issuer.issue_dispatch(request), request)
    consume_operation = AsyncMock()
    monkeypatch.setattr(
        onnuri_smoke_f12.authority, "consume_smoke_dispatch", consume_operation
    )
    values = _binding_values(now)
    values["candidate_digest"] = candidate_digest
    values["gate_envelope_digest"] = gate_envelope_digest

    with pytest.raises(onnuri_smoke_f12.F12ServiceError) as exc_info:
        await onnuri_smoke_f12.consume_dispatch(
            issuer=issuer,
            recovery_sealer=_MemorySealer(),
            opaque_capability=opaque.decode(),
            **values,
        )
    assert exc_info.value.code == "onnuri_smoke_f12_capability_rejected"

    consume_operation.assert_not_awaited()
    assert issuer.verify_calls == 0


@pytest.mark.asyncio
async def test_exact_duplicate_consume_recovers_bytes_without_issuer_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    expires_at = now + timedelta(seconds=45)
    issuer = _RecordingIssuer()
    sealer = _MemorySealer()
    binding = CapabilityBinding(
        organization_id=7,
        account_id="account-a",
        application_id="application-a",
        run_id="run-a",
        attempt_id="attempt-a",
        direction="outbound",
        idempotency_key=_IDEMPOTENCY_KEY,
        request_digest=_DIGEST,
        stock_call_id="call-a",
        callback_event_nonce="event-a",
        candidate_digest="b" * 64,
        gate_envelope_digest=_GATE_ENVELOPE_DIGEST,
        observed_event_wall_time=now,
    )
    policy = CapabilityPolicy(
        kind="dispatch",
        verification_domain=DISPATCH_CAPABILITY_DOMAIN,
        key_id=_DISPATCH_KEY_ID,
        other_key_id=_MEDIA_KEY_ID,
    )
    request = CapabilityIssueRequest(
        binding, policy, now, expires_at, _GATE_ENVELOPE_DIGEST
    )
    opaque, _ = signed_capability_bytes(await issuer.issue_dispatch(request), request)
    issuer.issue_requests.clear()
    receipt = DispatchConsumeReceipt(
        context=BoundCallContext(
            organization_id=7,
            account_id="account-a",
            application_id="application-a",
            run_id="run-a",
            attempt_id="attempt-a",
            direction="outbound",
            authority_deadline=expires_at,
            candidate_digest=_CANDIDATE_DIGEST,
            gate_envelope_digest=_GATE_ENVELOPE_DIGEST,
        ),
        idempotency_key=_IDEMPOTENCY_KEY,
        request_digest=_DIGEST,
        receipt_id="attempt-a:dispatch-consume",
        consumed_at=now + timedelta(seconds=2),
        dispatch_key_id=_DISPATCH_KEY_ID,
        verification_domain=DISPATCH_CAPABILITY_DOMAIN,
        signature="persisted-signature",
    )
    persisted = onnuri_smoke_f12._dispatch_receipt_bytes(receipt)
    sealer.values["persisted"] = persisted

    async def consume_operation(*args, builder, **kwargs):
        response = await builder(
            {"duplicate": True, "encrypted_consume_recovery": "persisted"}
        )
        return SimpleNamespace(), response["response"]

    monkeypatch.setattr(
        onnuri_smoke_f12.authority, "consume_smoke_dispatch", consume_operation
    )
    recovered = await onnuri_smoke_f12.consume_dispatch(
        issuer=issuer,
        recovery_sealer=sealer,
        opaque_capability=opaque.decode(),
        **_binding_values(now),
    )

    assert onnuri_smoke_f12._dispatch_receipt_bytes(recovered) == persisted
    assert issuer.verify_calls == 0
    assert issuer.receipt_messages == []
    assert issuer.issue_requests == []


def _registration_begin_payload() -> dict[str, object]:
    return {
        "organization_id": 7,
        "envelope_uuid": "11111111-1111-4111-8111-111111111111",
        "operation_kind": "register",
        "request_digest": "d" * 64,
        "candidate_digest": _CANDIDATE_DIGEST,
        "gate_envelope_digest": _GATE_ENVELOPE_DIGEST,
        "nonce_digest": "e" * 64,
        "prior_register_gate_id": None,
        "prior_register_operation_uuid": None,
        "execution_seal_uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "execution_nonce_digest": "e" * 64,
        "execution_stage_uuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "execution_stage": "register",
        "execution_stage_ordinal": 1,
    }

def _registration_consume_payload() -> dict[str, object]:
    payload = _registration_begin_payload()
    payload.pop("envelope_uuid")
    for field in (
        "execution_seal_uuid",
        "execution_nonce_digest",
        "execution_stage_uuid",
        "execution_stage",
        "execution_stage_ordinal",
    ):
        payload.pop(field)
    payload["registration_gate_id"] = 41
    payload["operation_uuid"] = "33333333-3333-4333-8333-333333333333"
    payload["opaque_authorization"] = _registration_opaque_authorization(payload)
    return payload


def _registration_opaque_authorization(
    payload: dict[str, object],
    *,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> str:
    issued_at = issued_at or datetime.now(UTC) - timedelta(seconds=1)
    expires_at = expires_at or issued_at + timedelta(seconds=60)
    claims = {
        "candidate_digest": payload["candidate_digest"],
        "concurrency_count": 1,
        "envelope_digest": payload["gate_envelope_digest"],
        "expires_at": expires_at.isoformat(),
        "gate_envelope_digest": payload["gate_envelope_digest"],
        "issued_at": issued_at.isoformat(),
        "max_elapsed_seconds": 60,
        "nonce_digest": payload["nonce_digest"],
        "operation_kind": payload["operation_kind"],
        "operation_uuid": payload["operation_uuid"],
        "organization_id": payload["organization_id"],
        "prior_register_gate_id": payload["prior_register_gate_id"],
        "prior_register_operation_uuid": payload["prior_register_operation_uuid"],
        "registration_gate_id": payload["registration_gate_id"],
        "request_digest": payload["request_digest"],
        "retry_count": 0,
        "transaction_count": 1,
        "verification_domain": "recova.onnuri.smoke.registration.v1",
    }
    unsigned = {
        "algorithm": "ES256",
        "claims": claims,
        "key_id": _DISPATCH_KEY_ID,
        "verification_domain": "recova.onnuri.smoke.registration.v1",
    }
    der = _REGISTRATION_PRIVATE_KEY.sign(
        canonical_json_bytes(unsigned), ec.ECDSA(hashes.SHA256())
    )
    r, s = decode_dss_signature(der)
    signature = base64.urlsafe_b64encode(
        r.to_bytes(32, "big") + s.to_bytes(32, "big")
    ).rstrip(b"=").decode("ascii")
    authorization = canonical_json_bytes({**unsigned, "signature": signature})
    return base64.urlsafe_b64encode(authorization).rstrip(b"=").decode("ascii")

def _execution_attestation(
    *,
    key: ec.EllipticCurvePrivateKey = _REGISTRATION_PRIVATE_KEY,
    key_id: str = _REGISTRATION_ATTESTATION_KEY_ID,
    domain: str = _EXECUTION_DOMAIN,
    claim_changes: dict[str, object] | None = None,
) -> str:
    completed = datetime.now(UTC).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )
    started = (
        datetime.now(UTC) - timedelta(seconds=1)
    ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    claims: dict[str, object] = {
        "accepted_expires_seconds": 3600,
        "authorization_nonce_digest": "e" * 64,
        "candidate_digest": _CANDIDATE_DIGEST,
        "challenge_response_wire_digest": None,
        "challenge_status": None,
        "completed_at": completed,
        "deregistered": False,
        "final_response_wire_digest": "2" * 64,
        "final_status": 200,
        "gate_envelope_digest": _GATE_ENVELOPE_DIGEST,
        "initial_request_wire_digest": "1" * 64,
        "operation_kind": "register",
        "operation_uuid": "33333333-3333-4333-8333-333333333333",
        "organization_id": 7,
        "outcome": "succeeded",
        "prior_register_gate_id": None,
        "prior_register_operation_uuid": None,
        "registration_gate_id": 41,
        "request_digest": "d" * 64,
        "response_count": 1,
        "retry_count": 0,
        "retry_request_wire_digest": None,
        "sip_transaction_binding_digest": "3" * 64,
        "started_at": started,
        "transaction_count": 1,
        "transport": "udp",
        "upstream_endpoint_digest": _UPSTREAM_ENDPOINT_DIGEST,
        "verification_domain": domain,
        "wire_request_count": 1,
    }
    claims.update(claim_changes or {})
    unsigned = {
        "algorithm": "ES256",
        "claims": claims,
        "key_id": key_id,
        "verification_domain": domain,
    }
    der = key.sign(canonical_json_bytes(unsigned), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    signature = base64.urlsafe_b64encode(
        r.to_bytes(32, "big") + s.to_bytes(32, "big")
    ).rstrip(b"=").decode()
    raw = canonical_json_bytes({**unsigned, "signature": signature})
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_registration_consume_route_returns_exact_started_contract_and_delegates(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _registration_consume_payload()
    gate = SimpleNamespace(
        id=payload["registration_gate_id"],
        operation_uuid=payload["operation_uuid"],
        operation_kind=payload["operation_kind"],
    )
    consume = AsyncMock(return_value=gate)
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "consume_onnuri_registration_operation",
        consume,
    )

    response = client.post(
        "/api/v1/internal/onnuri-smoke/registration/consume",
        headers=_headers(),
        json=payload,
    )

    assert response.status_code == 200
    assert response.json() == {
        "registration_gate_id": 41,
        "operation_uuid": "33333333-3333-4333-8333-333333333333",
        "operation_kind": "register",
        "request_digest": "d" * 64,
        "candidate_digest": _CANDIDATE_DIGEST,
        "gate_envelope_digest": _GATE_ENVELOPE_DIGEST,
        "nonce_digest": "e" * 64,
        "prior_register_gate_id": None,
        "prior_register_operation_uuid": None,
        "state": "started",
        "challenged": True,
        "transaction_count": 1,
        "retry_count": 0,
        "concurrency_count": 1,
    }
    delegated = consume.await_args.kwargs
    assert delegated == {
        "organization_id": 7,
        "registration_gate_id": 41,
        "operation_uuid": "33333333-3333-4333-8333-333333333333",
        "operation_kind": "register",
        "request_digest": "d" * 64,
        "candidate_digest": _CANDIDATE_DIGEST,
        "gate_envelope_digest": _GATE_ENVELOPE_DIGEST,
        "nonce_digest": "e" * 64,
        "prior_register_gate_id": None,
        "prior_register_operation_uuid": None,
    }
    assert payload["opaque_authorization"] not in response.text
    assert "opaque-provider-signature" not in response.text
    assert not any(
        "onnuri-smoke" in path for path in client.get("/openapi.json").json()["paths"]
    )


@pytest.mark.parametrize(
    ("headers", "mutation"),
    [
        ({}, None),
        (_headers(), ("operation_uuid", "not-a-uuid")),
        (_headers(), ("nonce_digest", "invalid")),
        (_headers(), ("unexpected", True)),
        (_headers(), ("opaque_authorization", "provider-secret")),
    ],
)
def test_registration_consume_route_rejects_unauthorized_and_malformed_without_leak(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    headers: dict[str, str],
    mutation: tuple[str, object] | None,
) -> None:
    consume = AsyncMock()
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "consume_onnuri_registration_operation",
        consume,
    )
    payload = _registration_consume_payload()
    if mutation is not None:
        payload[mutation[0]] = mutation[1]

    response = client.post(
        "/api/v1/internal/onnuri-smoke/registration/consume",
        headers=headers,
        json=payload,
    )

    assert response.status_code in {401, 409, 422}
    assert "provider-secret" not in response.text
    assert "opaque-provider-signature" not in response.text
    consume.assert_not_awaited()


@pytest.mark.parametrize("case", ["forged", "expired"])
def test_registration_consume_rejects_signed_envelope_attack_before_transition(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    consume = AsyncMock()
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "consume_onnuri_registration_operation",
        consume,
    )
    payload = _registration_consume_payload()
    if case == "forged":
        envelope = json.loads(
            base64.urlsafe_b64decode(payload["opaque_authorization"] + "==")
        )
        envelope["signature"] = base64.urlsafe_b64encode(b"\0" * 64).rstrip(
            b"="
        ).decode("ascii")
        payload["opaque_authorization"] = base64.urlsafe_b64encode(
            canonical_json_bytes(envelope)
        ).rstrip(b"=").decode("ascii")
    else:
        expired = datetime.now(UTC) - timedelta(seconds=1)
        payload["opaque_authorization"] = _registration_opaque_authorization(
            payload,
            issued_at=expired - timedelta(seconds=59),
            expires_at=expired,
        )

    response = client.post(
        "/api/v1/internal/onnuri-smoke/registration/consume",
        headers=_headers(),
        json=payload,
    )

    assert response.status_code == 409
    consume.assert_not_awaited()


def test_registration_provider_cannot_author_terminal_evidence() -> None:
    runner = (
        Path(__file__).parents[4]
        / "deploy"
        / "onnuri-jambonz-oss"
        / "run-registration-transaction.js"
    )
    content = runner.read_text()

    assert "childEnvironment" not in content
    assert "spawn(" not in content
    assert "opaque_execution_attestation" in content
    assert "registration-sip-attestor" in content


@pytest.mark.parametrize(
    ("error", "status_code"),
    [
        (TelephonyNumberInventoryConflictError("provider-conflict"), 409),
        (TelephonyNumberInventoryNotFoundError("provider-not-found"), 409),
    ],
)
def test_registration_consume_route_maps_authority_errors_without_provider_leak(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    status_code: int,
) -> None:
    consume = AsyncMock(side_effect=error)
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "consume_onnuri_registration_operation",
        consume,
    )
    payload = _registration_consume_payload()

    response = client.post(
        "/api/v1/internal/onnuri-smoke/registration/consume",
        headers=_headers(),
        json=payload,
    )

    assert response.status_code == status_code
    assert "provider-" not in response.text
    assert payload["opaque_authorization"] not in response.text


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_digest", "D" * 64),
        ("candidate_digest", "a" * 63),
        ("gate_envelope_digest", "g" * 64),
        ("nonce_digest", "secret"),
        ("envelope_uuid", "not-a-uuid"),
    ],
)
def test_registration_begin_contract_rejects_noncanonical_authority_inputs(
    field: str, value: object
) -> None:
    payload = _registration_begin_payload()
    payload[field] = value

    with pytest.raises(ValueError):
        RegistrationBeginRequest.model_validate(payload)


def test_registration_begin_contract_requires_exact_unregister_identity() -> None:
    payload = _registration_begin_payload()
    payload["operation_kind"] = "unregister"
    payload["execution_stage_uuid"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    payload["execution_stage"] = "unregister"
    payload["execution_stage_ordinal"] = 4

    with pytest.raises(ValueError):
        RegistrationBeginRequest.model_validate(payload)

    payload["prior_register_gate_id"] = 41
    payload["prior_register_operation_uuid"] = (
        "22222222-2222-4222-8222-222222222222"
    )
    assert RegistrationBeginRequest.model_validate(payload).operation_kind == "unregister"


def test_registration_finalize_contract_accepts_only_opaque_attestation() -> None:
    value = RegistrationFinalizeRequest.model_validate(
        {"opaque_execution_attestation": "opaque"}
    )
    assert value.opaque_execution_attestation.get_secret_value() == "opaque"

    with pytest.raises(ValueError):
        RegistrationFinalizeRequest.model_validate(
            {
                "opaque_execution_attestation": "opaque",
                "outcome": "succeeded",
            }
        )


def test_registration_begin_route_returns_domain_separated_redacted_authorization(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    issued_at = datetime(2026, 7, 16, 1, 2, 3, tzinfo=UTC)
    gate = SimpleNamespace(
        id=41,
        operation_uuid="33333333-3333-4333-8333-333333333333",
        operation_kind="register",
    )
    begin = AsyncMock(
        return_value={
            "gate": gate,
            "issued_at": issued_at,
            "expires_at": issued_at + timedelta(seconds=60),
            "candidate_digest": _CANDIDATE_DIGEST,
            "gate_envelope_digest": _GATE_ENVELOPE_DIGEST,
            "dispatch_domain": DISPATCH_CAPABILITY_DOMAIN,
            "dispatch_key_id": _DISPATCH_KEY_ID,
            "media_key_id": _MEDIA_KEY_ID,
            "prior_register_operation_uuid": None,
        }
    )
    signer = AsyncMock(return_value="es256-signature")
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "begin_onnuri_registration_operation",
        begin,
    )
    monkeypatch.setattr(
        onnuri_smoke_f12,
        "get_smoke_authority_runtime",
        lambda: SimpleNamespace(
            issuer=SimpleNamespace(sign_dispatch_receipt=signer)
        ),
    )

    response = client.post(
        "/api/v1/internal/onnuri-smoke/registration/begin",
        headers=_headers(),
        json=_registration_begin_payload(),
    )

    assert response.status_code == 200
    body = response.json()
    assert "envelope_uuid" not in body
    opaque = body["opaque_authorization"]
    decoded = json.loads(
        base64.urlsafe_b64decode(opaque + "=" * (-len(opaque) % 4))
    )
    claims = decoded["claims"]
    assert decoded["algorithm"] == "ES256"
    assert decoded["verification_domain"] == (
        "recova.onnuri.smoke.registration.v1"
    )
    assert claims["transaction_count"] == 1
    assert claims["retry_count"] == 0
    assert claims["concurrency_count"] == 1
    assert claims["max_elapsed_seconds"] == 60
    assert claims["candidate_digest"] == _CANDIDATE_DIGEST
    assert claims["request_digest"] == "d" * 64
    assert claims["nonce_digest"] == "e" * 64
    assert "11111111-1111-4111-8111-111111111111" not in response.text
    begin.assert_awaited_once()


@pytest.mark.parametrize(
    "error",
    [
        "wrong_tenant",
        "wrong_candidate",
        "wrong_gate",
        "wrong_nonce",
        "wrong_request",
        "operation_replay",
        "envelope_replay",
        "unregister_before_register",
        "terminal_mutation",
        "expired_window",
    ],
)
def test_registration_authority_rejections_are_redacted(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    error: str,
) -> None:
    operation = AsyncMock(
        side_effect=TelephonyNumberInventoryConflictError(error)
    )
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "begin_onnuri_registration_operation",
        operation,
    )

    response = client.post(
        "/api/v1/internal/onnuri-smoke/registration/begin",
        headers=_headers(),
        json=_registration_begin_payload(),
    )

    assert response.status_code == 409
    assert error not in response.text
    assert _CANDIDATE_DIGEST not in response.text
    assert _GATE_ENVELOPE_DIGEST not in response.text


@pytest.mark.parametrize(
    "claim_changes",
    [
        {},
        {
            "challenge_response_wire_digest": "4" * 64,
            "challenge_status": 401,
            "response_count": 2,
            "retry_request_wire_digest": "5" * 64,
            "wire_request_count": 2,
        },
        {
            "accepted_expires_seconds": 0,
            "deregistered": True,
            "operation_kind": "unregister",
            "prior_register_gate_id": 40,
            "prior_register_operation_uuid": (
                "22222222-2222-4222-8222-222222222222"
            ),
        },
    ],
)
def test_registration_finalize_accepts_direct_and_challenge_supplier_200(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    claim_changes: dict[str, object],
) -> None:
    gate = SimpleNamespace(
        id=41,
        operation_uuid="33333333-3333-4333-8333-333333333333",
        operation_kind=str(claim_changes.get("operation_kind", "register")),
        failure_class="succeeded",
    )
    finalize = AsyncMock(return_value=(gate, False))
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "finalize_onnuri_registration_operation",
        finalize,
    )

    response = client.post(
        "/api/v1/internal/onnuri-smoke/registration/finalize",
        headers=_headers(),
        json={
            "opaque_execution_attestation": _execution_attestation(
                claim_changes=claim_changes
            )
        },
    )

    assert response.status_code == 200
    assert response.json()["outcome"] == "succeeded"
    kwargs = finalize.await_args.kwargs
    assert kwargs["outcome"] == "succeeded"
    assert kwargs["deregistered"] is (
        claim_changes.get("operation_kind") == "unregister"
    )
    assert kwargs["response_count"] == claim_changes.get("response_count", 1)
    assert kwargs["execution_attestation_key_id"] == (
        _REGISTRATION_ATTESTATION_KEY_ID
    )
    assert len(kwargs["execution_attestation_digest"]) == 64


def test_registration_finalize_exact_replay_delegates_for_db_recovery(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = SimpleNamespace(
        id=41,
        operation_uuid="33333333-3333-4333-8333-333333333333",
        operation_kind="register",
        failure_class="succeeded",
    )
    finalize = AsyncMock(return_value=(gate, True))
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "finalize_onnuri_registration_operation",
        finalize,
    )
    opaque = _execution_attestation()

    response = client.post(
        "/api/v1/internal/onnuri-smoke/registration/finalize",
        headers=_headers(),
        json={"opaque_execution_attestation": opaque},
    )

    assert response.status_code == 200
    assert response.json()["recovered"] is True
    finalize.assert_awaited_once()
def test_registration_attestation_signature_and_spki_digests_are_distinct_stable(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = SimpleNamespace(
        id=41,
        operation_uuid="33333333-3333-4333-8333-333333333333",
        operation_kind="register",
        failure_class="succeeded",
    )
    finalize = AsyncMock(return_value=(gate, False))
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "finalize_onnuri_registration_operation",
        finalize,
    )
    opaque = _execution_attestation()
    envelope = json.loads(
        base64.urlsafe_b64decode(opaque + "=" * (-len(opaque) % 4))
    )
    raw_signature = base64.urlsafe_b64decode(
        envelope["signature"] + "=" * (-len(envelope["signature"]) % 4)
    )
    assert len(raw_signature) == 64
    spki = _REGISTRATION_PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    for _ in range(2):
        response = client.post(
            "/api/v1/internal/onnuri-smoke/registration/finalize",
            headers=_headers(),
            json={"opaque_execution_attestation": opaque},
        )
        assert response.status_code == 200

    first, second = [call.kwargs for call in finalize.await_args_list]
    assert first["execution_attestation_signature_digest"] == hashlib.sha256(
        raw_signature
    ).hexdigest()
    assert first["execution_attestation_key_digest"] == hashlib.sha256(spki).hexdigest()
    assert first["execution_attestation_signature_digest"] != first[
        "execution_attestation_key_digest"
    ]
    assert first["execution_attestation_signature_digest"] == second[
        "execution_attestation_signature_digest"
    ]
    assert first["execution_attestation_key_digest"] == second[
        "execution_attestation_key_digest"
    ]



@pytest.mark.parametrize(
    ("attestation_factory", "claim_changes"),
    [
        (
            lambda: _execution_attestation(
                key=ec.generate_private_key(ec.SECP256R1())
            ),
            None,
        ),
        (
            lambda: _execution_attestation(domain="wrong.execution.domain"),
            None,
        ),
        (
            _execution_attestation,
            {"response_count": 2},
        ),
        (
            _execution_attestation,
            {"initial_request_wire_digest": None},
        ),
        (
            _execution_attestation,
            {"accepted_expires_seconds": None},
        ),
        (
            _execution_attestation,
            {
                "accepted_expires_seconds": 1,
                "deregistered": True,
                "operation_kind": "unregister",
                "prior_register_gate_id": 40,
                "prior_register_operation_uuid": (
                    "22222222-2222-4222-8222-222222222222"
                ),
            },
        ),
        (
            _execution_attestation,
            {
                "started_at": "2026-07-16T00:00:00.000Z",
                "completed_at": "2026-07-16T00:01:00.001Z",
            },
        ),
    ],
)
def test_registration_finalize_rejects_untrusted_or_ambiguous_evidence_before_db(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    attestation_factory: object,
    claim_changes: dict[str, object] | None,
) -> None:
    finalize = AsyncMock()
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "finalize_onnuri_registration_operation",
        finalize,
    )
    factory = attestation_factory
    opaque = (
        factory()
        if claim_changes is None
        else factory(claim_changes=claim_changes)
    )

    response = client.post(
        "/api/v1/internal/onnuri-smoke/registration/finalize",
        headers=_headers(),
        json={"opaque_execution_attestation": opaque},
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "onnuri_smoke_f12_operation_rejected"}
    finalize.assert_not_awaited()


def test_registration_finalize_rejects_noncanonical_envelope_before_db(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    finalize = AsyncMock()
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "finalize_onnuri_registration_operation",
        finalize,
    )
    opaque = _execution_attestation()
    raw = base64.urlsafe_b64decode(opaque + "=" * (-len(opaque) % 4))
    noncanonical = base64.urlsafe_b64encode(raw + b"\n").rstrip(b"=").decode()

    response = client.post(
        "/api/v1/internal/onnuri-smoke/registration/finalize",
        headers=_headers(),
        json={"opaque_execution_attestation": noncanonical},
    )

    assert response.status_code == 409
    finalize.assert_not_awaited()


_EXECUTION_UUID = "11111111-1111-4111-8111-111111111111"
_STAGE_UUID = "22222222-2222-4222-8222-222222222222"
_ACCOUNT_UUID = "33333333-3333-4333-8333-333333333333"
_APPLICATION_UUID = "44444444-4444-4444-8444-444444444444"
_RUN_UUID = "55555555-5555-4555-8555-555555555555"
_ATTEMPT_UUID = "66666666-6666-4666-8666-666666666666"
_STOCK_UUID = "77777777-7777-4777-8777-777777777777"
_IDEMPOTENCY_UUID = "88888888-8888-4888-8888-888888888888"
_STOCK_DIGEST = hashlib.sha256(_STOCK_UUID.encode("ascii")).hexdigest()
_IDEMPOTENCY_DIGEST = hashlib.sha256(_IDEMPOTENCY_UUID.encode("ascii")).hexdigest()


def _execution_binding() -> dict[str, object]:
    return {
        "organization_id": 7,
        "execution_seal_uuid": _EXECUTION_UUID,
        "execution_nonce_digest": "1" * 64,
        "candidate_digest": _CANDIDATE_DIGEST,
        "gate_envelope_digest": _GATE_ENVELOPE_DIGEST,
    }


def _execution_seal_payload() -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        **_execution_binding(),
        "schema_version": "recova-g008-execution-seal-v1",
        "destination_hmac_digest": "d" * 64,
        "stages": ["register", "outbound_call", "inbound_call", "unregister"],
        "live_window_starts_at": now.isoformat(),
        "live_window_expires_at": (now + timedelta(minutes=5)).isoformat(),
        "retry_count": 0,
        "concurrency_count": 1,
        "call_deadline_seconds": 60,
        "reserved_inbound_did_digest": "2" * 64,
        "reserved_inbound_caller_digest": "3" * 64,
        "policy_digest": "9" * 64,
    }


def _execution_seal_receipt(
    *, state: str = "sealed", terminal_class: str | None = None
) -> dict[str, object]:
    payload = _execution_seal_payload()
    payload.update(
        {
            "state": state,
            "sealed_at": datetime.now(UTC).isoformat(),
            "completed_at": (
                datetime.now(UTC).isoformat() if state == "completed" else None
            ),
            "contained_at": (
                datetime.now(UTC).isoformat() if state == "contained" else None
            ),
            "terminal_class": terminal_class,
            "final_evidence_digest": "e" * 64 if state == "completed" else None,
            "final_evidence_signature_digest": (
                "f" * 64 if state == "completed" else None
            ),
            "final_evidence_key_digest": "0" * 64 if state == "completed" else None,
        }
    )
    return payload


def _stage_receipt(
    stage: str, ordinal: int, *, state: str = "started"
) -> dict[str, object]:
    return {
        **_execution_binding(),
        "stage_uuid": _STAGE_UUID,
        "stage": stage,
        "ordinal": ordinal,
        "state": state,
        "started_at": datetime.now(UTC).isoformat(),
        "terminal_at": datetime.now(UTC).isoformat() if state != "started" else None,
        "terminal_class": (
            {
                "register": "registered",
                "outbound_call": "call_completed",
                "inbound_call": "inbound_bound",
                "unregister": "unregistered",
            }[stage]
            if state != "started"
            else None
        ),
        "evidence_digest": "e" * 64 if state != "started" else None,
        "evidence_signature_digest": "f" * 64 if state != "started" else None,
        "evidence_key_digest": "0" * 64 if state != "started" else None,
        "registration_gate_id": None,
        "registration_operation_uuid": None,
        "prior_register_gate_id": None,
        "recovered": False,
    }


def test_execution_contract_forbids_policy_order_authority_and_raw_fields() -> None:
    valid = _execution_seal_payload()
    assert ExecutionSealRequest.model_validate(valid).retry_count == 0

    invalid_mutations = [
        {"stages": ["outbound_call", "register", "inbound_call", "unregister"]},
        {"retry_count": 1},
        {"concurrency_count": 2},
        {"call_deadline_seconds": 59},
        {"destination": "+821012345678"},
        {"sip_uri": "sip:user@example.invalid"},
    ]
    for mutation in invalid_mutations:
        candidate = {**valid, **mutation}
        with pytest.raises(ValueError):
            ExecutionSealRequest.model_validate(candidate)

    with pytest.raises(ValueError):
        ExecutionStageStartRequest.model_validate(
            {**_execution_binding(), "stage": "inbound_call", "ordinal": 2}
        )
    finalize = {
        **_execution_binding(),
        "stage": "outbound_call",
        "ordinal": 2,
        "stage_state": "succeeded",
        "terminal_class": "call_completed",
    }
    assert ExecutionStageFinalizeRequest.model_validate(finalize).ordinal == 2
    for caller_evidence_field in (
        "evidence_digest",
        "evidence_signature_digest",
        "evidence_key_digest",
    ):
        with pytest.raises(ValueError):
            ExecutionStageFinalizeRequest.model_validate(
                {**finalize, caller_evidence_field: "e" * 64}
            )

    for stage, ordinal, terminal_class in (
        ("register", 1, "registered"),
        ("unregister", 4, "unregistered"),
    ):
        with pytest.raises(ValueError, match="require signed attestation"):
            ExecutionStageFinalizeRequest.model_validate(
                {
                    **_execution_binding(),
                    "stage": stage,
                    "ordinal": ordinal,
                    "stage_state": "succeeded",
                    "terminal_class": terminal_class,
                }
            )


def test_execution_and_atomic_inbound_routes_delegate_exact_validated_contract(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    seal = AsyncMock(return_value=_execution_seal_receipt())
    start = AsyncMock(return_value=_stage_receipt("register", 1))
    finalize_stage = AsyncMock(
        return_value=_stage_receipt("outbound_call", 2, state="succeeded")
    )
    registration_operation_uuid = "33333333-3333-4333-8333-333333333333"
    status_receipt = _stage_receipt("register", 1, state="succeeded")
    status_receipt.update(
        {
            "registration_gate_id": 17,
            "registration_operation_uuid": registration_operation_uuid,
            "recovered": True,
        }
    )
    stage_status = AsyncMock(return_value=status_receipt)
    finalize_evidence = AsyncMock(return_value=_execution_seal_receipt(state="completed"))
    contain = AsyncMock(
        return_value=_execution_seal_receipt(
            state="contained", terminal_class="authority_unavailable"
        )
    )
    issued_at = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
    authority_deadline_at = issued_at + timedelta(seconds=60)
    bind_receipt_uuid = "99999999-9999-4999-8999-999999999999"
    signature = "A" * 86
    claims = {
        "schema": "recova-g008-inbound-bind-receipt-v1",
        "domain": "recova.onnuri.smoke.g008.inbound-bind.v1",
        "algorithm": "ES256",
        "organization_id": 7,
        "execution_seal_uuid": _EXECUTION_UUID,
        "execution_stage_uuid": _STAGE_UUID,
        "account_uuid": _ACCOUNT_UUID,
        "application_uuid": _APPLICATION_UUID,
        "stock_call_uuid": _STOCK_UUID,
        "stock_call_id_digest": _STOCK_DIGEST,
        "did_digest": "2" * 64,
        "caller_digest": "3" * 64,
        "direction": "inbound",
        "run_uuid": _RUN_UUID,
        "attempt_uuid": _ATTEMPT_UUID,
        "idempotency_uuid": _IDEMPOTENCY_UUID,
        "bind_receipt_uuid": bind_receipt_uuid,
        "request_digest": "4" * 64,
        "candidate_digest": "7" * 64,
        "gate_envelope_digest": "8" * 64,
        "issued_at": issued_at.isoformat(),
        "authority_deadline_at": authority_deadline_at.isoformat(),
    }
    unsigned_receipt = {
        "schema_version": "recova-g008-inbound-bind-receipt-v1",
        "algorithm": "ES256",
        "verification_domain": "recova.onnuri.smoke.g008.inbound-bind.v1",
        "key_id": _DISPATCH_KEY_ID,
        "claims": claims,
    }
    bind_receipt_digest = hashlib.sha256(
        canonical_json_bytes(unsigned_receipt)
    ).hexdigest()
    bind_receipt_signature_digest = hashlib.sha256(signature.encode()).hexdigest()
    claim_response = {
        "context": {
            "organization_id": 7,
            "execution_seal_uuid": _EXECUTION_UUID,
            "stage_uuid": _STAGE_UUID,
            "stage": "inbound_call",
            "ordinal": 3,
            "account_id": _ACCOUNT_UUID,
            "application_id": _APPLICATION_UUID,
            "run_uuid": _RUN_UUID,
            "attempt_uuid": _ATTEMPT_UUID,
            "idempotency_key": _IDEMPOTENCY_UUID,
            "bind_receipt_uuid": bind_receipt_uuid,
            "stock_call_id_digest": _STOCK_DIGEST,
            "direction": "inbound",
            "authority_deadline_at": authority_deadline_at.isoformat(),
            "did_digest": "2" * 64,
            "caller_digest": "3" * 64,
            "request_digest": "4" * 64,
            "candidate_digest": "7" * 64,
            "gate_envelope_digest": "8" * 64,
            "bound_at": issued_at.isoformat(),
            "bind_receipt_digest": bind_receipt_digest,
            "bind_receipt_signature_digest": bind_receipt_signature_digest,
            "bind_receipt_key_fingerprint": "9" * 64,
            "bind_receipt_key_id": _DISPATCH_KEY_ID,
        },
        "bind_receipt": {
            **unsigned_receipt,
            "signature": signature,
        },
        "recovered": False,
    }
    claim = AsyncMock(return_value=claim_response)
    for name, operation in (
        ("create_execution_seal", seal),
        ("start_execution_stage", start),
        ("finalize_execution_stage", finalize_stage),
        ("execution_stage_status", stage_status),
        ("finalize_execution_evidence", finalize_evidence),
        ("contain_execution", contain),
        ("claim_reserved_inbound_and_bind", claim),
    ):
        monkeypatch.setattr(onnuri_smoke_f12, name, operation)

    assert client.post(
        "/api/v1/internal/onnuri-smoke/execution/seal",
        headers=_headers(),
        json=_execution_seal_payload(),
    ).status_code == 200
    assert client.post(
        "/api/v1/internal/onnuri-smoke/execution/stage/start",
        headers=_headers(),
        json={**_execution_binding(), "stage": "register", "ordinal": 1},
    ).status_code == 200
    stage_finalize_payload = {
        **_execution_binding(),
        "stage": "outbound_call",
        "ordinal": 2,
        "stage_state": "succeeded",
        "terminal_class": "call_completed",
    }
    assert client.post(
        "/api/v1/internal/onnuri-smoke/execution/stage/finalize",
        headers=_headers(),
        json=stage_finalize_payload,
    ).status_code == 200
    finalize_stage.assert_awaited_once_with(
        **ExecutionStageFinalizeRequest.model_validate(
            stage_finalize_payload
        ).model_dump()
    )
    status_result = client.post(
        "/api/v1/internal/onnuri-smoke/execution/stage/status",
        headers=_headers(),
        json={**_execution_binding(), "stage": "register", "ordinal": 1},
    )
    assert status_result.status_code == 200
    assert status_result.json()["registration_gate_id"] == 17
    assert (
        status_result.json()["registration_operation_uuid"]
        == registration_operation_uuid
    )
    assert status_result.json()["recovered"] is True
    evidence_payload = _execution_binding()
    assert client.post(
        "/api/v1/internal/onnuri-smoke/execution/finalize-evidence",
        headers=_headers(),
        json=evidence_payload,
    ).status_code == 200
    assert client.post(
        "/api/v1/internal/onnuri-smoke/execution/contain",
        headers=_headers(),
        json={
            **_execution_binding(),
            "containment_class": "authority_unavailable",
        },
    ).status_code == 200
    claim_payload = {
        "organization_id": 7,
        "account_id": _ACCOUNT_UUID,
        "application_id": _APPLICATION_UUID,
        "stock_call_id": _STOCK_UUID,
        "did_digest": "2" * 64,
        "caller_digest": "3" * 64,
    }
    claim_result = client.post(
        "/api/v1/internal/onnuri-smoke/claim-reserved-inbound-and-bind",
        headers=_headers(),
        json=claim_payload,
    )
    assert claim_result.status_code == 200
    assert claim_result.json() == ClaimReservedInboundAndBindResponse.model_validate(
        claim_response
    ).model_dump(mode="json", by_alias=True)
    claim.assert_awaited_once_with(
        organization_id=7,
        account_uuid=UUID(_ACCOUNT_UUID),
        application_uuid=UUID(_APPLICATION_UUID),
        stock_call_uuid=UUID(_STOCK_UUID),
        did_digest="2" * 64,
        caller_digest="3" * 64,
    )

    validated_claim = ClaimReservedInboundAndBindRequest.model_validate(claim_payload)
    assert validated_claim.model_dump() == {
        "organization_id": 7,
        "account_id": UUID(_ACCOUNT_UUID),
        "application_id": UUID(_APPLICATION_UUID),
        "stock_call_id": UUID(_STOCK_UUID),
        "did_digest": "2" * 64,
        "caller_digest": "3" * 64,
    }
    for forbidden_field, forbidden_value in (
        ("execution_seal_uuid", _EXECUTION_UUID),
        ("stage_uuid", _STAGE_UUID),
        ("stage", "inbound_call"),
        ("ordinal", 3),
        ("run_uuid", _RUN_UUID),
        ("attempt_uuid", _ATTEMPT_UUID),
        ("idempotency_key", _IDEMPOTENCY_UUID),
        ("request_digest", "4" * 64),
        ("bind_receipt_digest", "5" * 64),
        ("bind_receipt_signature_digest", "6" * 64),
    ):
        with pytest.raises(ValueError):
            ClaimReservedInboundAndBindRequest.model_validate(
                claim_payload | {forbidden_field: forbidden_value}
            )


@pytest.mark.parametrize(
    "case",
    [
        "replay",
        "order",
        "expired",
        "cross_tenant",
        "binding_mismatch",
        "duplicate",
        "terminal",
    ],
)
def test_execution_failures_are_redacted_and_have_no_followup_transition(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    rejected = AsyncMock(
        side_effect=onnuri_smoke_f12.F12ServiceError(
            "onnuri_smoke_f12_operation_rejected", 409
        )
    )
    followup = AsyncMock()
    monkeypatch.setattr(onnuri_smoke_f12, "start_execution_stage", rejected)
    monkeypatch.setattr(onnuri_smoke_f12, "finalize_execution_stage", followup)

    payload = {**_execution_binding(), "stage": "register", "ordinal": 1}
    payload["execution_nonce_digest"] = hashlib.sha256(case.encode()).hexdigest()
    response = client.post(
        "/api/v1/internal/onnuri-smoke/execution/stage/start",
        headers=_headers(),
        json=payload,
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "onnuri_smoke_f12_operation_rejected"}
    assert _EXECUTION_UUID not in response.text
    rejected.assert_awaited_once()
    followup.assert_not_awaited()
def test_recovered_inbound_receipt_uses_committed_bound_at() -> None:
    issued_at = datetime(2026, 7, 18, 1, 2, 3, tzinfo=UTC)
    bound_at = issued_at + timedelta(seconds=2)
    signed_receipt = {
        "claims": {
            "organization_id": 7,
            "execution_seal_uuid": _EXECUTION_UUID,
            "execution_stage_uuid": _STAGE_UUID,
            "account_uuid": _ACCOUNT_UUID,
            "application_uuid": _APPLICATION_UUID,
            "run_uuid": _RUN_UUID,
            "attempt_uuid": _ATTEMPT_UUID,
            "idempotency_uuid": _IDEMPOTENCY_UUID,
            "bind_receipt_uuid": "55555555-5555-4555-8555-555555555555",
            "stock_call_id_digest": _STOCK_DIGEST,
            "authority_deadline_at": issued_at + timedelta(seconds=60),
            "did_digest": "2" * 64,
            "caller_digest": "3" * 64,
            "request_digest": "4" * 64,
            "candidate_digest": "7" * 64,
            "gate_envelope_digest": "8" * 64,
            "issued_at": issued_at,
        }
    }
    row = {
        "bound_at": bound_at,
        "recovered": True,
        "receipt_unsigned_digest": "a" * 64,
        "receipt_signature_digest": "b" * 64,
        "receipt_spki_digest": "c" * 64,
        "receipt_key_id": _DISPATCH_KEY_ID,
    }

    receipt = onnuri_smoke_f12._inbound_claim_receipt(row, signed_receipt)

    assert receipt["recovered"] is True
    assert receipt["context"]["bound_at"] == bound_at
    assert receipt["context"]["bound_at"] != issued_at

_EXECUTION_EVIDENCE_KEY_ID = "execution-evidence-v1"


def _locked_execution_projection(
    now: datetime, *, states: tuple[str, str, str, str]
) -> dict[str, object]:
    stages = [
        {
            "stage_uuid": f"22222222-2222-4222-8222-22222222222{ordinal}",
            "stage": stage,
            "ordinal": ordinal,
            "state": state,
            "started_at": now,
            "terminal_class": "call_completed" if state == "succeeded" else None,
            "evidence_digest": str(ordinal) * 64 if state == "succeeded" else None,
            "evidence_signature_digest": str(ordinal + 1) * 64
            if state == "succeeded"
            else None,
            "evidence_key_digest": str(ordinal + 2) * 64
            if state == "succeeded"
            else None,
            "evidence_key_id": _EXECUTION_EVIDENCE_KEY_ID
            if state == "succeeded"
            else None,
            "finalized_at": now if state == "succeeded" else None,
        }
        for ordinal, (stage, state) in enumerate(
            zip(
                ("register", "outbound_call", "inbound_call", "unregister"),
                states,
                strict=True,
            ),
            start=1,
        )
    ]
    return {
        **_execution_binding(),
        "schema_version": "recova-g008-execution-seal-v1",
        "destination_hmac_digest": "d" * 64,
        "reserved_inbound_did_digest": "2" * 64,
        "reserved_inbound_caller_digest": "3" * 64,
        "policy_digest": "9" * 64,
        "retry_count": 0,
        "concurrency_count": 1,
        "call_deadline_seconds": 60,
        "state": "running",
        "live_window_starts_at": now,
        "live_window_expires_at": now + timedelta(minutes=5),
        "sealed_at": now - timedelta(seconds=1),
        "started_at": now,
        "containment_class": None,
        "containment_evidence_digest": None,
        "containment_evidence_signature_digest": None,
        "containment_evidence_key_digest": None,
        "containment_evidence_key_id": None,
        "contained_at": None,
        "final_evidence_digest": None,
        "final_evidence_signature_digest": None,
        "final_evidence_key_digest": None,
        "final_evidence_key_id": None,
        "completed_at": None,
        "failed_at": None,
        "stages": stages,
    }


def _aggregate_ingredients(
    now: datetime, *, kind: str = "completion"
) -> dict[str, object]:
    return {
        "evidence_kind": kind,
        "evidence_at": now,
        "containment_class": None,
        "active_stage_ordinal": None,
        "seal": _locked_execution_projection(
            now, states=("succeeded", "succeeded", "succeeded", "succeeded")
        ),
        "registration_linkage": [
            {
                "ordinal": 1,
                "registration_gate_id": 17,
                "operation_uuid": "99999999-9999-4999-8999-999999999991",
                "operation_kind": "register",
                "unregisters_gate_id": None,
                "state": "completed",
                "request_digest": "a" * 64,
                "terminal_at": now,
                "execution_attestation_digest": "b" * 64,
                "execution_attestation_signature_digest": "c" * 64,
                "execution_attestation_key_digest": "d" * 64,
                "execution_attestation_key_id": "registration-attestation-v1",
                "execution_attested_at": now,
            },
            {
                "ordinal": 4,
                "registration_gate_id": 18,
                "operation_uuid": "99999999-9999-4999-8999-999999999994",
                "operation_kind": "unregister",
                "unregisters_gate_id": 17,
                "state": "completed",
                "request_digest": "e" * 64,
                "terminal_at": now,
                "execution_attestation_digest": "f" * 64,
                "execution_attestation_signature_digest": "0" * 64,
                "execution_attestation_key_digest": "1" * 64,
                "execution_attestation_key_id": "registration-attestation-v1",
                "execution_attested_at": now,
            },
        ],
    }


def test_execution_evidence_envelope_is_exact_canonical_locked_projection() -> None:
    now = datetime(2026, 7, 18, 1, 2, 3, 456789, tzinfo=UTC)
    envelope = onnuri_smoke_f12._execution_evidence_envelope(
        _aggregate_ingredients(now), key_id=_EXECUTION_EVIDENCE_KEY_ID
    )
    canonical = canonical_json_bytes(envelope)

    assert canonical == json.dumps(
        envelope,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    assert set(envelope) == {
        "algorithm",
        "algorithm_policy_id",
        "claims",
        "contract_version",
        "key_id",
        "signed_at",
        "verification_domain",
    }
    assert envelope["verification_domain"] == (
        "recova.onnuri.smoke.g008.execution-evidence.v1"
    )
    assert envelope["signed_at"] == "2026-07-18T01:02:03.456789Z"
    assert envelope["claims"]["kind"] == "completed"
    assert [row["ordinal"] for row in envelope["claims"]["stage_receipts"]] == [
        1,
        2,
        3,
        4,
    ]
    assert [
        (
            row["ordinal"],
            row["operation_kind"],
            row["unregisters_gate_id"],
        )
        for row in envelope["claims"]["registration_linkage"]
    ] == [(1, "register", None), (4, "unregister", 17)]
    assert not {
        "stages",
        "final_evidence_digest",
        "final_evidence_signature_digest",
        "final_evidence_key_digest",
        "final_evidence_key_id",
        "containment_evidence_digest",
        "containment_evidence_signature_digest",
        "containment_evidence_key_digest",
        "containment_evidence_key_id",
    } & envelope["claims"]["seal"].keys()


@pytest.mark.parametrize(
    ("stage_state", "terminal_class"),
    [
        ("succeeded", "call_completed"),
        ("failed", "call_failed"),
    ],
)
@pytest.mark.asyncio
async def test_stage_evidence_signs_exact_terminal_projection(
    monkeypatch: pytest.MonkeyPatch,
    stage_state: str,
    terminal_class: str,
) -> None:
    now = datetime(2026, 7, 18, 1, 2, 3, 456789, tzinfo=UTC)
    private_key = ec.generate_private_key(ec.SECP256R1())

    async def sign(canonical: bytes) -> SignedExecutionEvidence:
        der = private_key.sign(canonical, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return SignedExecutionEvidence(
            signature=r.to_bytes(32, "big") + s.to_bytes(32, "big"),
            key_id=_EXECUTION_EVIDENCE_KEY_ID,
            algorithm_policy_id="gcp-kms-ecdsa-p256-sha256-v1",
            public_key_digest="a" * 64,
        )

    projection = _locked_execution_projection(
        now, states=("succeeded", "started", "pending", "pending")
    )
    ingredients = {
        "evidence_kind": "stage",
        "evidence_at": now,
        "seal": projection,
        "stage_ordinal": 2,
        "stage_state": stage_state,
        "terminal_class": terminal_class,
        "registration_linkage": [],
    }
    monkeypatch.setenv(
        "ONNURI_SMOKE_EXECUTION_EVIDENCE_KEY_ID", _EXECUTION_EVIDENCE_KEY_ID
    )
    monkeypatch.setattr(
        onnuri_smoke_f12,
        "get_smoke_authority_runtime",
        lambda: SimpleNamespace(
            execution_evidence_signer=SimpleNamespace(sign=sign)
        ),
    )

    evidence = await onnuri_smoke_f12._build_execution_evidence(ingredients)
    envelope = json.loads(evidence["canonical_evidence"])
    raw_signature = evidence["evidence_signature"]
    claims = envelope["claims"]

    assert claims["state"] == stage_state
    assert claims["terminal_class"] == terminal_class
    assert claims["finalized_at"] == "2026-07-18T01:02:03.456789Z"
    assert projection["stages"][1]["state"] == "started"
    assert len(raw_signature) == 64
    private_key.public_key().verify(
        encode_dss_signature(
            int.from_bytes(raw_signature[:32], "big"),
            int.from_bytes(raw_signature[32:], "big"),
        ),
        evidence["canonical_evidence"],
        ec.ECDSA(hashes.SHA256()),
    )
    assert evidence["evidence_digest"] == hashlib.sha256(
        evidence["canonical_evidence"]
    ).hexdigest()
    assert evidence["evidence_signature_digest"] == hashlib.sha256(
        raw_signature
    ).hexdigest()


@pytest.mark.parametrize(
    "model, extra",
    [
        (ExecutionEvidenceFinalizeRequest, {"final_evidence_digest": "e" * 64}),
        (ExecutionContainRequest, {"containment_evidence_digest": "e" * 64}),
        (ExecutionContainRequest, {"signature": "raw-signature"}),
    ],
)
def test_terminal_execution_contract_forbids_caller_evidence(
    model: type, extra: dict[str, str]
) -> None:
    payload = _execution_binding()
    if model is ExecutionContainRequest:
        payload["containment_class"] = "authority_unavailable"
    with pytest.raises(ValueError):
        model.model_validate({**payload, **extra})


@pytest.mark.asyncio
async def test_finalize_evidence_duplicate_signs_once_and_never_returns_raw_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 7, 18, 1, 2, 3, 456789, tzinfo=UTC)
    signed_bytes: list[bytes] = []

    async def sign(canonical: bytes) -> SignedExecutionEvidence:
        signed_bytes.append(canonical)
        return SignedExecutionEvidence(
            signature=b"s" * 64,
            key_id=_EXECUTION_EVIDENCE_KEY_ID,
            algorithm_policy_id="gcp-kms-ecdsa-p256-sha256-v1",
            public_key_digest="a" * 64,
        )

    persisted = _locked_execution_projection(
        now, states=("succeeded", "succeeded", "succeeded", "succeeded")
    )
    persisted.update(
        {
            "state": "completed",
            "completed_at": now,
            "final_evidence_digest": "b" * 64,
            "final_evidence_signature_digest": hashlib.sha256(b"s" * 64).hexdigest(),
            "final_evidence_key_digest": "a" * 64,
            "final_evidence_key_id": _EXECUTION_EVIDENCE_KEY_ID,
        }
    )
    committed = False

    async def finalize(payload, *, evidence_builder):
        nonlocal committed
        assert payload == {
            **_execution_binding(),
            "execution_seal_uuid": _EXECUTION_UUID,
        }
        if not committed:
            await evidence_builder(_aggregate_ingredients(now))
            committed = True
        return persisted

    monkeypatch.setenv(
        "ONNURI_SMOKE_EXECUTION_EVIDENCE_KEY_ID", _EXECUTION_EVIDENCE_KEY_ID
    )
    monkeypatch.setattr(
        onnuri_smoke_f12,
        "get_smoke_authority_runtime",
        lambda: SimpleNamespace(
            execution_evidence_signer=SimpleNamespace(sign=sign)
        ),
    )
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "finalize_execution_evidence",
        finalize,
    )

    first = await onnuri_smoke_f12.finalize_execution_evidence(
        **_execution_binding()
    )
    duplicate = await onnuri_smoke_f12.finalize_execution_evidence(
        **_execution_binding()
    )

    assert duplicate == first
    assert len(signed_bytes) == 1
    assert first["final_evidence_key_id"] == _EXECUTION_EVIDENCE_KEY_ID
    assert "signature" not in first


@pytest.mark.asyncio
async def test_execution_evidence_signer_failure_maps_503_without_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 7, 18, 1, 2, 3, 456789, tzinfo=UTC)
    transitions = 0

    async def sign(canonical: bytes) -> SignedExecutionEvidence:
        del canonical
        raise RuntimeError("signer unavailable")

    async def finalize(payload, *, evidence_builder):
        nonlocal transitions
        del payload
        await evidence_builder(_aggregate_ingredients(now))
        transitions += 1
        raise AssertionError("transition must follow successful signing")

    monkeypatch.setenv(
        "ONNURI_SMOKE_EXECUTION_EVIDENCE_KEY_ID", _EXECUTION_EVIDENCE_KEY_ID
    )
    monkeypatch.setattr(
        onnuri_smoke_f12,
        "get_smoke_authority_runtime",
        lambda: SimpleNamespace(
            execution_evidence_signer=SimpleNamespace(sign=sign)
        ),
    )
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "finalize_execution_evidence",
        finalize,
    )

    with pytest.raises(onnuri_smoke_f12.F12ServiceError) as raised:
        await onnuri_smoke_f12.finalize_execution_evidence(**_execution_binding())

    assert raised.value.status_code == 503
    assert transitions == 0


@pytest.mark.asyncio
async def test_containment_signs_active_stage_then_aggregate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 7, 18, 1, 2, 3, 456789, tzinfo=UTC)
    signed_claim_kinds: list[str] = []

    async def sign(canonical: bytes) -> SignedExecutionEvidence:
        signed_claim_kinds.append(json.loads(canonical)["claims"]["kind"])
        return SignedExecutionEvidence(
            signature=bytes([len(signed_claim_kinds)]) * 64,
            key_id=_EXECUTION_EVIDENCE_KEY_ID,
            algorithm_policy_id="gcp-kms-ecdsa-p256-sha256-v1",
            public_key_digest="a" * 64,
        )

    async def contain(payload, *, evidence_builder):
        assert set(payload) == {
            "organization_id",
            "execution_seal_uuid",
            "execution_nonce_digest",
            "candidate_digest",
            "gate_envelope_digest",
            "containment_class",
        }
        stage_projection = _locked_execution_projection(
            now, states=("succeeded", "started", "pending", "pending")
        )
        await evidence_builder(
            {
                "evidence_kind": "stage_containment",
                "evidence_at": now,
                "seal": stage_projection,
                "stage_ordinal": 2,
                "stage_state": "contained",
                "terminal_class": payload["containment_class"],
                "registration_linkage": [],
            }
        )
        aggregate = _aggregate_ingredients(now, kind="containment")
        aggregate["containment_class"] = payload["containment_class"]
        aggregate["active_stage_ordinal"] = 2
        aggregate_stage = aggregate["seal"]["stages"][1]
        aggregate_stage.update(
            {
                "state": "contained",
                "terminal_class": payload["containment_class"],
                "evidence_digest": "d" * 64,
                "evidence_signature_digest": "e" * 64,
                "evidence_key_digest": "a" * 64,
                "evidence_key_id": _EXECUTION_EVIDENCE_KEY_ID,
                "finalized_at": now,
            }
        )
        await evidence_builder(aggregate)
        persisted = aggregate["seal"]
        persisted.update(
            {
                "state": "contained",
                "containment_class": payload["containment_class"],
                "contained_at": now,
                "containment_evidence_digest": "b" * 64,
                "containment_evidence_signature_digest": "c" * 64,
                "containment_evidence_key_digest": "a" * 64,
                "containment_evidence_key_id": _EXECUTION_EVIDENCE_KEY_ID,
            }
        )
        return persisted

    monkeypatch.setenv(
        "ONNURI_SMOKE_EXECUTION_EVIDENCE_KEY_ID", _EXECUTION_EVIDENCE_KEY_ID
    )
    monkeypatch.setattr(
        onnuri_smoke_f12,
        "get_smoke_authority_runtime",
        lambda: SimpleNamespace(
            execution_evidence_signer=SimpleNamespace(sign=sign)
        ),
    )
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "contain_execution",
        contain,
    )

    receipt = await onnuri_smoke_f12.contain_execution(
        **_execution_binding(), containment_class="authority_unavailable"
    )

    assert signed_claim_kinds == ["stage_containment", "contained"]
    assert receipt["containment_evidence_key_id"] == _EXECUTION_EVIDENCE_KEY_ID
    assert "signature" not in receipt


def _nonce_consume_payload(*, organization_id: int = 7) -> dict[str, object]:
    return {
        "organization_id": organization_id,
        "execution_seal_uuid": "00000000-0000-4000-8000-000000000101",
        "execution_nonce_digest": "1" * 64,
        "candidate_digest": "2" * 64,
        "gate_envelope_digest": "3" * 64,
        "trusted_keyset_digest": onnuri_smoke_f12._G008_TRUSTED_KEYSET_DIGEST,
    }


def test_nonce_consume_route_returns_exact_signed_redacted_receipt(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _nonce_consume_payload()
    receipt_payload = {
        "kind": "nonce_consumption",
        **payload,
        "state": "consumed",
        "pre_existing": False,
    }
    operation = AsyncMock(
        return_value={
            "payload": receipt_payload,
            "signature": {
                "algorithm": "Ed25519",
                "key_id": "recova-g008-authority-v1",
                "value": base64.b64encode(b"\0" * 64).decode("ascii"),
            },
        }
    )
    monkeypatch.setattr(onnuri_smoke_f12, "consume_execution_nonce", operation)

    response = client.post(
        "/api/v1/internal/onnuri-smoke/execution/nonce/consume",
        headers=_headers(),
        json=payload,
    )

    assert response.status_code == 200
    assert response.json()["payload"] == receipt_payload
    operation.assert_awaited_once()


def test_nonce_consume_cross_tenant_is_rejected_without_transition(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation = AsyncMock()
    monkeypatch.setattr(onnuri_smoke_f12, "consume_execution_nonce", operation)

    response = client.post(
        "/api/v1/internal/onnuri-smoke/execution/nonce/consume",
        headers=_headers(),
        json=_nonce_consume_payload(organization_id=8),
    )

    assert response.status_code == 403
    operation.assert_not_awaited()




def test_emergency_unregister_only_mints_linked_cleanup_authorization(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = {
        "organization_id": 7,
        "envelope_uuid": "00000000-0000-4000-8000-000000000201",
        "request_digest": "4" * 64,
        "candidate_digest": "5" * 64,
        "gate_envelope_digest": "6" * 64,
        "nonce_digest": "7" * 64,
        "execution_seal_uuid": "00000000-0000-4000-8000-000000000202",
        "execution_nonce_digest": "8" * 64,
        "execution_stage_uuid": "00000000-0000-4000-8000-000000000203",
        "prior_register_gate_id": 41,
        "prior_register_operation_uuid": "00000000-0000-4000-8000-000000000204",
    }
    authorization = {
        "registration_gate_id": 42,
        "operation_uuid": "00000000-0000-4000-8000-000000000205",
        "operation_kind": "unregister",
        "envelope_digest": "9" * 64,
        "expires_at": "2026-07-18T12:00:00Z",
        "opaque_authorization": "signed-cleanup-authorization",
    }
    operation = AsyncMock(return_value=authorization)
    monkeypatch.setattr(onnuri_smoke_f12, "emergency_unregister", operation)

    response = client.post(
        "/api/v1/internal/onnuri-smoke/registration/emergency-unregister",
        headers=_headers(),
        json=payload,
    )

    assert response.status_code == 200
    assert response.json()["operation_kind"] == "unregister"
    assert "deregistered" not in response.json()
    called = operation.await_args.kwargs
    assert called == {
        **payload,
        "envelope_uuid": UUID(payload["envelope_uuid"]),
        "execution_seal_uuid": UUID(payload["execution_seal_uuid"]),
        "execution_stage_uuid": UUID(payload["execution_stage_uuid"]),
        "prior_register_operation_uuid": UUID(
            payload["prior_register_operation_uuid"]
        ),
    }

@pytest.mark.asyncio
async def test_route_capability_requires_tenant_scoped_resolver_before_signing_or_persistence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    context = BoundCallContext(
        organization_id=7,
        account_id="account-a",
        application_id="application-a",
        run_id="run-a",
        attempt_id="attempt-a",
        direction="outbound",
        authority_deadline=now + timedelta(seconds=60),
        candidate_digest="b" * 64,
        gate_envelope_digest="c" * 64,
    )
    values = {
        "context": context,
        "idempotency_key": _IDEMPOTENCY_KEY,
        "request_digest": _DIGEST,
        "route_profile_digest": "d" * 64,
        "route_evidence_handle": "opaque-route-evidence-handle",
    }
    signer = AsyncMock(return_value="route-signature")
    persist = AsyncMock()
    monkeypatch.setattr(
        onnuri_smoke_f12,
        "get_smoke_authority_runtime",
        lambda: SimpleNamespace(
            issuer=SimpleNamespace(sign_dispatch_receipt=signer),
            recovery_sealer=SimpleNamespace(seal=AsyncMock()),
        ),
    )
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "persist_onnuri_outbound_diagnostic_capability",
        persist,
    )
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "recover_onnuri_outbound_diagnostic_capability",
        AsyncMock(return_value=None),
    )
    onnuri_smoke_f12.configure_route_evidence_resolver(None)

    with pytest.raises(onnuri_smoke_f12.F12ServiceError) as raised:
        await onnuri_smoke_f12.mint_route_chain_capability(**values)

    assert raised.value.code == "onnuri_smoke_f12_operation_rejected"
    signer.assert_not_awaited()
    persist.assert_not_awaited()


@pytest.mark.asyncio
async def test_route_capability_recovery_prelookup_avoids_resolver_and_signer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    context = BoundCallContext(
        organization_id=7,
        account_id="account-a",
        application_id="application-a",
        run_id="run-a",
        attempt_id="attempt-a",
        direction="outbound",
        authority_deadline=now + timedelta(seconds=60),
        candidate_digest="b" * 64,
        gate_envelope_digest="c" * 64,
    )
    claims = onnuri_smoke_f12.route_chain_capability_claims(
        onnuri_smoke_f12._route_capability_request(
            context=context,
            idempotency_key=_IDEMPOTENCY_KEY,
            request_digest=_DIGEST,
            route_profile_digest="d" * 64,
            route_evidence_handle="capability-recovery",
        ),
        provider_fact_packet_id="packet",
        provider_fact_packet_sha256="1" * 64,
        route_decision_id="decision",
        route_decision_sha256="2" * 64,
        route_conformance_id="conformance",
        route_conformance_sha256="3" * 64,
        adapter_entries_digest="4" * 64,
        keyset_sha256="5" * 64,
        revocations_sha256="6" * 64,
    )
    recovered_capability = RouteChainCapability(
        key_id=_DISPATCH_KEY_ID,
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
        nonce="a" * 64,
        claims=claims,
        signature="persisted-signature",
    )
    wire_payload = recovered_capability.model_dump(mode="json", exclude={"signature"})
    wire_payload["signature"] = "persisted-signature"
    wire = onnuri_smoke_f12.canonical_json_bytes(wire_payload)
    recovered = SimpleNamespace(
        encrypted_capability_recovery="persisted",
        token_digest=hashlib.sha256(wire).hexdigest(),
        signature_digest=hashlib.sha256(b"persisted-signature").hexdigest(),
        nonce_digest=hashlib.sha256(("a" * 64).encode()).hexdigest(),
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
    )
    lookup = AsyncMock(return_value=recovered)
    signer = AsyncMock()
    resolver = AsyncMock()
    monkeypatch.setattr(
        onnuri_smoke_f12.authority.db_client,
        "recover_onnuri_outbound_diagnostic_capability",
        lookup,
    )
    monkeypatch.setattr(
        onnuri_smoke_f12,
        "get_smoke_authority_runtime",
        lambda: SimpleNamespace(
            recovery_sealer=SimpleNamespace(unseal=AsyncMock(return_value=wire)),
            issuer=SimpleNamespace(sign_dispatch_receipt=signer),
        ),
    )
    onnuri_smoke_f12.configure_route_evidence_resolver(resolver)

    result = await onnuri_smoke_f12.mint_route_chain_capability(
        context=context,
        idempotency_key=_IDEMPOTENCY_KEY,
        request_digest=_DIGEST,
        route_profile_digest="d" * 64,
        route_evidence_handle="capability-recovery",
    )

    assert result.claims == claims
    lookup.assert_awaited_once()
    resolver.resolve.assert_not_awaited()
    signer.assert_not_awaited()


def _adapter_invoker(
    tmp_path: Path, script: bytes, *, stdout_max_bytes: int = 1024,
    stderr_max_bytes: int = 1024, timeout_ms: int = 100,
):
    adapter_path = tmp_path / "adapter"
    adapter_path.write_bytes(script)
    adapter_path.chmod(0o500)
    root_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    resolver = onnuri_smoke_f12.FileRouteEvidenceResolver(
        root=tmp_path, manifest=tmp_path / "manifest", uid=os.getuid(), gid=os.getgid()
    )
    adapter = {
        "path": "adapter",
        "sha256": hashlib.sha256(script).hexdigest(),
        "execution_mode": "fixed-executable-v1",
        "stdin_schema": "recova-onnuri-restricted-inventory-adapter-invocation-v1",
        "stdin_exactly_one_lf": True,
        "stdout_schema": "recova-onnuri-restricted-inventory-adapter-v1",
        "stdout_max_bytes": stdout_max_bytes,
        "stderr_max_bytes": stderr_max_bytes,
        "timeout_ms": timeout_ms,
    }
    invoker, descriptor = resolver._invoker(adapter, root_fd=root_fd)
    return invoker, descriptor, root_fd


def _adapter_invocation() -> SimpleNamespace:
    return SimpleNamespace(
        audience="route_chain",
        challenge_nonce="a" * 43,
        approved_root_locator_digest="b" * 64,
        inventory_locator_digest="c" * 64,
        inventory_version="v1",
        as_of_utc="2026-07-21T00:00:00.000Z",
    )


@pytest.mark.asyncio
@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="requires descriptor-native execution")
async def test_adapter_deadline_covers_exit_after_stream_close(tmp_path: Path) -> None:
    invoker, descriptor, root_fd = _adapter_invoker(
        tmp_path,
        b"#!/bin/sh\ncat >/dev/null\nexec 1>&- 2>&-\nsleep 5\n",
        timeout_ms=50,
    )
    try:
        with pytest.raises(RuntimeError, match="route_adapter_invocation_rejected"):
            await invoker(_adapter_invocation())
    finally:
        os.close(descriptor)
        os.close(root_fd)


@pytest.mark.asyncio
@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="requires descriptor-native execution")
async def test_adapter_timeout_reaps_child_without_descriptor_leak(tmp_path: Path) -> None:
    pid_file = tmp_path / "child.pid"
    before = len(os.listdir("/proc/self/fd"))
    script = (
        b"#!/bin/sh\n"
        b"cat >/dev/null\n"
        + f"echo $$ > {pid_file}\n".encode()
        + b"exec 1>&- 2>&-\nsleep 5\n"
    )
    invoker, descriptor, root_fd = _adapter_invoker(tmp_path, script, timeout_ms=50)
    try:
        with pytest.raises(RuntimeError, match="route_adapter_invocation_rejected"):
            await invoker(_adapter_invocation())
        pid = int(pid_file.read_text().strip())
        for _ in range(10):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            await asyncio.sleep(0.01)
        else:
            pytest.fail("adapter child survived timeout cleanup")
    finally:
        os.close(descriptor)
        os.close(root_fd)
    assert len(os.listdir("/proc/self/fd")) == before


async def _assert_process_group_gone(pid: int) -> None:
    for _ in range(25):
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            return
        await asyncio.sleep(0.01)
    pytest.fail("adapter process group survived cleanup")


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "linux" or not os.path.isdir("/proc/self/fd"), reason="requires Linux descriptor-native execution")
async def test_adapter_cancellation_reaps_delayed_process_group_without_descriptor_leak(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pid_file = tmp_path / "adapter.pid"
    child_pid_file = tmp_path / "child.pid"
    before = len(os.listdir("/proc/self/fd"))
    script = (
        b"#!/bin/sh\n"
        + f"echo $$ > {pid_file}\n".encode()
        + f"sleep 5 & echo $! > {child_pid_file}\n".encode()
        + b"wait\n"
    )
    invoker, descriptor, root_fd = _adapter_invoker(tmp_path, script, timeout_ms=5000)
    original_wait = asyncio.subprocess.Process.wait

    async def delayed_wait(process: asyncio.subprocess.Process) -> int:
        await asyncio.sleep(0.05)
        return await original_wait(process)

    monkeypatch.setattr(asyncio.subprocess.Process, "wait", delayed_wait)
    try:
        invocation = asyncio.create_task(invoker(_adapter_invocation()))
        for _ in range(25):
            if pid_file.exists() and child_pid_file.exists():
                break
            await asyncio.sleep(0.01)
        else:
            pytest.fail("adapter did not create its process group")
        pid = int(pid_file.read_text().strip())
        child_pid = int(child_pid_file.read_text().strip())
        invocation.cancel()
        with pytest.raises(asyncio.CancelledError):
            await invocation
        await _assert_process_group_gone(pid)
        with pytest.raises(ProcessLookupError):
            os.kill(child_pid, 0)
    finally:
        os.close(descriptor)
        os.close(root_fd)
    assert len(os.listdir("/proc/self/fd")) == before


@pytest.mark.asyncio
@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="requires descriptor-native execution")
@pytest.mark.parametrize(
    ("script", "stdout_max_bytes", "stderr_max_bytes"),
    [
        (b"#!/bin/sh\nhead -c 128 /dev/zero\n", 64, 1024),
        (b"#!/bin/sh\nhead -c 128 /dev/zero >&2\n", 1024, 64),
    ],
)
async def test_adapter_output_overflow_reaps_child(
    tmp_path: Path, script: bytes, stdout_max_bytes: int, stderr_max_bytes: int
) -> None:
    invoker, descriptor, root_fd = _adapter_invoker(
        tmp_path, script, stdout_max_bytes=stdout_max_bytes,
        stderr_max_bytes=stderr_max_bytes,
    )
    try:
        with pytest.raises(RuntimeError, match="route_adapter_invocation_rejected"):
            await invoker(_adapter_invocation())
    finally:
        os.close(descriptor)
        os.close(root_fd)


@pytest.mark.asyncio
@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="requires descriptor-native execution")
async def test_adapter_concurrent_invocations_do_not_share_reused_descriptors(
    tmp_path: Path,
) -> None:
    script = b"#!/bin/sh\ncat >/dev/null\nprintf '{}'\n"
    invoker, descriptor, root_fd = _adapter_invoker(tmp_path, script)
    try:
        assert await asyncio.gather(*[invoker(_adapter_invocation()) for _ in range(8)]) == [b"{}"] * 8
    finally:
        os.close(descriptor)
        os.close(root_fd)


@pytest.mark.asyncio
async def test_adapter_refuses_missing_native_descriptor_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    invoker, descriptor, root_fd = _adapter_invoker(tmp_path, b"#!/bin/sh\nprintf '{}'\n")
    original_stat = onnuri_smoke_f12.os.stat

    def unavailable_proc(path: str, *args: object, **kwargs: object):
        if isinstance(path, str) and path.startswith("/proc/self/fd/"):
            raise OSError
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(onnuri_smoke_f12.os, "stat", unavailable_proc)
    try:
        with pytest.raises(RuntimeError, match="route_adapter_invocation_rejected"):
            await invoker(_adapter_invocation())
    finally:
        os.close(descriptor)
        os.close(root_fd)
