from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_MODULE_PATH = Path(__file__).parents[2] / "scripts" / "verify_onnuri_g008_closure_manifest.py"
_SPEC = importlib.util.spec_from_file_location("g008_closure", _MODULE_PATH)
assert _SPEC and _SPEC.loader
closure = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(closure)
_GENERATOR_PATH = Path(__file__).parents[2] / "scripts" / "generate_onnuri_g008_closure_manifest.py"
_GENERATOR_SPEC = importlib.util.spec_from_file_location("g008_closure_generator", _GENERATOR_PATH)
assert _GENERATOR_SPEC and _GENERATOR_SPEC.loader
generator = importlib.util.module_from_spec(_GENERATOR_SPEC)
_GENERATOR_SPEC.loader.exec_module(generator)

CANONICAL_ROLES = tuple(sorted(closure._CANONICAL_KEYS))
PRIVATE_KEYS = {role: Ed25519PrivateKey.generate() for role in CANONICAL_ROLES}
PUBLIC_KEYS = {
    role: key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    for role, key in PRIVATE_KEYS.items()
}
NOW = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
ISSUED, EXPIRES = "2026-07-16T11:59:00Z", "2026-07-16T12:01:00Z"


def _d(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _sign(payload: dict, role: str) -> dict:
    canonical_role = closure._ROLE_AUTHORITY[role]
    signature = PRIVATE_KEYS[canonical_role].sign(closure.canonical_json_bytes(payload))
    return {
        "algorithm": "Ed25519",
        "key_id": closure._CANONICAL_KEYS[canonical_role][0],
        "value": base64.b64encode(signature).decode(),
    }


@pytest.fixture(autouse=True)
def _canonical_test_keyset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(closure, "_load_trusted_keys", lambda: PUBLIC_KEYS)
    monkeypatch.setattr(generator.verifier, "_load_trusted_keys", lambda: PUBLIC_KEYS)
    closure_public_digest = hashlib.sha256(PUBLIC_KEYS["phase-c-preflight"]).hexdigest()
    monkeypatch.setitem(
        generator.verifier._CANONICAL_KEYS,
        "phase-c-preflight",
        (closure._CANONICAL_KEYS["phase-c-preflight"][0], closure_public_digest),
    )


def _bindings() -> dict:
    return {
        "tenant_digest": _d("tenant"),
        "account_digest": _d("account"),
        "envelope_digest": _d("envelope"),
        "candidate_digest": _d("candidate"),
        "run_id_digest": _d("run-id"),
        "activation_nonce_digest": _d("activation-nonce"),
        "run_nonce_digest": _d("one-time-run-nonce"),
        "trusted_keyset_digest": closure._TRUSTED_KEYSET_SHA256,
        "execution_bundle_digest": hashlib.sha256(_bundle_bytes()).hexdigest(),
    }


def _receipt(kind: str, role: str, fields: dict, *, bound: bool = False) -> dict:
    payload = {
        "contract_version": "g008-bound-receipt-v1" if bound else "g008-independent-receipt-v1",
        "kind": kind,
        **_bindings(),
        "issued_at": ISSUED,
        "expires_at": EXPIRES,
        **fields,
    }
    digest_field = "receipt_digest" if bound else closure._EVIDENCE_SELF_DIGEST[kind]
    payload[digest_field] = _d("placeholder")
    unsigned = dict(payload)
    unsigned.pop(digest_field)
    payload[digest_field] = hashlib.sha256(closure.canonical_json_bytes(unsigned)).hexdigest()
    return {"payload": payload, "signature": _sign(payload, role)}


def _bundle_bytes() -> bytes:
    binding = {
        "organization_id": 7,
        "execution_seal_uuid": "11111111-1111-4111-8111-111111111111",
        "execution_nonce_digest": _d("activation-nonce"),
        "candidate_digest": _d("candidate"),
        "gate_envelope_digest": _d("envelope"),
    }

    def authority_receipt(payload: dict) -> dict:
        return {"payload": payload, "signature": _sign(payload, "closure-event")}

    nonce = authority_receipt({
        "kind": "nonce_consumption",
        **binding,
        "trusted_keyset_digest": closure._TRUSTED_KEYSET_SHA256,
        "state": "consumed",
        "pre_existing": False,
    })
    seal = authority_receipt({
        "kind": "execution_seal",
        **binding,
        "schema_version": "recova-g008-execution-seal-v1",
        "destination_hmac_digest": _d("destination"),
        "stages": ["register", "outbound_call", "inbound_call", "unregister"],
        "retry_count": 0,
        "concurrency_count": 1,
        "call_deadline_seconds": 60,
        "stage_deadline_seconds": 60,
        "live_window_starts_at": ISSUED,
        "live_window_expires_at": EXPIRES,
        "reserved_inbound_did_digest": _d("did"),
        "reserved_inbound_caller_digest": _d("caller"),
        "policy_digest": _d("policy"),
        "trusted_keyset_digest": closure._TRUSTED_KEYSET_SHA256,
        "state": "sealed",
        "pre_existing": False,
        "registration_attestation_key_id": "registration-attestation-v1",
        "registration_attestation_public_key_sha256": _d("registration-attestation-spki"),
    })
    stages = [
        authority_receipt({
            "kind": "stage_status",
            **binding,
            "stage": stage,
            "ordinal": ordinal,
            "state": "succeeded",
            "stage_deadline_seconds": 60,
        })
        for ordinal, stage in enumerate(
            ["register", "outbound_call", "inbound_call", "unregister"], 1
        )
    ]
    final = authority_receipt({
        "kind": "final_execution_evidence",
        **binding,
        "state": "completed",
        "trusted_keyset_digest": closure._TRUSTED_KEYSET_SHA256,
        "containment_verified": True,
        "stage_receipts": stages,
    })
    return closure.canonical_json_bytes({
        "schema_version": "recova-g008-execution-bundle-v2",
        "trusted_keyset_digest": closure._TRUSTED_KEYSET_SHA256,
        "nonce": nonce,
        "seal": seal,
        "stages": stages,
        "final": final,
    })


def _verify_manifest(doc: dict, **kwargs):
    return closure.verify_manifest(doc, _bundle_bytes(), **kwargs)


def _attempt(sequence: int, direction: str, start: int) -> dict:
    attempt_id = _d(f"attempt-{sequence}")
    provider_call_id = _d(f"provider-call-{sequence}")
    prior = None if sequence == 1 else _d(f"attempt-{sequence - 1}")
    shared = {
        "attempt_id_digest": attempt_id,
        "provider_call_id_digest": provider_call_id,
        "sequence": sequence,
        "direction": direction,
        "started_monotonic_ms": start,
        "ended_monotonic_ms": start + 50_000,
        "retry_count": 0,
        "concurrency_count": 1,
        "prior_attempt_id_digest": prior,
    }
    role_fields = {
        "dispatch": {"dispatch_artifact_digest": _d(f"dispatch-{sequence}")},
        "media": {"media_artifact_digest": _d(f"media-{sequence}")},
        "status": {
            "status_artifact_digest": _d(f"status-{sequence}"),
            "terminal_status": "terminal",
            "terminal_disposition": "completed",
        },
        "cdr": {"cdr_artifact_digest": _d(f"cdr-{sequence}"), "billed_duration_ms": 40_000},
        "human-rx": {
            "human_rx_artifact_digest": _d(f"rx-audio-{sequence}"),
            "human_rx_duration_ms": 10_000,
            "human_rx_acknowledgement": "redacted_heard",
            "human_rx_acknowledgement_artifact_digest": _d(f"rx-ack-{sequence}"),
        },
        "human-tx": {
            "human_tx_artifact_digest": _d(f"tx-audio-{sequence}"),
            "human_tx_duration_ms": 9_000,
            "human_tx_acknowledgement": "redacted_spoke",
            "human_tx_acknowledgement_artifact_digest": _d(f"tx-ack-{sequence}"),
        },
    }
    receipts = {
        role: _receipt(f"attempt_{role}", role, {**shared, **role_fields[role]}, bound=True)
        for role in closure._ATTEMPT_RECEIPT_ROLES
    }
    return {**shared, "evidence_receipts": receipts}


def _manifest(*, include_g007: bool = True) -> dict:
    register = _receipt(
        "register", "register",
        {"logical_register_count": 1, "retry_count": 0, "concurrency_count": 1},
        bound=True,
    )
    unregister = _receipt(
        "unregister", "unregister",
        {
            "register_receipt_digest": register["payload"]["receipt_digest"],
            "retry_count": 0,
            "concurrency_count": 1,
        },
        bound=True,
    )
    registration = {
        "logical_register_count": 1,
        "retry_count": 0,
        "concurrency_count": 1,
        "register_receipt": register,
        "unregister_receipt": unregister,
    }
    resource = {"resource_id_digest": _d("vm-resource"), "resource_type": "instance", "generation": 7}
    operation = {**resource, "provider_operation_digest": _d("provider-delete-op"), "result": "deleted"}
    absence = {**resource, "present": False, "provider_query_digest": _d("provider-absence-query")}
    evidence = {
        "provider_preflight": _receipt("provider_preflight", "provider-preflight", {"currency": "KRW", "starting_balance": "10"}),
        "supplier_scope": _receipt("supplier_scope", "supplier", {"rtp_cidr": "8.8.8.0/24", "rtcp_cidr": "1.1.1.0/24", "rtp_ports": {"start": 10000, "end": 10999}, "rtcp_ports": {"start": 11000, "end": 11999}}),
        "owned_mapping": _receipt("owned_mapping", "ownership", {"mapping_digest": _d("mapping")}),
        "secret_versions": _receipt("secret_versions", "secret-custodian", {"versions": {purpose: index + 1 for index, purpose in enumerate(closure._SECRET_PURPOSES)}}),
        "phase_b_baseline": _receipt("phase_b_baseline", "phase-b", {"baseline_manifest_digest": _d("phase-b")}),
        "g009_candidate": _receipt("g009_candidate", "g009", {}),
        "f12_readiness": _receipt("f12_readiness", "f12", {"ready": True}),
        "approval": _receipt("approval", "approver", {"approved": True}),
        "provider_deletion": _receipt("provider_deletion", "provider-deletion", {"resources": [resource], "operations": [operation]}),
        "network_preactivation": _receipt("network_preactivation", "network-inventory-pre", {"network_digest": _d("phase-b-network"), "generation": 10, "routers": [], "nats": []}),
        "network_postactivation": _receipt("network_postactivation", "network-inventory-post", {"network_digest": _d("phase-b-network"), "generation": 11, "routers": [], "nats": []}),
    }
    evidence["provider_postcall"] = _receipt(
        "provider_postcall", "provider-postcall",
        {"currency": "KRW", "ending_balance": "8.5", "cost_delta": "1.5", "preflight_receipt_digest": evidence["provider_preflight"]["payload"]["preflight_receipt_digest"]},
    )
    evidence["provider_absence"] = _receipt(
        "provider_absence", "provider-inventory",
        {"resources": [absence], "deletion_receipt_digest": evidence["provider_deletion"]["payload"]["deletion_receipt_digest"]},
    )
    if include_g007:
        evidence["g007_baseline"] = _receipt("g007_baseline", "g007", {"baseline_manifest_digest": _d("phase-b")})
    closure_bindings = {
        "phase_b_baseline_receipt_digest": evidence["phase_b_baseline"]["payload"]["baseline_receipt_digest"],
        "provider_deletion_receipt_digest": evidence["provider_deletion"]["payload"]["deletion_receipt_digest"],
        "provider_absence_receipt_digest": evidence["provider_absence"]["payload"]["absence_receipt_digest"],
        "network_preactivation_receipt_digest": evidence["network_preactivation"]["payload"]["inventory_receipt_digest"],
        "network_postactivation_receipt_digest": evidence["network_postactivation"]["payload"]["inventory_receipt_digest"],
    }
    events, previous = [], None
    for sequence, event_name in enumerate(closure._CLOSURE_KINDS, 1):
        payload = {
            "contract_version": "g008-closure-event-v1",
            "kind": "closure_event",
            **_bindings(),
            "issued_at": ISSUED,
            "expires_at": EXPIRES,
            "sequence": sequence,
            "event": event_name,
            "previous_event_receipt_digest": previous,
            "register_receipt_digest": register["payload"]["receipt_digest"],
            "unregister_receipt_digest": unregister["payload"]["receipt_digest"],
            "retry_count": 0,
            "concurrency_count": 1,
            "phase_b_expected_digest": _d("phase-b"),
            "phase_b_observed_digest": _d("phase-b"),
            "product_status": "Waiting",
            **closure_bindings,
            "event_receipt_digest": _d("placeholder"),
        }
        unsigned = dict(payload); unsigned.pop("event_receipt_digest")
        payload["event_receipt_digest"] = hashlib.sha256(closure.canonical_json_bytes(unsigned)).hexdigest()
        events.append({"payload": payload, "signature": _sign(payload, "closure-event")})
        previous = payload["event_receipt_digest"]
    baseline_receipt_digest = evidence["phase_b_baseline"]["payload"]["baseline_receipt_digest"]
    return {
        "version": "g008-closure-manifest-v4",
        **_bindings(),
        "issued_at": ISSUED,
        "expires_at": EXPIRES,
        "product_status": "Waiting",
        "phase_b": {"state": "deny_only", "baseline_manifest_digest": _d("phase-b"), "baseline_receipt_digest": baseline_receipt_digest, "closure_manifest_digest": _d("phase-b")},
        "registration": registration,
        "evidence": evidence,
        "attempts": [_attempt(1, "outbound", 1000), _attempt(2, "inbound", 61000)],
        "closure_events": events,
        "referenced_digests": {},
    }


def _finalize(doc: dict) -> dict:
    doc["referenced_digests"] = closure._referenced_digests(doc)
    unsigned = dict(doc); unsigned.pop("signature", None)
    doc["signature"] = _sign(unsigned, "closure-manifest")
    return doc


def _resign_receipt(receipt: dict, role: str, digest_field: str) -> None:
    unsigned = dict(receipt["payload"]); unsigned.pop(digest_field)
    receipt["payload"][digest_field] = hashlib.sha256(closure.canonical_json_bytes(unsigned)).hexdigest()
    receipt["signature"] = _sign(receipt["payload"], role)


def _bundle_with_mutation(mutator) -> bytes:
    bundle = json.loads(_bundle_bytes())
    receipt, role = mutator(bundle)
    receipt["signature"] = _sign(receipt["payload"], role)
    return closure.canonical_json_bytes(bundle)


def _verify_execution_bundle(bundle: bytes) -> None:
    closure._load_execution_bundle(
        bundle,
        hashlib.sha256(bundle).hexdigest(),
        PUBLIC_KEYS,
        NOW,
    )


def test_accepts_complete_manifest_and_optional_g007_absence() -> None:
    assert _verify_manifest(_finalize(_manifest()), now=NOW)["candidate_digest"] == _d("candidate")
    assert _verify_manifest(_finalize(_manifest(include_g007=False)), now=NOW)["candidate_digest"] == _d("candidate")


def test_rejects_third_call_contingency_fields_and_call_id_cross_binding() -> None:
    doc = _manifest()
    doc["attempts"].append(_attempt(3, "inbound", 120_000))
    with pytest.raises(closure.ManifestVerificationError, match="exactly two"):
        _verify_manifest(_finalize(doc), now=NOW)

    doc = _manifest()
    doc["attempts"][0]["contingency_cause_attempt_id_digest"] = None
    with pytest.raises(closure.ManifestVerificationError, match="fields invalid"):
        _verify_manifest(_finalize(doc), now=NOW)

    doc = _manifest()
    receipt = doc["attempts"][0]["evidence_receipts"]["status"]
    receipt["payload"]["provider_call_id_digest"] = _d("different-provider-call")
    _resign_receipt(receipt, "status", "receipt_digest")
    with pytest.raises(closure.ManifestVerificationError, match="binding mismatch"):
        _verify_manifest(_finalize(doc), now=NOW)


@pytest.mark.parametrize(
    ("role", "field", "value"),
    [
        ("status", "terminal_disposition", "pending"),
        ("cdr", "billed_duration_ms", 50_001),
        ("human-rx", "human_rx_duration_ms", 0),
        ("human-tx", "human_tx_acknowledgement", "unacknowledged"),
    ],
)
def test_rejects_label_only_or_unbounded_call_artifacts(role: str, field: str, value: object) -> None:
    doc = _manifest()
    receipt = doc["attempts"][0]["evidence_receipts"][role]
    receipt["payload"][field] = value
    _resign_receipt(receipt, role, "receipt_digest")
    with pytest.raises(closure.ManifestVerificationError):
        _verify_manifest(_finalize(doc), now=NOW)


def test_rejects_wrong_keyset_or_execution_bundle_binding() -> None:
    doc = _manifest()
    doc["trusted_keyset_digest"] = _d("caller-selected-keyset")
    with pytest.raises(closure.ManifestVerificationError, match="canonical trusted keyset"):
        _verify_manifest(_finalize(doc), now=NOW)

    doc = _manifest()
    doc["execution_bundle_digest"] = None
    with pytest.raises(closure.ManifestVerificationError, match="execution_bundle_digest"):
        _verify_manifest(_finalize(doc), now=NOW)


@pytest.mark.parametrize("change", ["extra", "missing"])
def test_rejects_non_exact_signed_stage_payload_fields(change: str) -> None:
    def mutate(bundle: dict):
        payload = bundle["stages"][0]["payload"]
        if change == "extra":
            payload["unexpected"] = "signed-but-forbidden"
        else:
            payload.pop("stage_deadline_seconds")
        return bundle["stages"][0], "closure-event"

    bundle = _bundle_with_mutation(mutate)
    with pytest.raises(closure.ManifestVerificationError, match="fields invalid"):
        _verify_execution_bundle(bundle)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("organization_id", 8),
        ("execution_seal_uuid", "22222222-2222-4222-8222-222222222222"),
        ("execution_nonce_digest", _d("other-stage-execution-nonce")),
        ("candidate_digest", _d("other-stage-candidate")),
        ("gate_envelope_digest", _d("other-stage-envelope")),
    ],
)
def test_rejects_signed_stage_receipt_not_cross_bound_to_seal(
    field: str, value: object
) -> None:
    def mutate(bundle: dict):
        bundle["stages"][0]["payload"][field] = value
        return bundle["stages"][0], "closure-event"

    bundle = _bundle_with_mutation(mutate)
    with pytest.raises(closure.ManifestVerificationError, match="stage is not bound"):
        _verify_execution_bundle(bundle)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("organization_id", 8),
        ("execution_seal_uuid", "22222222-2222-4222-8222-222222222222"),
        ("execution_nonce_digest", _d("other-execution-nonce")),
        ("candidate_digest", _d("other-candidate")),
        ("gate_envelope_digest", _d("other-envelope")),
    ],
)
def test_rejects_signed_final_receipt_not_cross_bound_to_seal(
    field: str, value: object
) -> None:
    def mutate(bundle: dict):
        bundle["final"]["payload"][field] = value
        return bundle["final"], "closure-event"

    bundle = _bundle_with_mutation(mutate)
    with pytest.raises(closure.ManifestVerificationError, match="final is not bound"):
        _verify_execution_bundle(bundle)


@pytest.mark.parametrize("change", ["extra", "missing"])
def test_rejects_non_exact_signed_final_payload_fields(change: str) -> None:
    def mutate(bundle: dict):
        payload = bundle["final"]["payload"]
        if change == "extra":
            payload["unexpected"] = "signed-but-forbidden"
        else:
            payload.pop("containment_verified")
        return bundle["final"], "closure-event"

    bundle = _bundle_with_mutation(mutate)
    with pytest.raises(closure.ManifestVerificationError, match="fields invalid"):
        _verify_execution_bundle(bundle)


@pytest.mark.parametrize(
    ("receipt_name", "field", "value"),
    [
        ("nonce", "organization_id", True),
        ("nonce", "execution_seal_uuid", "11111111-1111-4111-8111-11111111111A"),
        ("nonce", "execution_nonce_digest", "A" * 64),
        ("seal", "organization_id", 7.0),
        ("seal", "execution_seal_uuid", "not-a-uuid"),
        ("seal", "candidate_digest", "0" * 63),
        ("stage", "organization_id", "7"),
        ("stage", "execution_seal_uuid", "11111111111141118111111111111111"),
        ("stage", "gate_envelope_digest", None),
        ("final", "organization_id", False),
        ("final", "execution_seal_uuid", 111),
        ("final", "execution_nonce_digest", "g" * 64),
    ],
)
def test_rejects_canonical_resigned_malformed_execution_identities(
    receipt_name: str, field: str, value: object
) -> None:
    def mutate(bundle: dict):
        receipt = bundle["stages"][0] if receipt_name == "stage" else bundle[receipt_name]
        receipt["payload"][field] = value
        return receipt, "closure-event"

    bundle = _bundle_with_mutation(mutate)
    with pytest.raises(closure.ManifestVerificationError):
        _verify_execution_bundle(bundle)


@pytest.mark.parametrize(
    ("target", "field", "value"),
    [
        ("seal", "retry_count", False),
        ("seal", "concurrency_count", 1.0),
        ("seal", "call_deadline_seconds", "60"),
        ("seal", "stage_deadline_seconds", 60.0),
        ("stage", "ordinal", True),
        ("stage", "stage_deadline_seconds", "60"),
    ],
)
def test_rejects_canonical_resigned_non_integer_execution_policy(
    target: str, field: str, value: object
) -> None:
    def mutate(bundle: dict):
        receipt = bundle["seal"] if target == "seal" else bundle["stages"][0]
        receipt["payload"][field] = value
        return receipt, "closure-event"

    bundle = _bundle_with_mutation(mutate)
    with pytest.raises(closure.ManifestVerificationError, match="must be the integer"):
        _verify_execution_bundle(bundle)


def test_rejects_canonical_resigned_non_exact_seal_stage_list() -> None:
    def mutate(bundle: dict):
        bundle["seal"]["payload"]["stages"] = "register,outbound_call,inbound_call,unregister"
        return bundle["seal"], "closure-event"

    bundle = _bundle_with_mutation(mutate)
    with pytest.raises(closure.ManifestVerificationError, match="seal policy"):
        _verify_execution_bundle(bundle)


@pytest.mark.parametrize(
    ("starts", "expires"),
    [
        ("2026-7-16T11:59:00Z", EXPIRES),
        ("2026-07-16T11:59:00+00:00", EXPIRES),
        (EXPIRES, ISSUED),
        (ISSUED, "2026-07-16T12:10:00Z"),
        ("2026-07-16T12:00:30Z", "2026-07-16T12:01:00Z"),
    ],
)
def test_rejects_canonical_resigned_malformed_or_unordered_seal_window(
    starts: str, expires: str
) -> None:
    def mutate(bundle: dict):
        payload = bundle["seal"]["payload"]
        payload["live_window_starts_at"] = starts
        payload["live_window_expires_at"] = expires
        return bundle["seal"], "closure-event"

    bundle = _bundle_with_mutation(mutate)
    with pytest.raises(closure.ManifestVerificationError):
        _verify_execution_bundle(bundle)


def test_rejects_manifest_and_bundle_envelope_mismatch_after_resigning() -> None:
    doc = _manifest()
    doc["envelope_digest"] = _d("different-manifest-envelope")
    canonical_manifest = closure.canonical_json_bytes(_finalize(doc))
    resigned = json.loads(canonical_manifest)
    assert closure.canonical_json_bytes(resigned) == canonical_manifest

    with pytest.raises(closure.ManifestVerificationError, match="manifest envelope"):
        closure.verify_manifest(resigned, _bundle_bytes(), now=NOW)


def test_rejects_fabricated_provider_deletion_or_absence_inventory() -> None:
    doc = _manifest(); deletion = doc["evidence"]["provider_deletion"]
    deletion["payload"]["operations"][0]["result"] = "requested"
    _resign_receipt(deletion, "provider-deletion", "deletion_receipt_digest")
    with pytest.raises(closure.ManifestVerificationError, match="deletion"):
        _verify_manifest(_finalize(doc), now=NOW)
    doc = _manifest(); absence = doc["evidence"]["provider_absence"]
    absence["payload"]["resources"][0]["generation"] = 8
    _resign_receipt(absence, "provider-inventory", "absence_receipt_digest")
    with pytest.raises(closure.ManifestVerificationError, match="exactly match"):
        _verify_manifest(_finalize(doc), now=NOW)


@pytest.mark.parametrize(("name", "field", "value"), [
    ("network_preactivation", "nats", [{"resource_id_digest": _d("nat")}]),
    ("network_postactivation", "routers", [{"resource_id_digest": _d("router")}]),
    ("network_postactivation", "generation", 10),
])
def test_rejects_asserted_nat_router_absence_without_ordered_empty_inventory(name: str, field: str, value: object) -> None:
    doc = _manifest(); receipt = doc["evidence"][name]; receipt["payload"][field] = value
    _resign_receipt(receipt, closure._EVIDENCE_SPECS[name][0], "inventory_receipt_digest")
    with pytest.raises(closure.ManifestVerificationError):
        _verify_manifest(_finalize(doc), now=NOW)


@pytest.mark.parametrize("field", [
    "started_monotonic_ms", "ended_monotonic_ms", "retry_count", "concurrency_count",
    "prior_attempt_id_digest", "run_id_digest", "activation_nonce_digest",
])
def test_attempt_receipts_bind_timing_order_counters_and_activation(field: str) -> None:
    doc = _manifest(); receipt = doc["attempts"][1]["evidence_receipts"]["dispatch"]
    receipt["payload"][field] = 999 if field.endswith("_ms") or field.endswith("count") else _d("wrong")
    _resign_receipt(receipt, "dispatch", "receipt_digest")
    with pytest.raises(closure.ManifestVerificationError, match="binding mismatch"):
        _verify_manifest(_finalize(doc), now=NOW)


def test_rejects_unsigned_phase_b_equality_and_misbound_optional_g007() -> None:
    doc = _manifest(); doc["phase_b"]["baseline_manifest_digest"] = _d("fabricated")
    doc["phase_b"]["closure_manifest_digest"] = _d("fabricated")
    with pytest.raises(closure.ManifestVerificationError, match="cross-bound"):
        _verify_manifest(_finalize(doc), now=NOW)
    doc = _manifest(); receipt = doc["evidence"]["g007_baseline"]
    receipt["payload"]["baseline_manifest_digest"] = _d("other-baseline")
    _resign_receipt(receipt, "g007", "baseline_receipt_digest")
    with pytest.raises(closure.ManifestVerificationError, match="G007"):
        _verify_manifest(_finalize(doc), now=NOW)


def test_rejects_recomputed_self_asserted_receipt_digest_and_duplicate_proofs() -> None:
    doc = _manifest(); receipt = doc["evidence"]["provider_deletion"]
    receipt["payload"]["deletion_receipt_digest"] = _d("fabricated")
    receipt["signature"] = _sign(receipt["payload"], "provider-deletion")
    with pytest.raises(closure.ManifestVerificationError, match="canonical receipt"):
        _verify_manifest(_finalize(doc), now=NOW)
    doc = _manifest()
    second = doc["attempts"][1]["evidence_receipts"]["cdr"]
    first_digest = doc["attempts"][0]["evidence_receipts"]["cdr"]["payload"]["receipt_digest"]
    second["payload"]["receipt_digest"] = first_digest
    second["signature"] = _sign(second["payload"], "cdr")
    with pytest.raises(closure.ManifestVerificationError):
        _verify_manifest(_finalize(doc), now=NOW)


def test_rejects_replay_shaped_manifest_with_consumed_nonce_or_digest() -> None:
    doc = _finalize(_manifest()); nonces: set[str] = set(); manifests: set[str] = set()
    _verify_manifest(doc, now=NOW, consumed_run_nonces=nonces, consumed_manifest_digests=manifests)
    with pytest.raises(closure.ManifestVerificationError, match="already consumed"):
        _verify_manifest(copy.deepcopy(doc), now=NOW, consumed_run_nonces=nonces, consumed_manifest_digests=manifests)


def test_rejects_duplicate_run_bindings_and_receipt_missing_nonce() -> None:
    doc = _manifest(); doc["activation_nonce_digest"] = doc["run_nonce_digest"]
    with pytest.raises(closure.ManifestVerificationError, match="execution bundle is not bound"):
        _verify_manifest(_finalize(doc), now=NOW)
    doc = _manifest(); receipt = doc["evidence"]["approval"]
    receipt["payload"].pop("run_nonce_digest")
    receipt["signature"] = _sign(receipt["payload"], "approver")
    with pytest.raises(closure.ManifestVerificationError):
        _verify_manifest(_finalize(doc), now=NOW)

def test_production_generator_consumes_once_and_secures_ledger(tmp_path: Path) -> None:
    draft = _manifest()
    draft.pop("referenced_digests")
    ledger = tmp_path / "private" / "consumed.json"
    manifest, result = generator.assemble_manifest(
        draft,
        _bundle_bytes(),
        PRIVATE_KEYS["phase-c-preflight"],
        ledger,
        now=NOW,
    )
    assert result["manifest_digest"] == hashlib.sha256(closure.canonical_json_bytes(manifest)).hexdigest()
    assert ledger.stat().st_mode & 0o077 == 0
    with pytest.raises(generator.verifier.ManifestVerificationError, match="already consumed"):
        generator.assemble_manifest(
            copy.deepcopy(draft),
            _bundle_bytes(),
            PRIVATE_KEYS["phase-c-preflight"],
            ledger,
            now=NOW,
        )
    ledger.chmod(0o644)
    fresh = _manifest()
    fresh.pop("referenced_digests")
    fresh["run_nonce_digest"] = _d("fresh-run-nonce")
    with pytest.raises(generator.verifier.ManifestVerificationError, match="must not be group"):
        generator.assemble_manifest(
            fresh,
            _bundle_bytes(),
            PRIVATE_KEYS["phase-c-preflight"],
            ledger,
            now=NOW,
        )
    output = tmp_path / "closure.json"
    generator._write_exclusive(output, manifest)
    assert output.read_bytes() == closure.canonical_json_bytes(manifest) + b"\n"
    assert output.stat().st_mode & 0o077 == 0
    with pytest.raises(generator.verifier.ManifestVerificationError, match="new private file"):
        generator._write_exclusive(output, manifest)


def test_rejects_one_way_duplicate_cross_call_audio_and_bundle_tampering() -> None:
    doc = _manifest()
    doc["attempts"][0]["evidence_receipts"].pop("human-tx")
    with pytest.raises(closure.ManifestVerificationError):
        _verify_manifest(_finalize(doc), now=NOW)

    doc = _manifest()
    tx = doc["attempts"][0]["evidence_receipts"]["human-tx"]
    tx["payload"]["human_tx_artifact_digest"] = doc["attempts"][0]["evidence_receipts"]["human-rx"]["payload"]["human_rx_artifact_digest"]
    _resign_receipt(tx, "human-tx", "receipt_digest")
    with pytest.raises(closure.ManifestVerificationError, match="distinct"):
        _verify_manifest(_finalize(doc), now=NOW)

    doc = _manifest()
    tx = doc["attempts"][1]["evidence_receipts"]["human-tx"]
    tx["payload"]["human_tx_artifact_digest"] = doc["attempts"][0]["evidence_receipts"]["human-tx"]["payload"]["human_tx_artifact_digest"]
    _resign_receipt(tx, "human-tx", "receipt_digest")
    with pytest.raises(closure.ManifestVerificationError, match="across calls"):
        _verify_manifest(_finalize(doc), now=NOW)

    tampered = bytearray(_bundle_bytes())
    tampered[-2] ^= 1
    with pytest.raises(closure.ManifestVerificationError):
        closure.verify_manifest(_finalize(_manifest()), bytes(tampered), now=NOW)
