from __future__ import annotations

import base64
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from api.services.telephony import onnuri_route_receipts as subject

NOW = datetime(2026, 7, 21, tzinfo=UTC)
D = lambda c: c * 64


def _key(role: str, key_id: str = "test-key"):
    private = ec.generate_private_key(ec.SECP256R1())
    identity = D("1")
    record = {
        "key_id": key_id, "role": role, "identity_digest": identity,
        "issued_at_utc": "2026-07-20T00:00:00Z", "expires_at_utc": "2026-07-22T00:00:00Z",
        "public_key_pem": private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
    }
    return private, record


def _signature(private, record, payload, *, domain, role):
    return {
        "key_id": record["key_id"], "signer_identity_digest": record["identity_digest"], "role": role,
        "credential_digest": D("2"), "domain": domain, "algorithm": "ES256",
        "issued_at_utc": "2026-07-20T00:00:00Z", "expires_at_utc": "2026-07-22T00:00:00Z",
        "signature_b64": base64.b64encode(private.sign(subject.canonical_json(payload), ec.ECDSA(hashes.SHA256()))).decode(),
    }


def _packet():
    value = {"schema_version": subject.PACKET_SCHEMA, "packet_id": "packet-1", "issued_at_utc": "2026-07-21T00:00:00Z", "expires_at_utc": "2026-07-21T01:00:00Z"}
    value.update({field: D(str(index + 1)) for index, field in enumerate(subject.FACT_FIELDS)})
    value["fact_set_digest"] = subject.fact_set_digest(value)
    value["canonical_payload_sha256"] = subject.canonical_payload_sha256(value)
    return value


def _adapter(private, record, *, nonce="A" * 43, audience="route_chain"):
    entries = []
    value = {"schema_version": subject.ADAPTER_SCHEMA, "domain": subject.ADAPTER_DOMAIN, "algorithm": "ES256", "key_id": record["key_id"], "signer_identity_digest": record["identity_digest"], "role": "restricted_inventory_adapter", "issued_at_utc": "2026-07-21T00:00:00Z", "expires_at_utc": "2026-07-21T00:04:00Z", "challenge_nonce": nonce, "audience": audience, "approved_root_locator_digest": D("3"), "inventory_locator_digest": D("4"), "inventory_version": "v1", "entries": entries, "entries_digest": subject.sha256(subject.canonical_json(entries))}
    value["claims"] = {"purpose": "onnuri_route_inventory_attestation", "approved_root_locator_digest": value["approved_root_locator_digest"], "inventory_locator_digest": value["inventory_locator_digest"], "inventory_version": "v1", "entries_digest": value["entries_digest"], "entries_count": 0, "audience": audience, "challenge_nonce": nonce}
    unsigned = deepcopy(value); value["signature_b64"] = base64.b64encode(private.sign(subject.canonical_json(unsigned), ec.ECDSA(hashes.SHA256()))).decode()
    return value


def test_fixed_canonical_projections_exclude_only_self_hash_and_order_six_facts():
    packet = _packet()
    assert subject.canonical_json({"b": 1, "a": "한글"}) == b'{"a":"\xed\x95\x9c\xea\xb8\x80","b":1}'
    assert packet["fact_set_digest"] == subject.sha256(subject.canonical_json({name: packet[name] for name in subject.FACT_SET_FIELDS}))
    changed = deepcopy(packet); changed["canonical_payload_sha256"] = D("f")
    assert subject.canonical_payload_sha256(changed) == packet["canonical_payload_sha256"]
    changed["fact_set_digest"] = D("e")
    assert subject.canonical_payload_sha256(changed) != packet["canonical_payload_sha256"]


def test_packet_refuses_digest_mutations_and_self_referential_substitution():
    private, key = _key("provider_facts_issuer"); packet = _packet(); signatures = [_signature(private, key, packet, domain=subject.PACKET_DOMAIN, role="provider_facts_issuer")]
    subject.verify_provider_fact_packet(provider_fact_packet=packet, provider_fact_packet_signatures=signatures, trusted_keyset={"keys": [key]}, revocations=[], as_of_utc=NOW)
    for field in (*subject.FACT_FIELDS, "fact_set_digest", "canonical_payload_sha256"):
        altered = deepcopy(packet); altered[field] = D("f")
        with pytest.raises(subject.ReceiptError): subject.verify_provider_fact_packet(provider_fact_packet=altered, provider_fact_packet_signatures=signatures, trusted_keyset={"keys": [key]}, revocations=[], as_of_utc=NOW)


def test_packet_signature_rejects_wrong_role_time_and_revocation():
    private, key = _key("provider_facts_issuer"); packet = _packet(); signature = _signature(private, key, packet, domain=subject.PACKET_DOMAIN, role="provider_facts_issuer")
    bad_role = deepcopy(key); bad_role["role"] = "route_approver"
    with pytest.raises(subject.ReceiptError, match="role"): subject.verify_provider_fact_packet(provider_fact_packet=packet, provider_fact_packet_signatures=[signature], trusted_keyset={"keys": [bad_role]}, revocations=[], as_of_utc=NOW)
    with pytest.raises(subject.ReceiptError, match="revoked"): subject.verify_provider_fact_packet(provider_fact_packet=packet, provider_fact_packet_signatures=[signature], trusted_keyset={"keys": [key]}, revocations=[key["key_id"]], as_of_utc=NOW)
    with pytest.raises(subject.ReceiptError, match="time"): subject.verify_provider_fact_packet(provider_fact_packet=packet, provider_fact_packet_signatures=[signature], trusted_keyset={"keys": [key]}, revocations=[], as_of_utc=NOW + timedelta(days=2))


@pytest.mark.asyncio
async def test_adapter_binds_challenge_and_rejects_escaping_paths(tmp_path):
    private, key = _key("restricted_inventory_adapter"); adapter = _adapter(private, key)
    consumed: list[tuple[str, str, str, str]] = []
    async def consume(**value):
        consumed.append((value["key_id"], value["challenge_nonce"], value["audience"], value["signature_sha256"]))
    await subject.verify_restricted_inventory_adapter(adapter=subject.canonical_json(adapter), trusted_keyset={"keys": [key]}, revocations=[], as_of_utc=NOW, audience="route_chain", challenge_nonce="A" * 43, approved_root_locator_digest=D("3"), inventory_locator_digest=D("4"), inventory_version="v1", replay_consumer=consume)
    assert consumed
    escaped = _adapter(private, key, nonce="B" * 43); escaped["entries"] = [{"logical_name": "x", "relative_path": "../secret", "sha256": D("a"), "classification": "base"}]; escaped["entries_digest"] = subject.sha256(subject.canonical_json(escaped["entries"])); escaped["claims"]["entries_digest"] = escaped["entries_digest"]; escaped["claims"]["entries_count"] = 1; unsigned = deepcopy(escaped); unsigned.pop("signature_b64"); escaped["signature_b64"] = base64.b64encode(private.sign(subject.canonical_json(unsigned), ec.ECDSA(hashes.SHA256()))).decode()
    with pytest.raises(subject.ReceiptError, match="path"): await subject.verify_restricted_inventory_adapter(adapter=subject.canonical_json(escaped), trusted_keyset={"keys": [key]}, revocations=[], as_of_utc=NOW, audience="route_chain", challenge_nonce="B" * 43, approved_root_locator_digest=D("3"), inventory_locator_digest=D("4"), inventory_version="v1", replay_consumer=consume)


def test_canonical_raw_decoder_rejects_bom_utf8_duplicates_whitespace_order_and_size():
    canonical = subject.canonical_json({"a": "한글", "b": 1})
    assert subject.decode_canonical_route_object(canonical) == {"a": "한글", "b": 1}
    for raw in (b'\xef\xbb\xbf{"a":1}', b'{"a":1,"a":2}', b'{"b":1,"a":2}', b'{"a": 1}', b'\xff'):
        with pytest.raises(subject.ReceiptError, match="canonical_input"):
            subject.decode_canonical_route_json(raw)
    with pytest.raises(subject.ReceiptError, match="canonical_input"):
        subject.decode_canonical_route_json(b"x" * (subject.MAX_CANONICAL_ROUTE_OBJECT_BYTES + 1))


def test_receipt_verification_requires_same_authenticated_packet_and_recurses():
    provider_private, provider = _key("provider_facts_issuer", "provider"); approver_private, approver = _key("route_approver", "approver"); producer_private, producer = _key("conformance_producer", "producer"); packet = _packet(); keys = {"keys": [provider, approver, producer]}; p_sigs = [_signature(provider_private, provider, packet, domain=subject.PACKET_DOMAIN, role="provider_facts_issuer")]
    decision = {"schema_version": subject.DECISION_SCHEMA, "receipt_id": "decision", "issued_at_utc": "2026-07-21T00:00:00Z", "expires_at_utc": "2026-07-21T00:30:00Z", "provider_fact_packet_id": packet["packet_id"], "provider_fact_packet_sha256": subject.sha256(subject.canonical_json(packet)), "request_digest": D("7"), "candidate_digest": D("8"), "route_profile_digest": D("9"), "restricted_inventory_entries_digest": D("a")}
    d_sigs = [_signature(approver_private, approver, decision, domain="recova.onnuri.route-approver.v1", role="route_approver")]
    conformance = {"schema_version": subject.CONFORMANCE_SCHEMA, "receipt_id": "conformance", "issued_at_utc": "2026-07-21T00:00:00Z", "expires_at_utc": "2026-07-21T00:20:00Z", "provider_fact_packet_id": packet["packet_id"], "provider_fact_packet_sha256": subject.sha256(subject.canonical_json(packet)), "request_digest": D("7"), "candidate_digest": D("8"), "route_profile_digest": D("9"), "route_decision_id": "decision", "route_decision_sha256": subject.sha256(subject.canonical_json(decision))}
    c_sigs = [_signature(producer_private, producer, conformance, domain="recova.onnuri.route-conformance_producer.v1", role="conformance_producer")]
    subject.verify_conformance(route_conformance=conformance, route_conformance_signatures=c_sigs, route_decision=decision, route_decision_signatures=d_sigs, provider_fact_packet=packet, provider_fact_packet_signatures=p_sigs, trusted_keyset=keys, revocations=[], as_of_utc=NOW)
    replacement = deepcopy(packet); replacement["packet_id"] = "packet-2"; replacement["canonical_payload_sha256"] = subject.canonical_payload_sha256(replacement)
    with pytest.raises(subject.ReceiptError): subject.verify_conformance(route_conformance=conformance, route_conformance_signatures=c_sigs, route_decision=decision, route_decision_signatures=d_sigs, provider_fact_packet=replacement, provider_fact_packet_signatures=p_sigs, trusted_keyset=keys, revocations=[], as_of_utc=NOW)


@pytest.mark.asyncio
async def test_full_canonical_chain_consumes_only_the_fresh_challenge_bound_adapter():
    provider_private, provider = _key("provider_facts_issuer", "provider")
    approver_private, approver = _key("route_approver", "approver")
    producer_private, producer = _key("conformance_producer", "producer")
    adapter_private, adapter = _key("restricted_inventory_adapter", "adapter")
    packet = _packet()
    keyset = {"keys": [provider, approver, producer, adapter]}
    packet_signatures = [
        _signature(
            provider_private,
            provider,
            packet,
            domain=subject.PACKET_DOMAIN,
            role="provider_facts_issuer",
        )
    ]
    decision = {
        "schema_version": subject.DECISION_SCHEMA,
        "receipt_id": "decision-1",
        "issued_at_utc": "2026-07-21T00:00:00Z",
        "expires_at_utc": "2026-07-21T00:30:00Z",
        "provider_fact_packet_id": packet["packet_id"],
        "provider_fact_packet_sha256": subject.sha256(subject.canonical_json(packet)),
        "request_digest": D("7"),
        "candidate_digest": D("8"),
        "route_profile_digest": D("9"),
        "restricted_inventory_entries_digest": subject.sha256(subject.canonical_json([])),
    }
    decision_signatures = [
        _signature(
            approver_private,
            approver,
            decision,
            domain="recova.onnuri.route-approver.v1",
            role="route_approver",
        )
    ]
    conformance = {
        "schema_version": subject.CONFORMANCE_SCHEMA,
        "receipt_id": "conformance-1",
        "issued_at_utc": "2026-07-21T00:00:00Z",
        "expires_at_utc": "2026-07-21T00:20:00Z",
        "provider_fact_packet_id": packet["packet_id"],
        "provider_fact_packet_sha256": subject.sha256(subject.canonical_json(packet)),
        "request_digest": D("7"),
        "candidate_digest": D("8"),
        "route_profile_digest": D("9"),
        "route_decision_id": decision["receipt_id"],
        "route_decision_sha256": subject.sha256(subject.canonical_json(decision)),
    }
    conformance_signatures = [
        _signature(
            producer_private,
            producer,
            conformance,
            domain="recova.onnuri.route-conformance_producer.v1",
            role="conformance_producer",
        )
    ]
    replayed: list[tuple[str, str]] = []

    async def adapter_invoker(invocation):
        return subject.canonical_json(
            _adapter(adapter_private, adapter, nonce=invocation.challenge_nonce)
        )

    async def replay_consumer(**value):
        replayed.append((value["challenge_nonce"], value["signature_sha256"]))

    evidence = subject.CanonicalRouteEvidence(
        provider_fact_packet_bytes=subject.canonical_json(packet),
        provider_fact_packet_signatures_bytes=subject.canonical_json(packet_signatures),
        route_decision_bytes=subject.canonical_json(decision),
        route_decision_signatures_bytes=subject.canonical_json(decision_signatures),
        route_conformance_bytes=subject.canonical_json(conformance),
        route_conformance_signatures_bytes=subject.canonical_json(conformance_signatures),
        trusted_keyset_bytes=subject.canonical_json(keyset),
        revocations_bytes=subject.canonical_json([]),
    )

    verified = await subject.verify_route_chain(
        evidence=evidence,
        adapter_invoker=adapter_invoker,
        replay_consumer=replay_consumer,
        as_of_utc=NOW,
        expected_request_digest=D("7"),
        expected_candidate_digest=D("8"),
        expected_route_profile_digest=D("9"),
        approved_root_locator_digest=D("3"),
        inventory_locator_digest=D("4"),
        inventory_version="v1",
    )

    assert verified.route_decision_id == "decision-1"
    assert verified.route_conformance_id == "conformance-1"
    assert len(replayed) == 1
    assert replayed[0][0] != "A" * 43
