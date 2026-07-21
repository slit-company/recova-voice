"""Fail-closed, offline Onnuri route receipt verification.

This is deliberately the sole parser/canonicalizer for provider facts, route
receipts, and restricted inventory attestations.  Its public errors are stable
redacted codes; callers must not surface input values.
"""
from __future__ import annotations

import os

import base64
import hashlib
import json
import re
import secrets
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence


MAX_CANONICAL_ROUTE_OBJECT_BYTES = 256 * 1024
MAX_CANONICAL_ROUTE_SIGNATURES_BYTES = 128 * 1024
MAX_RESTRICTED_INVENTORY_ENTRY_BYTES = 256 * 1024
MAX_RESTRICTED_INVENTORY_ENTRIES = 1_024



class AdapterInvoker(Protocol):
    async def __call__(self, invocation: "AdapterInvocation") -> bytes: ...



class ReplayConsumer(Protocol):
    async def __call__(
        self,
        *,
        key_id: str,
        challenge_nonce: str,
        audience: str,
        signature_sha256: str,
        expires_at_utc: datetime,
    ) -> None: ...


@dataclass(frozen=True)
class AdapterInvocation:
    audience: str
    challenge_nonce: str
    approved_root_locator_digest: str
    inventory_locator_digest: str
    inventory_version: str
    as_of_utc: str


@dataclass(frozen=True)
class CanonicalRouteEvidence:
    provider_fact_packet_bytes: bytes
    provider_fact_packet_signatures_bytes: bytes
    route_decision_bytes: bytes
    route_decision_signatures_bytes: bytes
    route_conformance_bytes: bytes
    route_conformance_signatures_bytes: bytes
    trusted_keyset_bytes: bytes
    revocations_bytes: bytes

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PACKET_SCHEMA = "recova-onnuri-provider-fact-packet-v1"
ADAPTER_SCHEMA = "recova-onnuri-restricted-inventory-adapter-v1"
DECISION_SCHEMA = "recova-onnuri-route-decision-v1"
CONFORMANCE_SCHEMA = "recova-onnuri-route-conformance-v1"
PACKET_DOMAIN = "recova.onnuri.provider-fact.v1"
ADAPTER_DOMAIN = "recova.onnuri.restricted-inventory-adapter.v1"
FACT_FIELDS = (
    "support_reference_digest", "provider_identity_digest", "carrier_profile_digest",
    "registration_plane_fact_digest", "outbound_control_plane_fact_digest",
    "media_nat_plane_fact_digest", "dns_tls_fact_digest",
)
# The first six are the explicit operational fact/profile fields.  The seventh
# DNS/TLS fact remains separately bound in the payload and receipt.
FACT_SET_FIELDS = FACT_FIELDS[:6]
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
B64URL_256 = re.compile(r"[A-Za-z0-9_-]{43}\Z")

class ReceiptError(ValueError):
    """Redacted fail-closed refusal; never include supplied values."""


def _fail(code: str) -> None:
    raise ReceiptError(code)


def canonical_json(value: Any) -> bytes:
    """RFC-8785-compatible canonical bytes for the contract's JSON subset."""
    # Route contracts use strings, objects, arrays, booleans and integer counts.
    # Reject floats rather than silently using Python's non-JCS number encoder.
    def check(item: Any) -> None:
        if isinstance(item, float):
            _fail("route_canonical_value_rejected")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str): _fail("route_canonical_value_rejected")
                check(child)
        elif isinstance(item, list):
            for child in item: check(child)
        elif item is not None and not isinstance(item, (str, int, bool)):
            _fail("route_canonical_value_rejected")
    check(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def decode_canonical_route_json(raw: bytes, *, maximum_bytes: int = MAX_CANONICAL_ROUTE_OBJECT_BYTES) -> Any:
    """Decode one authority object only after byte-for-byte JCS validation."""
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum_bytes:
        _fail("route_canonical_input_rejected")
    if raw.startswith(b"\xef\xbb\xbf"):
        _fail("route_canonical_input_rejected")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail("route_canonical_input_rejected")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        item: dict[str, Any] = {}
        for key, value in pairs:
            if key in item:
                _fail("route_canonical_input_rejected")
            item[key] = value
        return item

    try:
        value = json.loads(text, object_pairs_hook=reject_duplicates)
    except (TypeError, ValueError, json.JSONDecodeError):
        _fail("route_canonical_input_rejected")
    if canonical_json(value) != raw:
        _fail("route_canonical_input_rejected")
    return value


def decode_canonical_route_object(raw: bytes) -> dict[str, Any]:
    value = decode_canonical_route_json(raw)
    if not isinstance(value, dict):
        _fail("route_canonical_input_rejected")
    return value


def decode_canonical_route_signatures(raw: bytes) -> list[dict[str, Any]]:
    value = decode_canonical_route_json(raw, maximum_bytes=MAX_CANONICAL_ROUTE_SIGNATURES_BYTES)
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        _fail("route_canonical_input_rejected")
    return value

def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _object(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields: _fail(code)
    return value


def _digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value): _fail(code)
    return value


def _time(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"): _fail(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail(code)
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0): _fail(code)
    return parsed.astimezone(UTC)


def _as_of(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None: _fail("route_time_rejected")
        return value.astimezone(UTC)
    return _time(value, "route_time_rejected")


def _b64(value: Any, code: str) -> bytes:
    if not isinstance(value, str): _fail(code)
    try: return base64.b64decode(value, validate=True)
    except Exception: _fail(code)


def _public_key(record: Mapping[str, Any]) -> ec.EllipticCurvePublicKey:
    encoded = record.get("public_key_pem") or record.get("public_key_b64") or record.get("public_key_base64")
    try:
        if isinstance(encoded, str) and "BEGIN" in encoded:
            key = serialization.load_pem_public_key(encoded.encode())
        elif isinstance(encoded, str):
            key = serialization.load_der_public_key(_b64(encoded, "route_key_rejected"))
        else: _fail("route_key_rejected")
    except Exception: _fail("route_key_rejected")
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1): _fail("route_key_rejected")
    return key


def _key_record(keyset: Any, key_id: str, role: str, as_of: datetime, *, independence: set[str] = set()) -> Mapping[str, Any]:
    keys = keyset.get("keys") if isinstance(keyset, dict) else keyset
    if not isinstance(keys, list): _fail("route_keyset_rejected")
    matches = [x for x in keys if isinstance(x, dict) and x.get("key_id") == key_id]
    if len(matches) != 1: _fail("route_key_unknown")
    key = matches[0]
    roles = key.get("roles", [key.get("role")])
    if role not in roles: _fail("route_key_role_rejected")
    if key.get("identity_digest") in independence or key_id in independence: _fail("route_key_independence_rejected")
    issued, expires = _time(key.get("issued_at_utc"), "route_key_time_rejected"), _time(key.get("expires_at_utc"), "route_key_time_rejected")
    if not issued <= as_of < expires: _fail("route_key_time_rejected")
    return key


def _revoked(revocations: Any, key_id: str, as_of: datetime) -> bool:
    rows = revocations.get("revocations", []) if isinstance(revocations, dict) else revocations if isinstance(revocations, list) else []
    if not isinstance(rows, list): _fail("route_revocations_rejected")
    for row in rows:
        if row == key_id or (isinstance(row, dict) and row.get("key_id") == key_id and (not row.get("revoked_at_utc") or _time(row["revoked_at_utc"], "route_revocations_rejected") <= as_of)):
            return True
    return False


def _verify_signature(payload: Mapping[str, Any], signature: Mapping[str, Any], keyset: Any, revocations: Any, as_of: datetime, *, domain: str, role: str, independence: set[str] = set()) -> None:
    fields = {"key_id", "signer_identity_digest", "role", "credential_digest", "domain", "algorithm", "issued_at_utc", "expires_at_utc", "signature_b64"}
    _object(signature, fields, "route_signature_schema_rejected")
    if signature["domain"] != domain or signature["algorithm"] != "ES256" or signature["role"] != role: _fail("route_signature_contract_rejected")
    _digest(signature["signer_identity_digest"], "route_signature_contract_rejected"); _digest(signature["credential_digest"], "route_signature_contract_rejected")
    issued, expires = _time(signature["issued_at_utc"], "route_signature_time_rejected"), _time(signature["expires_at_utc"], "route_signature_time_rejected")
    if not issued <= as_of < expires: _fail("route_signature_time_rejected")
    key = _key_record(keyset, signature["key_id"], role, as_of, independence=independence)
    if _revoked(revocations, signature["key_id"], as_of): _fail("route_key_revoked")
    if key.get("identity_digest") != signature["signer_identity_digest"]: _fail("route_signature_identity_rejected")
    try: _public_key(key).verify(_b64(signature["signature_b64"], "route_signature_rejected"), canonical_json(payload), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError): _fail("route_signature_rejected")


def canonical_payload_sha256(packet: Mapping[str, Any]) -> str:
    projection = dict(packet); projection.pop("canonical_payload_sha256", None)
    return sha256(canonical_json(projection))


def fact_set_digest(packet: Mapping[str, Any]) -> str:
    return sha256(canonical_json({name: packet[name] for name in FACT_SET_FIELDS}))


def verify_provider_fact_packet(*, provider_fact_packet: Mapping[str, Any], provider_fact_packet_signatures: Sequence[Mapping[str, Any]], trusted_keyset: Any, revocations: Any, as_of_utc: datetime | str) -> dict[str, Any]:
    as_of = _as_of(as_of_utc)
    fields = {"schema_version", "packet_id", "issued_at_utc", "expires_at_utc", *FACT_FIELDS, "fact_set_digest", "canonical_payload_sha256"}
    packet = _object(provider_fact_packet, fields, "route_packet_schema_rejected")
    if packet["schema_version"] != PACKET_SCHEMA or not isinstance(packet["packet_id"], str) or not packet["packet_id"]: _fail("route_packet_schema_rejected")
    issued, expires = _time(packet["issued_at_utc"], "route_packet_time_rejected"), _time(packet["expires_at_utc"], "route_packet_time_rejected")
    if expires - issued > timedelta(hours=24) or not issued <= as_of < expires: _fail("route_packet_time_rejected")
    for name in (*FACT_FIELDS, "fact_set_digest", "canonical_payload_sha256"): _digest(packet[name], "route_packet_digest_rejected")
    if packet["canonical_payload_sha256"] != canonical_payload_sha256(packet) or packet["fact_set_digest"] != fact_set_digest(packet): _fail("route_packet_digest_rejected")
    if not isinstance(provider_fact_packet_signatures, Sequence) or isinstance(provider_fact_packet_signatures, (str, bytes)) or not provider_fact_packet_signatures: _fail("route_signature_missing")
    ordered = sorted(provider_fact_packet_signatures, key=canonical_json)
    if list(provider_fact_packet_signatures) != ordered: _fail("route_signature_order_rejected")
    seen: set[str] = set()
    for signature in ordered:
        _verify_signature(packet, signature, trusted_keyset, revocations, as_of, domain=PACKET_DOMAIN, role="provider_facts_issuer")
        if signature["key_id"] in seen: _fail("route_signature_duplicate")
        seen.add(signature["key_id"])
    return {"packet_id": packet["packet_id"], "packet_sha256": sha256(canonical_json(packet)), "expires_at_utc": packet["expires_at_utc"], "packet": packet}


def _receipt_fields(kind: str) -> set[str]:
    base = {"schema_version", "receipt_id", "issued_at_utc", "expires_at_utc", "provider_fact_packet_id", "provider_fact_packet_sha256", "request_digest", "candidate_digest", "route_profile_digest"}
    return base | ({"restricted_inventory_entries_digest"} if kind == "decision" else {"route_decision_id", "route_decision_sha256"})


def _verify_receipt(receipt: Mapping[str, Any], kind: str, packet: Mapping[str, Any], as_of: datetime) -> dict[str, Any]:
    fields = _receipt_fields(kind); item = _object(receipt, fields, f"route_{kind}_schema_rejected")
    if item["schema_version"] != (DECISION_SCHEMA if kind == "decision" else CONFORMANCE_SCHEMA) or not isinstance(item["receipt_id"], str): _fail(f"route_{kind}_schema_rejected")
    issued, expires = _time(item["issued_at_utc"], f"route_{kind}_time_rejected"), _time(item["expires_at_utc"], f"route_{kind}_time_rejected")
    packet_expires = _time(packet["expires_at_utc"], "route_packet_time_rejected")
    if not issued <= as_of < expires or expires > packet_expires: _fail(f"route_{kind}_time_rejected")
    for name in fields - {"schema_version", "receipt_id", "issued_at_utc", "expires_at_utc", "provider_fact_packet_id", "route_decision_id"}: _digest(item[name], f"route_{kind}_digest_rejected")
    if item["provider_fact_packet_id"] != packet["packet_id"] or item["provider_fact_packet_sha256"] != sha256(canonical_json(packet)): _fail(f"route_{kind}_packet_mismatch")
    return item


def _receipt_signature_verify(receipt: Mapping[str, Any], signatures: Sequence[Mapping[str, Any]], role: str, keyset: Any, revocations: Any, as_of: datetime) -> None:
    if not isinstance(signatures, Sequence) or isinstance(signatures, (str, bytes)) or not signatures: _fail("route_signature_missing")
    domain_role = "approver" if role == "route_approver" else role
    for sig in signatures: _verify_signature(receipt, sig, keyset, revocations, as_of, domain=f"recova.onnuri.route-{domain_role}.v1", role=role)


async def create_decision(*, provider_fact_packet: Mapping[str, Any], provider_fact_packet_signatures: Sequence[Mapping[str, Any]], restricted_inventory_adapter: bytes, trusted_keyset: Any, revocations: Any, as_of_utc: datetime | str, request_digest: str, candidate_digest: str, route_profile_digest: str, receipt_id: str, expires_at_utc: str, adapter_challenge_nonce: str, approved_root_locator_digest: str, inventory_locator_digest: str, inventory_version: str, replay_consumer: ReplayConsumer, approved_root: Path | None = None) -> dict[str, Any]:
    packet = verify_provider_fact_packet(provider_fact_packet=provider_fact_packet, provider_fact_packet_signatures=provider_fact_packet_signatures, trusted_keyset=trusted_keyset, revocations=revocations, as_of_utc=as_of_utc)
    adapter = await verify_restricted_inventory_adapter(adapter=restricted_inventory_adapter, trusted_keyset=trusted_keyset, revocations=revocations, as_of_utc=as_of_utc, audience="route_decision", challenge_nonce=adapter_challenge_nonce, approved_root=approved_root, approved_root_locator_digest=approved_root_locator_digest, inventory_locator_digest=inventory_locator_digest, inventory_version=inventory_version, replay_consumer=replay_consumer)
    receipt = {"schema_version": DECISION_SCHEMA, "receipt_id": receipt_id, "issued_at_utc": _as_of(as_of_utc).isoformat().replace("+00:00", "Z"), "expires_at_utc": expires_at_utc, "provider_fact_packet_id": packet["packet_id"], "provider_fact_packet_sha256": packet["packet_sha256"], "request_digest": request_digest, "candidate_digest": candidate_digest, "route_profile_digest": route_profile_digest, "restricted_inventory_entries_digest": adapter["entries_digest"]}
    _verify_receipt(receipt, "decision", packet["packet"], _as_of(as_of_utc)); return receipt


def verify_decision(*, route_decision: Mapping[str, Any], route_decision_signatures: Sequence[Mapping[str, Any]], provider_fact_packet: Mapping[str, Any], provider_fact_packet_signatures: Sequence[Mapping[str, Any]], trusted_keyset: Any, revocations: Any, as_of_utc: datetime | str) -> dict[str, Any]:
    as_of = _as_of(as_of_utc); packet = verify_provider_fact_packet(provider_fact_packet=provider_fact_packet, provider_fact_packet_signatures=provider_fact_packet_signatures, trusted_keyset=trusted_keyset, revocations=revocations, as_of_utc=as_of)
    decision = _verify_receipt(route_decision, "decision", packet["packet"], as_of); _receipt_signature_verify(decision, route_decision_signatures, "route_approver", trusted_keyset, revocations, as_of); return decision


def create_conformance(*, route_decision: Mapping[str, Any], route_decision_signatures: Sequence[Mapping[str, Any]], provider_fact_packet: Mapping[str, Any], provider_fact_packet_signatures: Sequence[Mapping[str, Any]], trusted_keyset: Any, revocations: Any, as_of_utc: datetime | str, receipt_id: str, expires_at_utc: str) -> dict[str, Any]:
    decision = verify_decision(route_decision=route_decision, route_decision_signatures=route_decision_signatures, provider_fact_packet=provider_fact_packet, provider_fact_packet_signatures=provider_fact_packet_signatures, trusted_keyset=trusted_keyset, revocations=revocations, as_of_utc=as_of_utc)
    receipt = {"schema_version": CONFORMANCE_SCHEMA, "receipt_id": receipt_id, "issued_at_utc": _as_of(as_of_utc).isoformat().replace("+00:00", "Z"), "expires_at_utc": expires_at_utc, "provider_fact_packet_id": decision["provider_fact_packet_id"], "provider_fact_packet_sha256": decision["provider_fact_packet_sha256"], "request_digest": decision["request_digest"], "candidate_digest": decision["candidate_digest"], "route_profile_digest": decision["route_profile_digest"], "route_decision_id": decision["receipt_id"], "route_decision_sha256": sha256(canonical_json(decision))}
    _verify_receipt(receipt, "conformance", provider_fact_packet, _as_of(as_of_utc)); return receipt


def verify_conformance(*, route_conformance: Mapping[str, Any], route_conformance_signatures: Sequence[Mapping[str, Any]], route_decision: Mapping[str, Any], route_decision_signatures: Sequence[Mapping[str, Any]], provider_fact_packet: Mapping[str, Any], provider_fact_packet_signatures: Sequence[Mapping[str, Any]], trusted_keyset: Any, revocations: Any, as_of_utc: datetime | str) -> dict[str, Any]:
    as_of = _as_of(as_of_utc); decision = verify_decision(route_decision=route_decision, route_decision_signatures=route_decision_signatures, provider_fact_packet=provider_fact_packet, provider_fact_packet_signatures=provider_fact_packet_signatures, trusted_keyset=trusted_keyset, revocations=revocations, as_of_utc=as_of)
    conformance = _verify_receipt(route_conformance, "conformance", provider_fact_packet, as_of)
    if conformance["route_decision_id"] != decision["receipt_id"] or conformance["route_decision_sha256"] != sha256(canonical_json(decision)): _fail("route_conformance_decision_mismatch")
    _receipt_signature_verify(conformance, route_conformance_signatures, "conformance_producer", trusted_keyset, revocations, as_of); return conformance


def _verify_inventory_entry(root: Path | int, relative_path: str, expected_sha256: str) -> None:
    """Hash a regular, non-symlinked inventory entry through its opened inode."""
    close_root = isinstance(root, Path)
    root_fd = -1
    descriptor = -1
    try:
        root_fd = (
            os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            if close_root
            else os.dup(root)
        )
        root_info = os.fstat(root_fd)
        if not stat.S_ISDIR(root_info.st_mode):
            _fail("route_adapter_path_rejected")
        components = Path(relative_path).parts
        for component in components[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=root_fd,
            )
            os.close(root_fd)
            root_fd = next_fd
        descriptor = os.open(
            components[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size < 0
            or info.st_size > MAX_RESTRICTED_INVENTORY_ENTRY_BYTES
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            _fail("route_adapter_path_rejected")
        digest = hashlib.sha256()
        remaining = MAX_RESTRICTED_INVENTORY_ENTRY_BYTES
        while chunk := os.read(descriptor, min(65536, remaining + 1)):
            remaining -= len(chunk)
            if remaining < 0:
                _fail("route_adapter_path_rejected")
            digest.update(chunk)
        if digest.hexdigest() != expected_sha256:
            _fail("route_adapter_path_rejected")
    except OSError:
        _fail("route_adapter_path_rejected")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if root_fd >= 0:
            os.close(root_fd)


async def verify_restricted_inventory_adapter(*, adapter: bytes, trusted_keyset: Any, revocations: Any, as_of_utc: datetime | str, audience: str, challenge_nonce: str, approved_root: Path | int | None = None, approved_root_locator_digest: str, inventory_locator_digest: str, inventory_version: str, replay_consumer: ReplayConsumer) -> dict[str, Any]:

    as_of = _as_of(as_of_utc)
    obj = decode_canonical_route_object(adapter)
    fields = {"schema_version", "domain", "algorithm", "key_id", "signer_identity_digest", "role", "issued_at_utc", "expires_at_utc", "challenge_nonce", "audience", "approved_root_locator_digest", "inventory_locator_digest", "inventory_version", "entries", "entries_digest", "claims", "signature_b64"}; obj = _object(obj, fields, "route_adapter_schema_rejected")
    if obj["schema_version"] != ADAPTER_SCHEMA or obj["domain"] != ADAPTER_DOMAIN or obj["algorithm"] != "ES256" or obj["role"] != "restricted_inventory_adapter" or obj["audience"] != audience or not isinstance(obj["challenge_nonce"], str) or not B64URL_256.fullmatch(obj["challenge_nonce"]): _fail("route_adapter_contract_rejected")
    if obj["challenge_nonce"] != challenge_nonce: _fail("route_adapter_challenge_rejected")
    issued, expires = _time(obj["issued_at_utc"], "route_adapter_time_rejected"), _time(obj["expires_at_utc"], "route_adapter_time_rejected")
    if expires - issued > timedelta(seconds=300) or not issued <= as_of < expires: _fail("route_adapter_time_rejected")
    entries = obj["entries"]
    if (
        not isinstance(entries, list)
        or len(entries) > MAX_RESTRICTED_INVENTORY_ENTRIES
        or entries != sorted(entries, key=lambda x: (x.get("logical_name", ""), x.get("relative_path", "")))
    ):
        _fail("route_adapter_entries_rejected")
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        _object(entry, {"logical_name", "relative_path", "sha256", "classification"}, "route_adapter_entries_rejected")
        pair = (entry["logical_name"], entry["relative_path"])
        if pair in seen or entry["classification"] not in {"base", "produced", "generated", "tooling", "image-metadata"}: _fail("route_adapter_entries_rejected")
        seen.add(pair); _digest(entry["sha256"], "route_adapter_entries_rejected")
        rel = Path(entry["relative_path"])
        if rel.is_absolute() or not entry["relative_path"] or ".." in rel.parts: _fail("route_adapter_path_rejected")
        if approved_root is not None:
            _verify_inventory_entry(approved_root, entry["relative_path"], entry["sha256"])

    if obj["entries_digest"] != sha256(canonical_json(entries)): _fail("route_adapter_entries_rejected")
    claims = _object(obj["claims"], {"purpose", "approved_root_locator_digest", "inventory_locator_digest", "inventory_version", "entries_digest", "entries_count", "audience", "challenge_nonce"}, "route_adapter_claims_rejected")
    expected = {"purpose": "onnuri_route_inventory_attestation", "approved_root_locator_digest": obj["approved_root_locator_digest"], "inventory_locator_digest": obj["inventory_locator_digest"], "inventory_version": obj["inventory_version"], "entries_digest": obj["entries_digest"], "entries_count": len(entries), "audience": audience, "challenge_nonce": challenge_nonce}
    if claims != expected: _fail("route_adapter_claims_rejected")
    if (approved_root_locator_digest, inventory_locator_digest, inventory_version) != (obj["approved_root_locator_digest"], obj["inventory_locator_digest"], obj["inventory_version"]): _fail("route_adapter_binding_rejected")
    payload = dict(obj); signature = payload.pop("signature_b64")
    signature_record = {"key_id": obj["key_id"], "signer_identity_digest": obj["signer_identity_digest"], "role": obj["role"], "credential_digest": "0" * 64, "domain": obj["domain"], "algorithm": obj["algorithm"], "issued_at_utc": obj["issued_at_utc"], "expires_at_utc": obj["expires_at_utc"], "signature_b64": signature}
    _verify_signature(payload, signature_record, trusted_keyset, revocations, as_of, domain=ADAPTER_DOMAIN, role="restricted_inventory_adapter")
    try:
        await replay_consumer(key_id=obj["key_id"], challenge_nonce=challenge_nonce, audience=audience, signature_sha256=sha256(_b64(signature, "route_adapter_signature_rejected")), expires_at_utc=expires)
    except ReceiptError:
        raise
    except Exception:
        _fail("route_adapter_replay")
    return obj

@dataclass(frozen=True)
class VerifiedRouteChain:
    provider_fact_packet_id: str; provider_fact_packet_sha256: str; route_decision_id: str; route_decision_sha256: str; route_conformance_id: str; route_conformance_sha256: str; verified_as_of_utc: str; expires_at_utc: str; request_digest: str; candidate_digest: str; route_profile_digest: str; adapter_entries_digest: str; keyset_sha256: str; revocations_sha256: str

async def verify_route_chain(*, evidence: CanonicalRouteEvidence, adapter_invoker: AdapterInvoker, replay_consumer: ReplayConsumer, as_of_utc: datetime | str, expected_request_digest: str, expected_candidate_digest: str, expected_route_profile_digest: str, approved_root_locator_digest: str, inventory_locator_digest: str, inventory_version: str, approved_root: Path | int | None = None) -> VerifiedRouteChain:

    """Verify sealed canonical evidence and consume one challenge-bound adapter response."""
    as_of = _as_of(as_of_utc)
    if not isinstance(evidence, CanonicalRouteEvidence):
        _fail("route_canonical_input_rejected")
    for digest in (expected_request_digest, expected_candidate_digest, expected_route_profile_digest, approved_root_locator_digest, inventory_locator_digest):
        _digest(digest, "route_chain_binding_mismatch")
    if not isinstance(inventory_version, str) or not inventory_version:
        _fail("route_chain_binding_mismatch")
    packet = decode_canonical_route_object(evidence.provider_fact_packet_bytes)
    packet_signatures = decode_canonical_route_signatures(evidence.provider_fact_packet_signatures_bytes)
    decision = decode_canonical_route_object(evidence.route_decision_bytes)
    decision_signatures = decode_canonical_route_signatures(evidence.route_decision_signatures_bytes)
    conformance = decode_canonical_route_object(evidence.route_conformance_bytes)
    conformance_signatures = decode_canonical_route_signatures(evidence.route_conformance_signatures_bytes)
    keyset = decode_canonical_route_object(evidence.trusted_keyset_bytes)
    revocations = decode_canonical_route_json(evidence.revocations_bytes)
    verified_packet = verify_provider_fact_packet(provider_fact_packet=packet, provider_fact_packet_signatures=packet_signatures, trusted_keyset=keyset, revocations=revocations, as_of_utc=as_of)
    verified_decision = verify_decision(route_decision=decision, route_decision_signatures=decision_signatures, provider_fact_packet=packet, provider_fact_packet_signatures=packet_signatures, trusted_keyset=keyset, revocations=revocations, as_of_utc=as_of)
    verified_conformance = verify_conformance(route_conformance=conformance, route_conformance_signatures=conformance_signatures, route_decision=decision, route_decision_signatures=decision_signatures, provider_fact_packet=packet, provider_fact_packet_signatures=packet_signatures, trusted_keyset=keyset, revocations=revocations, as_of_utc=as_of)
    challenge_nonce = secrets.token_urlsafe(32)
    invocation = AdapterInvocation("route_chain", challenge_nonce, approved_root_locator_digest, inventory_locator_digest, inventory_version, as_of.isoformat().replace("+00:00", "Z"))
    try:
        adapter_raw = await adapter_invoker(invocation)
    except ReceiptError:
        raise
    except Exception:
        _fail("route_adapter_invocation_rejected")
    adapter = await verify_restricted_inventory_adapter(adapter=adapter_raw, trusted_keyset=keyset, revocations=revocations, as_of_utc=as_of, audience=invocation.audience, challenge_nonce=challenge_nonce, approved_root=approved_root, approved_root_locator_digest=approved_root_locator_digest, inventory_locator_digest=inventory_locator_digest, inventory_version=inventory_version, replay_consumer=replay_consumer)
    for receipt in (verified_decision, verified_conformance):
        if (receipt["request_digest"], receipt["candidate_digest"], receipt["route_profile_digest"]) != (expected_request_digest, expected_candidate_digest, expected_route_profile_digest): _fail("route_chain_binding_mismatch")
    expiry = min(_time(verified_packet["expires_at_utc"], "route_packet_time_rejected"), _time(verified_decision["expires_at_utc"], "route_decision_time_rejected"), _time(verified_conformance["expires_at_utc"], "route_conformance_time_rejected"), _time(adapter["expires_at_utc"], "route_adapter_time_rejected"))
    return VerifiedRouteChain(verified_packet["packet_id"], verified_packet["packet_sha256"], verified_decision["receipt_id"], sha256(evidence.route_decision_bytes), verified_conformance["receipt_id"], sha256(evidence.route_conformance_bytes), as_of.isoformat().replace("+00:00", "Z"), expiry.isoformat().replace("+00:00", "Z"), expected_request_digest, expected_candidate_digest, expected_route_profile_digest, adapter["entries_digest"], sha256(evidence.trusted_keyset_bytes), sha256(evidence.revocations_bytes))
