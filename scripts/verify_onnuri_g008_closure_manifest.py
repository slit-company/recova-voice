#!/usr/bin/env python3
"""Fail-closed offline verifier for the redacted G008 closure contract.

Every external assertion is its own signed receipt.  The closure-manifest
signature only binds those receipts together and is never evidence for them.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import os
import json
import re
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Mapping
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
_KEYSET_PATH = Path(__file__).resolve().parents[1] / "infra" / "onnuri-seoul-staging-phase-c-smoke" / "trusted_keys" / "phase_c_live_preflight_v1.json"
_TRUSTED_KEYSET_SHA256 = "00645f3af8230c742951c12f17a713afde209de12182cd6e3722ac59445507aa"
_CANONICAL_KEYS = {
    "phase-b": ("recova-g008-phase-b-v1", "83f0d748928d70bca5b2c3f9cf80c059d74b359a215ec0ba1f99c334e45968b0"),
    "supplier": ("recova-g008-supplier-v1", "06a4275c751d9e6145cde4c2380c2fd0bbb0b66bcc8542c82b4c611d5d365fdb"),
    "provider": ("recova-g008-provider-v1", "eb17788d64ad5dd51183b843910ad70da143dfc32b857aa29ad449b4b58505bf"),
    "derivative": ("recova-g008-derivative-v1", "fc49b9709d1b2e99dabc57b9f2857d30639fd13589c49c464b68ec1cf22e2dfa"),
    "f12": ("recova-g008-f12-v1", "e38b55ccd4827f4971750e9bcd66b54e745dda3f10d6977db5a50940df331e17"),
    "authority": ("recova-g008-authority-v1", "977e114e74aae8a837e41665a800e5b545ccd201883223569b95a566c1e9667d"),
    "cost": ("recova-g008-cost-v1", "3aa58f8873d25c0ea32e77194d395709fd392b43a56efcb92826543f23dc06ec"),
    "phase-c-preflight": ("recova-g008-phase-c-preflight-v1", "68af3d0f08a9553df3a97e6887e59d415896314f907e4fac0e6a80cc165e046e"),
}
_ROLE_AUTHORITY = {
    "provider-preflight": "provider", "provider-postcall": "cost", "supplier": "supplier",
    "ownership": "authority", "secret-custodian": "authority", "phase-b": "phase-b",
    "g007": "phase-b", "g009": "derivative", "f12": "f12", "approver": "phase-c-preflight",
    "provider-deletion": "provider", "provider-inventory": "provider",
    "network-inventory-pre": "authority", "network-inventory-post": "authority",
    "register": "authority", "unregister": "authority", "dispatch": "f12", "media": "f12",
    "status": "provider", "cdr": "cost", "human-rx": "authority", "human-tx": "authority",
    "closure-event": "authority", "closure-manifest": "phase-c-preflight",
}

_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$")
_RAW_VALUE = re.compile(r"(?:\+?[1-9][0-9]{7,14}|(?:https?|wss?)://|(?:sip|tel):)", re.I)
_SENSITIVE_KEY = re.compile(r"(?:phone|endpoint|address|number|uri|url|sdp|media)", re.I)
_MAX_FRESHNESS = timedelta(minutes=5)
_ALLOWED_LOCAL_V4_RANGES = tuple(
    ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_SECRET_PURPOSES = ("provider_auth", "rtp_control", "sip_registration")
_ATTEMPT_RECEIPT_ROLES = ("dispatch", "media", "status", "cdr", "human-rx", "human-tx")
_BINDING_FIELDS = {
    "contract_version", "kind", "tenant_digest", "account_digest", "envelope_digest",
    "candidate_digest", "run_id_digest", "activation_nonce_digest", "run_nonce_digest",
    "trusted_keyset_digest", "execution_bundle_digest", "issued_at", "expires_at",
}
_STAGE_RECEIPT_FIELDS = {
    "kind", "organization_id", "execution_seal_uuid", "execution_nonce_digest",
    "candidate_digest", "gate_envelope_digest", "stage", "ordinal", "state",
    "stage_deadline_seconds",
}
_FINAL_RECEIPT_FIELDS = {
    "kind", "organization_id", "execution_seal_uuid", "execution_nonce_digest",
    "candidate_digest", "gate_envelope_digest", "state", "trusted_keyset_digest",
    "containment_verified", "stage_receipts",
}
_ATTEMPT_ROLE_FIELDS = {
    "dispatch": {"provider_call_id_digest", "dispatch_artifact_digest"},
    "media": {"provider_call_id_digest", "media_artifact_digest"},
    "status": {
        "provider_call_id_digest", "status_artifact_digest", "terminal_status", "terminal_disposition",
    },
    "cdr": {"provider_call_id_digest", "cdr_artifact_digest", "billed_duration_ms"},
    "human-rx": {
        "provider_call_id_digest", "human_rx_artifact_digest", "human_rx_duration_ms",
        "human_rx_acknowledgement", "human_rx_acknowledgement_artifact_digest",
    },
    "human-tx": {
        "provider_call_id_digest", "human_tx_artifact_digest", "human_tx_duration_ms",
        "human_tx_acknowledgement", "human_tx_acknowledgement_artifact_digest",
    },
}
_EVIDENCE_SPECS: dict[str, tuple[str, set[str]]] = {
    "provider_preflight": ("provider-preflight", {"currency", "starting_balance", "preflight_receipt_digest"}),
    "provider_postcall": ("provider-postcall", {"currency", "ending_balance", "cost_delta", "preflight_receipt_digest", "postcall_receipt_digest"}),
    "supplier_scope": ("supplier", {"rtp_cidr", "rtcp_cidr", "rtp_ports", "rtcp_ports", "scope_receipt_digest"}),
    "owned_mapping": ("ownership", {"mapping_digest", "ownership_receipt_digest"}),
    "secret_versions": ("secret-custodian", {"versions", "version_receipt_digest"}),
    "phase_b_baseline": ("phase-b", {"baseline_manifest_digest", "baseline_receipt_digest"}),
    "g007_baseline": ("g007", {"baseline_manifest_digest", "baseline_receipt_digest"}),
    "g009_candidate": ("g009", {"candidate_receipt_digest"}),
    "f12_readiness": ("f12", {"ready", "readiness_receipt_digest"}),
    "approval": ("approver", {"approved", "approval_receipt_digest"}),
    "provider_deletion": ("provider-deletion", {"resources", "operations", "deletion_receipt_digest"}),
    "provider_absence": ("provider-inventory", {"resources", "deletion_receipt_digest", "absence_receipt_digest"}),
    "network_preactivation": ("network-inventory-pre", {"network_digest", "generation", "routers", "nats", "inventory_receipt_digest"}),
    "network_postactivation": ("network-inventory-post", {"network_digest", "generation", "routers", "nats", "inventory_receipt_digest"}),
}
_OPTIONAL_EVIDENCE = {"g007_baseline"}
_EVIDENCE_SELF_DIGEST = {
    "provider_preflight": "preflight_receipt_digest",
    "provider_postcall": "postcall_receipt_digest",
    "supplier_scope": "scope_receipt_digest",
    "owned_mapping": "ownership_receipt_digest",
    "secret_versions": "version_receipt_digest",
    "phase_b_baseline": "baseline_receipt_digest",
    "g007_baseline": "baseline_receipt_digest",
    "g009_candidate": "candidate_receipt_digest",
    "f12_readiness": "readiness_receipt_digest",
    "approval": "approval_receipt_digest",
    "provider_deletion": "deletion_receipt_digest",
    "provider_absence": "absence_receipt_digest",
    "network_preactivation": "inventory_receipt_digest",
    "network_postactivation": "inventory_receipt_digest",
}
_CLOSURE_KINDS = (
    "deregistration", "rtp_stop", "provider_credential_revocation", "iam_revocation",
    "firewall_revocation", "resource_destruction", "phase_b_equality", "waiting",
)


class ManifestVerificationError(ValueError):
    """The G008 closure proof is malformed, stale, unsafe, or untrusted."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestVerificationError(f"duplicate field: {key}")
        result[key] = value
    return result


def load_manifest(path: str | Path) -> dict[str, Any]:
    try:
        raw = Path(path).read_bytes()
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys, parse_constant=lambda value: (_ for _ in ()).throw(ManifestVerificationError(f"invalid JSON constant: {value}")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestVerificationError("manifest is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ManifestVerificationError("manifest must be an object")
    return value


def _object(value: Any, fields: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        actual = set(value) if isinstance(value, dict) else set()
        raise ManifestVerificationError(f"{name} fields invalid; missing={sorted(fields - actual)}, unknown={sorted(actual - fields)}")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ManifestVerificationError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _receipt_digest(payload: Mapping[str, Any], field: str) -> str:
    unsigned = dict(payload)
    claimed = _digest(unsigned.pop(field), field)
    computed = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    if claimed != computed:
        raise ManifestVerificationError(f"{field} does not match the canonical receipt payload")
    return claimed


def _execution_identity(payload: Mapping[str, Any], name: str) -> None:
    organization_id = payload["organization_id"]
    if type(organization_id) is not int or organization_id <= 0:
        raise ManifestVerificationError(f"{name}.organization_id must be a positive integer")
    seal_uuid = payload["execution_seal_uuid"]
    try:
        parsed_uuid = uuid.UUID(seal_uuid) if isinstance(seal_uuid, str) else None
    except ValueError as exc:
        raise ManifestVerificationError(
            f"{name}.execution_seal_uuid must be a canonical UUID"
        ) from exc
    if parsed_uuid is None or str(parsed_uuid) != seal_uuid:
        raise ManifestVerificationError(
            f"{name}.execution_seal_uuid must be a canonical UUID"
        )
    for field, value in payload.items():
        if field.endswith("_digest"):
            _digest(value, f"{name}.{field}")


def _exact_integer(value: Any, expected: int, name: str) -> None:
    if type(value) is not int or value != expected:
        raise ManifestVerificationError(f"{name} must be the integer {expected}")


def _load_trusted_keys() -> dict[str, bytes]:
    try:
        raw = _KEYSET_PATH.read_bytes()
    except OSError as exc:
        raise ManifestVerificationError("canonical trusted keyset is unavailable") from exc
    if hashlib.sha256(raw).hexdigest() != _TRUSTED_KEYSET_SHA256:
        raise ManifestVerificationError("canonical trusted keyset digest is invalid")
    try:
        keyset = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestVerificationError("canonical trusted keyset is invalid") from exc
    if canonical_json_bytes(keyset) != raw:
        raise ManifestVerificationError("canonical trusted keyset is not canonical")
    keyset = _object(keyset, {"keys", "schema_version"}, "trusted_keyset")
    if keyset["schema_version"] != "recova-phase-c-live-preflight-keyset.v1":
        raise ManifestVerificationError("canonical trusted keyset version is invalid")
    result: dict[str, bytes] = {}
    seen: set[bytes] = set()
    for entry_value in keyset["keys"]:
        entry = _object(
            entry_value,
            {"algorithm", "key_id", "public_key_base64url", "public_key_sha256", "role"},
            "trusted_key",
        )
        role = entry["role"]
        if role not in _CANONICAL_KEYS or entry["algorithm"] != "Ed25519":
            raise ManifestVerificationError("canonical trusted key binding is invalid")
        if (entry["key_id"], entry["public_key_sha256"]) != _CANONICAL_KEYS[role]:
            raise ManifestVerificationError("canonical trusted key binding is invalid")
        encoded = entry["public_key_base64url"]
        try:
            public = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        except (ValueError, TypeError, binascii.Error) as exc:
            raise ManifestVerificationError("canonical trusted key encoding is invalid") from exc
        if (
            len(public) != 32
            or base64.urlsafe_b64encode(public).rstrip(b"=").decode() != encoded
            or hashlib.sha256(public).hexdigest() != entry["public_key_sha256"]
            or role in result
            or public in seen
        ):
            raise ManifestVerificationError("canonical trusted keys are not distinct")
        result[role] = public
        seen.add(public)
    if set(result) != set(_CANONICAL_KEYS):
        raise ManifestVerificationError("canonical trusted key roles are incomplete")
    return result


def _resource_inventory(value: Any, name: str, *, absent: bool = False) -> list[tuple[str, str, int]]:
    if not isinstance(value, list) or not value:
        raise ManifestVerificationError(f"{name} must be a non-empty exact resource inventory")
    expected_fields = {"resource_id_digest", "resource_type", "generation"}
    if absent:
        expected_fields |= {"present", "provider_query_digest"}
    result: list[tuple[str, str, int]] = []
    for index, raw in enumerate(value):
        item = _object(raw, expected_fields, f"{name}[{index}]")
        resource_id = _digest(item["resource_id_digest"], f"{name}[{index}].resource_id_digest")
        resource_type, generation = item["resource_type"], item["generation"]
        if not isinstance(resource_type, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", resource_type):
            raise ManifestVerificationError(f"{name}[{index}].resource_type is invalid")
        if type(generation) is not int or generation < 1:
            raise ManifestVerificationError(f"{name}[{index}].generation is invalid")
        if absent:
            if item["present"] is not False:
                raise ManifestVerificationError(f"{name}[{index}] does not prove provider absence")
            _digest(item["provider_query_digest"], f"{name}[{index}].provider_query_digest")
        result.append((resource_type, resource_id, generation))
    if result != sorted(result) or len(set(result)) != len(result):
        raise ManifestVerificationError(f"{name} must be sorted and unique")
    return result


def _deletion_operations(value: Any, name: str) -> list[tuple[str, str, int]]:
    if not isinstance(value, list) or not value:
        raise ManifestVerificationError(f"{name} must be a non-empty provider operation inventory")
    result: list[tuple[str, str, int]] = []
    fields = {"resource_id_digest", "resource_type", "generation", "provider_operation_digest", "result"}
    for index, raw in enumerate(value):
        item = _object(raw, fields, f"{name}[{index}]")
        if item["result"] != "deleted":
            raise ManifestVerificationError(f"{name}[{index}] is not provider-confirmed deletion")
        _digest(item["provider_operation_digest"], f"{name}[{index}].provider_operation_digest")
        resource_type = item["resource_type"]
        resource_id = _digest(item["resource_id_digest"], f"{name}[{index}].resource_id_digest")
        generation = item["generation"]
        if not isinstance(resource_type, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", resource_type):
            raise ManifestVerificationError(f"{name}[{index}].resource_type is invalid")
        if type(generation) is not int or generation < 1:
            raise ManifestVerificationError(f"{name}[{index}].generation is invalid")
        result.append((resource_type, resource_id, generation))
    if result != sorted(result) or len(set(result)) != len(result):
        raise ManifestVerificationError(f"{name} must be sorted and unique")
    return result


def _network_absence(payload: Mapping[str, Any], name: str) -> None:
    _digest(payload["network_digest"], f"{name}.network_digest")
    if type(payload["generation"]) is not int or payload["generation"] < 1:
        raise ManifestVerificationError(f"{name}.generation is invalid")
    if payload["routers"] != [] or payload["nats"] != []:
        raise ManifestVerificationError(f"{name} must prove empty provider router and NAT inventories")


def _timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ManifestVerificationError(f"{name} must be a UTC RFC3339 timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ManifestVerificationError(f"{name} must be a UTC RFC3339 timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ManifestVerificationError(f"{name} must be a canonical UTC RFC3339 timestamp")
    return parsed


def _fresh_window(issued_value: Any, expires_value: Any, now: datetime, name: str) -> tuple[datetime, datetime]:
    issued = _timestamp(issued_value, f"{name}.issued_at")
    expires = _timestamp(expires_value, f"{name}.expires_at")
    if issued > now or expires <= now or expires <= issued or expires - issued > _MAX_FRESHNESS:
        raise ManifestVerificationError(f"{name} is not fresh")
    return issued, expires


def _decimal(value: Any, name: str) -> Decimal:
    if not isinstance(value, str) or not _DECIMAL.fullmatch(value):
        raise ManifestVerificationError(f"{name} must be a canonical non-negative decimal")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ManifestVerificationError(f"{name} must be a canonical non-negative decimal") from exc
    if not parsed.is_finite():
        raise ManifestVerificationError(f"{name} must be finite")
    return parsed


def _forbid_raw(value: Any, *, digest_context: bool = False) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            is_digest = key.endswith("_digest") or key.endswith("_receipt") or key in _ATTEMPT_RECEIPT_ROLES
            if _SENSITIVE_KEY.search(key) and not is_digest:
                raise ManifestVerificationError(f"raw-sensitive field is forbidden: {key}")
            _forbid_raw(child, digest_context=is_digest)
    elif isinstance(value, list):
        for child in value:
            _forbid_raw(child)
    elif isinstance(value, str) and not digest_context and _RAW_VALUE.search(value):
        raise ManifestVerificationError("raw phone, endpoint, or media value is forbidden")


def _verify_signature(
    payload: Mapping[str, Any],
    signature_value: Any,
    public_keys: Mapping[str, bytes],
    expected_role: str,
    name: str,
) -> None:
    canonical_role = _ROLE_AUTHORITY.get(expected_role)
    if canonical_role is None:
        raise ManifestVerificationError(f"{name} signer role is not canonical")
    expected_key_id = _CANONICAL_KEYS[canonical_role][0]
    signature = _object(signature_value, {"algorithm", "key_id", "value"}, f"{name}.signature")
    if signature["algorithm"] != "Ed25519" or signature["key_id"] != expected_key_id:
        raise ManifestVerificationError(f"{name} has the wrong signer")
    key = public_keys.get(canonical_role)
    if not isinstance(key, bytes) or len(key) != 32:
        raise ManifestVerificationError(f"{name} signer is not trusted")
    try:
        encoded = base64.b64decode(signature["value"], validate=True)
        if len(encoded) != 64:
            raise ValueError("wrong signature length")
        Ed25519PublicKey.from_public_bytes(key).verify(encoded, canonical_json_bytes(payload))
    except (ValueError, TypeError, binascii.Error, InvalidSignature) as exc:
        raise ManifestVerificationError(f"{name} signature is invalid") from exc


def _load_execution_bundle(
    source: bytes | bytearray | str | Path,
    expected_digest: str,
    public_keys: Mapping[str, bytes],
    now: datetime | None = None,
) -> Mapping[str, Any]:
    try:
        raw = bytes(source) if isinstance(source, (bytes, bytearray)) else Path(source).read_bytes()
        bundle = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ManifestVerificationError(f"invalid JSON constant: {value}")
            ),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestVerificationError("execution bundle is not valid JSON") from exc
    if canonical_json_bytes(bundle) != raw:
        raise ManifestVerificationError("execution bundle is not canonical")
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ManifestVerificationError("execution bundle digest mismatch")
    bundle = _object(
        bundle,
        {"schema_version", "trusted_keyset_digest", "nonce", "seal", "stages", "final"},
        "execution_bundle",
    )
    if (
        bundle["schema_version"] != "recova-g008-execution-bundle-v2"
        or bundle["trusted_keyset_digest"] != _TRUSTED_KEYSET_SHA256
    ):
        raise ManifestVerificationError("execution bundle trust binding is invalid")

    def signed(value: Any, name: str) -> Mapping[str, Any]:
        receipt = _object(value, {"payload", "signature"}, name)
        payload = receipt["payload"]
        if not isinstance(payload, dict):
            raise ManifestVerificationError(f"{name}.payload must be an object")
        _verify_signature(payload, receipt["signature"], public_keys, "closure-event", name)
        return payload

    nonce = signed(bundle["nonce"], "execution_bundle.nonce")
    nonce_fields = {
        "kind", "organization_id", "execution_seal_uuid", "execution_nonce_digest",
        "candidate_digest", "gate_envelope_digest", "trusted_keyset_digest", "state",
        "pre_existing",
    }
    _object(nonce, nonce_fields, "execution_bundle.nonce.payload")
    _execution_identity(nonce, "execution_bundle.nonce.payload")
    if (
        nonce["kind"] != "nonce_consumption"
        or nonce["state"] != "consumed"
        or nonce["pre_existing"] is not False
        or nonce["trusted_keyset_digest"] != _TRUSTED_KEYSET_SHA256
    ):
        raise ManifestVerificationError("execution nonce receipt is invalid")

    seal = signed(bundle["seal"], "execution_bundle.seal")
    seal_fields = {
        "kind", "organization_id", "execution_seal_uuid", "execution_nonce_digest",
        "candidate_digest", "gate_envelope_digest", "schema_version",
        "destination_hmac_digest", "stages", "retry_count", "concurrency_count",
        "call_deadline_seconds", "stage_deadline_seconds",
        "live_window_starts_at", "live_window_expires_at",
        "reserved_inbound_did_digest", "reserved_inbound_caller_digest", "policy_digest",
        "trusted_keyset_digest", "state", "pre_existing",
        "registration_attestation_key_id",
        "registration_attestation_public_key_sha256",
    }
    _object(seal, seal_fields, "execution_bundle.seal.payload")
    _execution_identity(seal, "execution_bundle.seal.payload")
    _exact_integer(seal["retry_count"], 0, "execution_bundle.seal.payload.retry_count")
    _exact_integer(
        seal["concurrency_count"], 1, "execution_bundle.seal.payload.concurrency_count"
    )
    _exact_integer(
        seal["call_deadline_seconds"], 60,
        "execution_bundle.seal.payload.call_deadline_seconds",
    )
    _exact_integer(
        seal["stage_deadline_seconds"], 60,
        "execution_bundle.seal.payload.stage_deadline_seconds",
    )
    live_starts = _timestamp(
        seal["live_window_starts_at"], "execution_bundle.seal.payload.live_window_starts_at"
    )
    live_expires = _timestamp(
        seal["live_window_expires_at"], "execution_bundle.seal.payload.live_window_expires_at"
    )
    if live_expires <= live_starts or live_expires - live_starts > _MAX_FRESHNESS:
        raise ManifestVerificationError("execution seal live window is not fresh and ordered")
    if now is not None and (live_starts > now or live_expires <= now):
        raise ManifestVerificationError("execution seal live window is not currently fresh")
    if (
        seal["kind"] != "execution_seal"
        or seal["schema_version"] != "recova-g008-execution-seal-v1"
        or seal["stages"] != ["register", "outbound_call", "inbound_call", "unregister"]
        or seal["state"] != "sealed"
        or seal["pre_existing"] is not False
        or seal["trusted_keyset_digest"] != _TRUSTED_KEYSET_SHA256
    ):
        raise ManifestVerificationError("execution seal policy is invalid")
    if (
        not isinstance(seal["registration_attestation_key_id"], str)
        or re.fullmatch(
            r"registration-attestation-[A-Za-z0-9._-]{1,96}",
            seal["registration_attestation_key_id"],
        ) is None
    ):
        raise ManifestVerificationError("execution seal attestation key ID is invalid")
    _digest(
        seal["registration_attestation_public_key_sha256"],
        "registration_attestation_public_key_sha256",
    )
    for field in (
        "organization_id", "execution_seal_uuid", "execution_nonce_digest",
        "candidate_digest", "gate_envelope_digest",
    ):
        if nonce.get(field) != seal.get(field):
            raise ManifestVerificationError("execution nonce and seal are not cross-bound")

    stages = bundle["stages"]
    if not isinstance(stages, list) or len(stages) != 4:
        raise ManifestVerificationError("execution bundle must contain exactly four stages")
    expected_stages = (("register", 1), ("outbound_call", 2), ("inbound_call", 3), ("unregister", 4))
    for index, (value, expected) in enumerate(zip(stages, expected_stages, strict=True)):
        payload = signed(value, f"execution_bundle.stages[{index}]")
        _object(payload, _STAGE_RECEIPT_FIELDS, f"execution_bundle.stages[{index}].payload")
        _execution_identity(payload, f"execution_bundle.stages[{index}].payload")
        _exact_integer(
            payload["ordinal"], expected[1],
            f"execution_bundle.stages[{index}].payload.ordinal",
        )
        _exact_integer(
            payload["stage_deadline_seconds"], 60,
            f"execution_bundle.stages[{index}].payload.stage_deadline_seconds",
        )
        if (
            payload["kind"] != "stage_status"
            or payload["stage"] != expected[0]
            or payload["state"] != "succeeded"
        ):
            raise ManifestVerificationError("execution bundle stages are not exact and successful")
        for field in (
            "organization_id", "execution_seal_uuid", "execution_nonce_digest",
            "candidate_digest", "gate_envelope_digest",
        ):
            if payload[field] != seal[field]:
                raise ManifestVerificationError("execution stage is not bound to the seal")
    final = signed(bundle["final"], "execution_bundle.final")
    _object(final, _FINAL_RECEIPT_FIELDS, "execution_bundle.final.payload")
    _execution_identity(final, "execution_bundle.final.payload")
    if (
        final["kind"] != "final_execution_evidence"
        or final["state"] != "completed"
        or final["containment_verified"] is not True
        or final["stage_receipts"] != stages
        or final["trusted_keyset_digest"] != _TRUSTED_KEYSET_SHA256
    ):
        raise ManifestVerificationError("execution bundle final containment is invalid")
    for field in (
        "organization_id", "execution_seal_uuid", "execution_nonce_digest",
        "candidate_digest", "gate_envelope_digest",
    ):
        if final[field] != seal[field]:
            raise ManifestVerificationError("execution bundle final is not bound to the seal")
    return bundle


def _ports(value: Any, name: str) -> tuple[int, int]:
    ports = _object(value, {"start", "end"}, name)
    start, end = ports["start"], ports["end"]
    if type(start) is not int or type(end) is not int or not (1 <= start <= end <= 65535):
        raise ManifestVerificationError(f"{name} is invalid")
    return start, end


def _validate_evidence(name: str, value: Any, bindings: Mapping[str, str], public_keys: Mapping[str, bytes], now: datetime) -> list[str]:
    role, specific = _EVIDENCE_SPECS[name]
    receipt = _object(value, {"payload", "signature"}, name)
    payload = _object(receipt["payload"], _BINDING_FIELDS | specific, f"{name}.payload")
    if payload["contract_version"] != "g008-independent-receipt-v1" or payload["kind"] != name:
        raise ManifestVerificationError(f"{name} contract is invalid")
    for field, expected in bindings.items():
        if _digest(payload[field], f"{name}.{field}") != expected:
            raise ManifestVerificationError(f"{name} binding mismatch: {field}")
    _fresh_window(payload["issued_at"], payload["expires_at"], now, name)
    if name in {"provider_preflight", "provider_postcall"}:
        if not isinstance(payload["currency"], str) or not re.fullmatch(r"[A-Z]{3}", payload["currency"]):
            raise ManifestVerificationError("provider currency is invalid")
        for field in specific & {"starting_balance", "ending_balance", "cost_delta"}:
            _decimal(payload[field], field)
    elif name == "supplier_scope":
        for field in ("rtp_cidr", "rtcp_cidr"):
            try:
                network = ipaddress.ip_network(payload[field], strict=True)
            except (TypeError, ValueError) as exc:
                raise ManifestVerificationError(f"{field} is invalid") from exc
            if not isinstance(network, ipaddress.IPv4Network) or str(network) != payload[field]:
                raise ManifestVerificationError(f"{field} must be a canonical safe unicast IPv4 CIDR")
            allowed_local = any(network.subnet_of(local_range) for local_range in _ALLOWED_LOCAL_V4_RANGES)
            if (not (network.is_global or allowed_local) or network.is_loopback or network.is_link_local
                    or network.is_multicast or network.is_reserved or network.is_unspecified):
                raise ManifestVerificationError(f"{field} must be a canonical safe unicast IPv4 CIDR")
        rtp = _ports(payload["rtp_ports"], "rtp_ports")
        rtcp = _ports(payload["rtcp_ports"], "rtcp_ports")
        if max(rtp[0], rtcp[0]) <= min(rtp[1], rtcp[1]):
            raise ManifestVerificationError("RTP and RTCP port scopes overlap")
    elif name == "secret_versions":
        versions = payload["versions"]
        if (not isinstance(versions, dict) or tuple(sorted(versions)) != _SECRET_PURPOSES
                or any(type(version) is not int or version <= 0 for version in versions.values())):
            raise ManifestVerificationError("secret versions must be the exact positive purpose map")
    elif name == "f12_readiness" and payload["ready"] is not True:
        raise ManifestVerificationError("F12 is not ready")
    elif name == "approval" and payload["approved"] is not True:
        raise ManifestVerificationError("G008 is not approved")
    elif name == "provider_deletion":
        resources = _resource_inventory(payload["resources"], "provider_deletion.resources")
        if _deletion_operations(payload["operations"], "provider_deletion.operations") != resources:
            raise ManifestVerificationError("provider deletion operations do not exactly match the resource inventory")
    elif name == "provider_absence":
        _resource_inventory(payload["resources"], "provider_absence.resources", absent=True)
    elif name in {"network_preactivation", "network_postactivation"}:
        _network_absence(payload, name)
    _verify_signature(payload, receipt["signature"], public_keys, role, name)
    return [_receipt_digest(payload, _EVIDENCE_SELF_DIGEST[name])]


def _validate_provider_causality(evidence: Mapping[str, Any]) -> None:
    preflight = evidence["provider_preflight"]["payload"]
    postcall = evidence["provider_postcall"]["payload"]
    preflight_digest = _digest(preflight["preflight_receipt_digest"], "preflight_receipt_digest")
    if (_digest(postcall["preflight_receipt_digest"], "preflight_receipt_digest") != preflight_digest
            or preflight["currency"] != postcall["currency"]):
        raise ManifestVerificationError("provider post-call receipt is not causally linked to preflight")
    starting = _decimal(preflight["starting_balance"], "starting_balance")
    ending = _decimal(postcall["ending_balance"], "ending_balance")
    cost = _decimal(postcall["cost_delta"], "cost_delta")
    if starting < ending or starting - ending != cost:
        raise ManifestVerificationError("provider post-call cost is inconsistent")


def _validate_inventory_causality(evidence: Mapping[str, Any]) -> None:
    deletion = evidence["provider_deletion"]["payload"]
    absence = evidence["provider_absence"]["payload"]
    deletion_digest = _receipt_digest(deletion, "deletion_receipt_digest")
    if absence["deletion_receipt_digest"] != deletion_digest:
        raise ManifestVerificationError("provider absence is not causally linked to deletion")
    deleted = _resource_inventory(deletion["resources"], "provider_deletion.resources")
    absent = _resource_inventory(absence["resources"], "provider_absence.resources", absent=True)
    if absent != deleted:
        raise ManifestVerificationError("provider absence inventory does not exactly match deleted resources")
    before = evidence["network_preactivation"]["payload"]
    after = evidence["network_postactivation"]["payload"]
    if before["network_digest"] != after["network_digest"] or after["generation"] <= before["generation"]:
        raise ManifestVerificationError("network absence inventories are not ordered observations of the same network")


def _validate_bound_receipt(
    value: Any,
    *,
    role: str,
    kind: str,
    bindings: Mapping[str, str],
    extra_bindings: Mapping[str, Any],
    public_keys: Mapping[str, bytes],
    now: datetime,
    name: str,
) -> str:
    fields = _BINDING_FIELDS | set(extra_bindings) | {"receipt_digest"}
    receipt = _object(value, {"payload", "signature"}, name)
    payload = _object(receipt["payload"], fields, f"{name}.payload")
    if payload["contract_version"] != "g008-bound-receipt-v1" or payload["kind"] != kind:
        raise ManifestVerificationError(f"{name} contract is invalid")
    for field, expected in {**bindings, **extra_bindings}.items():
        actual = (
            _digest(payload[field], field)
            if field.endswith("_digest") and expected is not None
            else payload[field]
        )
        if actual != expected:
            raise ManifestVerificationError(f"{name} binding mismatch: {field}")
    _fresh_window(payload["issued_at"], payload["expires_at"], now, name)
    _verify_signature(payload, receipt["signature"], public_keys, role, name)
    return _receipt_digest(payload, "receipt_digest")


def _validate_registration(
    value: Any, bindings: Mapping[str, str], public_keys: Mapping[str, bytes], now: datetime
) -> tuple[str, str]:
    registration = _object(
        value, {"logical_register_count", "retry_count", "concurrency_count", "register_receipt", "unregister_receipt"}, "registration"
    )
    if (type(registration["logical_register_count"]) is not int or registration["logical_register_count"] != 1
            or type(registration["retry_count"]) is not int or registration["retry_count"] != 0
            or type(registration["concurrency_count"]) is not int or registration["concurrency_count"] != 1):
        raise ManifestVerificationError("exactly one single-flight logical REGISTER with zero retry is required")
    register_digest = _validate_bound_receipt(
        registration["register_receipt"], role="register", kind="register", bindings=bindings,
        extra_bindings={"logical_register_count": 1, "retry_count": 0, "concurrency_count": 1},
        public_keys=public_keys, now=now, name="registration.register_receipt",
    )
    unregister_digest = _validate_bound_receipt(
        registration["unregister_receipt"], role="unregister", kind="unregister", bindings=bindings,
        extra_bindings={"register_receipt_digest": register_digest, "retry_count": 0, "concurrency_count": 1},
        public_keys=public_keys, now=now, name="registration.unregister_receipt",
    )
    if unregister_digest == register_digest:
        raise ManifestVerificationError("register and unregister receipts must be distinct")
    return register_digest, unregister_digest


def _validate_attempts(
    value: Any, bindings: Mapping[str, str], public_keys: Mapping[str, bytes], now: datetime
) -> list[str]:
    if not isinstance(value, list) or len(value) != 2:
        raise ManifestVerificationError("exactly two attempts are required")
    fields = {
        "sequence", "attempt_id_digest", "provider_call_id_digest", "direction",
        "started_monotonic_ms", "ended_monotonic_ms", "retry_count", "concurrency_count",
        "prior_attempt_id_digest", "evidence_receipts",
    }
    expected_directions = ["outbound", "inbound"]
    ids: list[str] = []
    call_ids: list[str] = []
    proof_digests: list[str] = []
    audio_digests: set[str] = set()
    previous_end: int | None = None
    for index, raw in enumerate(value):
        item = _object(raw, fields, f"attempts[{index}]")
        if type(item["sequence"]) is not int or item["sequence"] != index + 1 or item["direction"] != expected_directions[index]:
            raise ManifestVerificationError("attempt ledger is not in canonical order")
        attempt_id = _digest(item["attempt_id_digest"], "attempt_id_digest")
        provider_call_id = _digest(item["provider_call_id_digest"], "provider_call_id_digest")
        if attempt_id in ids or provider_call_id in call_ids:
            raise ManifestVerificationError("attempt and provider call IDs must be unique")
        ids.append(attempt_id)
        call_ids.append(provider_call_id)
        start, end = item["started_monotonic_ms"], item["ended_monotonic_ms"]
        if type(start) is not int or type(end) is not int or start < 0 or not 0 < end - start <= 60_000:
            raise ManifestVerificationError("attempt needs one <=60s monotonic proof")
        if previous_end is not None and start < previous_end:
            raise ManifestVerificationError("attempts overlap")
        previous_end = end
        if (type(item["retry_count"]) is not int or item["retry_count"] != 0
                or type(item["concurrency_count"]) is not int or item["concurrency_count"] != 1):
            raise ManifestVerificationError("attempt must be zero-retry and single-flight")
        expected_prior = None if index == 0 else ids[index - 1]
        if item["prior_attempt_id_digest"] != expected_prior:
            raise ManifestVerificationError("attempt causal link is invalid")
        receipts = _object(item["evidence_receipts"], set(_ATTEMPT_RECEIPT_ROLES), f"attempts[{index}].evidence_receipts")
        common = {
            "attempt_id_digest": attempt_id,
            "provider_call_id_digest": provider_call_id,
            "sequence": index + 1,
            "direction": item["direction"],
            "started_monotonic_ms": start,
            "ended_monotonic_ms": end,
            "retry_count": 0,
            "concurrency_count": 1,
            "prior_attempt_id_digest": expected_prior,
        }
        role_values = {
            "dispatch": {"dispatch_artifact_digest": receipts["dispatch"].get("payload", {}).get("dispatch_artifact_digest")},
            "media": {"media_artifact_digest": receipts["media"].get("payload", {}).get("media_artifact_digest")},
            "status": {
                "status_artifact_digest": receipts["status"].get("payload", {}).get("status_artifact_digest"),
                "terminal_status": "terminal", "terminal_disposition": "completed",
            },
            "cdr": {
                "cdr_artifact_digest": receipts["cdr"].get("payload", {}).get("cdr_artifact_digest"),
                "billed_duration_ms": receipts["cdr"].get("payload", {}).get("billed_duration_ms"),
            },
            "human-rx": {
                "human_rx_artifact_digest": receipts["human-rx"].get("payload", {}).get("human_rx_artifact_digest"),
                "human_rx_duration_ms": receipts["human-rx"].get("payload", {}).get("human_rx_duration_ms"),
                "human_rx_acknowledgement": "redacted_heard",
                "human_rx_acknowledgement_artifact_digest": receipts["human-rx"].get("payload", {}).get("human_rx_acknowledgement_artifact_digest"),
            },
            "human-tx": {
                "human_tx_artifact_digest": receipts["human-tx"].get("payload", {}).get("human_tx_artifact_digest"),
                "human_tx_duration_ms": receipts["human-tx"].get("payload", {}).get("human_tx_duration_ms"),
                "human_tx_acknowledgement": "redacted_spoke",
                "human_tx_acknowledgement_artifact_digest": receipts["human-tx"].get("payload", {}).get("human_tx_acknowledgement_artifact_digest"),
            },
        }
        for role in _ATTEMPT_RECEIPT_ROLES:
            extras = {**common, **role_values[role]}
            for field in _ATTEMPT_ROLE_FIELDS[role]:
                if field.endswith("_digest"):
                    _digest(extras[field], f"attempts[{index}].{role}.{field}")
            if role == "cdr" and (
                type(extras["billed_duration_ms"]) is not int
                or not 0 <= extras["billed_duration_ms"] <= end - start
            ):
                raise ManifestVerificationError("CDR billed duration is invalid")
            if role in {"human-rx", "human-tx"}:
                prefix = role.replace("-", "_")
                duration = extras[f"{prefix}_duration_ms"]
                if type(duration) is not int or not 0 < duration <= end - start:
                    raise ManifestVerificationError(
                        f"{role} duration must be nonzero and bounded by the call"
                    )
            proof_digests.append(_validate_bound_receipt(
                receipts[role], role=role, kind=f"attempt_{role}", bindings=bindings,
                extra_bindings=extras, public_keys=public_keys, now=now,
                name=f"attempts[{index}].{role}_receipt",
            ))
        rx_payload = receipts["human-rx"]["payload"]
        tx_payload = receipts["human-tx"]["payload"]
        directional_digests = {
            rx_payload["human_rx_artifact_digest"],
            rx_payload["human_rx_acknowledgement_artifact_digest"],
            tx_payload["human_tx_artifact_digest"],
            tx_payload["human_tx_acknowledgement_artifact_digest"],
        }
        if len(directional_digests) != 4 or directional_digests & audio_digests:
            raise ManifestVerificationError(
                "human RX and TX evidence must be distinct within and across calls"
            )
        audio_digests.update(directional_digests)
        proof_digests.extend((attempt_id, provider_call_id))
    return proof_digests


def _validate_closure_events(
    value: Any,
    bindings: Mapping[str, str],
    phase_b_digest: str,
    register_digest: str,
    unregister_digest: str,
    closure_bindings: Mapping[str, str],
    public_keys: Mapping[str, bytes],
    now: datetime,
) -> list[str]:
    if not isinstance(value, list) or len(value) != len(_CLOSURE_KINDS):
        raise ManifestVerificationError("closure event ledger is incomplete")
    fields = _BINDING_FIELDS | {
        "sequence", "event", "event_receipt_digest", "previous_event_receipt_digest",
        "register_receipt_digest", "unregister_receipt_digest", "retry_count", "concurrency_count",
        "phase_b_expected_digest", "phase_b_observed_digest", "product_status",
    } | set(closure_bindings)
    event_digests: list[str] = []
    for index, raw in enumerate(value):
        event = _object(raw, {"payload", "signature"}, f"closure_events[{index}]")
        payload = _object(event["payload"], fields, f"closure_events[{index}].payload")
        if payload["contract_version"] != "g008-closure-event-v1" or payload["kind"] != "closure_event":
            raise ManifestVerificationError("closure event contract is invalid")
        for field, expected in bindings.items():
            if _digest(payload[field], field) != expected:
                raise ManifestVerificationError(f"closure event binding mismatch: {field}")
        _fresh_window(payload["issued_at"], payload["expires_at"], now, f"closure_events[{index}]")
        digest = _receipt_digest(payload, "event_receipt_digest")
        expected_previous = None if index == 0 else event_digests[index - 1]
        if (type(payload["sequence"]) is not int or payload["sequence"] != index + 1
                or payload["event"] != _CLOSURE_KINDS[index]
                or payload["previous_event_receipt_digest"] != expected_previous):
            raise ManifestVerificationError("closure events are not ordered and causal")
        if (_digest(payload["register_receipt_digest"], "register_receipt_digest") != register_digest
                or _digest(payload["unregister_receipt_digest"], "unregister_receipt_digest") != unregister_digest
                or type(payload["retry_count"]) is not int or payload["retry_count"] != 0
                or type(payload["concurrency_count"]) is not int or payload["concurrency_count"] != 1):
            raise ManifestVerificationError("closure event is not bound to register/unregister zero-retry single-flight receipts")
        if (_digest(payload["phase_b_expected_digest"], "phase_b_expected_digest") != phase_b_digest
                or _digest(payload["phase_b_observed_digest"], "phase_b_observed_digest") != phase_b_digest):
            raise ManifestVerificationError("Phase B exact equality is not proven")
        for field, expected in closure_bindings.items():
            if _digest(payload[field], field) != expected:
                raise ManifestVerificationError(f"closure event evidence binding mismatch: {field}")
        if payload["product_status"] != "Waiting":
            raise ManifestVerificationError("product promotion is forbidden")
        _verify_signature(payload, event["signature"], public_keys, "closure-event", f"closure_events[{index}]")
        event_digests.append(digest)
    if len(set(event_digests)) != len(event_digests):
        raise ManifestVerificationError("closure event digests must be unique")
    return event_digests


def _referenced_digests(manifest: Mapping[str, Any]) -> dict[str, str]:
    refs: dict[str, str] = {}
    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else key
                if key.endswith("_digest") and isinstance(child, str):
                    refs[child_path] = _digest(child, child_path)
                elif key not in {"signature", "referenced_digests"}:
                    visit(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}.{index}")
    visit(manifest, "")
    return refs


def verify_manifest(
    manifest: Mapping[str, Any],
    execution_bundle: bytes | bytearray | str | Path,
    *,
    now: datetime | None = None,
    consumed_run_nonces: set[str] | None = None,
    consumed_manifest_digests: set[str] | None = None,
) -> dict[str, str]:
    """Verify the complete G008 proof and return redacted digest evidence only."""
    fields = {
        "version", "tenant_digest", "account_digest", "envelope_digest", "candidate_digest",
        "run_id_digest", "activation_nonce_digest", "run_nonce_digest", "trusted_keyset_digest",
        "execution_bundle_digest", "issued_at", "expires_at", "product_status", "phase_b",
        "registration", "evidence", "attempts", "closure_events", "referenced_digests", "signature",
    }
    doc = _object(manifest, fields, "manifest")
    _forbid_raw(doc)
    if doc["version"] != "g008-closure-manifest-v4" or doc["product_status"] != "Waiting":
        raise ManifestVerificationError("manifest version or product status is invalid")
    current = (now or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    _fresh_window(doc["issued_at"], doc["expires_at"], current, "manifest")
    public_keys = _load_trusted_keys()
    if _digest(doc["trusted_keyset_digest"], "trusted_keyset_digest") != _TRUSTED_KEYSET_SHA256:
        raise ManifestVerificationError("manifest is not bound to the canonical trusted keyset")
    execution_bundle_digest = _digest(doc["execution_bundle_digest"], "execution_bundle_digest")
    execution_bundle_value = _load_execution_bundle(
        execution_bundle, execution_bundle_digest, public_keys, current
    )
    evidence_fields = set(doc["evidence"]) if isinstance(doc["evidence"], dict) else set()
    required_evidence = set(_EVIDENCE_SPECS) - _OPTIONAL_EVIDENCE
    if frozenset(evidence_fields) not in {frozenset(required_evidence), frozenset(_EVIDENCE_SPECS)}:
        raise ManifestVerificationError("evidence fields invalid or optional G007 evidence is malformed")
    evidence = _object(doc["evidence"], evidence_fields, "evidence")
    canonical_roles = {_ROLE_AUTHORITY[role] for role in _ROLE_AUTHORITY}
    if set(public_keys) != set(_CANONICAL_KEYS) or any(
        not isinstance(public_keys.get(role), bytes) or len(public_keys[role]) != 32
        for role in canonical_roles
    ):
        raise ManifestVerificationError("canonical trusted Ed25519 keyset is incomplete")
    binding_names = (
        "tenant_digest", "account_digest", "envelope_digest", "candidate_digest",
        "run_id_digest", "activation_nonce_digest", "run_nonce_digest",
        "trusted_keyset_digest", "execution_bundle_digest",
    )
    bindings = {field: _digest(doc[field], field) for field in binding_names}
    bundle_seal = execution_bundle_value["seal"]["payload"]
    if (
        bundle_seal["candidate_digest"] != bindings["candidate_digest"]
        or bundle_seal["execution_nonce_digest"] != bindings["activation_nonce_digest"]
    ):
        raise ManifestVerificationError("execution bundle is not bound to this manifest")
    if bundle_seal["gate_envelope_digest"] != bindings["envelope_digest"]:
        raise ManifestVerificationError("manifest envelope is not bound to the execution bundle")
    if len({bindings["run_id_digest"], bindings["activation_nonce_digest"], bindings["run_nonce_digest"]}) != 3:
        raise ManifestVerificationError("run ID, activation nonce, and one-time run nonce must be distinct")
    register_digest, unregister_digest = _validate_registration(
        doc["registration"], bindings, public_keys, current
    )
    proof_digests = [register_digest, unregister_digest]
    evidence_digests: dict[str, str] = {}
    for name in _EVIDENCE_SPECS:
        if name in evidence:
            validated = _validate_evidence(name, evidence[name], bindings, public_keys, current)
            proof_digests.extend(validated)
            evidence_digests[name] = validated[0]
    _validate_provider_causality(evidence)
    _validate_inventory_causality(evidence)
    phase_b = _object(
        doc["phase_b"],
        {"state", "baseline_manifest_digest", "baseline_receipt_digest", "closure_manifest_digest"},
        "phase_b",
    )
    phase_b_digest = _digest(phase_b["baseline_manifest_digest"], "baseline_manifest_digest")
    baseline_payload = evidence["phase_b_baseline"]["payload"]
    if (
        phase_b["state"] != "deny_only"
        or _digest(phase_b["closure_manifest_digest"], "closure_manifest_digest") != phase_b_digest
        or baseline_payload["baseline_manifest_digest"] != phase_b_digest
        or phase_b["baseline_receipt_digest"] != evidence_digests["phase_b_baseline"]
    ):
        raise ManifestVerificationError("Phase B equality is not cross-bound to its signed deny-only baseline")
    if "g007_baseline" in evidence:
        g007 = evidence["g007_baseline"]["payload"]
        if g007["baseline_manifest_digest"] != phase_b_digest:
            raise ManifestVerificationError("optional G007 receipt is not cross-bound to the Phase B baseline")
    proof_digests.extend(_validate_attempts(doc["attempts"], bindings, public_keys, current))
    closure_bindings = {
        "phase_b_baseline_receipt_digest": evidence_digests["phase_b_baseline"],
        "provider_deletion_receipt_digest": evidence_digests["provider_deletion"],
        "provider_absence_receipt_digest": evidence_digests["provider_absence"],
        "network_preactivation_receipt_digest": evidence_digests["network_preactivation"],
        "network_postactivation_receipt_digest": evidence_digests["network_postactivation"],
    }
    proof_digests.extend(
        _validate_closure_events(
            doc["closure_events"], bindings, phase_b_digest, register_digest, unregister_digest,
            closure_bindings, public_keys, current
        )
    )
    if len(set(proof_digests)) != len(proof_digests):
        raise ManifestVerificationError("proof receipt digests must be globally unique")
    refs = _referenced_digests(doc)
    if not isinstance(doc["referenced_digests"], dict) or doc["referenced_digests"] != refs:
        raise ManifestVerificationError("referenced digest map is not exact")
    unsigned = dict(doc)
    signature = unsigned.pop("signature")
    _verify_signature(unsigned, signature, public_keys, "closure-manifest", "manifest")
    manifest_digest = hashlib.sha256(canonical_json_bytes(doc)).hexdigest()
    run_nonce = bindings["run_nonce_digest"]
    if consumed_run_nonces is not None and run_nonce in consumed_run_nonces:
        raise ManifestVerificationError("run nonce was already consumed")
    if consumed_manifest_digests is not None and manifest_digest in consumed_manifest_digests:
        raise ManifestVerificationError("manifest digest was already consumed")
    if consumed_run_nonces is not None:
        consumed_run_nonces.add(run_nonce)
    if consumed_manifest_digests is not None:
        consumed_manifest_digests.add(manifest_digest)
    return {"manifest_digest": manifest_digest, **refs}


def _load_consumption_ledger(path: Path) -> tuple[set[str], set[str]]:
    if not path.exists():
        return set(), set()
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ManifestVerificationError("consumption ledger is not valid JSON") from exc
    ledger = _object(value, {"run_nonce_digests", "manifest_digests"}, "consumption_ledger")
    result: list[set[str]] = []
    for field in ("run_nonce_digests", "manifest_digests"):
        items = ledger[field]
        if not isinstance(items, list) or items != sorted(items) or len(items) != len(set(items)):
            raise ManifestVerificationError(f"consumption_ledger.{field} must be a sorted unique list")
        result.append({_digest(item, f"consumption_ledger.{field}") for item in items})
    return result[0], result[1]


def _write_consumption_ledger(path: Path, run_nonces: set[str], manifest_digests: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    payload = {
        "run_nonce_digests": sorted(run_nonces),
        "manifest_digests": sorted(manifest_digests),
    }
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json_bytes(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise ManifestVerificationError("consumption ledger could not be persisted") from exc
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass


def consume_manifest(
    manifest: Mapping[str, Any],
    execution_bundle: bytes | bytearray | str | Path,
    ledger_path: Path,
    *,
    now: datetime | None = None,
) -> dict[str, str]:
    """Verify and durably consume one manifest under an exclusive offline lock."""
    lock_path = ledger_path.with_name(f".{ledger_path.name}.lock")
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        lock_path.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise ManifestVerificationError("consumption ledger is locked by another verifier") from exc
    try:
        if ledger_path.exists() and ledger_path.stat().st_mode & 0o077:
            raise ManifestVerificationError("consumption ledger must not be group- or world-accessible")
        run_nonces, manifest_digests = _load_consumption_ledger(ledger_path)
        result = verify_manifest(
            manifest,
            execution_bundle,
            now=now,
            consumed_run_nonces=run_nonces,
            consumed_manifest_digests=manifest_digests,
        )
        _write_consumption_ledger(ledger_path, run_nonces, manifest_digests)
        return result
    finally:
        try:
            lock_path.rmdir()
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a strict redacted G008 closure manifest offline.")
    parser.add_argument("manifest")
    parser.add_argument("--execution-bundle", required=True, type=Path)
    parser.add_argument("--consumption-ledger", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = consume_manifest(
            load_manifest(args.manifest), args.execution_bundle, args.consumption_ledger
        )
        print(json.dumps(result, sort_keys=True))
    except (ValueError, ManifestVerificationError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
