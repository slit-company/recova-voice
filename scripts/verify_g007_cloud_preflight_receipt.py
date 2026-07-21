#!/usr/bin/env python3
"""Fail-closed offline verifier for canonical G007 cloud-preflight receipts.

The receipt is an operator-exported, redacted JSON document.  This program never
contacts a provider, reads remote state, or accepts credentials/state contents.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

CONTRACT_VERSION = "g007-cloud-preflight-receipt.v1"
PROJECT_ID = "slit-497603"
REGION = "asia-northeast3"
MAX_VALIDITY = timedelta(seconds=60)
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
API_RE = re.compile(r"^[a-z][a-z0-9-]{1,62}\.googleapis\.com$")
CONSTRAINT_RE = re.compile(r"^constraints/[A-Za-z][A-Za-zA-Z0-9.]{2,127}$")
QUOTA_METRIC_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
REQUIRED_APIS = (
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "iam.googleapis.com",
    "orgpolicy.googleapis.com",
    "serviceusage.googleapis.com",
    "storage.googleapis.com",
)
REQUIRED_ORG_POLICIES = (
    "constraints/compute.requireOsLogin",
    "constraints/compute.requireShieldedVm",
    "constraints/compute.vmExternalIpAccess",
    "constraints/storage.publicAccessPrevention",
)
BACKEND_FIELDS = frozenset(
    {
        "bucket_sha256",
        "prefix_sha256",
        "generation",
        "config_sha256",
        "public_access_prevention",
        "uniform_bucket_level_access",
        "versioning_enabled",
        "recovery",
    }
)
RECOVERY_FIELDS = frozenset({"retention_days", "soft_delete_days"})
QUOTA_FIELDS = frozenset({"metric", "limit", "usage"})
SUBNET_FIELDS = frozenset({"cidr", "collision_free"})
POLICY_FIELDS = frozenset({"constraint", "enforced"})
RECEIPT_FIELDS = frozenset(
    {
        "contract_version",
        "project_id",
        "region",
        "required_apis",
        "regional_quotas",
        "org_policies",
        "subnets",
        "delegated_deployer_identity_sha256",
        "phase_b_backend",
        "phase_c_backend",
        "observed_at",
        "expires_at",
        "signer_key_id",
        "signature",
    }
)


class ReceiptVerificationError(ValueError):
    """The exported receipt is incomplete, stale, untrusted, or invalid."""


def _reject(message: str) -> None:
    raise ReceiptVerificationError(message)


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Encode the sole accepted receipt/key JSON representation."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject("duplicate_json_key")
        result[key] = value
    return result


def _reject_nonstandard_json_constant(_value: str) -> None:
    _reject("invalid_json")


def load_canonical_json(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicate_object, parse_constant=_reject_nonstandard_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptVerificationError(f"invalid_{label}_json") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        _reject(f"noncanonical_{label}_json")
    return value


def _require_string(value: Any, name: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or (pattern and not pattern.fullmatch(value)):
        _reject(f"invalid_{name}")
    return value


def _require_digest(value: Any, name: str) -> str:
    return _require_string(value, name, DIGEST_RE)


def _require_nonnegative_int(value: Any, name: str) -> int:
    if type(value) is not int or value < 0:
        _reject(f"invalid_{name}")
    return value


def _parse_timestamp(value: Any, name: str) -> datetime:
    text = _require_string(value, name, TIMESTAMP_RE)
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ReceiptVerificationError(f"invalid_{name}") from exc


def _decode_unpadded_base64(value: Any, name: str) -> bytes:
    text = _require_string(value, name)
    if "=" in text or not re.fullmatch(r"[A-Za-z0-9_-]+", text):
        _reject(f"invalid_{name}")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError as exc:
        raise ReceiptVerificationError(f"invalid_{name}") from exc


def _validate_apis(value: Any) -> None:
    if not isinstance(value, list) or tuple(value) != REQUIRED_APIS:
        _reject("required_apis_incomplete")
    if any(not isinstance(api, str) or not API_RE.fullmatch(api) for api in value):
        _reject("invalid_required_apis")


def _validate_quotas(value: Any) -> None:
    if not isinstance(value, list) or not value:
        _reject("regional_quotas_incomplete")
    metrics: list[str] = []
    for quota in value:
        if not isinstance(quota, dict) or set(quota) != QUOTA_FIELDS:
            _reject("invalid_regional_quotas")
        metric = _require_string(quota["metric"], "quota_metric", QUOTA_METRIC_RE)
        limit = _require_nonnegative_int(quota["limit"], "quota_limit")
        usage = _require_nonnegative_int(quota["usage"], "quota_usage")
        if usage > limit:
            _reject("regional_quota_exhausted")
        metrics.append(metric)
    if metrics != sorted(metrics) or len(set(metrics)) != len(metrics):
        _reject("unnormalized_regional_quotas")


def _validate_org_policies(value: Any) -> None:
    if not isinstance(value, list) or not value:
        _reject("org_policies_incomplete")
    constraints: list[str] = []
    for policy in value:
        if not isinstance(policy, dict) or set(policy) != POLICY_FIELDS:
            _reject("invalid_org_policies")
        constraint = _require_string(policy["constraint"], "org_policy_constraint", CONSTRAINT_RE)
        if type(policy["enforced"]) is not bool:
            _reject("invalid_org_policy_observation")
        constraints.append(constraint)
    if tuple(constraints) != REQUIRED_ORG_POLICIES:
        _reject("org_policies_incomplete")


def _validate_subnets(value: Any) -> None:
    if not isinstance(value, list) or not value:
        _reject("subnets_incomplete")
    networks: list[ipaddress.IPv4Network] = []
    for subnet in value:
        if not isinstance(subnet, dict) or set(subnet) != SUBNET_FIELDS:
            _reject("invalid_subnets")
        cidr = _require_string(subnet["cidr"], "subnet_cidr")
        if subnet["collision_free"] is not True:
            _reject("subnet_collision_detected")
        try:
            network = ipaddress.ip_network(cidr, strict=True)
        except ValueError as exc:
            raise ReceiptVerificationError("invalid_subnet_cidr") from exc
        if not isinstance(network, ipaddress.IPv4Network) or str(network) != cidr:
            _reject("invalid_subnet_cidr")
        networks.append(network)
    if networks != sorted(networks, key=lambda network: (int(network.network_address), network.prefixlen)):
        _reject("unnormalized_subnets")
    if len(set(networks)) != len(networks) or any(left.overlaps(right) for left, right in zip(networks, networks[1:])):
        _reject("overlapping_subnets")


def _validate_backend(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != BACKEND_FIELDS:
        _reject(f"invalid_{name}_backend")
    for field in ("bucket_sha256", "prefix_sha256", "config_sha256"):
        _require_digest(value[field], f"{name}_{field}")
    if type(value["generation"]) is not int or value["generation"] <= 0:
        _reject(f"invalid_{name}_generation")
    for field in ("public_access_prevention", "uniform_bucket_level_access", "versioning_enabled"):
        if value[field] is not True:
            _reject(f"{name}_{field}_not_enabled")
    recovery = value["recovery"]
    if not isinstance(recovery, dict) or set(recovery) != RECOVERY_FIELDS:
        _reject(f"invalid_{name}_recovery")
    for field in RECOVERY_FIELDS:
        if type(recovery[field]) is not int or recovery[field] <= 0:
            _reject(f"invalid_{name}_{field}")
    return value


def verify_receipt(
    raw: bytes,
    *,
    trusted_public_keys: Mapping[str, str],
    now: datetime,
) -> dict[str, str]:
    """Verify one complete receipt and return only redacted verification material."""
    if now.tzinfo is None or now.utcoffset() is None:
        _reject("now_must_be_timezone_aware")
    receipt = load_canonical_json(raw, label="receipt")
    if set(receipt) != RECEIPT_FIELDS:
        _reject("unknown_or_missing_fields")
    if receipt["contract_version"] != CONTRACT_VERSION:
        _reject("unsupported_contract_version")
    if receipt["project_id"] != PROJECT_ID or receipt["region"] != REGION:
        _reject("scope_mismatch")
    _validate_apis(receipt["required_apis"])
    _validate_quotas(receipt["regional_quotas"])
    _validate_org_policies(receipt["org_policies"])
    _validate_subnets(receipt["subnets"])
    deployer_hash = _require_digest(receipt["delegated_deployer_identity_sha256"], "delegated_deployer_identity_sha256")
    phase_b = _validate_backend(receipt["phase_b_backend"], "phase_b")
    phase_c = _validate_backend(receipt["phase_c_backend"], "phase_c")
    if any(
        phase_b[field] == phase_c[field]
        for field in ("bucket_sha256", "prefix_sha256", "config_sha256")
    ):
        _reject("phase_backends_not_distinct")
    observed_at = _parse_timestamp(receipt["observed_at"], "observed_at")
    expires_at = _parse_timestamp(receipt["expires_at"], "expires_at")
    now = now.astimezone(UTC).replace(microsecond=0)
    if observed_at > now or expires_at <= now or expires_at <= observed_at or expires_at - observed_at > MAX_VALIDITY:
        _reject("receipt_not_fresh")
    key_id = _require_string(receipt["signer_key_id"], "signer_key_id", KEY_ID_RE)
    public_key = trusted_public_keys.get(key_id)
    if not isinstance(public_key, str):
        _reject("untrusted_signer")
    key_bytes = _decode_unpadded_base64(public_key, "trusted_public_key")
    signature = _decode_unpadded_base64(receipt["signature"], "signature")
    if len(key_bytes) != 32 or len(signature) != 64:
        _reject("invalid_signature_material")
    signed_payload = dict(receipt)
    del signed_payload["signature"]
    try:
        VerifyKey(key_bytes).verify(canonical_json_bytes(signed_payload), signature)
    except (BadSignatureError, ValueError) as exc:
        raise ReceiptVerificationError("invalid_signature") from exc
    scope_hash = hashlib.sha256(f"{PROJECT_ID}\x00{REGION}\x00{deployer_hash}".encode("ascii")).hexdigest()
    return {
        "contract_version": CONTRACT_VERSION,
        "receipt_digest": hashlib.sha256(canonical_json_bytes(signed_payload)).hexdigest(),
        "scope_hash": scope_hash,
        "signer_key_hash": hashlib.sha256(key_id.encode("utf-8")).hexdigest(),
        "observed_at": observed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify one redacted G007 cloud-preflight receipt offline")
    parser.add_argument("receipt", type=Path, help="canonical operator-exported receipt JSON")
    parser.add_argument("--trusted-keys", required=True, type=Path, help="canonical JSON key-id to Ed25519 public-key map")
    parser.add_argument("--now", required=True, help="UTC time as YYYY-MM-DDTHH:MM:SSZ")
    args = parser.parse_args(argv)
    try:
        trusted_keys = load_canonical_json(args.trusted_keys.read_bytes(), label="trusted_keys")
        now = _parse_timestamp(args.now, "now")
        receipt = verify_receipt(args.receipt.read_bytes(), trusted_public_keys=trusted_keys, now=now)
    except (OSError, ValueError, ReceiptVerificationError) as exc:
        print(f"G007 cloud-preflight receipt verification refused: {exc}", file=sys.stderr)
        return 1
    print(canonical_json_bytes(receipt).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
