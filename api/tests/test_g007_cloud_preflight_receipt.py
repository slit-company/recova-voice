from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
from datetime import UTC, datetime
from pathlib import Path

import pytest
from nacl.signing import SigningKey

_MODULE_PATH = Path(__file__).parents[2] / "scripts" / "verify_g007_cloud_preflight_receipt.py"
_SPEC = importlib.util.spec_from_file_location("g007_cloud_preflight_receipt", _MODULE_PATH)
assert _SPEC and _SPEC.loader
verifier = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(verifier)

_NOW = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
_SIGNING_KEY = SigningKey(bytes(range(32)))
_KEY_ID = "g007-offline-operator"
_KEYS = {
    _KEY_ID: base64.urlsafe_b64encode(bytes(_SIGNING_KEY.verify_key)).decode("ascii").rstrip("="),
}
_DIGEST = "a" * 64


def _backend(seed: str) -> dict[str, object]:
    return {
        "bucket_sha256": hashlib.sha256(f"{seed}:bucket".encode()).hexdigest(),
        "prefix_sha256": hashlib.sha256(f"{seed}:prefix".encode()).hexdigest(),
        "generation": 3,
        "config_sha256": hashlib.sha256(f"{seed}:config".encode()).hexdigest(),
        "public_access_prevention": True,
        "uniform_bucket_level_access": True,
        "versioning_enabled": True,
        "recovery": {"retention_days": 7, "soft_delete_days": 7},
    }


def _payload() -> dict[str, object]:
    return {
        "contract_version": verifier.CONTRACT_VERSION,
        "project_id": "slit-497603",
        "region": "asia-northeast3",
        "required_apis": list(verifier.REQUIRED_APIS),
        "regional_quotas": [
            {"metric": "CPUS", "limit": 8, "usage": 0},
            {"metric": "INSTANCES", "limit": 2, "usage": 0},
        ],
        "org_policies": [
            {"constraint": constraint, "enforced": True}
            for constraint in verifier.REQUIRED_ORG_POLICIES
        ],
        "subnets": [
            {"cidr": "10.73.96.0/24", "collision_free": True},
            {"cidr": "10.73.97.0/24", "collision_free": True},
        ],
        "delegated_deployer_identity_sha256": _DIGEST,
        "phase_b_backend": _backend("b"),
        "phase_c_backend": _backend("e"),
        "observed_at": "2026-07-16T11:59:30Z",
        "expires_at": "2026-07-16T12:00:30Z",
        "signer_key_id": _KEY_ID,
    }


def _signed(payload: dict[str, object] | None = None) -> bytes:
    receipt = copy.deepcopy(payload or _payload())
    signed = verifier.canonical_json_bytes(receipt)
    receipt["signature"] = base64.urlsafe_b64encode(_SIGNING_KEY.sign(signed).signature).decode("ascii").rstrip("=")
    return verifier.canonical_json_bytes(receipt)


def _verify(raw: bytes) -> dict[str, str]:
    return verifier.verify_receipt(raw, trusted_public_keys=_KEYS, now=_NOW)


def test_complete_current_receipt_emits_only_redacted_digest() -> None:
    result = _verify(_signed())

    assert set(result) == {
        "contract_version",
        "receipt_digest",
        "scope_hash",
        "signer_key_hash",
        "observed_at",
        "expires_at",
    }
    assert result["contract_version"] == verifier.CONTRACT_VERSION
    assert _DIGEST not in result.values()
    assert result["observed_at"] == "2026-07-16T11:59:30Z"


@pytest.mark.parametrize(
    "field",
    [
        "required_apis",
        "regional_quotas",
        "org_policies",
        "subnets",
        "delegated_deployer_identity_sha256",
        "phase_b_backend",
        "phase_c_backend",
        "observed_at",
        "expires_at",
    ],
)
def test_each_required_preflight_scope_cannot_be_omitted(field: str) -> None:
    payload = _payload()
    del payload[field]

    with pytest.raises(verifier.ReceiptVerificationError, match="unknown_or_missing_fields"):
        _verify(_signed(payload))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda receipt: receipt.__setitem__("project_id", "other-project"),
        lambda receipt: receipt.__setitem__("region", "us-central1"),
        lambda receipt: receipt["required_apis"].pop(),
        lambda receipt: receipt["regional_quotas"][0].__setitem__("usage", 9),
        lambda receipt: receipt["org_policies"][0].__setitem__("enforced", "unknown"),
        lambda receipt: receipt["subnets"][0].__setitem__("collision_free", False),
        lambda receipt: receipt["phase_c_backend"].__setitem__(
            "bucket_sha256", receipt["phase_b_backend"]["bucket_sha256"]
        ),
        lambda receipt: receipt.__setitem__("expires_at", "2026-07-16T12:01:00Z"),
    ],
    ids=["project", "region", "apis", "quota", "policy", "collision", "backend", "freshness"],
)
def test_tampered_scope_is_rejected_even_with_a_valid_signature(mutate) -> None:
    payload = _payload()
    mutate(payload)

    with pytest.raises(verifier.ReceiptVerificationError):
        _verify(_signed(payload))


def test_tampering_after_signing_unknown_and_duplicate_fields_fail_closed() -> None:
    tampered = _signed()
    receipt = verifier.load_canonical_json(tampered, label="receipt")
    receipt["delegated_deployer_identity_sha256"] = "c" * 64
    with pytest.raises(verifier.ReceiptVerificationError, match="invalid_signature"):
        _verify(verifier.canonical_json_bytes(receipt))

    receipt = verifier.load_canonical_json(tampered, label="receipt")
    receipt["unexpected"] = "value"
    with pytest.raises(verifier.ReceiptVerificationError, match="unknown_or_missing_fields"):
        _verify(verifier.canonical_json_bytes(receipt))

    with pytest.raises(verifier.ReceiptVerificationError, match="duplicate_json_key"):
        _verify(b'{"contract_version":"g007-cloud-preflight-receipt.v1","contract_version":"g007-cloud-preflight-receipt.v1"}')


def test_untrusted_signer_and_stale_receipt_fail_closed() -> None:
    payload = _payload()
    payload["signer_key_id"] = "unknown-key"
    with pytest.raises(verifier.ReceiptVerificationError, match="untrusted_signer"):
        _verify(_signed(payload))

    payload = _payload()
    payload["expires_at"] = "2026-07-16T12:00:00Z"
    with pytest.raises(verifier.ReceiptVerificationError, match="receipt_not_fresh"):
        _verify(_signed(payload))
