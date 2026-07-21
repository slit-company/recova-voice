"""Pure canonical policy for password-free Onnuri staging proofs."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal, InvalidOperation
from typing import Any


class OnnuriPreflightPolicyError(ValueError):
    pass
LEGACY_EVALUATOR_VERSION = "recova_onnuri_staging_policy_v1"
SMOKE_EVALUATOR_VERSION = "recova_onnuri_smoke_authority_v2"
DISPATCH_CAPABILITY_DOMAIN = "recova.onnuri.smoke.dispatch.v1"
MEDIA_CAPABILITY_DOMAIN = "recova.onnuri.smoke.media.v1"
SMOKE_MAX_ATTEMPTS = 3
SMOKE_MAX_DURATION_SECONDS = 60
SMOKE_MAX_DIRECTION_ATTEMPTS = 1


def validate_evaluator_linkage(
    evaluator_version: str | None,
    *,
    envelope_id: int | None,
    attempt_id: int | None,
    authenticated_operator_user_id: int | None,
    workflow_owner_user_id: int | None,
    idempotency_key: str | None,
) -> None:
    """Keep legacy rows valid while making v2 linkage all-or-nothing."""
    if evaluator_version in (None, LEGACY_EVALUATOR_VERSION):
        if any(
            value is not None
            for value in (
                envelope_id,
                attempt_id,
                authenticated_operator_user_id,
                workflow_owner_user_id,
                idempotency_key,
            )
        ):
            raise OnnuriPreflightPolicyError("legacy_evaluator_linkage_forbidden")
        return
    if evaluator_version != SMOKE_EVALUATOR_VERSION:
        raise OnnuriPreflightPolicyError("unsupported_evaluator_version")
    if any(
        value is None
        for value in (
            envelope_id,
            attempt_id,
            authenticated_operator_user_id,
            workflow_owner_user_id,
            idempotency_key,
        )
    ):
        raise OnnuriPreflightPolicyError("smoke_evaluator_linkage_required")
    if not isinstance(idempotency_key, str) or not idempotency_key.strip():
        raise OnnuriPreflightPolicyError("smoke_evaluator_idempotency_invalid")


EXCEPTION_POLICY = "exception_waiting"
RETAIN_STANDARD_POLICY = "retain_standard"
DECIMAL_FIELDS = frozenset(
    {
        "starting_balance",
        "warning_balance",
        "stop_balance",
        "max_discovery_smoke_spend",
        "max_soak_spend",
    }
)
STRING_FIELDS = frozenset(
    {
        "soak_policy",
        "authorization_scope",
        "proxy_provenance",
        "authorization_reference",
        "outbound_proxy",
        "source_cidr",
        "currency",
        "provider_evidence_ref",
        "starting_balance_evidence_ref",
        "observed_at",
        "scheduler_checkpoint_ref",
        "firewall_checkpoint_ref",
        "sink_checkpoint_ref",
        "identity_checkpoint_ref",
        "owned_destinations_ref",
    }
)
INTEGER_FIELDS = frozenset(
    {
        "max_inbound_attempts",
        "max_outbound_attempts",
        "max_duration_seconds",
        "max_concurrency",
        "cps",
        "retries",
    }
)
ALLOWED_FIELDS = STRING_FIELDS | DECIMAL_FIELDS | INTEGER_FIELDS
EXCEPTION_LIMITS = {
    "max_inbound_attempts": 2,
    "max_outbound_attempts": 2,
    "max_duration_seconds": 120,
    "max_concurrency": 1,
    "cps": 1,
    "retries": 0,
}


def canonicalize_proof_input(value: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if not isinstance(value, dict):
        raise OnnuriPreflightPolicyError("input_must_be_object")
    unknown = set(value) - ALLOWED_FIELDS
    if unknown:
        raise OnnuriPreflightPolicyError("input_contains_unknown_field")

    canonical: dict[str, Any] = {}
    for key, item in value.items():
        if key in DECIMAL_FIELDS:
            canonical[key] = _decimal(item, key)
        elif key in INTEGER_FIELDS:
            if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                raise OnnuriPreflightPolicyError(f"{key}_invalid")
            canonical[key] = item
        elif not isinstance(item, str) or not item.strip():
            raise OnnuriPreflightPolicyError(f"{key}_must_be_nonblank_string")
        else:
            canonical[key] = item.strip()

    _validate_policy(canonical)
    encoded = json.dumps(
        canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return canonical, hashlib.sha256(encoded).hexdigest()


def _decimal(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise OnnuriPreflightPolicyError(f"{field}_must_be_decimal_string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise OnnuriPreflightPolicyError(f"{field}_invalid") from exc
    if not parsed.is_finite() or parsed < 0 or format(parsed, "f") != value:
        raise OnnuriPreflightPolicyError(f"{field}_invalid")
    return format(parsed, "f")


def _require_fields(canonical: dict[str, Any]) -> None:
    if not ALLOWED_FIELDS.issubset(canonical):
        raise OnnuriPreflightPolicyError("required_fields_missing")


def _validate_policy(canonical: dict[str, Any]) -> None:
    policy = canonical.get("soak_policy")
    if policy not in {EXCEPTION_POLICY, RETAIN_STANDARD_POLICY}:
        raise OnnuriPreflightPolicyError("invalid_soak_policy")
    _require_fields(canonical)
    balances = {field: Decimal(canonical[field]) for field in DECIMAL_FIELDS}

    if policy == EXCEPTION_POLICY:
        if (
            canonical["authorization_scope"] != "through_application_smoke"
            or canonical["proxy_provenance"] != "user_approved_canary_assumption"
            or canonical["outbound_proxy"] != "61.78.32.184:5060/UDP"
            or canonical["source_cidr"] != "61.78.32.184/32"
            or any(canonical[key] != value for key, value in EXCEPTION_LIMITS.items())
            or balances["warning_balance"]
            != balances["starting_balance"] * Decimal("0.20")
            or balances["stop_balance"] != 0
            or balances["max_discovery_smoke_spend"]
            != balances["starting_balance"]
            or balances["max_soak_spend"] != 0
        ):
            raise OnnuriPreflightPolicyError("exception_controls_invalid")
        return

    if (
        canonical["authorization_scope"] != "retain_standard"
        or canonical["proxy_provenance"] != "supplier_authoritative"
        or canonical["retries"] != 0
        or balances["starting_balance"] <= 0
        or balances["max_soak_spend"] <= 0
        or balances["max_discovery_smoke_spend"] != 0
        or balances["warning_balance"] < 0
        or balances["stop_balance"] < 0
        or canonical["max_inbound_attempts"] < 20
        or canonical["max_outbound_attempts"] < 20
        or canonical["max_duration_seconds"] <= 0
        or canonical["max_concurrency"] < 10
        or canonical["cps"] <= 0
    ):
        raise OnnuriPreflightPolicyError("retain_standard_controls_invalid")
