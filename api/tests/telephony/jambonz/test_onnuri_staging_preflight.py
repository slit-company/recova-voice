from decimal import Decimal

import pytest

from api.db.telephony_number_inventory_client import TelephonyNumberInventoryConflictError
from api.services.onnuri_staging_preflight import canonicalize_preflight_input


def _exception_input() -> dict:
    starting = Decimal("10.00")
    return {
        "soak_policy": "exception_waiting",
        "authorization_scope": "through_application_smoke",
        "proxy_provenance": "user_approved_canary_assumption",
        "authorization_reference": "operator-approved-no-traffic-reference",
        "starting_balance": format(starting, "f"),
        "warning_balance": format(starting * Decimal("0.20"), "f"),
        "stop_balance": "0",
        "max_discovery_smoke_spend": format(starting, "f"),
        "max_soak_spend": "0",
        "outbound_proxy": "61.78.32.184:5060/UDP",
        "source_cidr": "61.78.32.184/32",
        "currency": "KRW",
        "provider_evidence_ref": "portal-balance-observation",
        "starting_balance_evidence_ref": "portal-balance-observation",
        "observed_at": "2026-07-13T17:00:00Z",
        "scheduler_checkpoint_ref": "no-traffic-scheduler-checkpoint",
        "firewall_checkpoint_ref": "no-traffic-firewall-checkpoint",
        "sink_checkpoint_ref": "no-traffic-sink-checkpoint",
        "identity_checkpoint_ref": "no-traffic-identity-checkpoint",
        "owned_destinations_ref": "owned-destinations-register",
        "max_inbound_attempts": 2,
        "max_outbound_attempts": 2,
        "max_duration_seconds": 120,
        "max_concurrency": 1,
        "cps": 1,
        "retries": 0,
    }


def test_preflight_canonical_hash_is_key_order_independent():
    first, first_hash = canonicalize_preflight_input(_exception_input())
    second, second_hash = canonicalize_preflight_input(dict(reversed(_exception_input().items())))

    assert first == second
    assert first_hash == second_hash
    assert len(first_hash) == 64


@pytest.mark.parametrize(
    "input_value",
    [
        {**_exception_input(), "password": "prohibited"},
        {**_exception_input(), "supplier_password_hash": "prohibited"},
        {**_exception_input(), "unexpected_control": "rejected"},
        {**_exception_input(), "warning_balance": "2.01"},
        {**_exception_input(), "starting_balance": "NaN"},
    ],
)
def test_preflight_rejects_secret_material_and_invalid_exception_credit(input_value):
    with pytest.raises(TelephonyNumberInventoryConflictError):
        canonicalize_preflight_input(input_value)
def _retain_standard_input() -> dict:
    value = _exception_input()
    value.update(
        {
            "soak_policy": "retain_standard",
            "authorization_scope": "retain_standard",
            "proxy_provenance": "supplier_authoritative",
            "outbound_proxy": "supplier-authoritative-proxy",
            "source_cidr": "supplier-authoritative-cidr",
            "starting_balance": "100.00",
            "warning_balance": "20.00",
            "stop_balance": "1.00",
            "max_discovery_smoke_spend": "0",
            "max_soak_spend": "10.00",
            "max_inbound_attempts": 20,
            "max_outbound_attempts": 20,
            "max_duration_seconds": 3600,
            "max_concurrency": 10,
            "cps": 1,
            "retries": 0,
        }
    )
    return value


def test_preflight_canonicalization_strips_strings_and_validates_retain_standard():
    canonical, _ = canonicalize_preflight_input(
        {**_retain_standard_input(), "authorization_reference": "  supplier-ref  "}
    )

    assert canonical["authorization_reference"] == "supplier-ref"


@pytest.mark.parametrize(
    "input_value",
    [
        {**_retain_standard_input(), "max_soak_spend": "0"},
        {**_retain_standard_input(), "authorization_scope": "through_application_smoke"},
        {**_retain_standard_input(), "max_concurrency": 1},
    ],
)
def test_retain_standard_requires_full_authoritative_controls(input_value):
    with pytest.raises(TelephonyNumberInventoryConflictError):
        canonicalize_preflight_input(input_value)
