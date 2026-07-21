from __future__ import annotations

import base64
import copy
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from nacl.signing import SigningKey

_MODULE_PATH = Path(__file__).parents[2] / "scripts" / "verify_external_receipts.py"
_SPEC = importlib.util.spec_from_file_location("external_receipt_verifier", _MODULE_PATH)
assert _SPEC and _SPEC.loader
verifier = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(verifier)

_NOW = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
_SIGNER = SigningKey(b"\x01" * 32)
_KEY_ID = "authority-2026-07"
_KEYS = {
    _KEY_ID: base64.urlsafe_b64encode(bytes(_SIGNER.verify_key)).rstrip(b"=").decode("ascii")
}


def _signed(payload: dict[str, object]) -> bytes:
    unsigned = copy.deepcopy(payload)
    signature = _SIGNER.sign(verifier.canonical_json_bytes(unsigned)).signature
    unsigned["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return verifier.canonical_json_bytes(unsigned)


def _provider() -> dict[str, object]:
    return {
        "kind": "provider-credit.v1",
        "provider_id": "provider-a",
        "account_id": "account-a",
        "starting_balance": "100.00",
        "currency": "KRW",
        "observed_at": "2026-07-16T11:59:30Z",
        "expires_at": "2026-07-16T12:00:30Z",
        "evidence_digest": "a" * 64,
        "signer_key_id": _KEY_ID,
    }


def _supplier() -> dict[str, object]:
    return {
        "kind": "supplier-rtp.v1",
        "supplier_id": "supplier-a",
        "account_id": "account-a",
        "ipv4_cidrs": ["198.51.100.0/25", "198.51.100.128/25"],
        "udp_port_ranges": [{"start": 10000, "end": 10010}, {"start": 20000, "end": 20000}],
        "sip_proxy_identity": "proxy-a",
        "observed_at": "2026-07-16T11:59:30Z",
        "expires_at": "2026-07-16T12:00:30Z",
        "evidence_digest": "b" * 64,
        "signer_key_id": _KEY_ID,
    }


def _verify(payload: dict[str, object], scope: tuple[str, str]) -> dict[str, str]:
    return verifier.verify_receipt(_signed(payload), trusted_public_keys=_KEYS, expected_scope=scope, now=_NOW)


def test_valid_provider_and_supplier_receipts_emit_only_redacted_receipts():
    provider = _verify(_provider(), ("provider-a", "account-a"))
    supplier = _verify(_supplier(), ("supplier-a", "account-a"))

    for receipt in (provider, supplier):
        assert set(receipt) == {"kind", "receipt_digest", "scope_hash", "signer_key_hash", "observed_at", "expires_at"}
        assert receipt["receipt_digest"] != "a" * 64
        assert receipt["scope_hash"] != "account-a"
    assert provider["kind"] == "provider-credit.v1"
    assert supplier["kind"] == "supplier-rtp.v1"


@pytest.mark.parametrize(
    ("payload", "scope"),
    [
        ({**_provider(), "starting_balance": "01.00"}, ("provider-a", "account-a")),
        ({**_provider(), "starting_balance": "100"}, ("provider-a", "account-a")),
        ({**_provider(), "currency": "krw"}, ("provider-a", "account-a")),
        ({**_supplier(), "ipv4_cidrs": ["198.51.100.1/24"]}, ("supplier-a", "account-a")),
        ({**_supplier(), "ipv4_cidrs": ["198.51.100.128/25", "198.51.100.0/25"]}, ("supplier-a", "account-a")),
        ({**_supplier(), "ipv4_cidrs": ["198.51.100.0/24", "198.51.100.0/25"]}, ("supplier-a", "account-a")),
        ({**_supplier(), "udp_port_ranges": [{"start": 0, "end": 1}]}, ("supplier-a", "account-a")),
        ({**_supplier(), "udp_port_ranges": [{"start": 10001, "end": 10002}, {"start": 10000, "end": 10001}]}, ("supplier-a", "account-a")),
    ],
)
def test_malformed_amount_currency_cidr_and_ports_fail_closed(payload, scope):
    with pytest.raises(verifier.ReceiptVerificationError):
        _verify(payload, scope)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda receipt: receipt.update({"expires_at": "2026-07-16T11:59:59Z"}),
        lambda receipt: receipt.update({"observed_at": "2026-07-16T12:00:01Z", "expires_at": "2026-07-16T12:00:31Z"}),
        lambda receipt: receipt.update({"expires_at": "2026-07-16T12:01:00Z"}),
        lambda receipt: receipt.update({"provider_id": "provider-b"}),
        lambda receipt: receipt.update({"signer_key_id": "unknown-key"}),
    ],
)
def test_stale_future_wrong_scope_and_wrong_signer_fail_closed(mutation):
    payload = _provider()
    mutation(payload)
    with pytest.raises(verifier.ReceiptVerificationError):
        _verify(payload, ("provider-a", "account-a"))


def test_tampering_duplicate_keys_unknown_fields_and_noncanonical_json_fail_closed():
    signed = _signed(_provider())
    tampered = json.loads(signed)
    tampered["evidence_digest"] = "c" * 64
    with pytest.raises(verifier.ReceiptVerificationError):
        verifier.verify_receipt(verifier.canonical_json_bytes(tampered), trusted_public_keys=_KEYS, expected_scope=("provider-a", "account-a"), now=_NOW)

    with pytest.raises(verifier.ReceiptVerificationError):
        _verify({**_provider(), "unexpected": "field"}, ("provider-a", "account-a"))

    duplicate = b'{"account_id":"account-a","account_id":"account-b"}'
    with pytest.raises(verifier.ReceiptVerificationError, match="duplicate_json_key"):
        verifier.verify_receipt(duplicate, trusted_public_keys=_KEYS, expected_scope=("provider-a", "account-a"), now=_NOW)
