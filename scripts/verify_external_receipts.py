#!/usr/bin/env python3
"""Fail-closed offline verifier for signed Onnuri external authorities."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Mapping

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

_MAX_VALIDITY = timedelta(seconds=60)
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_AMOUNT_RE = re.compile(r"^(0|[1-9][0-9]*)\.[0-9]{2}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_COMMON_FIELDS = frozenset(
    {"kind", "account_id", "observed_at", "expires_at", "evidence_digest", "signer_key_id", "signature"}
)
_PROVIDER_FIELDS = _COMMON_FIELDS | frozenset({"provider_id", "starting_balance", "currency"})
_SUPPLIER_FIELDS = _COMMON_FIELDS | frozenset(
    {"supplier_id", "ipv4_cidrs", "udp_port_ranges", "sip_proxy_identity"}
)


class ReceiptVerificationError(ValueError):
    """A receipt is malformed, untrusted, stale, or cryptographically invalid."""


def _reject(message: str) -> None:
    raise ReceiptVerificationError(message)


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the only accepted JSON encoding for a receipt or signed payload."""
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



def _load_canonical_receipt(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicate_object, parse_constant=_reject_nonstandard_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptVerificationError("invalid_json") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        _reject("noncanonical_json")
    return value


def _require_string(value: Any, name: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or (pattern and not pattern.fullmatch(value)):
        _reject(f"invalid_{name}")
    return value


def _parse_timestamp(value: Any, name: str) -> datetime:
    text = _require_string(value, name, _TIMESTAMP_RE)
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


def _validate_common(receipt: dict[str, Any], fields: frozenset[str], now: datetime) -> tuple[datetime, datetime]:
    if set(receipt) != fields:
        _reject("unknown_or_missing_fields")
    _require_string(receipt["account_id"], "account_id", _ID_RE)
    _require_string(receipt["signer_key_id"], "signer_key_id", _KEY_ID_RE)
    _require_string(receipt["evidence_digest"], "evidence_digest", _DIGEST_RE)
    observed_at = _parse_timestamp(receipt["observed_at"], "observed_at")
    expires_at = _parse_timestamp(receipt["expires_at"], "expires_at")
    if observed_at > now or expires_at <= now or expires_at <= observed_at or expires_at - observed_at > _MAX_VALIDITY:
        _reject("receipt_not_fresh")
    return observed_at, expires_at


def _validate_provider(receipt: dict[str, Any], now: datetime, expected_scope: tuple[str, str]) -> tuple[datetime, datetime]:
    if receipt.get("kind") != "provider-credit.v1":
        _reject("wrong_receipt_kind")
    observed_at, expires_at = _validate_common(receipt, _PROVIDER_FIELDS, now)
    provider_id = _require_string(receipt["provider_id"], "provider_id", _ID_RE)
    if (provider_id, receipt["account_id"]) != expected_scope:
        _reject("scope_mismatch")
    amount = _require_string(receipt["starting_balance"], "starting_balance", _AMOUNT_RE)
    try:
        if not Decimal(amount).is_finite():
            _reject("invalid_starting_balance")
    except InvalidOperation as exc:
        raise ReceiptVerificationError("invalid_starting_balance") from exc
    _require_string(receipt["currency"], "currency", _CURRENCY_RE)
    return observed_at, expires_at


def _validate_supplier(receipt: dict[str, Any], now: datetime, expected_scope: tuple[str, str]) -> tuple[datetime, datetime]:
    if receipt.get("kind") != "supplier-rtp.v1":
        _reject("wrong_receipt_kind")
    observed_at, expires_at = _validate_common(receipt, _SUPPLIER_FIELDS, now)
    supplier_id = _require_string(receipt["supplier_id"], "supplier_id", _ID_RE)
    if (supplier_id, receipt["account_id"]) != expected_scope:
        _reject("scope_mismatch")
    _require_string(receipt["sip_proxy_identity"], "sip_proxy_identity", _ID_RE)
    cidrs = receipt["ipv4_cidrs"]
    if not isinstance(cidrs, list) or not cidrs:
        _reject("invalid_ipv4_cidrs")
    networks: list[ipaddress.IPv4Network] = []
    for cidr in cidrs:
        if not isinstance(cidr, str):
            _reject("invalid_ipv4_cidrs")
        try:
            network = ipaddress.ip_network(cidr, strict=True)
        except ValueError as exc:
            raise ReceiptVerificationError("invalid_ipv4_cidrs") from exc
        if not isinstance(network, ipaddress.IPv4Network) or str(network) != cidr:
            _reject("invalid_ipv4_cidrs")
        networks.append(network)
    if networks != sorted(networks, key=lambda item: (int(item.network_address), item.prefixlen)):
        _reject("unnormalized_ipv4_cidrs")
    if any(left.overlaps(right) for left, right in zip(networks, networks[1:])):
        _reject("overlapping_ipv4_cidrs")
    ranges = receipt["udp_port_ranges"]
    if not isinstance(ranges, list) or not ranges:
        _reject("invalid_udp_port_ranges")
    normalized_ranges: list[tuple[int, int]] = []
    for port_range in ranges:
        if not isinstance(port_range, dict) or set(port_range) != {"start", "end"}:
            _reject("invalid_udp_port_ranges")
        start, end = port_range["start"], port_range["end"]
        if type(start) is not int or type(end) is not int or not 1 <= start <= end <= 65535:
            _reject("invalid_udp_port_ranges")
        normalized_ranges.append((start, end))
    if normalized_ranges != sorted(normalized_ranges):
        _reject("unnormalized_udp_port_ranges")
    if any(right[0] <= left[1] for left, right in zip(normalized_ranges, normalized_ranges[1:])):
        _reject("overlapping_udp_port_ranges")
    return observed_at, expires_at


def verify_receipt(
    raw: bytes,
    *,
    trusted_public_keys: Mapping[str, str],
    expected_scope: tuple[str, str],
    now: datetime,
) -> dict[str, str]:
    """Verify exactly one canonical receipt and return only redacted evidence."""
    if now.tzinfo is None or now.utcoffset() is None:
        _reject("now_must_be_timezone_aware")
    receipt = _load_canonical_receipt(raw)
    now = now.astimezone(UTC).replace(microsecond=0)
    if not isinstance(expected_scope, tuple) or len(expected_scope) != 2 or not all(
        isinstance(item, str) and _ID_RE.fullmatch(item) for item in expected_scope
    ):
        _reject("invalid_expected_scope")
    kind = receipt.get("kind")
    if kind == "provider-credit.v1":
        observed_at, expires_at = _validate_provider(receipt, now, expected_scope)
        identity = receipt["provider_id"]
    elif kind == "supplier-rtp.v1":
        observed_at, expires_at = _validate_supplier(receipt, now, expected_scope)
        identity = receipt["supplier_id"]
    else:
        _reject("wrong_receipt_kind")
    key_id = receipt["signer_key_id"]
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
    scope_hash = hashlib.sha256(f"{identity}\x00{receipt['account_id']}".encode("utf-8")).hexdigest()
    return {
        "kind": kind,
        "receipt_digest": hashlib.sha256(canonical_json_bytes(signed_payload)).hexdigest(),
        "scope_hash": scope_hash,
        "signer_key_hash": hashlib.sha256(key_id.encode("utf-8")).hexdigest(),
        "observed_at": observed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify one canonical signed external receipt offline")
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--authority-id", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--trusted-keys", required=True, type=Path, help="canonical JSON key-id to public-key map")
    parser.add_argument("--now", required=True, help="UTC time as YYYY-MM-DDTHH:MM:SSZ")
    args = parser.parse_args(argv)
    try:
        keys_raw = args.trusted_keys.read_bytes()
        trusted_keys = _load_canonical_receipt(keys_raw)
        now = _parse_timestamp(args.now, "now")
        receipt = verify_receipt(args.receipt.read_bytes(), trusted_public_keys=trusted_keys, expected_scope=(args.authority_id, args.account_id), now=now)
    except (OSError, ValueError, ReceiptVerificationError) as exc:
        print(f"receipt verification refused: {exc}", file=sys.stderr)
        return 1
    print(canonical_json_bytes(receipt).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
