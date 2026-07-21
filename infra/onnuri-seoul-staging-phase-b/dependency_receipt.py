#!/usr/bin/env python3
"""Create and verify offline Ed25519 Phase B dependency receipts.

This program only reads explicit local files.  It does not invoke Terraform,
read cloud state, use credentials, or contact a network service.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

CONTRACT_VERSION = "onnuri-phase-b-dependency-receipt-v1"
HASH_FIELDS = {
    "canonical_state_sha256",
    "canonical_output_sha256",
    "canonical_source_sha256",
}
PAYLOAD_FIELDS = {
    "contract_version",
    "project_id",
    "region",
    "subnet_ipv4_cidr",
    "state_backend_bucket",
    "state_backend_prefix",
    "state_generation",
    "state_serial",
    *HASH_FIELDS,
    "ingress_deny_rule_self_link",
    "egress_deny_rule_self_link",
    "issued_at",
    "expires_at",
    "signer_key_id",
}
SCOPE_FIELDS = {
    "project_id",
    "region",
    "subnet_ipv4_cidr",
    "state_backend_bucket",
    "state_backend_prefix",
}
RECEIPT_FIELDS = {"payload", "signature_b64"}
KEY_ID = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


class ReceiptError(ValueError):
    """Raised when a receipt or its local input is not trustworthy."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json_bytes(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_object, parse_constant=lambda value: (_ for _ in ()).throw(ReceiptError(f"invalid JSON constant: {value}")))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReceiptError(f"invalid {label} JSON") from error


def read_json(path: str, label: str) -> Any:
    try:
        return parse_json_bytes(Path(path).read_bytes(), label)
    except OSError as error:
        raise ReceiptError(f"cannot read {label}") from error


def require_exact_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReceiptError(f"{label} has missing or unknown fields")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ReceiptError(f"invalid {label}")
    return value


def parse_timestamp(value: Any, label: str) -> datetime:
    text = require_string(value, label)
    if not TIMESTAMP.fullmatch(text):
        raise ReceiptError(f"invalid {label}")
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ReceiptError(f"invalid {label}") from error


def validate_payload(value: Any) -> dict[str, Any]:
    payload = require_exact_fields(value, PAYLOAD_FIELDS, "payload")
    if payload["contract_version"] != CONTRACT_VERSION:
        raise ReceiptError("unsupported contract version")
    for name in PAYLOAD_FIELDS - {"contract_version", "state_generation", "state_serial", "issued_at", "expires_at"}:
        require_string(payload[name], name)
    if not KEY_ID.fullmatch(payload["signer_key_id"]):
        raise ReceiptError("invalid signer_key_id")
    for name in HASH_FIELDS:
        if not SHA256.fullmatch(payload[name]):
            raise ReceiptError(f"invalid {name}")
    for name in ("state_generation", "state_serial"):
        if isinstance(payload[name], bool) or not isinstance(payload[name], int) or payload[name] < 0:
            raise ReceiptError(f"invalid {name}")
    issued = parse_timestamp(payload["issued_at"], "issued_at")
    expires = parse_timestamp(payload["expires_at"], "expires_at")
    if issued >= expires:
        raise ReceiptError("receipt expiry must follow issuance")
    prefix = payload["state_backend_prefix"]
    if prefix.startswith("/") or prefix.endswith("/"):
        raise ReceiptError("invalid state_backend_prefix")
    expected_firewall_prefix = f"https://www.googleapis.com/compute/v1/projects/{payload['project_id']}/global/firewalls/"
    for name in ("ingress_deny_rule_self_link", "egress_deny_rule_self_link"):
        if not payload[name].startswith(expected_firewall_prefix):
            raise ReceiptError(f"invalid {name}")
    return payload


def decode_b64(value: Any, label: str, expected_length: int) -> bytes:
    text = require_string(value, label)
    try:
        decoded = base64.b64decode(text.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise ReceiptError(f"invalid {label}") from error
    if len(decoded) != expected_length:
        raise ReceiptError(f"invalid {label}")
    return decoded


def read_private_key(path: str) -> tuple[str, Ed25519PrivateKey]:
    value = require_exact_fields(read_json(path, "private key"), {"key_id", "private_key_b64"}, "private key")
    key_id = require_string(value["key_id"], "key_id")
    if not KEY_ID.fullmatch(key_id):
        raise ReceiptError("invalid key_id")
    return key_id, Ed25519PrivateKey.from_private_bytes(decode_b64(value["private_key_b64"], "private_key_b64", 32))


def read_trusted_key(path: str) -> tuple[str, Ed25519PublicKey]:
    value = require_exact_fields(read_json(path, "trusted key"), {"key_id", "public_key_b64"}, "trusted key")
    key_id = require_string(value["key_id"], "key_id")
    if not KEY_ID.fullmatch(key_id):
        raise ReceiptError("invalid key_id")
    return key_id, Ed25519PublicKey.from_public_bytes(decode_b64(value["public_key_b64"], "public_key_b64", 32))


def read_scope(path: str) -> dict[str, Any]:
    scope = require_exact_fields(read_json(path, "expected scope"), SCOPE_FIELDS, "expected scope")
    for name in SCOPE_FIELDS:
        require_string(scope[name], name)
    return scope


def sign(manifest_path: str, private_key_path: str) -> bytes:
    payload = validate_payload(read_json(manifest_path, "manifest"))
    key_id, private_key = read_private_key(private_key_path)
    if payload["signer_key_id"] != key_id:
        raise ReceiptError("manifest signer_key_id does not match private key")
    signature = private_key.sign(canonical_json(payload))
    return canonical_json({"payload": payload, "signature_b64": base64.b64encode(signature).decode("ascii")})


def verify(receipt_path: str, trusted_key_path: str, scope_path: str, now: str | None = None) -> None:
    raw = Path(receipt_path).read_bytes()
    receipt = require_exact_fields(parse_json_bytes(raw, "receipt"), RECEIPT_FIELDS, "receipt")
    if canonical_json(receipt) != raw:
        raise ReceiptError("receipt is not canonical JSON")
    payload = validate_payload(receipt["payload"])
    scope = read_scope(scope_path)
    if any(payload[name] != scope[name] for name in SCOPE_FIELDS):
        raise ReceiptError("receipt scope does not match expected scope")
    key_id, public_key = read_trusted_key(trusted_key_path)
    if payload["signer_key_id"] != key_id:
        raise ReceiptError("untrusted signer_key_id")
    try:
        public_key.verify(decode_b64(receipt["signature_b64"], "signature_b64", 64), canonical_json(payload))
    except InvalidSignature as error:
        raise ReceiptError("invalid receipt signature") from error
    current = parse_timestamp(now, "now") if now is not None else datetime.now(timezone.utc).replace(microsecond=0)
    if current >= parse_timestamp(payload["expires_at"], "expires_at"):
        raise ReceiptError("receipt has expired")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sign_parser = commands.add_parser("sign")
    sign_parser.add_argument("--manifest", required=True)
    sign_parser.add_argument("--private-key", required=True)
    sign_parser.add_argument("--output", required=True)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--receipt", required=True)
    verify_parser.add_argument("--trusted-key", required=True)
    verify_parser.add_argument("--expected-scope", required=True)
    verify_parser.add_argument("--now")
    args = parser.parse_args(argv)
    try:
        if args.command == "sign":
            Path(args.output).write_bytes(sign(args.manifest, args.private_key))
        else:
            verify(args.receipt, args.trusted_key, args.expected_scope, args.now)
    except (OSError, ReceiptError) as error:
        print(f"receipt verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
