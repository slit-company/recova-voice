#!/usr/bin/env python3
"""Create and independently verify fail-closed G008 derivative receipts."""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA_VERSION = "recova-g008-derivative-v3"
REQUIRED_IMAGES = ("recova-backend", "postgres", "recova-redis", "f12-ingress")
PLATFORM = "linux/amd64"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")
SOURCE_TREE_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
BACKEND_SOURCE = "https://github.com/slit-company/recova-voice"
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
LICENSE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+() -]{0,127}\Z")
IMAGE = re.compile(r"[^\s@/:]+(?:/[^\s@/:]+)*/[^\s@/:]+@sha256:[0-9a-f]{64}\Z")
LABEL_FIELDS = {
    "org.opencontainers.image.source",
    "org.opencontainers.image.revision",
    "org.opencontainers.image.licenses",
    "org.recova.base.digest",
}
SOURCE_PROVENANCE_FIELDS = {"label", "type", "value"}
ROOT_FIELDS = {"schema_version", "payload", "signature"}
PAYLOAD_FIELDS = {
    "candidate_manifest_sha256",
    "images",
    "issued_at",
    "expires_at",
    "live_window",
    "signer",
    "key_fingerprint",
}
IMAGE_FIELDS = {
    "name",
    "image",
    "platform",
    "labels",
    "source_provenance",
    "sbom_sha256",
    "vulnerability_sha256",
    "image_receipt_sha256",
}
RECEIPT_BOUND_IMAGE_FIELDS = IMAGE_FIELDS - {"image_receipt_sha256"}
INPUT_IMAGE_FIELDS = RECEIPT_BOUND_IMAGE_FIELDS - {"source_provenance"}
SIGNATURE_FIELDS = {"algorithm", "key_fingerprint", "value_b64"}
WINDOW_FIELDS = {"starts_at", "ends_at"}


class ReceiptError(ValueError):
    """A fail-closed derivative receipt refusal."""


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _duplicates_rejected(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReceiptError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read_json(path: Path, label: str, *, canonical: bool = False) -> tuple[Any, bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ReceiptError(f"cannot read {label}") from exc
    try:
        value = json.loads(raw, object_pairs_hook=_duplicates_rejected)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptError(f"invalid {label} JSON") from exc
    if canonical and raw != canonical_json(value):
        raise ReceiptError(f"{label} is not canonical JSON with one trailing newline")
    return value, raw


def _exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReceiptError(f"{label} must be an object")
    missing = fields - value.keys()
    extra = value.keys() - fields
    if missing or extra:
        details = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if extra:
            details.append("unknown " + ", ".join(sorted(extra)))
        raise ReceiptError(f"{label} has " + "; ".join(details))
    return value


def _text(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ReceiptError(f"invalid {label}")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is None:
        raise ReceiptError(f"invalid {label}; expected UTC RFC3339 seconds")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ReceiptError(f"invalid {label}") from exc
    return parsed


def _immutable_image(value: Any, label: str) -> str:
    image = _text(value, label, IMAGE)
    repository = image.rsplit("@", 1)[0]
    final_component = repository.rsplit("/", 1)[-1]
    if not final_component:
        raise ReceiptError(f"{label} must identify a repository")
    return image


def _source(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ReceiptError(f"invalid {label}")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.strip("/")
    ):
        raise ReceiptError(f"invalid {label}")
    return value


def _fingerprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sha256(raw)


def _validate_labels(value: Any, label: str, image_name: str) -> tuple[dict[str, str], dict[str, str]]:
    labels = _exact_object(value, LABEL_FIELDS, label)
    source = _source(labels["org.opencontainers.image.source"], f"{label}.source")
    revision = labels["org.opencontainers.image.revision"]
    if image_name == "recova-backend":
        if source != BACKEND_SOURCE:
            raise ReceiptError("recova-backend source label mismatch")
        snapshot = _text(revision, f"{label}.revision", SOURCE_TREE_SHA256)
        provenance = {
            "label": "org.opencontainers.image.revision",
            "type": "source_tree_sha256",
            "value": "sha256:" + snapshot,
        }
    else:
        if REVISION.fullmatch(revision):
            provenance = {
                "label": "org.opencontainers.image.revision",
                "type": "git_revision",
                "value": revision,
            }
        else:
            snapshot = revision.removeprefix("sha256:")
            _text(snapshot, f"{label}.revision", SOURCE_TREE_SHA256)
            provenance = {
                "label": "org.opencontainers.image.revision",
                "type": "source_image_digest",
                "value": "sha256:" + snapshot,
            }
    _text(labels["org.opencontainers.image.licenses"], f"{label}.licenses", LICENSE)
    _immutable_image(labels["org.recova.base.digest"], f"{label}.base")
    return labels, provenance


def image_receipt_digest(image: dict[str, Any]) -> str:
    return sha256(canonical_json({key: image[key] for key in sorted(RECEIPT_BOUND_IMAGE_FIELDS)}))


def _validate_images(value: Any, *, require_receipt_digest: bool) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(REQUIRED_IMAGES):
        raise ReceiptError("images must contain exactly four entries")
    fields = IMAGE_FIELDS if require_receipt_digest else INPUT_IMAGE_FIELDS
    result: list[dict[str, Any]] = []
    names: set[str] = set()
    image_refs: set[str] = set()
    for index, raw in enumerate(value):
        image = _exact_object(raw, fields, f"images[{index}]")
        name = _text(image["name"], f"images[{index}].name", SAFE_ID)
        if name in names:
            raise ReceiptError("duplicate image name")
        names.add(name)
        image_ref = _immutable_image(image["image"], f"images[{index}].image")
        if image_ref in image_refs:
            raise ReceiptError("duplicate image digest reference")
        image_refs.add(image_ref)
        if image["platform"] != PLATFORM:
            raise ReceiptError(f"images[{index}].platform must be {PLATFORM}")
        _, expected_provenance = _validate_labels(image["labels"], f"images[{index}].labels", name)
        if require_receipt_digest:
            provenance = _exact_object(
                image["source_provenance"], SOURCE_PROVENANCE_FIELDS, f"images[{index}].source_provenance"
            )
            if provenance != expected_provenance:
                raise ReceiptError(f"images[{index}] source provenance mismatch")
        else:
            image = dict(image, source_provenance=expected_provenance)
        _text(image["sbom_sha256"], f"images[{index}].sbom_sha256", DIGEST)
        _text(image["vulnerability_sha256"], f"images[{index}].vulnerability_sha256", DIGEST)
        if require_receipt_digest:
            _text(image["image_receipt_sha256"], f"images[{index}].image_receipt_sha256", DIGEST)
            if image["image_receipt_sha256"] != image_receipt_digest(image):
                raise ReceiptError(f"images[{index}] receipt digest mismatch")
        result.append(image)
    if names != set(REQUIRED_IMAGES):
        raise ReceiptError("images must contain exactly recova-backend, postgres, recova-redis, and f12-ingress")
    return sorted(result, key=lambda item: REQUIRED_IMAGES.index(item["name"]))


def _validate_window(payload: dict[str, Any], as_of: datetime | None) -> None:
    issued = _timestamp(payload["issued_at"], "issued_at")
    expires = _timestamp(payload["expires_at"], "expires_at")
    window = _exact_object(payload["live_window"], WINDOW_FIELDS, "live_window")
    starts = _timestamp(window["starts_at"], "live_window.starts_at")
    ends = _timestamp(window["ends_at"], "live_window.ends_at")
    if not issued <= starts < ends <= expires:
        raise ReceiptError("receipt issue/expiry must cover the non-empty live window")
    if as_of is not None:
        if as_of.tzinfo is None or as_of.utcoffset() is None:
            raise ReceiptError("as_of must be timezone-aware")
        now = as_of.astimezone(UTC)
        if not issued <= now <= expires:
            raise ReceiptError("receipt is not currently valid")
        if not starts <= now <= ends:
            raise ReceiptError("live window is stale or not yet open")


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise ReceiptError("invalid Ed25519 private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ReceiptError("private key is not Ed25519")
    return key


def _load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise ReceiptError("invalid Ed25519 public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ReceiptError("public key is not Ed25519")
    return key


def create_receipt(
    candidate_manifest: Path,
    image_metadata: Path,
    private_key_path: Path,
    signer: str,
    issued_at: str,
    expires_at: str,
    live_window_start: str,
    live_window_end: str,
) -> dict[str, Any]:
    _, candidate_raw = read_json(candidate_manifest, "candidate manifest", canonical=True)
    metadata, _ = read_json(image_metadata, "image metadata", canonical=True)
    metadata = _exact_object(metadata, {"images"}, "image metadata")
    images = _validate_images(metadata["images"], require_receipt_digest=False)
    images = [dict(image, image_receipt_sha256=image_receipt_digest(image)) for image in images]
    key = _load_private_key(private_key_path)
    fingerprint = _fingerprint(key.public_key())
    payload = {
        "candidate_manifest_sha256": sha256(candidate_raw),
        "expires_at": expires_at,
        "images": images,
        "issued_at": issued_at,
        "key_fingerprint": fingerprint,
        "live_window": {"ends_at": live_window_end, "starts_at": live_window_start},
        "signer": _text(signer, "signer", SAFE_ID),
    }
    _validate_window(payload, None)
    encoded = canonical_json(payload)
    signature = base64.b64encode(key.sign(encoded)).decode("ascii")
    return {
        "payload": payload,
        "schema_version": SCHEMA_VERSION,
        "signature": {"algorithm": "Ed25519", "key_fingerprint": fingerprint, "value_b64": signature},
    }


def verify_receipt(
    receipt_path: Path,
    candidate_manifest: Path,
    public_key_path: Path,
    as_of: datetime,
) -> dict[str, Any]:
    receipt, _ = read_json(receipt_path, "derivative receipt", canonical=True)
    receipt = _exact_object(receipt, ROOT_FIELDS, "receipt")
    if receipt["schema_version"] != SCHEMA_VERSION:
        raise ReceiptError(f"schema_version must be {SCHEMA_VERSION}")
    payload = _exact_object(receipt["payload"], PAYLOAD_FIELDS, "payload")
    signature = _exact_object(receipt["signature"], SIGNATURE_FIELDS, "signature")
    if signature["algorithm"] != "Ed25519":
        raise ReceiptError("signature algorithm must be Ed25519")
    key = _load_public_key(public_key_path)
    fingerprint = _fingerprint(key)
    if payload["key_fingerprint"] != fingerprint or signature["key_fingerprint"] != fingerprint:
        raise ReceiptError("signing key fingerprint mismatch")
    _text(payload["signer"], "signer", SAFE_ID)
    images = _validate_images(payload["images"], require_receipt_digest=True)
    if payload["images"] != images:
        raise ReceiptError("images must use the canonical required order")
    _validate_window(payload, as_of)
    _, candidate_raw = read_json(candidate_manifest, "candidate manifest", canonical=True)
    _text(payload["candidate_manifest_sha256"], "candidate_manifest_sha256", DIGEST)
    if payload["candidate_manifest_sha256"] != sha256(candidate_raw):
        raise ReceiptError("candidate manifest digest mismatch")
    try:
        encoded_signature = base64.b64decode(signature["value_b64"], validate=True)
        if len(encoded_signature) != 64:
            raise ValueError("wrong signature length")
        key.verify(encoded_signature, canonical_json(payload))
    except (binascii.Error, InvalidSignature, TypeError, ValueError) as exc:
        raise ReceiptError("invalid derivative receipt signature") from exc
    return receipt


def _parse_as_of(value: str) -> datetime:
    return _timestamp(value, "as_of")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create", help="create a signed derivative receipt")
    create.add_argument("--candidate-manifest", type=Path, required=True)
    create.add_argument("--image-metadata", type=Path, required=True)
    create.add_argument("--private-key", type=Path, required=True)
    create.add_argument("--signer", required=True)
    create.add_argument("--issued-at", required=True)
    create.add_argument("--expires-at", required=True)
    create.add_argument("--live-window-start", required=True)
    create.add_argument("--live-window-end", required=True)
    create.add_argument("--output", type=Path, required=True)
    verify = subparsers.add_parser("verify", help="independently verify a derivative receipt")
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--candidate-manifest", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--as-of", type=_parse_as_of)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            receipt = create_receipt(
                args.candidate_manifest,
                args.image_metadata,
                args.private_key,
                args.signer,
                args.issued_at,
                args.expires_at,
                args.live_window_start,
                args.live_window_end,
            )
            args.output.write_bytes(canonical_json(receipt))
            print(f"created {SCHEMA_VERSION} receipt")
        else:
            verify_receipt(args.receipt, args.candidate_manifest, args.public_key, args.as_of or datetime.now(UTC))
            print(f"verified {SCHEMA_VERSION} receipt")
    except (OSError, ReceiptError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
