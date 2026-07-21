#!/usr/bin/env python3
"""Canonical fail-closed assembler for a fully signed G008 closure manifest.

This tool never creates provider facts. Its draft input must contain the complete
redacted, role-signed receipt set and closure ledger. It computes the exact
reference map, adds only the closure-manifest signature, verifies every role
and cross-binding, then durably consumes the run nonce before publishing.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import importlib.util
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

_VERIFIER_PATH = Path(__file__).with_name("verify_onnuri_g008_closure_manifest.py")
_SPEC = importlib.util.spec_from_file_location("onnuri_g008_closure_verifier", _VERIFIER_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("G008 closure verifier could not be loaded")
verifier = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(verifier)


def _decode_private_key(value: str) -> Ed25519PrivateKey:
    try:
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32:
            raise ValueError("wrong length")
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise verifier.ManifestVerificationError(
            "closure-manifest private key must be a base64-encoded 32-byte Ed25519 seed"
        ) from exc


def _read_private_seed(path: Path) -> Ed25519PrivateKey:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as handle:
            if os.fstat(handle.fileno()).st_mode & 0o077:
                raise verifier.ManifestVerificationError(
                    "closure-manifest private key file must be private"
                )
            encoded = handle.read(256)
    except OSError as exc:
        raise verifier.ManifestVerificationError(
            "closure-manifest private key file is unavailable"
        ) from exc
    try:
        return _decode_private_key(encoded.decode("ascii").strip())
    except UnicodeDecodeError as exc:
        raise verifier.ManifestVerificationError(
            "closure-manifest private key file is invalid"
        ) from exc


def _require_canonical_closure_key(key: Ed25519PrivateKey) -> None:
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    expected = verifier._CANONICAL_KEYS["phase-c-preflight"][1]
    if verifier.hashlib.sha256(public).hexdigest() != expected:
        raise verifier.ManifestVerificationError(
            "closure-manifest private key does not match the canonical pinned signer"
        )


def assemble_manifest(
    draft: dict[str, Any],
    execution_bundle: bytes | bytearray | str | Path,
    closure_private_key: Ed25519PrivateKey,
    ledger_path: Path,
    *,
    now: Any | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Assemble, fully verify, and atomically consume one redacted draft."""
    if "signature" in draft:
        raise verifier.ManifestVerificationError("draft must not contain a manifest signature")
    _require_canonical_closure_key(closure_private_key)
    expected = {
        "version", "tenant_digest", "account_digest", "envelope_digest", "candidate_digest",
        "run_id_digest", "activation_nonce_digest", "run_nonce_digest", "trusted_keyset_digest",
        "execution_bundle_digest", "issued_at", "expires_at", "product_status", "phase_b",
        "registration", "evidence", "attempts", "closure_events",
    }
    if set(draft) != expected:
        raise verifier.ManifestVerificationError("draft fields are not the exact unsigned manifest schema")
    try:
        bundle_raw = (
            bytes(execution_bundle)
            if isinstance(execution_bundle, (bytes, bytearray))
            else Path(execution_bundle).read_bytes()
        )
    except OSError as exc:
        raise verifier.ManifestVerificationError(
            "canonical execution bundle is unavailable"
        ) from exc
    bundle_digest = verifier.hashlib.sha256(bundle_raw).hexdigest()
    if draft["execution_bundle_digest"] != bundle_digest:
        raise verifier.ManifestVerificationError(
            "draft execution_bundle_digest does not match canonical bundle bytes"
        )
    manifest = dict(draft)
    manifest["referenced_digests"] = {}
    manifest["referenced_digests"] = verifier._referenced_digests(manifest)
    unsigned = dict(manifest)
    signature = closure_private_key.sign(verifier.canonical_json_bytes(unsigned))
    manifest["signature"] = {
        "algorithm": "Ed25519",
        "key_id": verifier._CANONICAL_KEYS["phase-c-preflight"][0],
        "value": base64.b64encode(signature).decode("ascii"),
    }
    result = verifier.consume_manifest(manifest, bundle_raw, ledger_path, now=now)
    return manifest, result


def _write_exclusive(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(verifier.canonical_json_bytes(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise verifier.ManifestVerificationError("output must be a new private file") from exc
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Assemble a canonical signed G008 closure manifest.")
    parser.add_argument("draft", help="exact redacted unsigned manifest JSON")
    parser.add_argument("output", type=Path)
    parser.add_argument("--execution-bundle", required=True, type=Path)
    parser.add_argument("--closure-private-key-file", required=True, type=Path)

    parser.add_argument("--consumption-ledger", required=True, type=Path)
    args = parser.parse_args()
    try:
        draft = verifier.load_manifest(args.draft)
        private_key = _read_private_seed(args.closure_private_key_file)
        manifest, _ = assemble_manifest(
            draft,
            args.execution_bundle,
            private_key,
            args.consumption_ledger,
        )
        _write_exclusive(args.output, manifest)
    except (ValueError, verifier.ManifestVerificationError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
