#!/usr/bin/env python3
"""Create independently signed Phase C live-preflight receipts, including the dedicated redacted IAM-provisioning role, and bundles."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from scripts import verify_phase_c_live_preflight as verifier
except ModuleNotFoundError:  # Direct execution puts scripts/ on sys.path.
    import verify_phase_c_live_preflight as verifier


class CreationError(ValueError):
    """A deliberately non-sensitive creation failure."""


def _fail(code: str) -> NoReturn:
    raise CreationError(code)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _read_canonical(path: str | Path, json_code: str, canonical_code: str) -> Any:
    try:
        raw = Path(path).read_bytes()
    except (OSError, TypeError):
        _fail("input_unavailable")
    try:
        value = verifier._decode_json(raw, json_code)
    except verifier.VerificationError as exc:
        raise CreationError(str(exc)) from None
    if verifier._canonical(value) != raw:
        _fail(canonical_code)
    return value


def _load_context(path: str | Path) -> tuple[dict[str, Any], str]:
    context = _read_canonical(path, "context_json", "context_noncanonical")
    try:
        context = verifier._validate_context(context)
    except verifier.VerificationError as exc:
        raise CreationError(str(exc)) from None
    return context, verifier._canonical(context).decode("utf-8")


def _load_private(path: str | Path, trusted_public: bytes) -> Ed25519PrivateKey:
    try:
        raw = Path(path).read_bytes()
        key = serialization.load_pem_private_key(raw, password=None)
    except (OSError, TypeError, ValueError):
        _fail("private_key_invalid")
    if not isinstance(key, Ed25519PrivateKey):
        _fail("private_key_invalid")
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if public != trusted_public:
        _fail("private_key_mismatch")
    return key


def _timestamp(value: str, code: str) -> datetime:
    try:
        return verifier._timestamp(value, code)
    except verifier.VerificationError as exc:
        raise CreationError(str(exc)) from None


def _common(context: dict[str, Any]) -> dict[str, str]:
    return {
        "project_id": context["project_id"],
        "region": context["region"],
        "run_id_digest": verifier._sha(context["run_id"].encode()),
        "activation_nonce_digest": verifier._sha(context["activation_nonce"].encode()),
        "phase_b_manifest_sha256": context["phase_b"]["manifest_sha256"],
        "candidate_manifest_sha256": context["derivative"]["candidate_manifest_sha256"],
        "network_self_link_sha256": verifier._sha(context["phase_b"]["network_self_link"].encode()),
        "live_window_start_utc": context["live_window_start_utc"],
        "live_window_end_utc": context["live_window_end_utc"],
    }


def _signed(payload: dict[str, Any], role: str, private: Ed25519PrivateKey) -> dict[str, Any]:
    key_id = verifier.TRUSTED_KEYS[role][0]
    signature = base64.urlsafe_b64encode(private.sign(verifier._canonical(payload))).rstrip(b"=").decode()
    return {
        "payload": payload,
        "signature": {"algorithm": "Ed25519", "key_id": key_id, "value": signature},
    }


def _trusted_keys() -> dict[str, bytes]:
    try:
        return verifier._load_keys()
    except verifier.VerificationError as exc:
        raise CreationError(str(exc)) from None


def _write_new(path: str | Path, value: Any) -> None:
    raw = verifier._canonical(value)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except (OSError, TypeError):
        _fail("output_unavailable")
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        try:
            Path(path).unlink()
        except OSError:
            pass
        _fail("output_write_failed")




def _read_regular(path: str | Path, code: str) -> bytes:
    try:
        info = os.lstat(path)
        if not os.path.isfile(path) or os.path.islink(path) or not __import__("stat").S_ISREG(info.st_mode):
            _fail(code)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            current = os.fstat(descriptor)
            if current.st_dev != info.st_dev or current.st_ino != info.st_ino or not __import__("stat").S_ISREG(current.st_mode):
                _fail(code)
            raw = os.read(descriptor, 262145)
        finally:
            os.close(descriptor)
        if len(raw) > 262144:
            _fail(code)
        return raw
    except (OSError, TypeError):
        _fail(code)


def seal_route_evidence_bundle(
    manifest_path: str | Path,
    file_arguments: list[str],
    adapter_path: str | Path,
    output_path: str | Path,
) -> tuple[str, str]:
    raw_manifest = _read_regular(manifest_path, "route_evidence_bundle_unavailable")
    try:
        bundle = verifier._decode_json(raw_manifest, "route_evidence_bundle_json")
        bundle = verifier._exact(bundle, verifier.ROUTE_EVIDENCE_SOURCE_KEYS, "route_evidence_bundle_schema")
    except verifier.VerificationError as exc:
        raise CreationError(str(exc)) from None
    if verifier._canonical(bundle) != raw_manifest:
        _fail("route_evidence_bundle_noncanonical")
    if (
        bundle["schema_version"] != "recova-onnuri-route-evidence-bundle-v1"
        or verifier.SECRET_VERSION.fullmatch(bundle["numeric_version_resource_name"] or "") is None
        or not isinstance(bundle["organization_id"], int) or bundle["organization_id"] <= 0
        or not all(isinstance(bundle[name], str) and verifier.HEX64.fullmatch(bundle[name]) for name in ("request_digest", "candidate_digest", "route_profile_digest", "approved_root_locator_digest", "inventory_locator_digest"))
        or not isinstance(bundle["opaque_handle"], str) or not bundle["opaque_handle"] or verifier.HEX64.fullmatch(bundle["opaque_handle"]) is not None
        or not isinstance(bundle["inventory_version"], str) or not bundle["inventory_version"]
    ):
        _fail("route_evidence_bundle_binding")
    supplied: dict[str, Path] = {}
    for value in file_arguments:
        if not isinstance(value, str) or "=" not in value:
            _fail("route_evidence_file_argument")
        name, path = value.split("=", 1)
        if name not in verifier.ROUTE_EVIDENCE_FILE_NAMES or not path or name in supplied:
            _fail("route_evidence_file_argument")
        supplied[name] = Path(path)
    if set(supplied) != set(verifier.ROUTE_EVIDENCE_FILE_NAMES):
        _fail("route_evidence_file_argument")
    encoded: dict[str, str] = {}
    for name in verifier.ROUTE_EVIDENCE_FILE_NAMES:
        raw = _read_regular(supplied[name], "route_evidence_file_unavailable")
        digest = bundle[f"{name}_sha256"]
        if not isinstance(digest, str) or verifier.HEX64.fullmatch(digest) is None or verifier._sha(raw) != digest:
            _fail("route_evidence_file_binding")
        encoded[name] = base64.b64encode(raw).decode("ascii")
    adapter = _read_regular(adapter_path, "route_evidence_adapter_unavailable")
    if (
        bundle["adapter_path"] != "adapter"
        or not isinstance(bundle["adapter_sha256"], str)
        or verifier.HEX64.fullmatch(bundle["adapter_sha256"]) is None
        or verifier._sha(adapter) != bundle["adapter_sha256"]
        or bundle["adapter_execution_mode"] != "fixed-executable-v1"
        or bundle["adapter_stdin_schema"] != "recova-onnuri-restricted-inventory-adapter-invocation-v1"
        or bundle["adapter_stdin_exactly_one_lf"] is not True
        or bundle["adapter_stdout_schema"] != "recova-onnuri-restricted-inventory-adapter-v1"
        or type(bundle["adapter_stdout_max_bytes"]) is not int or not 0 < bundle["adapter_stdout_max_bytes"] <= 262144
        or type(bundle["adapter_stderr_max_bytes"]) is not int or not 0 <= bundle["adapter_stderr_max_bytes"] <= 262144
        or type(bundle["adapter_timeout_ms"]) is not int or not 0 < bundle["adapter_timeout_ms"] <= 5000
    ):
        _fail("route_evidence_adapter_binding")
    sealed = {key: value for key, value in bundle.items() if key != "adapter_path"} | encoded | {
        "adapter": base64.b64encode(adapter).decode("ascii")
    }
    raw = verifier._canonical(sealed) + b"\n"
    try:
        fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(raw); output.flush(); os.fsync(output.fileno())
    except (OSError, TypeError):
        _fail("output_unavailable")
    except Exception:
        try: Path(output_path).unlink()
        except OSError: pass
        _fail("output_write_failed")
    return verifier._sha(raw), verifier._sha(bundle["opaque_handle"].encode())


def create_bootstrap_manifest(
    secret_versions_path: str | Path,
    transaction_authority_service_account: str,
    output_path: str | Path,
    route_evidence_bundle_path: str | Path,
    route_evidence_bundle_sha256: str,
) -> str:

    secret_versions = _read_canonical(
        secret_versions_path,
        "bootstrap_secret_versions_json",
        "bootstrap_secret_versions_noncanonical",
    )
    try:
        verifier._secret_map(secret_versions, verifier.G008_SECRET_IDS)
    except verifier.VerificationError as exc:
        raise CreationError(str(exc)) from None
    if (
        not isinstance(transaction_authority_service_account, str)
        or verifier.SERVICE_ACCOUNT.fullmatch(transaction_authority_service_account) is None
    ):
        _fail("bootstrap_manifest_authority")
    route_evidence_bundle = _read_canonical(
        route_evidence_bundle_path,
        "bootstrap_route_evidence_bundle_json",
        "bootstrap_route_evidence_bundle_noncanonical",
    )
    try:
        route_evidence_bundle = verifier._exact(route_evidence_bundle, verifier.ROUTE_EVIDENCE_SOURCE_KEYS, "bootstrap_manifest_route_evidence")
    except verifier.VerificationError as exc:
        raise CreationError(str(exc)) from None
    if (
        verifier.SECRET_VERSION.fullmatch(route_evidence_bundle["numeric_version_resource_name"] or "") is None
        or route_evidence_bundle["schema_version"] != "recova-onnuri-route-evidence-bundle-v1"
        or not isinstance(route_evidence_bundle["organization_id"], int)
        or route_evidence_bundle["organization_id"] <= 0
        or not all(isinstance(route_evidence_bundle[name], str) and verifier.HEX64.fullmatch(route_evidence_bundle[name]) for name in ("request_digest", "candidate_digest", "route_profile_digest"))
        or not isinstance(route_evidence_bundle["opaque_handle"], str)
        or not route_evidence_bundle["opaque_handle"]
        or verifier.HEX64.fullmatch(route_evidence_bundle["opaque_handle"]) is not None
    ):
        _fail("bootstrap_manifest_route_evidence")

    if verifier.HEX64.fullmatch(route_evidence_bundle_sha256) is None:
        _fail("bootstrap_manifest_route_evidence")

    binding_input = {
        "schema_version": "recova-g008-sealed-bootstrap-manifest-v1",
        "transaction_authority_service_account": transaction_authority_service_account,
        "secret_version_mounts": {
            purpose: {
                "version_resource_name": secret_versions[purpose],
                "target": target,
                "consumer": consumer,
                "read_only": True,
            }
            for purpose, (target, consumer) in verifier.G008_MOUNT_SPECS.items()
        },
        "execution_versions": {
            key: secret_versions[purpose]
            for key, purpose in verifier.BOOTSTRAP_EXECUTION_PURPOSES.items()
        },
        "route_evidence_bundle": {
            "numeric_version_resource_name": route_evidence_bundle["numeric_version_resource_name"],
            "content_sha256": route_evidence_bundle_sha256,
            "schema_version": route_evidence_bundle["schema_version"],
            "organization_id": route_evidence_bundle["organization_id"],
            "request_digest": route_evidence_bundle["request_digest"],
            "candidate_digest": route_evidence_bundle["candidate_digest"],
            "route_profile_digest": route_evidence_bundle["route_profile_digest"],
            "opaque_handle_digest": verifier._sha(route_evidence_bundle["opaque_handle"].encode()),
        }
    }

    binding_sha256 = verifier._sha(verifier._canonical(binding_input))
    manifest = {
        **binding_input,
        "binding_sha256": binding_sha256,
    }
    raw = verifier._canonical_bootstrap_manifest(manifest)
    try:
        fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except (OSError, TypeError):
        _fail("output_unavailable")
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        verifier.validate_bootstrap_manifest(
            output_path,
            binding_sha256,
            secret_versions,
        )
    except Exception as exc:
        try:
            Path(output_path).unlink()
        except OSError:
            pass
        if isinstance(exc, verifier.VerificationError):
            raise CreationError(str(exc)) from None
        if isinstance(exc, CreationError):
            raise
        _fail("output_write_failed")
    return binding_sha256


def sign_source(
    role: str,
    context_path: str | Path,
    private_key_path: str | Path,
    observed_at_utc: str,
    expires_at_utc: str,
    output_path: str | Path,
) -> None:
    if role not in verifier.SOURCE_ROLES:
        _fail("source_role")
    context, _ = _load_context(context_path)
    if role not in verifier.source_roles(context):
        _fail("source_role_not_required")
    current = _now().astimezone(timezone.utc)
    observed = _timestamp(observed_at_utc, "receipt_time")
    expires = _timestamp(expires_at_utc, "receipt_time")
    window_end = _timestamp(context["live_window_end_utc"], "context_window")
    if (
        observed > current
        or current - observed > timedelta(seconds=60)
        or expires != window_end
        or expires <= current
        or observed >= expires
    ):
        _fail("receipt_freshness")
    trusted = _trusted_keys()
    trust_role = verifier.ROLE_FOR_RECEIPT[role]
    if role == "iam_provisioning" and trust_role != "iam-provisioning":
        _fail("iam_provisioning_role")
    private = _load_private(private_key_path, trusted[trust_role])
    payload = {
        "contract_version": "recova-phase-c-live-prerequisite.v1",
        "kind": role,
        "claims_sha256": verifier._sha(verifier._canonical(context[role])),
        **_common(context),
        "observed_at_utc": observed_at_utc,
        "expires_at_utc": expires_at_utc,
        "signer_key_id": verifier.TRUSTED_KEYS[trust_role][0],
    }
    _write_new(output_path, _signed(payload, trust_role, private))


def _parse_receipts(
    values: list[str],
    required_roles: tuple[str, ...],
) -> dict[str, Path]:
    if len(values) != len(required_roles):
        _fail("receipt_roles")
    result: dict[str, Path] = {}
    for value in values:
        if not isinstance(value, str) or "=" not in value:
            _fail("receipt_argument")
        role, path = value.split("=", 1)
        if role not in required_roles or not path or role in result:
            _fail("receipt_roles")
        result[role] = Path(path)
    if set(result) != set(required_roles) or len({path.resolve() for path in result.values()}) != len(result):
        _fail("receipt_roles")
    return result


def assemble(
    context_path: str | Path,
    receipt_arguments: list[str],
    private_key_path: str | Path,
    issued_at_utc: str,
    expires_at_utc: str,
    output_path: str | Path,
) -> None:
    context, context_json = _load_context(context_path)
    receipt_paths = _parse_receipts(receipt_arguments, verifier.source_roles(context))
    trusted = _trusted_keys()
    current = _now().astimezone(timezone.utc)
    common = _common(context)
    receipts: dict[str, Any] = {}
    payload_digests: dict[str, str] = {}
    source_expiries: list[datetime] = []
    for name in verifier.source_roles(context):
        receipt = _read_canonical(receipt_paths[name], "receipt_json", "receipt_noncanonical")
        role = verifier.ROLE_FOR_RECEIPT[name]
        try:
            payload, payload_digests[name] = verifier._verify_signature(
                receipt, role, trusted[role], verifier.RECEIPT_PAYLOAD_KEYS
            )
        except verifier.VerificationError as exc:
            raise CreationError(str(exc)) from None
        if payload["contract_version"] != "recova-phase-c-live-prerequisite.v1" or payload["kind"] != name or payload["claims_sha256"] != verifier._sha(verifier._canonical(context[name])):
            _fail("receipt_claims_binding")
        if any(payload[key] != value for key, value in common.items()):
            _fail("receipt_common_binding")
        observed = _timestamp(payload["observed_at_utc"], "receipt_time")
        source_expires = _timestamp(payload["expires_at_utc"], "receipt_time")
        if (
            observed > current
            or current - observed > timedelta(seconds=60)
            or source_expires != _timestamp(context["live_window_end_utc"], "context_window")
            or source_expires <= current
            or observed >= source_expires
        ):
            _fail("receipt_freshness")
        source_expiries.append(source_expires)
        receipts[name] = receipt

    issued = _timestamp(issued_at_utc, "aggregate_time")
    expires = _timestamp(expires_at_utc, "aggregate_time")
    window_end = _timestamp(context["live_window_end_utc"], "context_window")
    if (
        issued > current
        or current - issued > timedelta(seconds=60)
        or expires != window_end
        or expires <= current
        or expires <= issued
        or expires > min(source_expiries)
    ):
        _fail("aggregate_freshness")
    private = _load_private(private_key_path, trusted["phase-c-preflight"])
    aggregate_payload = {
        "contract_version": "recova-phase-c-live-preflight.v1",
        "kind": "phase_c_live_preflight",
        **common,
        "authorized_context_sha256": verifier._sha(verifier._canonical(context)),
        "receipt_payload_sha256": {key: payload_digests[key] for key in sorted(payload_digests)},
        "issued_at_utc": issued_at_utc,
        "expires_at_utc": expires_at_utc,
        "signer_key_id": verifier.TRUSTED_KEYS["phase-c-preflight"][0],
    }
    bundle = {
        "schema_version": "recova-phase-c-live-preflight-bundle.v1",
        "receipts": receipts,
        "aggregate": _signed(aggregate_payload, "phase-c-preflight", private),
    }
    _write_new(output_path, bundle)
    try:
        verifier.verify_bundle(output_path, context_json, verification_stage="plan", now=current)
    except Exception as exc:
        try:
            Path(output_path).unlink()
        except OSError:
            pass
        if isinstance(exc, verifier.VerificationError):
            raise CreationError(str(exc)) from None
        _fail("verification_failed")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        raise CreationError("arguments")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="create_phase_c_live_preflight.py")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    source = commands.add_parser("sign-source")
    source.add_argument("--role", required=True, choices=verifier.SOURCE_ROLES)
    source.add_argument("--context", required=True)
    source.add_argument("--private-key", required=True)
    source.add_argument("--observed-at-utc", required=True)
    source.add_argument("--expires-at-utc", required=True)
    source.add_argument("--output", required=True)
    aggregate = commands.add_parser("assemble")
    aggregate.add_argument("--context", required=True)
    aggregate.add_argument("--receipt", action="append", required=True)
    aggregate.add_argument("--private-key", required=True)
    aggregate.add_argument("--issued-at-utc", required=True)
    aggregate.add_argument("--expires-at-utc", required=True)
    aggregate.add_argument("--output", required=True)
    bootstrap = commands.add_parser("create-bootstrap-manifest")
    bootstrap.add_argument("--secret-versions", required=True)
    bootstrap.add_argument("--transaction-authority-service-account", required=True)
    bootstrap.add_argument("--route-evidence-bundle", required=True)
    bootstrap.add_argument("--output", required=True)
    bootstrap.add_argument("--route-evidence-bundle-sha256", required=True)
    route_bundle = commands.add_parser("seal-route-evidence-bundle")
    route_bundle.add_argument("--manifest", required=True)
    route_bundle.add_argument("--file", action="append", required=True)
    route_bundle.add_argument("--adapter", required=True)
    route_bundle.add_argument("--output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "sign-source":
            sign_source(args.role, args.context, args.private_key, args.observed_at_utc, args.expires_at_utc, args.output)
        elif args.command == "assemble":
            assemble(args.context, args.receipt, args.private_key, args.issued_at_utc, args.expires_at_utc, args.output)
        elif args.command == "create-bootstrap-manifest":
            binding_sha256 = create_bootstrap_manifest(
                args.secret_versions,
                args.transaction_authority_service_account,
                args.output,
                args.route_evidence_bundle,
                args.route_evidence_bundle_sha256,
            )
            sys.stdout.write(json.dumps({
                "g008_bootstrap_manifest_binding_sha256": binding_sha256,
            }, sort_keys=True, separators=(",", ":")) + "\n")
        else:
            bundle_sha256, handle_digest = seal_route_evidence_bundle(
                args.manifest, args.file, args.adapter, args.output,
            )
            sys.stdout.write(json.dumps({
                "route_evidence_bundle_sha256": bundle_sha256,
                "route_evidence_handle_digest": handle_digest,
            }, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except (CreationError, verifier.VerificationError) as exc:
        sys.stderr.write(f"phase_c_live_preflight_create:{exc}\n")
        return 1
    except Exception:
        sys.stderr.write("phase_c_live_preflight_create:internal_error\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
