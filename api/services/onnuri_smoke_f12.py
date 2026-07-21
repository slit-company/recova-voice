"""Fail-closed application boundary for the internal Onnuri F12 runtime."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat

from datetime import UTC, datetime, timedelta
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Literal, Protocol
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from pydantic import SecretStr

from api.db.telephony_number_inventory_client import (
    TelephonyNumberInventoryConflictError,
    TelephonyNumberInventoryNotFoundError,
)
from api.services import onnuri_staging_preflight as authority
from api.services.onnuri_smoke_capabilities import (
    CapabilityBinding,
    CapabilityIssueRequest,
    CapabilityPolicy,
    ECDSA_P256_SHA256_POLICY_ID,
    EXECUTION_EVIDENCE_DOMAIN,
    SmokeCapabilityIssuer,
    SmokeCapabilityUnavailableError,
    SmokeRecoverySealer,
    canonical_json_bytes,
    configure_smoke_authority_runtime_from_environment,
    get_smoke_authority_runtime,
    issued_digests,
    opaque_signing_bytes,
    parse_dispatch_capability,
    parse_media_capability,
    sha256_hex,
    signed_capability_bytes,
)
from api.services.telephony.onnuri_preflight_policy import DISPATCH_CAPABILITY_DOMAIN
from api.services.telephony.onnuri_route_receipts import (
    AdapterInvoker,
    CanonicalRouteEvidence,
    ReplayConsumer,
    verify_route_chain,
)
from api.services.telephony.providers.jambonz.facade.auth import (
    canonical_signing_bytes,
    route_chain_capability_claims,
)
from api.services.telephony.providers.jambonz.facade.models import (
    BoundCallContext,
    CallStatus,
    CallbackReceipt,
    DispatchConsumeReceipt,
    FailureCategory,
    MediaAuthorityReceipt,
    RouteChainCapability,
    RouteChainCapabilityRequest,
    ROUTE_CHAIN_CAPABILITY_DOMAIN,
    StockCallBindReceipt,
    StockCallBindRequest,
)


_CREDENTIAL_DIGEST_ENV = "ONNURI_SMOKE_F12_CREDENTIAL_SHA256"
_TRUSTED_ISSUER_ENV = "ONNURI_SMOKE_F12_TRUSTED_MTLS_ISSUER"
_ALLOWED_IDENTITIES_ENV = "ONNURI_SMOKE_F12_ALLOWED_MTLS_IDENTITIES"
_IDENTITY_ORGANIZATION_SCOPES_ENV = "ONNURI_SMOKE_F12_IDENTITY_ORGANIZATION_SCOPES"
_GLOBAL_CONTROL_PLANE_IDENTITIES_ENV = (
    "ONNURI_SMOKE_F12_GLOBAL_CONTROL_PLANE_IDENTITIES"
)
_DISPATCH_KEY_ID_ENV = "ONNURI_SMOKE_DISPATCH_KEY_ID"
_DISPATCH_PUBLIC_KEY_FILE_ENV = "ONNURI_SMOKE_DISPATCH_PUBLIC_KEY_FILE"
_MEDIA_KEY_ID_ENV = "ONNURI_SMOKE_MEDIA_KEY_ID"
_G008_INBOUND_BIND_SCHEMA = "recova-g008-inbound-bind-receipt-v1"
_G008_INBOUND_BIND_DOMAIN = "recova.onnuri.smoke.g008.inbound-bind.v1"
_G008_INBOUND_BIND_ALGORITHM = "ES256"
_REGISTRATION_ATTESTATION_KEY_ID_ENV = (
    "ONNURI_SMOKE_REGISTRATION_ATTESTATION_KEY_ID"
)
_REGISTRATION_ATTESTATION_PUBLIC_KEY_FILE_ENV = (
    "ONNURI_SMOKE_REGISTRATION_ATTESTATION_PUBLIC_KEY_FILE"
)
_REGISTRATION_UPSTREAM_ENDPOINT_DIGEST_ENV = (
    "ONNURI_SMOKE_REGISTRATION_UPSTREAM_ENDPOINT_SHA256"
)
_REGISTRATION_EXECUTION_DOMAIN = (
    "recova.onnuri.smoke.registration.execution.v1"
)
_EXECUTION_EVIDENCE_KEY_ID_ENV = "ONNURI_SMOKE_EXECUTION_EVIDENCE_KEY_ID"
_EXECUTION_EVIDENCE_CONTRACT_VERSION = "recova-g008-execution-evidence-v1"
_G008_AUTHORITY_KEY_ID = "recova-g008-authority-v1"
_G008_AUTHORITY_PRIVATE_KEY_FILE_ENV = "ONNURI_SMOKE_G008_AUTHORITY_PRIVATE_KEY_FILE"
_G008_TRUSTED_KEYSET_PATH = Path("/opt/g008/trusted/phase_c_live_preflight_v1.json")
_G008_TRUSTED_KEYSET_DIGEST = (
    "00645f3af8230c742951c12f17a713afde209de12182cd6e3722ac59445507aa"
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class RouteEvidenceResolution:
    """F12-only authority inputs resolved from one opaque tenant-scoped handle."""

    evidence: CanonicalRouteEvidence
    adapter_invoker: AdapterInvoker
    replay_consumer: ReplayConsumer
    approved_root_locator_digest: str
    inventory_locator_digest: str
    inventory_version: str
    as_of_utc: datetime
    approved_root: int | None = None
    adapter_descriptor: int | None = None




class RouteEvidenceResolver(Protocol):
    async def resolve(
        self,
        *,
        organization_id: int,
        route_evidence_handle: str,
    ) -> RouteEvidenceResolution: ...


_route_evidence_resolver: RouteEvidenceResolver | None = None


def configure_route_evidence_resolver(resolver: RouteEvidenceResolver | None) -> None:
    """Install the F12-owned opaque route evidence resolver at runtime startup."""
    global _route_evidence_resolver
    _route_evidence_resolver = resolver

_ROUTE_EVIDENCE_ROOT_ENV = "ONNURI_SMOKE_F12_ROUTE_EVIDENCE_ROOT"
_ROUTE_EVIDENCE_MANIFEST_ENV = "ONNURI_SMOKE_F12_ROUTE_EVIDENCE_MANIFEST_FILE"
_ROUTE_EVIDENCE_UID_ENV = "ONNURI_SMOKE_F12_ROUTE_EVIDENCE_UID"
_ROUTE_EVIDENCE_GID_ENV = "ONNURI_SMOKE_F12_ROUTE_EVIDENCE_GID"
_ROUTE_EVIDENCE_FILES = ("provider_fact_packet", "provider_fact_packet_signatures", "route_decision", "route_decision_signatures", "route_conformance", "route_conformance_signatures", "trusted_keyset", "revocations")
_ROUTE_EVIDENCE_MAX_LIFETIME = timedelta(hours=1)



class FileRouteEvidenceResolver:
    """F12-only sealed route evidence store; callers receive no raw locations."""

    def __init__(self, *, root: Path, manifest: Path, uid: int, gid: int) -> None:
        self._root, self._manifest, self._uid, self._gid = root, manifest, uid, gid

    @staticmethod
    def _read(path: Path, *, uid: int, gid: int, mode: int = 0o400) -> bytes:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != mode:
                    raise ValueError
                raw = os.read(descriptor, 262145)
                if len(raw) > 262144:
                    raise ValueError
                return raw
            finally:
                os.close(descriptor)
        except (OSError, ValueError):
            raise F12ServiceError("onnuri_smoke_f12_operation_rejected", 409) from None

    def _evidence_file(self, name: str, expected_sha256: object) -> bytes:
        if (
            name not in _ROUTE_EVIDENCE_FILES
            or not isinstance(expected_sha256, str)
            or _SHA256_RE.fullmatch(expected_sha256) is None
        ):
            raise F12ServiceError("onnuri_smoke_f12_operation_rejected", 409)
        result = self._read(self._root / name, uid=self._uid, gid=self._gid)
        if not hmac.compare_digest(hashlib.sha256(result).hexdigest(), expected_sha256):
            raise F12ServiceError("onnuri_smoke_f12_operation_rejected", 409)
        return result


    def _invoker(self, adapter: object, *, root_fd: int) -> tuple[AdapterInvoker, int]:
        if not isinstance(adapter, dict) or set(adapter) != {"path", "sha256", "execution_mode", "stdin_schema", "stdin_exactly_one_lf", "stdout_schema", "stdout_max_bytes", "stderr_max_bytes", "timeout_ms"} or adapter["path"] != "adapter" or adapter["execution_mode"] != "fixed-executable-v1" or adapter["stdin_schema"] != "recova-onnuri-restricted-inventory-adapter-invocation-v1" or adapter["stdin_exactly_one_lf"] is not True or adapter["stdout_schema"] != "recova-onnuri-restricted-inventory-adapter-v1" or not isinstance(adapter["sha256"], str) or _SHA256_RE.fullmatch(adapter["sha256"]) is None or type(adapter["stdout_max_bytes"]) is not int or not 0 < adapter["stdout_max_bytes"] <= 262144 or type(adapter["stderr_max_bytes"]) is not int or not 0 <= adapter["stderr_max_bytes"] <= 262144 or type(adapter["timeout_ms"]) is not int or not 0 < adapter["timeout_ms"] <= 5000:
            raise F12ServiceError("onnuri_smoke_f12_operation_rejected", 409)
        descriptor = -1
        try:
            descriptor = os.open("adapter", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self._uid or info.st_gid != self._gid or stat.S_IMODE(info.st_mode) != 0o500 or info.st_size > 262144:
                raise ValueError
            raw = bytearray()
            while chunk := os.read(descriptor, 65536):
                raw.extend(chunk)
                if len(raw) > 262144:
                    raise ValueError
            if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), adapter["sha256"]):
                raise ValueError
        except (OSError, ValueError):
            if descriptor >= 0:
                os.close(descriptor)
            raise F12ServiceError("onnuri_smoke_f12_operation_rejected", 409) from None

        async def invoke(invocation: Any) -> bytes:
            payload = json.dumps({key: getattr(invocation, key) for key in ("audience", "challenge_nonce", "approved_root_locator_digest", "inventory_locator_digest", "inventory_version", "as_of_utc")}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            executable_fd = os.dup(descriptor)
            process: asyncio.subprocess.Process | None = None

            async def drain(stream: asyncio.StreamReader, cap: int) -> bytes:
                result = bytearray()
                while chunk := await stream.read(min(65536, cap - len(result) + 1)):
                    result.extend(chunk)
                    if len(result) > cap:
                        raise RuntimeError("route_adapter_output_limit_exceeded")
                return bytes(result)

            async def cleanup() -> bool:
                if process is None:
                    return True
                if process.stdin is not None:
                    process.stdin.close()
                if process.returncode is None:
                    try:
                        os.killpg(process.pid, 9)
                    except (AttributeError, OSError, ProcessLookupError):
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                try:
                    await asyncio.shield(process.wait())
                except asyncio.CancelledError:
                    await asyncio.shield(process.wait())
                    raise
                return process.returncode is not None

            async def execute() -> bytes:
                nonlocal process
                executable = f"/proc/self/fd/{executable_fd}"
                try:
                    executable_info = os.stat(executable)
                    descriptor_info = os.fstat(executable_fd)
                except OSError as exc:
                    raise RuntimeError("route_adapter_native_descriptor_unavailable") from exc
                if (
                    executable_info.st_dev != descriptor_info.st_dev
                    or executable_info.st_ino != descriptor_info.st_ino
                ):
                    raise RuntimeError("route_adapter_native_descriptor_unavailable")
                process = await asyncio.create_subprocess_exec(
                    executable,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env={"PATH": "/usr/bin:/bin"},
                    pass_fds=(executable_fd,),
                    start_new_session=True,
                )
                assert process.stdin is not None and process.stdout is not None and process.stderr is not None
                process.stdin.write(payload)
                await process.stdin.drain()
                process.stdin.close()
                stdout, stderr = await asyncio.gather(
                    drain(process.stdout, adapter["stdout_max_bytes"]),
                    drain(process.stderr, adapter["stderr_max_bytes"]),
                )
                await process.wait()
                if process.returncode:
                    raise RuntimeError("route_adapter_exit_failure")
                return stdout

            cleanup_required = False
            try:
                result = await asyncio.wait_for(execute(), timeout=adapter["timeout_ms"] / 1000)
            except asyncio.CancelledError:
                cleanup_required = True
                raise
            except (OSError, RuntimeError, ValueError, TimeoutError, asyncio.IncompleteReadError):
                cleanup_required = True
                raise RuntimeError("route_adapter_invocation_rejected") from None
            else:
                return result
            finally:
                try:
                    reaped = await cleanup() if cleanup_required else True
                finally:
                    os.close(executable_fd)
                if not reaped:
                    raise RuntimeError("route_adapter_cleanup_failed") from None

        return invoke, descriptor



    def _validated_manifest(self, *, organization_id: int, route_evidence_handle: str, as_of: datetime) -> tuple[dict[str, Any], dict[str, bytes], AdapterInvoker, int, int]:
        try:
            manifest = json.loads(self._read(self._manifest, uid=self._uid, gid=self._gid))
            required = {
                "schema_version", "numeric_version_resource_name", "organization_id",
                "request_digest", "candidate_digest", "route_profile_digest", "opaque_handle",
                "approved_root_locator_digest", "inventory_locator_digest", "inventory_version",
                "adapter_execution_mode", "adapter_stdin_schema", "adapter_stdin_exactly_one_lf",
                "adapter_stdout_schema", "adapter_stdout_max_bytes", "adapter_stderr_max_bytes",
                "adapter_timeout_ms", "adapter_sha256", *(f"{name}_sha256" for name in _ROUTE_EVIDENCE_FILES),
            }
            root_digest, locator_digest, version = manifest["approved_root_locator_digest"], manifest["inventory_locator_digest"], manifest["inventory_version"]
            expected_digests = {
                "request_digest": os.environ.get("ONNURI_REQUEST_DIGEST"),
                "candidate_digest": os.environ.get("ONNURI_CANDIDATE_DIGEST"),
                "route_profile_digest": os.environ.get("ONNURI_ROUTE_PROFILE_DIGEST"),
            }
            if (
                set(manifest) != required
                or manifest["schema_version"] != "recova-onnuri-route-evidence-bundle-v1"
                or manifest["opaque_handle"] != route_evidence_handle
                or manifest["organization_id"] != organization_id
                or not isinstance(manifest["numeric_version_resource_name"], str)
                or any(not isinstance(manifest[name], str) or _SHA256_RE.fullmatch(manifest[name]) is None or manifest[name] != expected for name, expected in expected_digests.items())
                or not isinstance(manifest["adapter_sha256"], str) or _SHA256_RE.fullmatch(manifest["adapter_sha256"]) is None
                or _SHA256_RE.fullmatch(root_digest) is None
                or _SHA256_RE.fullmatch(locator_digest) is None
                or not isinstance(version, str) or not version
            ):
                raise ValueError
            raw = {
                name: self._evidence_file(name, manifest[f"{name}_sha256"])
                for name in _ROUTE_EVIDENCE_FILES
            }
            root_fd = os.open(self._root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            root_info = os.fstat(root_fd)
            if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != self._uid or root_info.st_gid != self._gid:
                os.close(root_fd)
                raise ValueError
            adapter = {
                "path": "adapter", "sha256": manifest["adapter_sha256"],
                "execution_mode": manifest["adapter_execution_mode"], "stdin_schema": manifest["adapter_stdin_schema"],
                "stdin_exactly_one_lf": manifest["adapter_stdin_exactly_one_lf"], "stdout_schema": manifest["adapter_stdout_schema"],
                "stdout_max_bytes": manifest["adapter_stdout_max_bytes"], "stderr_max_bytes": manifest["adapter_stderr_max_bytes"], "timeout_ms": manifest["adapter_timeout_ms"],
            }
            try:
                invoker, adapter_descriptor = self._invoker(adapter, root_fd=root_fd)
            except F12ServiceError:
                os.close(root_fd)
                raise
            return manifest, raw, invoker, root_fd, adapter_descriptor
        except (KeyError, TypeError, ValueError, AttributeError, OSError, F12ServiceError):
            raise F12ServiceError("onnuri_smoke_f12_operation_rejected", 409) from None



    async def resolve(self, *, organization_id: int, route_evidence_handle: str) -> RouteEvidenceResolution:
        as_of = datetime.now(UTC)
        manifest, raw, invoker, root_fd, adapter_descriptor = self._validated_manifest(
            organization_id=organization_id,
            route_evidence_handle=route_evidence_handle,
            as_of=as_of,
        )
        root_digest = manifest["approved_root_locator_digest"]
        locator_digest = manifest["inventory_locator_digest"]
        version = manifest["inventory_version"]
        async def consume(**kwargs: Any) -> None:
            try:
                await asyncio.wait_for(authority.db_client.consume_onnuri_route_adapter_replay(**kwargs), timeout=2)
            except TimeoutError as exc:
                raise RuntimeError("route_adapter_replay_timeout") from exc
        return RouteEvidenceResolution(CanonicalRouteEvidence(**{f"{name}_bytes": value for name, value in raw.items()}), invoker, consume, root_digest, locator_digest, version, as_of, root_fd, adapter_descriptor)


def configure_route_evidence_resolver_from_environment() -> None:
    """Configure optional route evidence only when its complete contract is present."""
    names = (_ROUTE_EVIDENCE_ROOT_ENV, _ROUTE_EVIDENCE_MANIFEST_ENV, _ROUTE_EVIDENCE_UID_ENV, _ROUTE_EVIDENCE_GID_ENV)
    present = [name in os.environ for name in names]
    if not any(present):
        configure_route_evidence_resolver(None)
        return
    try:
        if not all(present):
            raise ValueError
        root, manifest = Path(os.environ[_ROUTE_EVIDENCE_ROOT_ENV]), Path(os.environ[_ROUTE_EVIDENCE_MANIFEST_ENV])
        uid, gid = int(os.environ[_ROUTE_EVIDENCE_UID_ENV]), int(os.environ[_ROUTE_EVIDENCE_GID_ENV])
        root_info = os.lstat(root)
        if (
            root.is_symlink()
            or manifest.is_symlink()
            or not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != uid
            or root_info.st_gid != gid
            or stat.S_IMODE(root_info.st_mode) != 0o500
            or uid != 65532
            or gid != 65532
        ):
            raise ValueError
        resolver = FileRouteEvidenceResolver(root=root, manifest=manifest, uid=uid, gid=gid)
        # Startup must fail closed before the service accepts any request when the
        # mounted fixed-entry inventory is corrupt. Tenant binding is rechecked at resolve.
        startup_manifest = json.loads(resolver._read(manifest, uid=uid, gid=gid))
        _, _, _, probe_root_fd, probe_adapter_fd = resolver._validated_manifest(
            organization_id=startup_manifest.get("organization_id"),
            route_evidence_handle=startup_manifest.get("opaque_handle"),
            as_of=datetime.now(UTC),
        )
        os.close(probe_adapter_fd)
        os.close(probe_root_fd)
        configure_route_evidence_resolver(resolver)
    except (OSError, ValueError, F12ServiceError):
        configure_route_evidence_resolver(None)
        raise RuntimeError("onnuri_smoke_f12_route_evidence_configuration_invalid") from None
_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_EXACT_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
)
_EXECUTION_CLAIM_KEYS = {
    "accepted_expires_seconds",
    "authorization_nonce_digest",
    "candidate_digest",
    "challenge_response_wire_digest",
    "challenge_status",
    "completed_at",
    "deregistered",
    "final_response_wire_digest",
    "final_status",
    "gate_envelope_digest",
    "initial_request_wire_digest",
    "operation_kind",
    "operation_uuid",
    "organization_id",
    "outcome",
    "prior_register_gate_id",
    "prior_register_operation_uuid",
    "registration_gate_id",
    "request_digest",
    "response_count",
    "retry_count",
    "retry_request_wire_digest",
    "sip_transaction_binding_digest",
    "started_at",
    "transaction_count",
    "transport",
    "upstream_endpoint_digest",
    "verification_domain",
    "wire_request_count",
}
_STATUS_TERMINAL = frozenset(
    {
        CallStatus.COMPLETED.value,
        CallStatus.BUSY.value,
        CallStatus.NO_ANSWER.value,
        CallStatus.FAILED.value,
        CallStatus.CANCELED.value,
        CallStatus.CONTAINED.value,
    }
)
_REGISTRATION_VERIFICATION_DOMAIN = "recova.onnuri.smoke.registration.v1"


@dataclass
class F12ServiceError(Exception):
    code: str
    status_code: int


@dataclass(frozen=True)
class F12Caller:
    identity: str
    organization_ids: frozenset[int]
    global_control_plane: bool = False

    def authorize(self, organization_id: int) -> None:
        if (
            type(organization_id) is not int
            or organization_id <= 0
            or self.global_control_plane
            or organization_id not in self.organization_ids
        ):
            raise F12ServiceError("onnuri_smoke_f12_tenant_scope_rejected", 403)


def _configuration() -> tuple[
    str, str, frozenset[str], dict[str, frozenset[int]], frozenset[str]
]:
    digest = os.getenv(_CREDENTIAL_DIGEST_ENV, "").strip().lower()
    issuer = os.getenv(_TRUSTED_ISSUER_ENV, "").strip()
    identities = frozenset(
        item.strip()
        for item in os.getenv(_ALLOWED_IDENTITIES_ENV, "").split(",")
        if item.strip()
    )
    global_identities = frozenset(
        item.strip()
        for item in os.getenv(_GLOBAL_CONTROL_PLANE_IDENTITIES_ENV, "").split(",")
        if item.strip()
    )
    try:
        raw_scopes = json.loads(
            os.getenv(_IDENTITY_ORGANIZATION_SCOPES_ENV, "").strip() or "{}"
        )
        if not isinstance(raw_scopes, dict):
            raise ValueError
        scopes = {
            identity: frozenset(organization_ids)
            for identity, organization_ids in raw_scopes.items()
            if (
                isinstance(identity, str)
                and identity
                and isinstance(organization_ids, list)
                and organization_ids
                and all(type(item) is int and item > 0 for item in organization_ids)
            )
        }
        if len(scopes) != len(raw_scopes):
            raise ValueError
    except (TypeError, ValueError, json.JSONDecodeError):
        scopes = {}
    return digest, issuer, identities, scopes, global_identities


def _validate_authority_key_separation(
    *,
    attestation_key_id: str,
    attestation_key_digest: str,
    runtime: Any,
) -> None:
    issuer_key_ids = runtime.issuer.key_ids()
    issuer_key_digests = runtime.issuer.public_key_digests()
    evidence_key_ids = runtime.execution_evidence_signer.key_ids()
    evidence_key_digests = runtime.execution_evidence_signer.public_key_digests()
    all_key_ids = issuer_key_ids | evidence_key_ids
    all_key_digests = issuer_key_digests | evidence_key_digests
    if (
        len(all_key_ids) != len(issuer_key_ids) + len(evidence_key_ids)
        or len(all_key_digests) != len(issuer_key_digests) + len(evidence_key_digests)
        or attestation_key_id in all_key_ids
        or attestation_key_digest in all_key_digests
    ):
        raise RuntimeError("onnuri_smoke_authority_key_separation_invalid")


def validate_startup_configuration() -> None:
    if os.getenv("ENVIRONMENT", "local").lower() != "production":
        return
    configure_route_evidence_resolver_from_environment()
    digest, issuer, identities, scopes, global_identities = _configuration()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise RuntimeError(f"{_CREDENTIAL_DIGEST_ENV} must be a SHA-256 hex digest")
    if not issuer:
        raise RuntimeError(f"{_TRUSTED_ISSUER_ENV} is required in production")
    if not identities:
        raise RuntimeError(f"{_ALLOWED_IDENTITIES_ENV} is required in production")
    if (
        set(scopes) | set(global_identities) != set(identities)
        or set(scopes) & set(global_identities)
    ):
        raise RuntimeError(
            "onnuri_smoke_f12_identity_organization_scopes_invalid"
        )
    attestation_key_id = os.getenv(
        _REGISTRATION_ATTESTATION_KEY_ID_ENV, ""
    ).strip()
    attestation_key_path = Path(
        os.getenv(_REGISTRATION_ATTESTATION_PUBLIC_KEY_FILE_ENV, "")
    )
    upstream_digest = os.getenv(
        _REGISTRATION_UPSTREAM_ENDPOINT_DIGEST_ENV, ""
    ).strip()
    try:
        attestation_key = serialization.load_pem_public_key(
            attestation_key_path.read_bytes()
        )
    except (OSError, ValueError, TypeError):
        raise RuntimeError(
            "onnuri_smoke_registration_attestation_configuration_invalid"
        ) from None
    if (
        _KEY_ID_RE.fullmatch(attestation_key_id) is None
        or attestation_key_path.is_symlink()
        or not isinstance(attestation_key, ec.EllipticCurvePublicKey)
        or not isinstance(attestation_key.curve, ec.SECP256R1)
        or _SHA256_RE.fullmatch(upstream_digest) is None
    ):
        raise RuntimeError(
            "onnuri_smoke_registration_attestation_configuration_invalid"
        )
    attestation_key_digest = hashlib.sha256(
        attestation_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
    runtime = get_smoke_authority_runtime()
    if not runtime.configuration_ready():
        runtime = configure_smoke_authority_runtime_from_environment()
    if not runtime.configuration_ready():
        raise RuntimeError("onnuri_smoke_authority_runtime_unavailable")
    _validate_authority_key_separation(
        attestation_key_id=attestation_key_id,
        attestation_key_digest=attestation_key_digest,
        runtime=runtime,
    )
    try:
        _load_g008_authority_signing_key(_G008_TRUSTED_KEYSET_DIGEST)
    except F12ServiceError:
        raise RuntimeError("onnuri_smoke_f12_authority_unavailable") from None


def _load_g008_authority_signing_key(
    trusted_keyset_digest: str,
) -> ed25519.Ed25519PrivateKey:
    private_path = Path(
        os.getenv(
            _G008_AUTHORITY_PRIVATE_KEY_FILE_ENV,
            "/run/secrets/g008-authority-ed25519-private-key",
        )
    )
    try:
        keyset_raw = _G008_TRUSTED_KEYSET_PATH.read_bytes()
        if (
            private_path.is_symlink()
            or _G008_TRUSTED_KEYSET_PATH.is_symlink()
            or hashlib.sha256(keyset_raw).hexdigest() != _G008_TRUSTED_KEYSET_DIGEST
            or not hmac.compare_digest(
                trusted_keyset_digest.encode("ascii"),
                _G008_TRUSTED_KEYSET_DIGEST.encode("ascii"),
            )
        ):
            raise ValueError
        keyset = json.loads(keyset_raw)
        if canonical_json_bytes(keyset) != keyset_raw:
            raise ValueError
        matches = [
            entry
            for entry in keyset.get("keys", ())
            if entry.get("role") == "authority"
            and entry.get("key_id") == _G008_AUTHORITY_KEY_ID
            and entry.get("algorithm") == "Ed25519"
        ]
        if len(matches) != 1:
            raise ValueError
        private_key = serialization.load_pem_private_key(
            private_path.read_bytes(), password=None
        )
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise ValueError
        public_raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        expected_public = base64.urlsafe_b64decode(
            matches[0]["public_key_base64url"]
            + "=" * (-len(matches[0]["public_key_base64url"]) % 4)
        )
        if (
            not hmac.compare_digest(public_raw, expected_public)
            or hashlib.sha256(public_raw).hexdigest()
            != matches[0]["public_key_sha256"]
        ):
            raise ValueError
        return private_key
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise F12ServiceError("onnuri_smoke_f12_authority_unavailable", 503) from None


def _signed_g008_authority_receipt(
    payload: dict[str, Any], *, key: ed25519.Ed25519PrivateKey | None = None
) -> dict[str, Any]:
    signing_key = key or _load_g008_authority_signing_key(
        payload["trusted_keyset_digest"]
    )
    signature = base64.b64encode(
        signing_key.sign(canonical_json_bytes(payload))
    ).decode("ascii")
    return {
        "payload": payload,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": _G008_AUTHORITY_KEY_ID,
            "value": signature,
        },
    }

def authenticate(*, identity: str, issuer: str, credential: str) -> F12Caller:
    (
        expected_digest,
        trusted_issuer,
        allowed_identities,
        scopes,
        global_identities,
    ) = _configuration()
    configured = (
        len(expected_digest) == 64
        and bool(trusted_issuer)
        and bool(allowed_identities)
        and set(scopes) | set(global_identities) == set(allowed_identities)
        and not set(scopes) & set(global_identities)
    )
    presented_digest = hashlib.sha256(credential.encode("utf-8")).hexdigest()
    allowed = any(
        hmac.compare_digest(identity.encode("utf-8"), item.encode("utf-8"))
        for item in allowed_identities
    )
    if not (
        configured
        and hmac.compare_digest(presented_digest, expected_digest)
        and hmac.compare_digest(issuer.encode("utf-8"), trusted_issuer.encode("utf-8"))
        and allowed
    ):
        raise F12ServiceError("onnuri_smoke_f12_unauthorized", 401)
    return F12Caller(
        identity=identity,
        organization_ids=scopes.get(identity, frozenset()),
        global_control_plane=identity in global_identities,
    )


def _rejected(exc: Exception) -> F12ServiceError:
    if isinstance(exc, TelephonyNumberInventoryNotFoundError):
        return F12ServiceError("onnuri_smoke_f12_partition_rejected", 409)
    message = str(exc)
    if "replay" in message or "reused" in message:
        return F12ServiceError("onnuri_smoke_f12_replay_rejected", 409)
    return F12ServiceError("onnuri_smoke_f12_operation_rejected", 409)


@dataclass(frozen=True)
class _RouteCapabilityBinding:
    """Issuer-compatible exact claims binding for the separate route authority."""

    claims_value: dict[str, object]

    def claims(self, *, authority_deadline: datetime) -> dict[str, object]:
        return self.claims_value


def _route_capability_request(
    *,
    context: BoundCallContext,
    idempotency_key: str,
    request_digest: str,
    route_profile_digest: str,
    route_evidence_handle: str,
) -> RouteChainCapabilityRequest:
    return RouteChainCapabilityRequest(
        context=context,
        idempotency_key=idempotency_key,
        request_digest=request_digest,
        route_profile_digest=route_profile_digest,
        route_evidence_handle=route_evidence_handle,
    )


def _parse_route_chain_capability(opaque: bytes) -> RouteChainCapability:
    try:
        raw = json.loads(opaque)
        value = RouteChainCapability.model_validate(raw)
        canonical = value.model_dump(mode="json", exclude={"signature"}, exclude_none=True)
        canonical["signature"] = value.signature.get_secret_value()
        if canonical_json_bytes(canonical) != opaque:
            raise ValueError("noncanonical_route_capability")
        return value
    except Exception as exc:
        raise ValueError("invalid_route_capability") from exc


def _route_claims_for(
    *,
    context: BoundCallContext,
    idempotency_key: str,
    request_digest: str,
    route_profile_digest: str,
    claims: dict[str, Any],
) -> dict[str, object]:
    identifiers = (
        "provider_fact_packet_id",
        "route_decision_id",
        "route_conformance_id",
    )
    digests = (
        "provider_fact_packet_sha256",
        "route_decision_sha256",
        "route_conformance_sha256",
        "adapter_entries_digest",
        "keyset_sha256",
        "revocations_sha256",
    )
    if any(not isinstance(claims.get(name), str) or not claims[name] for name in identifiers):
        raise ValueError("route_claim_identifier_invalid")
    if any(
        not isinstance(claims.get(name), str)
        or _SHA256_RE.fullmatch(claims[name]) is None
        for name in digests
    ):
        raise ValueError("route_claim_digest_invalid")
    return route_chain_capability_claims(
        _route_capability_request(
            context=context,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            route_profile_digest=route_profile_digest,
            route_evidence_handle="capability-recovery",
        ),
        **{name: claims[name] for name in (*identifiers, *digests)},
    )  # type: ignore[arg-type]


async def mint_route_chain_capability(**values: Any) -> RouteChainCapability:
    """Resolve F12-owned evidence, verify it, then sign one opaque capability."""
    context = values.get("context")
    route_profile_digest = values.get("route_profile_digest")
    request_digest = values.get("request_digest")
    idempotency_key = values.get("idempotency_key")
    handle = values.get("route_evidence_handle")
    if (
        not isinstance(context, BoundCallContext)
        or not isinstance(route_profile_digest, str)
        or _SHA256_RE.fullmatch(route_profile_digest) is None
        or not isinstance(request_digest, str)
        or _SHA256_RE.fullmatch(request_digest) is None
        or not isinstance(idempotency_key, str)
        or not isinstance(handle, str)

    ):
        raise F12ServiceError("onnuri_smoke_f12_operation_rejected", 409)
    recovered_row = await _call(
        authority.db_client.recover_onnuri_outbound_diagnostic_capability,
        organization_id=context.organization_id,
        authorization_attempt_uuid=context.attempt_id,
        idempotency_key=idempotency_key,
        request_digest=request_digest,
        candidate_digest=context.candidate_digest,
        gate_envelope_digest=context.gate_envelope_digest,
        route_profile_digest=route_profile_digest,
    )
    if recovered_row is not None:
        try:
            recovered_wire = await get_smoke_authority_runtime().recovery_sealer.unseal(
                ciphertext=recovered_row.encrypted_capability_recovery
            )
            recovered = _parse_route_chain_capability(recovered_wire)
            expected_claims = _route_claims_for(
                context=context,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                route_profile_digest=route_profile_digest,
                claims=recovered.claims,
            )
            now = datetime.now(UTC)
            if (
                not hmac.compare_digest(recovered_row.token_digest, sha256_hex(recovered_wire))
                or not hmac.compare_digest(
                    recovered_row.signature_digest,
                    sha256_hex(recovered.signature.get_secret_value()),
                )
                or not hmac.compare_digest(
                    recovered_row.nonce_digest, sha256_hex(recovered.nonce)
                )
                or recovered.claims != expected_claims
                or recovered.issued_at != recovered_row.issued_at
                or recovered.expires_at != recovered_row.expires_at
                or recovered.issued_at > now
                or recovered.expires_at <= now
            ):
                raise ValueError("route_capability_recovery_invalid")
            return recovered
        except F12ServiceError:
            raise
        except Exception:
            raise F12ServiceError("onnuri_smoke_f12_operation_rejected", 409) from None
    resolved: RouteEvidenceResolution | None = None

    try:
        resolved = await _route_evidence_resolver.resolve(
            organization_id=context.organization_id,
            route_evidence_handle=handle,
        )
        chain = await verify_route_chain(
            evidence=resolved.evidence,
            adapter_invoker=resolved.adapter_invoker,
            replay_consumer=resolved.replay_consumer,
            as_of_utc=resolved.as_of_utc,
            expected_request_digest=request_digest,
            expected_candidate_digest=context.candidate_digest,
            expected_route_profile_digest=route_profile_digest,
            approved_root_locator_digest=resolved.approved_root_locator_digest,
            inventory_locator_digest=resolved.inventory_locator_digest,
            inventory_version=resolved.inventory_version,
            approved_root=resolved.approved_root,
        )
        issued_at = datetime.now(UTC)
        expires_at = min(issued_at + timedelta(seconds=60), datetime.fromisoformat(chain.expires_at_utc.replace("Z", "+00:00")))
        if expires_at <= issued_at:
            raise ValueError("route_chain_expired")
        claims = route_chain_capability_claims(
            _route_capability_request(context=context, idempotency_key=idempotency_key, request_digest=request_digest, route_profile_digest=route_profile_digest, route_evidence_handle=handle),
            provider_fact_packet_id=chain.provider_fact_packet_id,
            provider_fact_packet_sha256=chain.provider_fact_packet_sha256,
            route_decision_id=chain.route_decision_id,
            route_decision_sha256=chain.route_decision_sha256,
            route_conformance_id=chain.route_conformance_id,
            route_conformance_sha256=chain.route_conformance_sha256,
            adapter_entries_digest=chain.adapter_entries_digest,
            keyset_sha256=chain.keyset_sha256,
            revocations_sha256=chain.revocations_sha256,
        )
        policy = CapabilityPolicy(kind="dispatch", verification_domain=ROUTE_CHAIN_CAPABILITY_DOMAIN, key_id=os.getenv(_DISPATCH_KEY_ID_ENV, "").strip(), other_key_id=os.getenv(_MEDIA_KEY_ID_ENV, "").strip(), algorithm_policy_id=ECDSA_P256_SHA256_POLICY_ID)
        unsigned = RouteChainCapability(key_id=policy.key_id, issued_at=issued_at, expires_at=expires_at, nonce=hashlib.sha256(os.urandom(32)).hexdigest(), claims=claims, signature=SecretStr("unsigned"))
        signature = await get_smoke_authority_runtime().issuer.sign_dispatch_receipt(signing_bytes=canonical_signing_bytes(unsigned, exclude={"signature"}), policy=policy)
        if not isinstance(signature, str) or not signature:
            raise ValueError("route_capability_signature_invalid")
        capability = unsigned.model_copy(update={"signature": SecretStr(signature)})
        opaque = canonical_json_bytes(capability.model_dump(mode="json"))
        sealer = get_smoke_authority_runtime().recovery_sealer
        encrypted_wire = await sealer.seal(plaintext=opaque, expires_at=expires_at)
        row = await _call(authority.db_client.persist_onnuri_outbound_diagnostic_capability, nonce_digest=sha256_hex(capability.nonce), organization_id=context.organization_id, authorization_attempt_uuid=context.attempt_id, idempotency_key=idempotency_key, request_digest=request_digest, candidate_digest=context.candidate_digest, gate_envelope_digest=context.gate_envelope_digest, route_profile_digest=route_profile_digest, route_digest=chain.route_decision_sha256, provider_digest=chain.provider_fact_packet_sha256, keyset_digest=chain.keyset_sha256, token_digest=sha256_hex(opaque), signature_digest=sha256_hex(signature), encrypted_capability_recovery=encrypted_wire, issued_at=issued_at, expires_at=expires_at)
        recovered_wire = await sealer.unseal(ciphertext=row.encrypted_capability_recovery)
        recovered = _parse_route_chain_capability(recovered_wire)
        if (not hmac.compare_digest(row.token_digest, sha256_hex(recovered_wire)) or not hmac.compare_digest(row.signature_digest, sha256_hex(recovered.signature.get_secret_value())) or recovered.claims != claims or recovered.expires_at != row.expires_at or recovered.issued_at != row.issued_at or not hmac.compare_digest(row.nonce_digest, sha256_hex(recovered.nonce))):
            raise ValueError("route_capability_recovery_invalid")
        return recovered
    except F12ServiceError:
        raise
    except Exception:
        raise F12ServiceError("onnuri_smoke_f12_operation_rejected", 409) from None
    finally:
        if resolved is not None:
            if resolved.approved_root is not None:
                os.close(resolved.approved_root)
            if resolved.adapter_descriptor is not None:
                os.close(resolved.adapter_descriptor)


async def _call(
    operation: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any
) -> Any:
    try:
        return await operation(*args, **kwargs)
    except (
        TelephonyNumberInventoryConflictError,
        TelephonyNumberInventoryNotFoundError,
    ) as exc:
        raise _rejected(exc) from exc
    except Exception:
        raise F12ServiceError("onnuri_smoke_f12_backend_unavailable", 503) from None


def _attempt_receipt(row: Any) -> dict[str, Any]:
    return {"attempt_uuid": row.attempt_uuid, "state": row.state}


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


async def begin_registration(**values: Any) -> dict[str, Any]:
    runtime = get_smoke_authority_runtime()
    normalized = dict(values)
    normalized["envelope_uuid"] = str(normalized["envelope_uuid"])
    normalized["execution_seal_uuid"] = str(normalized["execution_seal_uuid"])
    normalized["execution_stage_uuid"] = str(normalized["execution_stage_uuid"])
    if normalized.get("prior_register_operation_uuid") is not None:
        normalized["prior_register_operation_uuid"] = str(
            normalized["prior_register_operation_uuid"]
        )
    context = await _call(
        authority.db_client.begin_onnuri_registration_operation,
        **normalized,
    )
    gate = context["gate"]
    claims = {
        "candidate_digest": context["candidate_digest"],
        "concurrency_count": 1,
        "envelope_digest": context["gate_envelope_digest"],
        "expires_at": context["expires_at"].isoformat(),
        "gate_envelope_digest": context["gate_envelope_digest"],
        "issued_at": context["issued_at"].isoformat(),
        "max_elapsed_seconds": 60,
        "nonce_digest": normalized["nonce_digest"],
        "operation_kind": normalized["operation_kind"],
        "operation_uuid": gate.operation_uuid,
        "organization_id": normalized["organization_id"],
        "prior_register_gate_id": normalized.get("prior_register_gate_id"),
        "prior_register_operation_uuid": context[
            "prior_register_operation_uuid"
        ],
        "registration_gate_id": gate.id,
        "request_digest": normalized["request_digest"],
        "retry_count": 0,
        "transaction_count": 1,
        "verification_domain": _REGISTRATION_VERIFICATION_DOMAIN,
    }
    unsigned = {
        "algorithm": "ES256",
        "claims": claims,
        "key_id": context["dispatch_key_id"],
        "verification_domain": _REGISTRATION_VERIFICATION_DOMAIN,
    }
    signing_bytes = canonical_json_bytes(unsigned)
    policy = CapabilityPolicy(
        kind="dispatch",
        verification_domain=context["dispatch_domain"],
        key_id=context["dispatch_key_id"],
        other_key_id=context["media_key_id"],
    )
    try:
        signature = await runtime.issuer.sign_dispatch_receipt(
            signing_bytes=signing_bytes,
            policy=policy,
        )
    except Exception as exc:
        raise _capability_error(exc) from None
    authorization = canonical_json_bytes({**unsigned, "signature": signature})
    return {
        "registration_gate_id": gate.id,
        "operation_uuid": gate.operation_uuid,
        "operation_kind": gate.operation_kind,
        "envelope_digest": context["gate_envelope_digest"],
        "expires_at": context["expires_at"],
        "opaque_authorization": _b64url(authorization),
    }

def _validate_registration_authorization(
    opaque_authorization: SecretStr, values: dict[str, Any]
) -> None:
    if not isinstance(opaque_authorization, SecretStr):
        raise F12ServiceError("onnuri_smoke_f12_operation_rejected", 409)
    encoded = opaque_authorization.get_secret_value()
    try:
        padding = "=" * (-len(encoded) % 4)
        raw = base64.urlsafe_b64decode((encoded + padding).encode("ascii"))
        if _b64url(raw) != encoded:
            raise ValueError
        envelope = json.loads(raw)
        if canonical_json_bytes(envelope) != raw:
            raise ValueError
        claims = envelope["claims"]
        expected = {
            "candidate_digest": values["candidate_digest"],
            "concurrency_count": 1,
            "envelope_digest": values["gate_envelope_digest"],
            "gate_envelope_digest": values["gate_envelope_digest"],
            "max_elapsed_seconds": 60,
            "nonce_digest": values["nonce_digest"],
            "operation_kind": values["operation_kind"],
            "operation_uuid": values["operation_uuid"],
            "organization_id": values["organization_id"],
            "prior_register_gate_id": values.get("prior_register_gate_id"),
            "prior_register_operation_uuid": values.get(
                "prior_register_operation_uuid"
            ),
            "registration_gate_id": values["registration_gate_id"],
            "request_digest": values["request_digest"],
            "retry_count": 0,
            "transaction_count": 1,
            "verification_domain": _REGISTRATION_VERIFICATION_DOMAIN,
        }
        if (
            not isinstance(envelope, dict)
            or set(envelope)
            != {
                "algorithm",
                "claims",
                "key_id",
                "signature",
                "verification_domain",
            }
            or envelope["algorithm"] != "ES256"
            or envelope["verification_domain"] != _REGISTRATION_VERIFICATION_DOMAIN
            or not isinstance(claims, dict)
            or any(claims.get(key) != value for key, value in expected.items())
            or set(claims)
            != {
                "candidate_digest",
                "concurrency_count",
                "envelope_digest",
                "expires_at",
                "gate_envelope_digest",
                "issued_at",
                "max_elapsed_seconds",
                "nonce_digest",
                "operation_kind",
                "operation_uuid",
                "organization_id",
                "prior_register_gate_id",
                "prior_register_operation_uuid",
                "registration_gate_id",
                "request_digest",
                "retry_count",
                "transaction_count",
                "verification_domain",
            }
        ):
            raise ValueError

        key_id = os.getenv(_DISPATCH_KEY_ID_ENV, "").strip()
        public_key_path = Path(os.getenv(_DISPATCH_PUBLIC_KEY_FILE_ENV, ""))
        if (
            not key_id
            or envelope["key_id"] != key_id
            or not public_key_path.is_file()
            or public_key_path.is_symlink()
        ):
            raise ValueError
        issued_at = datetime.fromisoformat(claims["issued_at"])
        expires_at = datetime.fromisoformat(claims["expires_at"])
        now = datetime.now(UTC)
        if (
            issued_at.tzinfo is None
            or expires_at.tzinfo is None
            or issued_at.isoformat() != claims["issued_at"]
            or expires_at.isoformat() != claims["expires_at"]
            or issued_at > now
            or now >= expires_at
            or expires_at <= issued_at
            or expires_at - issued_at > timedelta(seconds=60)
            or now - issued_at > timedelta(seconds=60)
            or expires_at - now > timedelta(seconds=60)
        ):
            raise ValueError

        public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise ValueError
        signature = base64.urlsafe_b64decode(
            (envelope["signature"] + "=" * (-len(envelope["signature"]) % 4)).encode(
                "ascii"
            )
        )
        if len(signature) != 64 or _b64url(signature) != envelope["signature"]:
            raise ValueError
        unsigned = {
            "algorithm": envelope["algorithm"],
            "claims": claims,
            "key_id": envelope["key_id"],
            "verification_domain": envelope["verification_domain"],
        }
        public_key.verify(
            encode_dss_signature(
                int.from_bytes(signature[:32], "big"),
                int.from_bytes(signature[32:], "big"),
            ),
            canonical_json_bytes(unsigned),
            ec.ECDSA(hashes.SHA256()),
        )
    except (
        binascii.Error,
        InvalidSignature,
        KeyError,
        OSError,
        OverflowError,
        TypeError,
        ValueError,
    ):
        raise F12ServiceError("onnuri_smoke_f12_operation_rejected", 409) from None


async def consume_registration(**values: Any) -> dict[str, Any]:
    normalized = dict(values)
    opaque_authorization = normalized.pop("opaque_authorization")
    normalized["operation_uuid"] = str(normalized["operation_uuid"])
    if normalized.get("prior_register_operation_uuid") is not None:
        normalized["prior_register_operation_uuid"] = str(
            normalized["prior_register_operation_uuid"]
        )
    _validate_registration_authorization(opaque_authorization, normalized)
    gate = await _call(
        authority.db_client.consume_onnuri_registration_operation,
        **normalized,
    )
    return {
        "registration_gate_id": gate.id,
        "operation_uuid": gate.operation_uuid,
        "operation_kind": gate.operation_kind,
        "request_digest": normalized["request_digest"],
        "candidate_digest": normalized["candidate_digest"],
        "gate_envelope_digest": normalized["gate_envelope_digest"],
        "nonce_digest": normalized["nonce_digest"],
        "prior_register_gate_id": normalized.get("prior_register_gate_id"),
        "prior_register_operation_uuid": normalized.get(
            "prior_register_operation_uuid"
        ),
        "state": "started",
        "challenged": True,
        "transaction_count": 1,
        "retry_count": 0,
        "concurrency_count": 1,
    }



def _execution_rejected() -> F12ServiceError:
    return F12ServiceError("onnuri_smoke_f12_operation_rejected", 409)


def _strict_int(value: Any, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError
    return value


def _digest_or_none(value: Any) -> str | None:
    if value is not None and (
        not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None
    ):
        raise ValueError
    return value


def _exact_utc(value: Any) -> datetime:
    if not isinstance(value, str) or _EXACT_UTC_RE.fullmatch(value) is None:
        raise ValueError
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC:
        raise ValueError
    return parsed


def _verify_execution_attestation(
    opaque_execution_attestation: SecretStr,
) -> dict[str, Any]:
    if not isinstance(opaque_execution_attestation, SecretStr):
        raise _execution_rejected()
    encoded = opaque_execution_attestation.get_secret_value()
    try:
        raw = base64.urlsafe_b64decode(
            (encoded + "=" * (-len(encoded) % 4)).encode("ascii")
        )
        if not raw or len(raw) > 24576 or _b64url(raw) != encoded:
            raise ValueError
        envelope = json.loads(raw)
        if canonical_json_bytes(envelope) != raw or not isinstance(envelope, dict):
            raise ValueError
        if set(envelope) != {
            "algorithm",
            "claims",
            "key_id",
            "signature",
            "verification_domain",
        }:
            raise ValueError
        claims = envelope["claims"]
        key_id = os.getenv(_REGISTRATION_ATTESTATION_KEY_ID_ENV, "").strip()
        endpoint_digest = os.getenv(
            _REGISTRATION_UPSTREAM_ENDPOINT_DIGEST_ENV, ""
        ).strip()
        public_key_path = Path(
            os.getenv(_REGISTRATION_ATTESTATION_PUBLIC_KEY_FILE_ENV, "")
        )
        if (
            envelope["algorithm"] != "ES256"
            or envelope["verification_domain"] != _REGISTRATION_EXECUTION_DOMAIN
            or envelope["key_id"] != key_id
            or _KEY_ID_RE.fullmatch(key_id) is None
            or not isinstance(claims, dict)
            or set(claims) != _EXECUTION_CLAIM_KEYS
            or claims["verification_domain"] != _REGISTRATION_EXECUTION_DOMAIN
            or claims["upstream_endpoint_digest"] != endpoint_digest
            or _SHA256_RE.fullmatch(endpoint_digest) is None
            or not public_key_path.is_file()
            or public_key_path.is_symlink()
        ):
            raise ValueError

        signature_text = envelope["signature"]
        if not isinstance(signature_text, str):
            raise ValueError
        signature = base64.urlsafe_b64decode(
            (signature_text + "=" * (-len(signature_text) % 4)).encode("ascii")
        )
        if len(signature) != 64 or _b64url(signature) != signature_text:
            raise ValueError
        public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise ValueError
        unsigned = {
            "algorithm": envelope["algorithm"],
            "claims": claims,
            "key_id": envelope["key_id"],
            "verification_domain": envelope["verification_domain"],
        }
        public_key.verify(
            encode_dss_signature(
                int.from_bytes(signature[:32], "big"),
                int.from_bytes(signature[32:], "big"),
            ),
            canonical_json_bytes(unsigned),
            ec.ECDSA(hashes.SHA256()),
        )

        operation_kind = claims["operation_kind"]
        operation_uuid = claims["operation_uuid"]
        if (
            operation_kind not in {"register", "unregister"}
            or not isinstance(operation_uuid, str)
            or str(UUID(operation_uuid)) != operation_uuid
        ):
            raise ValueError
        organization_id = _strict_int(
            claims["organization_id"], minimum=1, maximum=2**63 - 1
        )
        registration_gate_id = _strict_int(
            claims["registration_gate_id"], minimum=1, maximum=2**63 - 1
        )
        for name in (
            "authorization_nonce_digest",
            "candidate_digest",
            "gate_envelope_digest",
            "request_digest",
        ):
            if not isinstance(claims[name], str) or _SHA256_RE.fullmatch(
                claims[name]
            ) is None:
                raise ValueError

        prior_gate_id = claims["prior_register_gate_id"]
        prior_operation_uuid = claims["prior_register_operation_uuid"]
        linked = prior_gate_id is not None and prior_operation_uuid is not None
        if (
            linked != (operation_kind == "unregister")
            or (
                prior_gate_id is not None
                and (type(prior_gate_id) is not int or prior_gate_id <= 0)
            )
            or (
                prior_operation_uuid is not None
                and (
                    not isinstance(prior_operation_uuid, str)
                    or str(UUID(prior_operation_uuid)) != prior_operation_uuid
                )
            )
        ):
            raise ValueError

        transaction_count = _strict_int(
            claims["transaction_count"], minimum=1, maximum=1
        )
        retry_count = _strict_int(claims["retry_count"], minimum=0, maximum=0)
        wire_request_count = _strict_int(
            claims["wire_request_count"], minimum=0, maximum=2
        )
        response_count = _strict_int(
            claims["response_count"], minimum=0, maximum=2
        )
        initial_digest = _digest_or_none(claims["initial_request_wire_digest"])
        retry_digest = _digest_or_none(claims["retry_request_wire_digest"])
        challenge_digest = _digest_or_none(
            claims["challenge_response_wire_digest"]
        )
        final_digest = _digest_or_none(claims["final_response_wire_digest"])
        binding_digest = _digest_or_none(
            claims["sip_transaction_binding_digest"]
        )
        challenge_status = claims["challenge_status"]
        final_status = claims["final_status"]
        if challenge_status is not None:
            _strict_int(challenge_status, minimum=100, maximum=699)
        if final_status is not None:
            _strict_int(final_status, minimum=100, maximum=699)
        has_challenge = challenge_status is not None
        if (
            claims["transport"] != "udp"
            or challenge_status not in {None, 401, 407}
            or has_challenge != (challenge_digest is not None)
            or wire_request_count
            != (int(initial_digest is not None) + int(retry_digest is not None))
            or response_count
            != (int(challenge_digest is not None) + int(final_digest is not None))
            or (initial_digest is None) != (binding_digest is None)
            or (retry_digest is not None and not has_challenge)
            or (wire_request_count == 2 and retry_digest is None)
            or (has_challenge and wire_request_count == 0)
            or (final_status is not None and final_digest is None)
        ):
            raise ValueError

        started_at = _exact_utc(claims["started_at"])
        completed_at = _exact_utc(claims["completed_at"])
        elapsed_seconds = (completed_at - started_at).total_seconds()
        if (
            elapsed_seconds < 0
            or elapsed_seconds > 60
            or completed_at > datetime.now(UTC) + timedelta(seconds=5)
        ):
            raise ValueError

        accepted_expires = claims["accepted_expires_seconds"]
        if accepted_expires is not None:
            _strict_int(accepted_expires, minimum=0, maximum=86400)
        if (
            final_status == 200
            and final_digest is not None
            and (
                (
                    operation_kind == "register"
                    and type(accepted_expires) is int
                    and accepted_expires > 0
                )
                or (operation_kind == "unregister" and accepted_expires == 0)
            )
        ):
            outcome = "succeeded"
            deregistered = operation_kind == "unregister"
        elif final_status is not None and final_digest is not None:
            outcome = "failed"
            deregistered = False
            if accepted_expires is not None:
                raise ValueError
        else:
            outcome = "contained"
            deregistered = False
            if accepted_expires is not None:
                raise ValueError
        if (
            claims["outcome"] != outcome
            or type(claims["deregistered"]) is not bool
            or claims["deregistered"] is not deregistered
            or (
                outcome == "succeeded"
                and (
                    response_count not in {1, 2}
                    or wire_request_count != response_count
                    or initial_digest is None
                    or binding_digest is None
                )
            )
        ):
            raise ValueError

        return {
            "organization_id": organization_id,
            "registration_gate_id": registration_gate_id,
            "operation_uuid": operation_uuid,
            "operation_kind": operation_kind,
            "nonce_digest": claims["authorization_nonce_digest"],
            "candidate_digest": claims["candidate_digest"],
            "gate_envelope_digest": claims["gate_envelope_digest"],
            "request_digest": claims["request_digest"],
            "prior_register_gate_id": prior_gate_id,
            "prior_register_operation_uuid": prior_operation_uuid,
            "outcome": outcome,
            "transaction_count": transaction_count,
            "retry_count": retry_count,
            "response_count": response_count,
            "wire_request_count": wire_request_count,
            "deregistered": deregistered,
            "accepted_expires_seconds": accepted_expires,
            "execution_attestation_canonical": raw,
            "execution_attestation_signature": signature,
            "execution_attestation_digest": hashlib.sha256(raw).hexdigest(),
            "execution_attestation_signature_digest": hashlib.sha256(
                signature
            ).hexdigest(),
            "execution_attestation_key_digest": hashlib.sha256(
                public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).hexdigest(),
            "execution_attestation_key_id": key_id,
            "execution_attested_at": completed_at,
        }
    except (
        binascii.Error,
        InvalidSignature,
        KeyError,
        OSError,
        OverflowError,
        TypeError,
        UnicodeError,
        ValueError,
    ):
        raise _execution_rejected() from None


async def finalize_registration(
    *, opaque_execution_attestation: SecretStr, caller: F12Caller
) -> dict[str, Any]:
    normalized = _verify_execution_attestation(opaque_execution_attestation)
    caller.authorize(normalized["organization_id"])
    gate, recovered = await _call(
        authority.db_client.finalize_onnuri_registration_operation,
        **normalized,
    )
    return {
        "registration_gate_id": gate.id,
        "operation_uuid": gate.operation_uuid,
        "operation_kind": gate.operation_kind,
        "outcome": gate.failure_class,
        "recovered": recovered,
    }


async def authority_ready() -> bool:
    runtime = get_smoke_authority_runtime()
    try:
        _load_g008_authority_signing_key(_G008_TRUSTED_KEYSET_DIGEST)
    except F12ServiceError:
        return False
    return runtime.configuration_ready() and await authority.db_client.onnuri_smoke_authority_ready()


def _bound_context_from_attempt(row: Any) -> BoundCallContext:
    deadline = row.authority_deadline_at or row.allocated_at
    return BoundCallContext(
        organization_id=row.organization_id,
        account_id=row.account_id,
        application_id=row.application_id,
        run_id=row.run_id,
        attempt_id=row.attempt_uuid,
        direction=row.direction,
        authority_deadline=deadline,
        candidate_digest=row.candidate_digest,
        gate_envelope_digest=row.gate_envelope_digest,
    )


def _bound_context_from_g008_projection(row: dict[str, Any]) -> BoundCallContext:
    claims = row["canonical_claims"]
    return BoundCallContext(
        organization_id=claims["organization_id"],
        account_id=claims["account_uuid"],
        application_id=claims["application_uuid"],
        run_id=claims["run_uuid"],
        attempt_id=claims["attempt_uuid"],
        direction="inbound",
        authority_deadline=claims["authority_deadline_at"],
        candidate_digest=claims["candidate_digest"],
        gate_envelope_digest=claims["gate_envelope_digest"],
    )


def _facade_status(row: Any) -> CallStatus:
    if row.state == "terminal" and row.terminal_class in _STATUS_TERMINAL:
        return CallStatus(row.terminal_class)
    aliases = {
        "dispatch_issued": CallStatus.DISPATCH_CONSUMED,
        "dispatch_issuing": CallStatus.DISPATCH_CONSUMED,
        "outbound_answer_recorded_media_issued": CallStatus.MEDIA_ISSUED,
        "inbound_answer_committed_media_issued": CallStatus.MEDIA_ISSUED,
        "outbound_answer_recorded_media_consumed": CallStatus.MEDIA_CONSUMED,
        "inbound_answer_committed_media_consumed": CallStatus.MEDIA_CONSUMED,
        "terminal": CallStatus.FAILED,
    }
    try:
        return aliases[row.state] if row.state in aliases else CallStatus(row.state)
    except ValueError as exc:
        raise F12ServiceError("onnuri_smoke_f12_operation_rejected", 409) from exc


async def get_bound_call_status(
    *, organization_id: int, account_id: str, stock_call_id_digest: str
) -> Any:
    from api.schemas.onnuri_smoke import FacadeBoundCallStatusResponse

    projection = await _call(
        authority.db_client.lookup_g008_bound_status,
        organization_id=organization_id,
        account_uuid=account_id,
        stock_call_id_digest=stock_call_id_digest,
    )
    if projection is not None:
        claims = projection["canonical_claims"]
        terminal_state = projection.get("terminal_state")
        try:
            if (
                projection["state"] != "bound"
                or claims["organization_id"] != organization_id
                or claims["account_uuid"] != account_id
                or claims["stock_call_id_digest"] != stock_call_id_digest
                or claims["direction"] != "inbound"
                or str(UUID(claims["application_uuid"]))
                != claims["application_uuid"]
            ):
                raise ValueError
            status = (
                CallStatus(terminal_state)
                if projection.get("terminal")
                else CallStatus.STOCK_BOUND
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise F12ServiceError(
                "onnuri_smoke_f12_operation_rejected", 409
            ) from exc
        bound_at = projection["bound_at"]
        return FacadeBoundCallStatusResponse(
            context=_bound_context_from_g008_projection(projection),
            status=status,
            idempotency_key=claims["idempotency_uuid"],
            request_digest=claims["request_digest"],
            candidate_digest=claims["candidate_digest"],
            allocated_at=bound_at,
            stock_bound_at=bound_at,
            authority_deadline=claims["authority_deadline_at"],
            terminal_at=projection.get("finalized_at"),
            contained_at=(
                projection.get("finalized_at")
                if terminal_state == CallStatus.CONTAINED.value
                else None
            ),
        )

    row = await _call(
        authority.db_client.lookup_onnuri_smoke_bound_attempt,
        organization_id=organization_id,
        account_id=account_id,
        stock_call_id_digest=stock_call_id_digest,
    )
    status = _facade_status(row)
    return FacadeBoundCallStatusResponse(
        context=_bound_context_from_attempt(row),
        status=status,
        idempotency_key=row.idempotency_key,
        request_digest=row.allocation_request_digest,
        candidate_digest=row.candidate_digest,
        allocated_at=row.allocated_at,
        stock_bound_at=row.stock_bound_at,
        authority_deadline=row.authority_deadline_at,
        terminal_at=row.terminal_at,
        contained_at=row.contained_at,
    )


async def accept_call_event(
    *, context: BoundCallContext, event_nonce_digest: str, idempotency_key: str,
    request_digest: str, event_type: str, normalized_status: str,
    occurred_at: datetime, duration_seconds: int | None,
    redacted_cause_category: str | None,
) -> CallbackReceipt:
    if context.direction.value == "inbound" and context.stock_call_id is not None:
        stock_call_id_digest = sha256_hex(context.stock_call_id)
        projection = await _call(
            authority.db_client.lookup_g008_bound_status,
            organization_id=context.organization_id,
            account_uuid=context.account_id,
            stock_call_id_digest=stock_call_id_digest,
        )
        if projection is not None:
            claims = projection["canonical_claims"]
            if (
                projection["state"] != "bound"
                or claims["organization_id"] != context.organization_id
                or claims["account_uuid"] != context.account_id
                or claims["application_uuid"] != context.application_id
                or claims["stock_call_id_digest"] != stock_call_id_digest
                or claims["direction"] != context.direction.value
                or claims["run_uuid"] != context.run_id
                or claims["attempt_uuid"] != context.attempt_id
                or claims["candidate_digest"] != context.candidate_digest
                or claims["gate_envelope_digest"] != context.gate_envelope_digest
            ):
                raise F12ServiceError(
                    "onnuri_smoke_f12_operation_rejected", 409
                )
    row = await _call(
        authority.db_client.accept_onnuri_smoke_callback,
        organization_id=context.organization_id,
        account_id=context.account_id,
        application_id=context.application_id,
        run_id=context.run_id,
        attempt_uuid=context.attempt_id,
        stock_call_id_digest=sha256_hex(context.stock_call_id or ""),
        event_nonce_digest=event_nonce_digest,
        idempotency_key=idempotency_key,
        request_digest=request_digest,
        event_type=event_type,
        normalized_status=normalized_status,
        occurred_at=occurred_at,
        duration_seconds=duration_seconds,
        redacted_cause_category=redacted_cause_category,
    )
    if (
        context.direction.value == "outbound"
        and normalized_status == CallStatus.COMPLETED.value
    ):
        await _call(
            authority.db_client.bind_g008_outbound_observation,
            {
                "organization_id": context.organization_id,
                "attempt_uuid": str(context.attempt_id),
            },
        )
    return CallbackReceipt(
        organization_id=context.organization_id,
        event_nonce=event_nonce_digest,
        idempotency_key=row.idempotency_key,
        request_digest=row.request_digest,
        accepted_at=row.accepted_at,
        status=CallStatus(row.normalized_status),
    )


async def request_call_containment(
    *, context: BoundCallContext, category: FailureCategory
) -> dict[str, Any]:
    row = await _call(
        authority.db_client.request_onnuri_smoke_containment,
        organization_id=context.organization_id,
        account_id=context.account_id,
        application_id=context.application_id,
        run_id=context.run_id,
        attempt_uuid=context.attempt_id,
        stock_call_id_digest=sha256_hex(context.stock_call_id or ""),
        category=category.value,
    )
    return _attempt_receipt(row)

def _secret_bytes(value: SecretStr | str) -> bytes:
    raw = value.get_secret_value() if isinstance(value, SecretStr) else value
    return raw.encode("utf-8")


def _dispatch_receipt_bytes(value: DispatchConsumeReceipt) -> bytes:
    payload = value.model_dump(mode="json", exclude={"signature"}, exclude_none=True)
    payload["signature"] = value.signature.get_secret_value()
    return canonical_json_bytes(payload)


def _media_receipt_bytes(value: MediaAuthorityReceipt) -> bytes:
    payload = value.model_dump(
        mode="json", exclude={"opaque_media_capability"}, exclude_none=True
    )
    payload["opaque_media_capability"] = (
        value.opaque_media_capability.get_secret_value()
    )
    return canonical_json_bytes(payload)


def _context(
    binding: CapabilityBinding, *, deadline: datetime, stock_call_id: str | None = None
) -> BoundCallContext:
    return BoundCallContext(
        organization_id=binding.organization_id,
        account_id=binding.account_id,
        application_id=binding.application_id,
        run_id=binding.run_id,
        attempt_id=binding.attempt_id,
        direction=binding.direction,
        stock_call_id=stock_call_id,
        authority_deadline=deadline,
        candidate_digest=binding.candidate_digest,
        gate_envelope_digest=binding.gate_envelope_digest,
    )


def _binding(
    values: dict[str, Any], *, direction: Literal["outbound", "inbound"]
) -> CapabilityBinding:
    return CapabilityBinding(
        organization_id=values["organization_id"],
        account_id=values["account_id"],
        application_id=values["application_id"],
        run_id=values["run_id"],
        attempt_id=values["attempt_uuid"],
        direction=direction,
        idempotency_key=values["idempotency_key"],
        request_digest=values["request_digest"],
        candidate_digest=values["candidate_digest"],
        gate_envelope_digest=values["gate_envelope_digest"],
        stock_call_id=values.get("stock_call_id"),
        callback_event_nonce=values.get("event_nonce"),
        observed_event_wall_time=values.get("observed_wall_time"),
    )

def _require_locked_digests(
    values: dict[str, Any], context: dict[str, Any]
) -> None:
    for name in ("candidate_digest", "gate_envelope_digest"):
        if not hmac.compare_digest(
            values[name].encode("ascii"), context[name].encode("ascii")
        ):
            raise ValueError(f"{name}_mismatch")


def _capability_error(exc: Exception) -> F12ServiceError:
    if isinstance(exc, SmokeCapabilityUnavailableError):
        return F12ServiceError("onnuri_smoke_capability_backend_unavailable", 503)
    return F12ServiceError("onnuri_smoke_f12_capability_rejected", 409)


async def allocate_and_issue_dispatch(
    *,
    issuer: SmokeCapabilityIssuer | None = None,
    recovery_sealer: SmokeRecoverySealer | None = None,
    **values: Any,
) -> tuple[Any, bytes]:
    """Commit allocation first, then issue exactly once from its locked envelope."""
    runtime = get_smoke_authority_runtime()
    issuer = issuer if issuer is not None else runtime.issuer
    recovery_sealer = (
        recovery_sealer if recovery_sealer is not None else runtime.recovery_sealer
    )
    allocation_fields = {
        name: values[name]
        for name in (
            "envelope_uuid",
            "organization_id",
            "proof_id",
            "inventory_id",
            "telephony_configuration_id",
            "workflow_id",
            "authenticated_operator_user_id",
            "workflow_owner_user_id",
            "idempotency_key",
            "request_digest",
            "destination_hmac_digest",
        )
    }
    for optional in (
        "manual_acknowledgement_digest",
        "manual_acknowledged_at",
    ):
        if optional in values:
            allocation_fields[optional] = values[optional]
    row = await _call(
        authority.allocate_smoke_attempt,
        direction="outbound",
        **allocation_fields,
    )
    opaque = await issue_dispatch(
        row.attempt_uuid,
        issuer=issuer,
        recovery_sealer=recovery_sealer,
        **values,
    )
    return row, opaque


async def issue_dispatch(
    attempt_uuid: str,
    *,
    issuer: SmokeCapabilityIssuer | None = None,
    recovery_sealer: SmokeRecoverySealer | None = None,
    **values: Any,
) -> bytes:
    """Issue from locked envelope policy and recover byte-identical duplicates."""
    runtime = get_smoke_authority_runtime()
    issuer = issuer if issuer is not None else runtime.issuer
    recovery_sealer = (
        recovery_sealer if recovery_sealer is not None else runtime.recovery_sealer
    )

    async def builder(context: dict[str, Any]) -> dict[str, Any]:
        try:
            binding = _binding(
                {
                    **values,
                    "attempt_uuid": context["attempt_uuid"],
                    "request_digest": context["request_digest"],
                    "idempotency_key": context["idempotency_key"],
                    "candidate_digest": context["candidate_digest"],
                    "gate_envelope_digest": context["gate_envelope_digest"],
                },
                direction="outbound",
            )
            if context["duplicate"]:
                response = await recovery_sealer.unseal(
                    ciphertext=context["encrypted_issue_recovery"]
                )
                parsed = parse_dispatch_capability(response)
                if parsed.claims != binding.claims(
                    authority_deadline=context["expires_at"]
                ):
                    raise ValueError("claim_binding_mismatch")
                return {"response": response}
            policy = CapabilityPolicy(
                kind="dispatch",
                verification_domain=context["domain"],
                key_id=context["key_id"],
                other_key_id=context["other_key_id"],
                algorithm_policy_id=context["algorithm_policy_id"],
            )
            request = CapabilityIssueRequest(
                binding=binding,
                policy=policy,
                issued_at=context["issued_at"],
                expires_at=context["expires_at"],
                gate_envelope_digest=context["gate_envelope_digest"],
            )
            issued = await issuer.issue_dispatch(request)
            opaque, _ = signed_capability_bytes(issued, request)
            digests = issued_digests(issued, opaque)
            encrypted_wire = await recovery_sealer.seal(
                plaintext=opaque, expires_at=request.expires_at
            )
            if await recovery_sealer.unseal(ciphertext=encrypted_wire) != opaque:
                raise ValueError("recovery_round_trip_mismatch")
            return {
                "response": opaque,
                "issued_at": issued.issued_at,
                "expires_at": issued.expires_at,
                "domain": issued.policy.verification_domain,
                "key_id": issued.policy.key_id,
                "algorithm_policy_id": issued.policy.algorithm_policy_id,
                "nonce_digest": digests.nonce_digest,
                "token_digest": digests.token_digest,
                "receipt_digest": digests.receipt_digest,
                "encrypted_issue_recovery": encrypted_wire,
            }
        except Exception as exc:
            raise _capability_error(exc) from None

    try:
        _row, response = await _call(
            authority.issue_smoke_dispatch,
            attempt_uuid,
            organization_id=values["organization_id"],
            builder=builder,
        )
        return response
    except Exception:
        try:
            await authority.set_smoke_terminal(
                attempt_uuid,
                organization_id=values["organization_id"],
                terminal_class="authority_failure",
                terminal_reason="dispatch_issue_failed",
                contain=True,
            )
        except Exception:
            pass
        raise


async def consume_dispatch(
    *,
    issuer: SmokeCapabilityIssuer | None = None,
    recovery_sealer: SmokeRecoverySealer | None = None,
    **values: Any,
) -> DispatchConsumeReceipt:
    runtime = get_smoke_authority_runtime()
    issuer = issuer if issuer is not None else runtime.issuer
    recovery_sealer = (
        recovery_sealer if recovery_sealer is not None else runtime.recovery_sealer
    )
    opaque = _secret_bytes(values["opaque_capability"])
    binding = _binding(values, direction="outbound")
    try:
        raw_capability = json.loads(opaque)
        if not isinstance(raw_capability, dict):
            raise ValueError("invalid_capability_shape")
        route_consume_fields: dict[str, Any] | None = None
        capability_domain = raw_capability.get("verification_domain")
        if capability_domain == ROUTE_CHAIN_CAPABILITY_DOMAIN:
            parsed = _parse_route_chain_capability(opaque)
            route_profile_digest = parsed.claims.get("route_profile_digest")
            if not isinstance(route_profile_digest, str) or _SHA256_RE.fullmatch(route_profile_digest) is None:
                raise ValueError("route_claim_missing")
            context = _context(binding, deadline=parsed.expires_at)
            expected_claims = _route_claims_for(context=context, idempotency_key=binding.idempotency_key, request_digest=binding.request_digest, route_profile_digest=route_profile_digest, claims=parsed.claims)
            if parsed.claims != expected_claims:
                raise ValueError("claim_binding_mismatch")
            verification_binding: CapabilityBinding | _RouteCapabilityBinding = _RouteCapabilityBinding(expected_claims)
            verification_signing_bytes = canonical_signing_bytes(parsed, exclude={"signature"})
            token_digest = sha256_hex(opaque)
            nonce_digest = sha256_hex(parsed.nonce)
            receipt_digest = sha256_hex(parsed.signature.get_secret_value())
            verified = await issuer.verify("dispatch", opaque, verification_signing_bytes, parsed.signature.get_secret_value(), verification_binding)
            if not (hmac.compare_digest(verified.token_digest, token_digest) and hmac.compare_digest(verified.nonce_digest, nonce_digest) and hmac.compare_digest(verified.receipt_digest, receipt_digest)):
                raise ValueError("capability_digest_mismatch")
            route_consume_fields = {
                "nonce_digest": nonce_digest, "token_digest": token_digest,
                "signature_digest": receipt_digest, "organization_id": binding.organization_id,
                "authorization_attempt_uuid": binding.attempt_uuid,
                "idempotency_key": binding.idempotency_key, "request_digest": binding.request_digest,
                "candidate_digest": binding.candidate_digest, "gate_envelope_digest": binding.gate_envelope_digest,
                "route_profile_digest": route_profile_digest, "route_digest": parsed.claims["route_decision_sha256"],
                "provider_digest": parsed.claims["provider_fact_packet_sha256"], "keyset_digest": parsed.claims["keyset_sha256"],
                "key_id": parsed.key_id, "other_key_id": os.getenv(_MEDIA_KEY_ID_ENV, "").strip(),
                "domain": parsed.verification_domain, "algorithm_policy_id": ECDSA_P256_SHA256_POLICY_ID,
            }
        elif capability_domain == DISPATCH_CAPABILITY_DOMAIN:
            parsed = parse_dispatch_capability(opaque)
            expected_claims = binding.claims(authority_deadline=parsed.expires_at)
            if parsed.claims != expected_claims:
                raise ValueError("claim_binding_mismatch")
            verification_binding = binding
            verification_signing_bytes = opaque_signing_bytes(opaque, kind="dispatch")
            token_digest = sha256_hex(opaque)
            nonce_digest = sha256_hex(parsed.nonce)
            receipt_digest = sha256_hex(parsed.signature.get_secret_value())
        else:
            raise ValueError("unsupported_capability_domain")
    except Exception as exc:
        raise _capability_error(exc) from None

    async def builder(context: dict[str, Any]) -> dict[str, Any]:
        try:
            if context["duplicate"]:
                return {
                    "response": await recovery_sealer.unseal(
                        ciphertext=context["encrypted_consume_recovery"]
                    )
                }
            verified = await issuer.verify(
                "dispatch",
                opaque,
                verification_signing_bytes,
                parsed.signature.get_secret_value(),
                verification_binding,
            )
            if (
                not hmac.compare_digest(
                    verified.token_digest.encode("utf-8"),
                    token_digest.encode("utf-8"),
                )
                or not hmac.compare_digest(
                    verified.nonce_digest.encode("utf-8"),
                    nonce_digest.encode("utf-8"),
                )
                or not hmac.compare_digest(
                    verified.receipt_digest.encode("utf-8"),
                    receipt_digest.encode("utf-8"),
                )
            ):
                raise ValueError("capability_digest_mismatch")
            policy = CapabilityPolicy(
                kind="dispatch",
                verification_domain=context["domain"],
                key_id=context["key_id"],
                other_key_id=context["other_key_id"],
                algorithm_policy_id=context["algorithm_policy_id"],
            )
            unsigned_receipt = DispatchConsumeReceipt(
                context=_context(binding, deadline=context["expires_at"]),
                idempotency_key=context["idempotency_key"],
                request_digest=context["request_digest"],
                receipt_id=f"{context['attempt_uuid']}:dispatch-consume",
                consumed_at=context["consumed_at"],
                dispatch_key_id=policy.key_id,
                verification_domain=policy.verification_domain,
                signature=SecretStr("unsigned"),
            )
            signature = await issuer.sign_dispatch_receipt(
                signing_bytes=canonical_signing_bytes(
                    unsigned_receipt, exclude={"signature"}
                ),
                policy=policy,
            )
            if not signature:
                raise ValueError("receipt_signature_invalid")
            receipt = unsigned_receipt.model_copy(
                update={"signature": SecretStr(signature)}
            )
            response = _dispatch_receipt_bytes(receipt)
            encrypted_recovery = await recovery_sealer.seal(
                plaintext=response, expires_at=context["expires_at"]
            )
            if await recovery_sealer.unseal(ciphertext=encrypted_recovery) != response:
                raise ValueError("recovery_round_trip_mismatch")
            return {
                "response": response,
                "encrypted_consume_recovery": encrypted_recovery,
            }
        except Exception as exc:
            raise _capability_error(exc) from None

    if route_consume_fields is not None:
        _row, response = await _call(
            authority.db_client.consume_onnuri_outbound_route_capability,
            **route_consume_fields,
            builder=builder,
        )
    else:
        _row, response = await _call(
            authority.consume_smoke_dispatch,
            values["attempt_uuid"],
            organization_id=binding.organization_id,
            nonce_digest=nonce_digest,
            token_digest=token_digest,
            request_digest=binding.request_digest,
            receipt_digest=receipt_digest,
            builder=builder,
            account_id=binding.account_id,
            application_id=binding.application_id,
            run_id=binding.run_id,
        )
    return DispatchConsumeReceipt.model_validate_json(response)


async def bind_stock_call(request: StockCallBindRequest) -> StockCallBindReceipt:
    context = request.context
    if context.stock_call_id != request.stock_call_id:
        raise F12ServiceError("onnuri_smoke_f12_operation_rejected", 409)

    stock_call_id_digest = sha256_hex(request.stock_call_id)
    bind_request_digest = sha256_hex(
        canonical_json_bytes(request.model_dump(mode="json", exclude_none=True))
    )
    inbound_authority = (
        {
            "source_account_id": request.source_account_id,
            "source_application_id": request.source_application_id,
            "did_digest": request.did_digest,
            "caller_mobile_digest": request.caller_mobile_digest,
            "candidate_digest": request.candidate_digest,
        }
        if context.direction == "inbound"
        else {}
    )
    row = await _call(
        authority.bind_smoke_stock_call,
        context.attempt_id,
        organization_id=context.organization_id,
        idempotency_key=request.idempotency_key,
        request_digest=request.request_digest,
        stock_call_id_digest=stock_call_id_digest,
        callback_nonce_digest=bind_request_digest,
        account_id=context.account_id,
        application_id=context.application_id,
        run_id=context.run_id,
        **inbound_authority,
    )
    if (
        row.attempt_uuid != context.attempt_id
        or row.organization_id != context.organization_id
        or row.direction != context.direction
        or row.idempotency_key != request.idempotency_key
        or row.allocation_request_digest != request.request_digest
        or row.state != "stock_bound"
        or row.stock_bound_at is None
    ):
        raise F12ServiceError("onnuri_smoke_f12_operation_rejected", 409)

    return StockCallBindReceipt(
        context=context,
        stock_call_id=request.stock_call_id,
        idempotency_key=request.idempotency_key,
        request_digest=request.request_digest,
        bind_receipt_id=f"{context.attempt_id}:stock-bind",
        bound_at=row.stock_bound_at,
        media_capability_issued=False,
    )


async def _mint_media(
    *,
    direction: Literal["outbound", "inbound"],
    issuer: SmokeCapabilityIssuer,
    recovery_sealer: SmokeRecoverySealer,
    values: dict[str, Any],
) -> MediaAuthorityReceipt:
    caller_binding = _binding(values, direction=direction)

    async def builder(context: dict[str, Any]) -> dict[str, Any]:
        try:
            _require_locked_digests(values, context)
            binding = _binding(
                {
                    **values,
                    "attempt_uuid": context["attempt_uuid"],
                    "idempotency_key": context["idempotency_key"],
                    "request_digest": context["request_digest"],
                    "candidate_digest": context["candidate_digest"],
                    "gate_envelope_digest": context["gate_envelope_digest"],
                },
                direction=direction,
            )
            if context["duplicate"]:
                recovered = await recovery_sealer.unseal(
                    ciphertext=context["encrypted_response_recovery"]
                )
                receipt = MediaAuthorityReceipt.model_validate_json(recovered)
                if (
                    receipt.context
                    != _context(
                        binding,
                        deadline=context["deadline_at"],
                        stock_call_id=binding.stock_call_id,
                    )
                    or receipt.idempotency_key != context["idempotency_key"]
                    or receipt.request_digest != context["request_digest"]
                    or receipt.stock_call_id != binding.stock_call_id
                ):
                    raise ValueError("claim_binding_mismatch")
                return {"response": recovered}
            policy = CapabilityPolicy(
                kind="media",
                verification_domain=context["domain"],
                key_id=context["key_id"],
                other_key_id=context["other_key_id"],
                algorithm_policy_id=context["algorithm_policy_id"],
            )
            request = CapabilityIssueRequest(
                binding=binding,
                policy=policy,
                issued_at=context["issued_at"],
                expires_at=context["expires_at"],
                gate_envelope_digest=context["gate_envelope_digest"],
            )
            issued = await issuer.issue_media(request)
            opaque, _ = signed_capability_bytes(issued, request)
            digests = issued_digests(issued, opaque)
            receipt = MediaAuthorityReceipt(
                context=_context(
                    binding,
                    deadline=context["deadline_at"],
                    stock_call_id=binding.stock_call_id,
                ),
                stock_call_id=binding.stock_call_id,
                idempotency_key=context["idempotency_key"],
                request_digest=context["request_digest"],
                authority_receipt_id=f"{context['attempt_uuid']}:media-authority",
                committed_at=context["committed_at"],
                authority_deadline=context["deadline_at"],
                media_verification_domain=context["domain"],
                media_key_id=context["key_id"],
                opaque_media_capability=SecretStr(opaque.decode("utf-8")),
            )
            response = _media_receipt_bytes(receipt)
            encrypted_response = await recovery_sealer.seal(
                plaintext=response, expires_at=issued.expires_at
            )
            if await recovery_sealer.unseal(ciphertext=encrypted_response) != response:
                raise ValueError("recovery_round_trip_mismatch")
            return {
                "response": response,
                "issued_at": issued.issued_at,
                "expires_at": issued.expires_at,
                "domain": issued.policy.verification_domain,
                "key_id": issued.policy.key_id,
                "algorithm_policy_id": issued.policy.algorithm_policy_id,
                "nonce_digest": digests.nonce_digest,
                "token_digest": digests.token_digest,
                "receipt_digest": digests.receipt_digest,
                "encrypted_response_recovery": encrypted_response,
            }
        except Exception as exc:
            raise _capability_error(exc) from None

    operation = (
        authority.record_outbound_answer_and_mint_media
        if direction == "outbound"
        else authority.commit_inbound_answer_intent_and_mint_media
    )
    try:
        inbound_authority = (
            {
                "source_account_id": values.get("source_account_id"),
                "source_application_id": values.get("source_application_id"),
                "did_digest": values.get("did_digest"),
                "caller_mobile_digest": values.get("caller_mobile_digest"),
                "candidate_digest": values.get("candidate_digest"),
            }
            if direction == "inbound"
            else {}
        )
        _row, response = await _call(
            operation,
            attempt_uuid=values["attempt_uuid"],
            organization_id=values["organization_id"],
            idempotency_key=values["idempotency_key"],
            callback_nonce_digest=sha256_hex(values["event_nonce"]),
            request_digest=values["request_digest"],
            stock_call_id_digest=sha256_hex(caller_binding.stock_call_id or ""),
            authority_wall_at=values["observed_wall_time"],
            deadline_at=values["proposed_deadline"],
            approved_pause_milliseconds=values.get("approved_pause_milliseconds", 0),
            builder=builder,
            account_id=caller_binding.account_id,
            application_id=caller_binding.application_id,
            run_id=caller_binding.run_id,
            **inbound_authority,
        )
        return MediaAuthorityReceipt.model_validate_json(response)
    except Exception:
        try:
            await authority.set_smoke_terminal(
                values["attempt_uuid"],
                organization_id=values["organization_id"],
                terminal_class="authority_failure",
                terminal_reason="media_issue_failed",
                contain=True,
            )
        except Exception:
            pass
        raise


async def record_answer_and_mint_media(
    *,
    issuer: SmokeCapabilityIssuer | None = None,
    recovery_sealer: SmokeRecoverySealer | None = None,
    **values: Any,
) -> MediaAuthorityReceipt:
    runtime = get_smoke_authority_runtime()
    return await _mint_media(
        direction="outbound",
        issuer=issuer if issuer is not None else runtime.issuer,
        recovery_sealer=(
            recovery_sealer if recovery_sealer is not None else runtime.recovery_sealer
        ),
        values=values,
    )


async def commit_inbound_answer_intent_and_mint_media(
    *,
    issuer: SmokeCapabilityIssuer | None = None,
    recovery_sealer: SmokeRecoverySealer | None = None,
    **values: Any,
) -> MediaAuthorityReceipt:
    runtime = get_smoke_authority_runtime()
    return await _mint_media(
        direction="inbound",
        issuer=issuer if issuer is not None else runtime.issuer,
        recovery_sealer=(
            recovery_sealer if recovery_sealer is not None else runtime.recovery_sealer
        ),
        values=values,
    )


async def consume_media(
    *, issuer: SmokeCapabilityIssuer | None = None, **values: Any
) -> dict[str, Any]:
    if issuer is None:
        issuer = get_smoke_authority_runtime().issuer
    attempt_uuid = values.pop("attempt_uuid")
    opaque = _secret_bytes(values.pop("opaque_capability"))
    binding = CapabilityBinding(
        organization_id=values.pop("organization_id"),
        account_id=values.pop("account_id"),
        application_id=values.pop("application_id"),
        run_id=values.pop("run_id"),
        attempt_id=attempt_uuid,
        direction=values.pop("direction"),
        idempotency_key=values.pop("idempotency_key"),
        request_digest=values.pop("request_digest"),
        stock_call_id=values.pop("stock_call_id"),
        callback_event_nonce=values.pop("event_nonce"),
        candidate_digest=values.pop("candidate_digest"),
        gate_envelope_digest=values.pop("gate_envelope_digest"),
        observed_event_wall_time=values.pop("observed_wall_time"),
    )
    try:
        parsed = parse_media_capability(opaque)
        expires_at = datetime.fromisoformat(parsed["expires_at"].replace("Z", "+00:00"))
        if parsed["claims"] != binding.claims(authority_deadline=expires_at):
            raise ValueError("claim_binding_mismatch")
        verified = await issuer.verify(
            "media",
            opaque,
            opaque_signing_bytes(opaque, kind="media"),
            parsed["signature"],
            binding,
        )
        if not hmac.compare_digest(
            verified.token_digest.encode("utf-8"),
            sha256_hex(opaque).encode("utf-8"),
        ):
            raise ValueError("token_digest_mismatch")
    except Exception as exc:
        raise _capability_error(exc) from None
    return _attempt_receipt(
        await _call(
            authority.consume_smoke_media,
            attempt_uuid,
            organization_id=binding.organization_id,
            nonce_digest=verified.nonce_digest,
            token_digest=verified.token_digest,
            stock_call_id_digest=sha256_hex(binding.stock_call_id or ""),
            request_digest=binding.request_digest,
            receipt_digest=verified.receipt_digest,
        )
    )


async def set_terminal(**values: Any) -> dict[str, Any]:
    attempt_uuid = values.pop("attempt_uuid")
    requested = (values["terminal_class"], values["terminal_reason"], values["contain"])
    row = await _call(authority.set_smoke_terminal, attempt_uuid, **values)
    committed = (row.terminal_class, row.terminal_reason, row.state == "contained")
    if committed != requested:
        raise F12ServiceError("onnuri_smoke_f12_replay_rejected", 409)
    return _attempt_receipt(row)


async def redacted_status(
    envelope_uuid: str, *, organization_id: int
) -> dict[str, Any]:
    row = await _call(
        authority.get_smoke_redacted_status,
        envelope_uuid,
        organization_id=organization_id,
    )
    if row is None:
        raise F12ServiceError("onnuri_smoke_f12_partition_rejected", 409)
    return row


def _canonical_evidence_value(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("execution_evidence_timestamp_invalid")
        return (
            value.astimezone(UTC)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
    if isinstance(value, dict):
        return {key: _canonical_evidence_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_evidence_value(item) for item in value]
    if value is None or type(value) in {bool, int, str}:
        return value
    raise ValueError("execution_evidence_projection_invalid")


def _execution_evidence_envelope(
    ingredients: dict[str, Any], *, key_id: str
) -> dict[str, Any]:
    if set(ingredients) == {
        "evidence_kind",
        "evidence_at",
        "containment_class",
        "active_stage_ordinal",
        "seal",
        "registration_linkage",
    }:
        kind = {
            "completion": "completed",
            "containment": "contained",
        }.get(ingredients["evidence_kind"])
        if kind is None:
            raise ValueError("execution_evidence_kind_invalid")
        seal = dict(ingredients["seal"])
        stages = seal.pop("stages")
        for field in (
            "containment_evidence_digest",
            "containment_evidence_signature_digest",
            "containment_evidence_key_digest",
            "containment_evidence_key_id",
            "final_evidence_digest",
            "final_evidence_signature_digest",
            "final_evidence_key_digest",
            "final_evidence_key_id",
        ):
            seal.pop(field)
        if (
            not isinstance(stages, list)
            or [stage.get("ordinal") for stage in stages] != [1, 2, 3, 4]
            or ingredients["evidence_kind"] == "completion"
            and any(stage.get("state") != "succeeded" for stage in stages)
        ):
            raise ValueError("execution_evidence_stage_set_invalid")
        registration_linkage = ingredients["registration_linkage"]
        linkage_ordinals = [
            linkage.get("ordinal")
            for linkage in registration_linkage
            if isinstance(linkage, dict)
        ]
        if (
            len(linkage_ordinals) != len(registration_linkage)
            or any(type(ordinal) is not int for ordinal in linkage_ordinals)
            or linkage_ordinals != sorted(set(linkage_ordinals))
            or any(ordinal not in {1, 4} for ordinal in linkage_ordinals)
            or ingredients["evidence_kind"] == "completion"
            and linkage_ordinals != [1, 4]
        ):
            raise ValueError("execution_evidence_registration_linkage_invalid")
        claims = {
            "kind": kind,
            "seal": seal,
            "stage_receipts": stages,
            "registration_linkage": registration_linkage,
        }
    elif set(ingredients) == {
        "evidence_kind",
        "evidence_at",
        "seal",
        "stage_ordinal",
        "stage_state",
        "terminal_class",
        "registration_linkage",
    }:
        ordinal = ingredients["stage_ordinal"]
        stages = ingredients["seal"]["stages"]
        if (
            ingredients["evidence_kind"] not in {"stage", "stage_containment"}
            or [stage.get("ordinal") for stage in stages] != [1, 2, 3, 4]
            or ordinal not in {1, 2, 3, 4}
        ):
            raise ValueError("execution_evidence_stage_set_invalid")
        stage = dict(stages[ordinal - 1])
        linkage = ingredients["registration_linkage"]
        if ordinal in {1, 4}:
            if len(linkage) != 1 or linkage[0].get("ordinal") != ordinal:
                raise ValueError("execution_evidence_registration_linkage_invalid")
        elif linkage:
            raise ValueError("execution_evidence_registration_linkage_invalid")
        stage["state"] = ingredients["stage_state"]
        stage["terminal_class"] = ingredients["terminal_class"]
        stage["finalized_at"] = ingredients["evidence_at"]
        claims = {
            **stage,
            "kind": ingredients["evidence_kind"],
            "containment_class": (
                ingredients["terminal_class"]
                if ingredients["evidence_kind"] == "stage_containment"
                else None
            ),
            **({"registration_linkage": linkage[0]} if ordinal in {1, 4} else {}),
        }
    else:
        raise ValueError("execution_evidence_projection_invalid")
    return _canonical_evidence_value(
        {
            "algorithm": "ES256",
            "algorithm_policy_id": ECDSA_P256_SHA256_POLICY_ID,
            "claims": claims,
            "contract_version": _EXECUTION_EVIDENCE_CONTRACT_VERSION,
            "key_id": key_id,
            "signed_at": ingredients["evidence_at"],
            "verification_domain": EXECUTION_EVIDENCE_DOMAIN,
        }
    )


async def _build_execution_evidence(ingredients: dict[str, Any]) -> dict[str, Any]:
    key_id = os.getenv(_EXECUTION_EVIDENCE_KEY_ID_ENV, "").strip()
    if _KEY_ID_RE.fullmatch(key_id) is None:
        raise RuntimeError("onnuri_smoke_execution_evidence_key_id_invalid")
    canonical_evidence = canonical_json_bytes(
        _execution_evidence_envelope(ingredients, key_id=key_id)
    )
    signed = await get_smoke_authority_runtime().execution_evidence_signer.sign(
        canonical_evidence
    )
    if (
        not isinstance(signed.signature, bytes)
        or len(signed.signature) != 64
        or signed.algorithm_policy_id != ECDSA_P256_SHA256_POLICY_ID
        or _SHA256_RE.fullmatch(signed.public_key_digest) is None
        or not hmac.compare_digest(
            signed.key_id.encode("utf-8"), key_id.encode("utf-8")
        )
    ):
        raise RuntimeError("onnuri_smoke_execution_evidence_signer_invalid")
    return {
        "canonical_evidence": canonical_evidence,
        "evidence_signature": signed.signature,
        "evidence_digest": sha256_hex(canonical_evidence),
        "evidence_signature_digest": sha256_hex(signed.signature),
        "evidence_key_digest": signed.public_key_digest,
        "evidence_key_id": key_id,
    }

def _execution_binding_payload(values: dict[str, Any]) -> dict[str, Any]:
    return {
        "organization_id": values["organization_id"],
        "execution_seal_uuid": str(values["execution_seal_uuid"]),
        "execution_nonce_digest": values["execution_nonce_digest"],
        "candidate_digest": values["candidate_digest"],
        "gate_envelope_digest": values["gate_envelope_digest"],
    }


def _execution_seal_receipt(row: dict[str, Any]) -> dict[str, Any]:
    stages = row["stages"]
    stage_names = [
        item["stage"] if isinstance(item, dict) else item for item in stages
    ]
    return {
        "organization_id": row["organization_id"],
        "execution_seal_uuid": row["execution_seal_uuid"],
        "execution_nonce_digest": row["execution_nonce_digest"],
        "candidate_digest": row["candidate_digest"],
        "gate_envelope_digest": row["gate_envelope_digest"],
        "schema_version": row["schema_version"],
        "destination_hmac_digest": row["destination_hmac_digest"],
        "stages": stage_names,
        "live_window_starts_at": row["live_window_starts_at"],
        "live_window_expires_at": row["live_window_expires_at"],
        "retry_count": row["retry_count"],
        "concurrency_count": row["concurrency_count"],
        "call_deadline_seconds": row["call_deadline_seconds"],
        "stage_deadline_at": row.get("stage_deadline_at"),
        "reserved_inbound_did_digest": row["reserved_inbound_did_digest"],
        "reserved_inbound_caller_digest": row[
            "reserved_inbound_caller_digest"
        ],
        "policy_digest": row["policy_digest"],
        "state": row["state"],
        "sealed_at": row["sealed_at"],
        "completed_at": row.get("completed_at"),
        "contained_at": row.get("contained_at"),
        "terminal_class": row.get("containment_class"),
        "containment_evidence_digest": row.get("containment_evidence_digest"),
        "containment_evidence_signature_digest": row.get(
            "containment_evidence_signature_digest"
        ),
        "containment_evidence_key_digest": row.get(
            "containment_evidence_key_digest"
        ),
        "containment_evidence_key_id": row.get("containment_evidence_key_id"),
        "final_evidence_digest": row.get("final_evidence_digest"),
        "final_evidence_signature_digest": row.get(
            "final_evidence_signature_digest"
        ),
        "final_evidence_key_digest": row.get("final_evidence_key_digest"),
        "final_evidence_key_id": row.get("final_evidence_key_id"),
    }


def _execution_stage_receipt(
    row: dict[str, Any], *, ordinal: int
) -> dict[str, Any]:
    if "stages" in row:
        stage = next(item for item in row["stages"] if item["ordinal"] == ordinal)
        stage = {**row, **stage}
    else:
        stage = row
    return {
        "organization_id": row["organization_id"],
        "execution_seal_uuid": row["execution_seal_uuid"],
        "execution_nonce_digest": row["execution_nonce_digest"],
        "candidate_digest": row["candidate_digest"],
        "gate_envelope_digest": row["gate_envelope_digest"],
        "stage_uuid": stage["stage_uuid"],
        "stage": stage["stage"],
        "ordinal": stage["ordinal"],
        "state": stage["state"],
        "started_at": stage.get("started_at"),
        "terminal_at": stage.get("terminal_at", stage.get("finalized_at")),
        "stage_deadline_at": row.get("stage_deadline_at"),
        "terminal_class": stage.get("terminal_class"),
        "evidence_digest": stage.get("evidence_digest"),
        "evidence_signature_digest": stage.get("evidence_signature_digest"),
        "evidence_key_digest": stage.get("evidence_key_digest"),
        "evidence_key_id": stage.get("evidence_key_id"),
        "registration_gate_id": stage.get("registration_gate_id"),
        "registration_operation_uuid": stage.get("registration_operation_uuid"),
        "prior_register_gate_id": stage.get("prior_register_gate_id"),
        "recovered": stage.get("recovered", False),
    }


def _g008_dispatch_signing_context() -> tuple[CapabilityPolicy, str]:
    key_id = os.getenv(_DISPATCH_KEY_ID_ENV, "").strip()
    media_key_id = os.getenv(_MEDIA_KEY_ID_ENV, "").strip()
    public_key_path = Path(os.getenv(_DISPATCH_PUBLIC_KEY_FILE_ENV, ""))
    if (
        _KEY_ID_RE.fullmatch(key_id) is None
        or _KEY_ID_RE.fullmatch(media_key_id) is None
        or key_id == media_key_id
        or not public_key_path.is_file()
        or public_key_path.is_symlink()
    ):
        raise _capability_error(ValueError("g008_inbound_bind_signer_unavailable"))
    try:
        public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    except (OSError, TypeError, ValueError):
        raise _capability_error(ValueError("g008_inbound_bind_signer_unavailable")) from None
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise _capability_error(ValueError("g008_inbound_bind_signer_unavailable"))
    fingerprint = hashlib.sha256(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
    return (
        CapabilityPolicy(
            kind="dispatch",
            verification_domain="recova.onnuri.smoke.dispatch.v1",
            key_id=key_id,
            other_key_id=media_key_id,
        ),
        fingerprint,
    )


async def _build_g008_inbound_bind_receipt(
    ingredients: dict[str, Any],
) -> dict[str, Any]:
    from api.schemas.onnuri_smoke import G008InboundBindClaims, G008InboundBindReceipt

    if set(ingredients) != {"canonical_claims"}:
        raise _execution_rejected()
    claims = ingredients["canonical_claims"]
    if not isinstance(claims, dict):
        raise _execution_rejected()
    try:
        validated_claims = G008InboundBindClaims.model_validate(claims)
        signed_claims = validated_claims.model_dump(mode="json", by_alias=True)
    except Exception:
        raise _execution_rejected() from None

    runtime = get_smoke_authority_runtime()
    policy, fingerprint = _g008_dispatch_signing_context()
    unsigned = {
        "schema_version": _G008_INBOUND_BIND_SCHEMA,
        "algorithm": _G008_INBOUND_BIND_ALGORITHM,
        "verification_domain": _G008_INBOUND_BIND_DOMAIN,
        "key_id": policy.key_id,
        "claims": signed_claims,
    }
    signing_bytes = canonical_json_bytes(unsigned)
    try:
        signature = await runtime.issuer.sign_dispatch_receipt(
            signing_bytes=signing_bytes,
            policy=policy,
        )
        signed = {**unsigned, "signature": signature}
        G008InboundBindReceipt.model_validate(signed)
        signed_bytes = canonical_json_bytes(signed)
        deadline = validated_claims.authority_deadline_at
        recovery_ciphertext = await runtime.recovery_sealer.seal(
            plaintext=signed_bytes,
            expires_at=deadline,
        )
    except Exception as exc:
        raise _capability_error(exc) from None
    return {
        "receipt_schema": _G008_INBOUND_BIND_SCHEMA,
        "receipt_domain": _G008_INBOUND_BIND_DOMAIN,
        "receipt_algorithm": _G008_INBOUND_BIND_ALGORITHM,
        "receipt_key_id": policy.key_id,
        "receipt_spki_digest": fingerprint,
        "receipt_signature_digest": sha256_hex(signature),
        "receipt_unsigned_digest": sha256_hex(signing_bytes),
        "canonical_claims": claims,
        "recovery_ciphertext": recovery_ciphertext,
        "recovery_ciphertext_digest": sha256_hex(recovery_ciphertext),
    }


async def _recover_g008_inbound_bind_receipt(row: dict[str, Any]) -> dict[str, Any]:
    from api.schemas.onnuri_smoke import G008InboundBindClaims, G008InboundBindReceipt

    ciphertext = row.get("recovery_ciphertext")
    if (
        not isinstance(ciphertext, str)
        or row.get("recovery_ciphertext_digest") != sha256_hex(ciphertext)
    ):
        raise F12ServiceError("onnuri_smoke_f12_backend_unavailable", 503)
    try:
        signed_bytes = await get_smoke_authority_runtime().recovery_sealer.unseal(
            ciphertext=ciphertext
        )
        signed = json.loads(signed_bytes)
        receipt = G008InboundBindReceipt.model_validate(signed)
        unsigned = {key: value for key, value in signed.items() if key != "signature"}
        if (
            canonical_json_bytes(signed) != signed_bytes
            or canonical_json_bytes(signed["claims"])
            != canonical_json_bytes(
                G008InboundBindClaims.model_validate(
                    row["canonical_claims"]
                ).model_dump(mode="json", by_alias=True)
            )
            or receipt.schema_version != row["receipt_schema"]
            or receipt.verification_domain != row["receipt_domain"]
            or receipt.algorithm != row["receipt_algorithm"]
            or receipt.key_id != row["receipt_key_id"]
            or sha256_hex(canonical_json_bytes(unsigned))
            != row["receipt_unsigned_digest"]
            or sha256_hex(receipt.signature) != row["receipt_signature_digest"]
        ):
            raise ValueError
        _, fingerprint = _g008_dispatch_signing_context()
        if fingerprint != row["receipt_spki_digest"]:
            raise ValueError
    except F12ServiceError:
        raise
    except Exception:
        raise F12ServiceError("onnuri_smoke_f12_operation_rejected", 409) from None
    return signed


def _inbound_claim_receipt(
    row: dict[str, Any], signed_receipt: dict[str, Any]
) -> dict[str, Any]:
    claims = signed_receipt["claims"]
    bound_at = row.get("bound_at")
    if not isinstance(bound_at, datetime) or bound_at.tzinfo is None:
        raise F12ServiceError("onnuri_smoke_f12_backend_unavailable", 503)
    return {
        "context": {
            "organization_id": claims["organization_id"],
            "execution_seal_uuid": claims["execution_seal_uuid"],
            "stage_uuid": claims["execution_stage_uuid"],
            "stage": "inbound_call",
            "ordinal": 3,
            "account_id": claims["account_uuid"],
            "application_id": claims["application_uuid"],
            "run_uuid": claims["run_uuid"],
            "attempt_uuid": claims["attempt_uuid"],
            "idempotency_key": claims["idempotency_uuid"],
            "bind_receipt_uuid": claims["bind_receipt_uuid"],
            "stock_call_id_digest": claims["stock_call_id_digest"],
            "direction": "inbound",
            "authority_deadline_at": claims["authority_deadline_at"],
            "did_digest": claims["did_digest"],
            "caller_digest": claims["caller_digest"],
            "request_digest": claims["request_digest"],
            "candidate_digest": claims["candidate_digest"],
            "gate_envelope_digest": claims["gate_envelope_digest"],
            "bound_at": bound_at,
            "bind_receipt_digest": row["receipt_unsigned_digest"],
            "bind_receipt_signature_digest": row["receipt_signature_digest"],
            "bind_receipt_key_fingerprint": row["receipt_spki_digest"],
            "bind_receipt_key_id": row["receipt_key_id"],
        },
        "bind_receipt": signed_receipt,
        "recovered": bool(row.get("recovered", False)),
    }


async def consume_execution_nonce(**values: Any) -> dict[str, Any]:
    payload = {
        **_execution_binding_payload(values),
        "trusted_keyset_digest": values["trusted_keyset_digest"],
    }
    signing_key = _load_g008_authority_signing_key(
        payload["trusted_keyset_digest"]
    )
    await _call(authority.db_client.consume_execution_nonce, payload)
    return _signed_g008_authority_receipt(
        {
            "kind": "nonce_consumption",
            **payload,
            "state": "consumed",
            "pre_existing": False,
        },
        key=signing_key,
    )


async def emergency_unregister(**values: Any) -> dict[str, Any]:
    return await begin_registration(
        **values,
        operation_kind="unregister",
        execution_stage="unregister",
        execution_stage_ordinal=4,
    )

async def create_execution_seal(**values: Any) -> dict[str, Any]:
    trusted_keyset_digest = values.get(
        "trusted_keyset_digest", _G008_TRUSTED_KEYSET_DIGEST
    )
    payload = _execution_binding_payload(values)
    payload.update(
        {
            "schema_version": values["schema_version"],
            "destination_hmac_digest": values["destination_hmac_digest"],
            "stages": list(values["stages"]),
            "live_window_starts_at": values["live_window_starts_at"],
            "live_window_expires_at": values["live_window_expires_at"],
            "sealed_at": datetime.now(UTC),
            "retry_count": values["retry_count"],
            "concurrency_count": values["concurrency_count"],
            "call_deadline_seconds": values["call_deadline_seconds"],
            "reserved_inbound_did_digest": values["reserved_inbound_did_digest"],
            "reserved_inbound_caller_digest": values[
                "reserved_inbound_caller_digest"
            ],
            "policy_digest": values["policy_digest"],
        }
    )
    signing_key = _load_g008_authority_signing_key(trusted_keyset_digest)
    row = await _call(authority.db_client.create_execution_seal, payload)
    return _signed_g008_authority_receipt(
        {"kind": "execution_seal", **_execution_seal_receipt(row), "pre_existing": False,
         "trusted_keyset_digest": trusted_keyset_digest,
         "stage_deadline_seconds": values["stage_deadline_seconds"]},
        key=signing_key,
    )


async def start_execution_stage(**values: Any) -> dict[str, Any]:
    payload = _execution_binding_payload(values)
    payload.update({"stage": values["stage"], "ordinal": values["ordinal"], "started_at": datetime.now(UTC)})
    signing_key = _load_g008_authority_signing_key(values["trusted_keyset_digest"])
    row = await _call(authority.db_client.start_execution_stage, payload)
    return _signed_g008_authority_receipt(
        {"kind": "stage_start", **_execution_stage_receipt(row, ordinal=values["ordinal"]),
         "trusted_keyset_digest": values["trusted_keyset_digest"],
         "stage_deadline_seconds": values["stage_deadline_seconds"]},
        key=signing_key,
    )


async def execution_stage_status(**values: Any) -> dict[str, Any]:
    payload = _execution_binding_payload(values)
    payload.update({"stage": values["stage"], "ordinal": values["ordinal"]})
    signing_key = _load_g008_authority_signing_key(values["trusted_keyset_digest"])
    row = await _call(authority.db_client.get_execution_stage_status, **payload)
    if row is None:
        raise F12ServiceError("onnuri_smoke_f12_partition_rejected", 409)
    if "recovered" not in row:
        raise F12ServiceError("onnuri_smoke_f12_backend_unavailable", 503)
    return _signed_g008_authority_receipt(
        {"kind": "stage_status", **_execution_stage_receipt(row, ordinal=values["ordinal"]),
         "trusted_keyset_digest": values["trusted_keyset_digest"],
         "stage_deadline_seconds": values["stage_deadline_seconds"]},
        key=signing_key,
    )


async def finalize_execution_stage(**values: Any) -> dict[str, Any]:
    payload = _execution_binding_payload(values)
    payload.update({"stage": values["stage"], "ordinal": values["ordinal"], "stage_state": values["stage_state"], "terminal_class": values["terminal_class"]})
    signing_key = _load_g008_authority_signing_key(values["trusted_keyset_digest"])
    row = await _call(authority.db_client.finalize_execution_stage, payload, evidence_builder=_build_execution_evidence)
    return _signed_g008_authority_receipt(
        {"kind": "stage_finalize", **_execution_stage_receipt(row, ordinal=values["ordinal"]),
         "trusted_keyset_digest": values["trusted_keyset_digest"],
         "stage_deadline_seconds": values["stage_deadline_seconds"]},
        key=signing_key,
    )


def _verify_g008_authority_receipt(receipt: Any, *, kind: str, binding: dict[str, Any]) -> None:
    if not isinstance(receipt, dict) or set(receipt) != {"payload", "signature"}:
        raise _execution_rejected()
    try:
        from api.schemas.onnuri_smoke import G008AuthorityReceipt

        parsed = G008AuthorityReceipt.model_validate(receipt)
        payload = parsed.payload
        signature = parsed.signature
        key = _load_g008_authority_signing_key(binding["trusted_keyset_digest"])
        key.public_key().verify(base64.b64decode(signature.value, validate=True), canonical_json_bytes(payload))
    except Exception:
        raise _execution_rejected() from None
    if payload.get("kind") != kind or any(payload.get(key) != value for key, value in binding.items()):
        raise _execution_rejected()


async def finalize_execution_evidence(**values: Any) -> dict[str, Any]:
    trusted_keyset_digest = values.get("trusted_keyset_digest")
    payload = _execution_binding_payload(values)
    containment_receipt = values.get("containment_receipt")
    stage_receipts = values.get("stage_receipts", [])
    if containment_receipt is not None:
        if trusted_keyset_digest is None:
            raise _execution_rejected()
        _verify_g008_authority_receipt(containment_receipt, kind="execution_containment", binding={**payload, "trusted_keyset_digest": trusted_keyset_digest, "state": "contained"})
        if len(stage_receipts) != 4:
            raise _execution_rejected()
        for ordinal, receipt in enumerate(stage_receipts, 1):
            _verify_g008_authority_receipt(receipt, kind="stage_status", binding={**payload, "trusted_keyset_digest": trusted_keyset_digest, "ordinal": ordinal, "state": "succeeded"})
    row = await _call(
        authority.db_client.finalize_execution_evidence,
        payload,
        evidence_builder=_build_execution_evidence,
    )
    if trusted_keyset_digest is None:
        return _execution_seal_receipt(row)
    signing_key = _load_g008_authority_signing_key(trusted_keyset_digest)
    return _signed_g008_authority_receipt(
        {"kind": "final_execution_evidence", **_execution_seal_receipt(row),
         "trusted_keyset_digest": trusted_keyset_digest, "containment_verified": True,
         "stage_receipts": stage_receipts, "containment_receipt": containment_receipt},
        key=signing_key,
    )


async def contain_execution(**values: Any) -> dict[str, Any]:
    trusted_keyset_digest = values.get("trusted_keyset_digest")
    payload = _execution_binding_payload(values)
    payload["containment_class"] = values["containment_class"]
    row = await _call(
        authority.db_client.contain_execution,
        payload,
        evidence_builder=_build_execution_evidence,
    )
    if trusted_keyset_digest is None:
        return _execution_seal_receipt(row)
    signing_key = _load_g008_authority_signing_key(trusted_keyset_digest)
    return _signed_g008_authority_receipt(
        {"kind": "execution_containment", **_execution_seal_receipt(row),
         "trusted_keyset_digest": trusted_keyset_digest},
        key=signing_key,
    )

async def claim_reserved_inbound_and_bind(**values: Any) -> dict[str, Any]:
    if set(values) != {
        "organization_id",
        "account_uuid",
        "application_uuid",
        "stock_call_uuid",
        "did_digest",
        "caller_digest",
    }:
        raise _execution_rejected()
    payload = {
        "organization_id": values["organization_id"],
        "account_uuid": str(values["account_uuid"]),
        "application_uuid": str(values["application_uuid"]),
        "stock_call_uuid": str(values["stock_call_uuid"]),
        "did_digest": values["did_digest"],
        "caller_digest": values["caller_digest"],
    }
    row = await _call(
        authority.db_client.claim_reserved_inbound_and_bind,
        payload,
        receipt_builder=_build_g008_inbound_bind_receipt,
    )
    signed_receipt = await _recover_g008_inbound_bind_receipt(row)
    return _inbound_claim_receipt(row, signed_receipt)
