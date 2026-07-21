"""Backend-only capability contracts for the Onnuri smoke authority.

G001 deliberately provides no signer or recovery cipher. Production therefore
fails closed until a later gate injects implementations bound to PostgreSQL's
immutable envelope policy.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Mapping, Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pydantic import ValidationError

from api.services.telephony.onnuri_preflight_policy import (
    DISPATCH_CAPABILITY_DOMAIN,
    MEDIA_CAPABILITY_DOMAIN,
)
from api.services.telephony.providers.jambonz.facade.auth import canonical_signing_bytes
from api.services.telephony.providers.jambonz.facade.models import (
    CONTRACT_VERSION,
    ROUTE_CHAIN_CAPABILITY_DOMAIN,
    RouteChainCapability,
    SIGNING_ALGORITHM,
    SignedCapability,
)


ECDSA_P256_SHA256_POLICY_ID = "gcp-kms-ecdsa-p256-sha256-v1"
EXECUTION_EVIDENCE_DOMAIN = "recova.onnuri.smoke.g008.execution-evidence.v1"
MAX_CAPABILITY_SECONDS = 60
CapabilityKind = Literal["dispatch", "media"]
_RUNTIME_ENV = {
    "dispatch_private_key": "ONNURI_SMOKE_DISPATCH_PRIVATE_KEY_FILE",
    "dispatch_public_key": "ONNURI_SMOKE_DISPATCH_PUBLIC_KEY_FILE",
    "dispatch_key_id": "ONNURI_SMOKE_DISPATCH_KEY_ID",
    "media_private_key": "ONNURI_SMOKE_MEDIA_PRIVATE_KEY_FILE",
    "media_public_key": "ONNURI_SMOKE_MEDIA_PUBLIC_KEY_FILE",
    "media_key_id": "ONNURI_SMOKE_MEDIA_KEY_ID",
    "execution_evidence_private_key": "ONNURI_SMOKE_EXECUTION_EVIDENCE_PRIVATE_KEY_FILE",
    "execution_evidence_public_key": "ONNURI_SMOKE_EXECUTION_EVIDENCE_PUBLIC_KEY_FILE",
    "execution_evidence_key_id": "ONNURI_SMOKE_EXECUTION_EVIDENCE_KEY_ID",
    "recovery_key": "ONNURI_SMOKE_RECOVERY_KEY_FILE",
}
_RECOVERY_VERSION = 1
_RECOVERY_AAD_PREFIX = b"recova.onnuri.smoke.recovery.v1:"


class SmokeCapabilityUnavailableError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("onnuri_smoke_capability_backend_unavailable")


class SmokeCapabilityInvalidError(ValueError):
    def __init__(self) -> None:
        super().__init__("onnuri_smoke_capability_material_invalid")


@dataclass(frozen=True)
class CapabilityPolicy:
    kind: CapabilityKind
    verification_domain: str
    key_id: str
    other_key_id: str
    algorithm_policy_id: str = ECDSA_P256_SHA256_POLICY_ID


@dataclass(frozen=True)
class CapabilityBinding:
    """Exact facade claims plus callback binding facts; never authority outputs."""

    organization_id: int
    account_id: str
    application_id: str
    run_id: str
    attempt_id: str
    direction: Literal["outbound", "inbound"]
    idempotency_key: str
    request_digest: str
    candidate_digest: str
    gate_envelope_digest: str
    stock_call_id: str | None = None
    callback_event_nonce: str | None = None
    observed_event_wall_time: datetime | None = None

    def claims(self, *, authority_deadline: datetime) -> dict[str, Any]:
        claims: dict[str, Any] = {
            "organization_id": self.organization_id,
            "account_id": self.account_id,
            "application_id": self.application_id,
            "run_id": self.run_id,
            "attempt_id": self.attempt_id,
            "direction": self.direction,
            "authority_deadline": authority_deadline.isoformat(),
            "idempotency_key": self.idempotency_key,
            "request_digest": self.request_digest,
            "candidate_digest": self.candidate_digest,
            "gate_envelope_digest": self.gate_envelope_digest,
            "contract_version": CONTRACT_VERSION,
        }
        if self.stock_call_id is not None:
            claims["stock_call_id"] = self.stock_call_id
        if self.callback_event_nonce is not None:
            claims["callback_event_nonce"] = self.callback_event_nonce
        if self.observed_event_wall_time is not None:
            claims["observed_event_wall_time"] = self.observed_event_wall_time.isoformat()
        return claims


@dataclass(frozen=True)
class CapabilityIssueRequest:
    """Authority inputs fixed by the locked envelope and database clock."""

    binding: CapabilityBinding
    policy: CapabilityPolicy
    issued_at: datetime
    expires_at: datetime
    gate_envelope_digest: str

    def __post_init__(self) -> None:
        if self.gate_envelope_digest != self.binding.gate_envelope_digest:
            raise SmokeCapabilityInvalidError()


@dataclass(frozen=True)
class IssuedCapability:
    """ES256 issuer output; secret material is repr-hidden."""

    policy: CapabilityPolicy
    issued_at: datetime
    expires_at: datetime
    nonce: str = field(repr=False)
    signature: str = field(repr=False)


@dataclass(frozen=True)
class VerifiedCapability:
    nonce_digest: str
    token_digest: str
    receipt_digest: str


@dataclass(frozen=True)
class SignedExecutionEvidence:
    """Transient ES256 result; detached verification material is persistence-safe."""

    signature: bytes = field(repr=False)
    key_id: str
    algorithm_policy_id: str
    public_key_digest: str


@runtime_checkable
class ExecutionEvidenceSigner(Protocol):
    def configuration_ready(self) -> bool: ...
    async def sign(self, canonical_evidence: bytes) -> SignedExecutionEvidence: ...


@runtime_checkable
class SmokeCapabilityIssuer(Protocol):
    async def issue_dispatch(self, request: CapabilityIssueRequest) -> IssuedCapability: ...
    async def issue_media(self, request: CapabilityIssueRequest) -> IssuedCapability: ...
    async def sign_dispatch_receipt(
        self, *, signing_bytes: bytes, policy: CapabilityPolicy
    ) -> str: ...
    async def verify(
        self,
        kind: CapabilityKind,
        opaque_capability: bytes,
        signing_bytes: bytes,
        signature: str,
        binding: CapabilityBinding,
    ) -> VerifiedCapability: ...


@runtime_checkable
class SmokeRecoverySealer(Protocol):
    async def seal(self, *, plaintext: bytes, expires_at: datetime) -> str: ...
    async def unseal(self, *, ciphertext: str) -> bytes: ...


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    try:
        encoded = value.encode("ascii")
        if b"=" in encoded:
            raise ValueError
        return base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise SmokeCapabilityInvalidError() from None


def _is_sha256_hex(value: str | None) -> bool:
    return bool(
        value
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _read_regular_file(path_value: str, *, error: str) -> bytes:
    path = Path(path_value)
    if not path_value or not path.is_file() or path.is_symlink():
        raise RuntimeError(error)
    try:
        return path.read_bytes()
    except OSError:
        raise RuntimeError(error) from None


class PrivatePemSmokeCapabilityIssuer:
    """Distinct local ES256 issuers loaded only from explicit PEM file references."""

    def __init__(
        self,
        *,
        dispatch_private_key_file: str,
        dispatch_public_key_file: str,
        dispatch_key_id: str,
        media_private_key_file: str,
        media_public_key_file: str,
        media_key_id: str,
    ) -> None:
        if (
            not dispatch_key_id
            or not media_key_id
            or dispatch_key_id == media_key_id
            or DISPATCH_CAPABILITY_DOMAIN == MEDIA_CAPABILITY_DOMAIN
        ):
            raise RuntimeError("onnuri_smoke_issuer_separation_invalid")
        self._key_ids = {"dispatch": dispatch_key_id, "media": media_key_id}
        self._domains = {
            "dispatch": DISPATCH_CAPABILITY_DOMAIN,
            "media": MEDIA_CAPABILITY_DOMAIN,
        }
        self._private_keys = {
            "dispatch": self._load_private(dispatch_private_key_file),
            "media": self._load_private(media_private_key_file),
        }
        self._public_keys = {
            "dispatch": self._load_public(dispatch_public_key_file),
            "media": self._load_public(media_public_key_file),
        }
        for kind in ("dispatch", "media"):
            if (
                self._private_keys[kind].public_key().public_numbers()
                != self._public_keys[kind].public_numbers()
            ):
                raise RuntimeError("onnuri_smoke_issuer_public_key_mismatch")
        if (
            self._public_keys["dispatch"].public_numbers()
            == self._public_keys["media"].public_numbers()
        ):
            raise RuntimeError("onnuri_smoke_issuer_key_reuse_invalid")

    @staticmethod
    def _load_private(path: str) -> ec.EllipticCurvePrivateKey:
        try:
            value = serialization.load_pem_private_key(
                _read_regular_file(path, error="onnuri_smoke_private_key_file_invalid"),
                password=None,
            )
        except (TypeError, ValueError):
            raise RuntimeError("onnuri_smoke_private_key_file_invalid") from None
        if not isinstance(value, ec.EllipticCurvePrivateKey) or not isinstance(
            value.curve, ec.SECP256R1
        ):
            raise RuntimeError("onnuri_smoke_private_key_file_invalid")
        return value

    @staticmethod
    def _load_public(path: str) -> ec.EllipticCurvePublicKey:
        try:
            value = serialization.load_pem_public_key(
                _read_regular_file(path, error="onnuri_smoke_public_key_file_invalid")
            )
        except (TypeError, ValueError):
            raise RuntimeError("onnuri_smoke_public_key_file_invalid") from None
        if not isinstance(value, ec.EllipticCurvePublicKey) or not isinstance(
            value.curve, ec.SECP256R1
        ):
            raise RuntimeError("onnuri_smoke_public_key_file_invalid")
        return value


    def configuration_ready(self) -> bool:
        return (
            self._key_ids["dispatch"] != self._key_ids["media"]
            and self._domains["dispatch"] != self._domains["media"]
            and self._private_keys["dispatch"].public_key().public_numbers()
            == self._public_keys["dispatch"].public_numbers()
            and self._private_keys["media"].public_key().public_numbers()
            == self._public_keys["media"].public_numbers()
        )

    def key_ids(self) -> frozenset[str]:
        return frozenset(self._key_ids.values())

    def public_key_digests(self) -> frozenset[str]:
        return frozenset(
            _public_key_digest(key) for key in self._public_keys.values()
        )

    def _validate_request(
        self, kind: CapabilityKind, request: CapabilityIssueRequest
    ) -> None:
        expected_other = "media" if kind == "dispatch" else "dispatch"
        if (
            request.policy.kind != kind
            or request.policy.verification_domain != self._domains[kind]
            or request.policy.key_id != self._key_ids[kind]
            or request.policy.other_key_id != self._key_ids[expected_other]
            or not _is_sha256_hex(request.binding.candidate_digest)
            or not _is_sha256_hex(request.binding.gate_envelope_digest)
            or not _is_sha256_hex(request.binding.request_digest)
            or not _is_sha256_hex(request.gate_envelope_digest)
            or request.gate_envelope_digest != request.binding.gate_envelope_digest
        ):
            raise SmokeCapabilityInvalidError()

    def _sign(self, kind: CapabilityKind, value: bytes) -> str:
        der = self._private_keys[kind].sign(value, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    async def _issue(
        self, kind: CapabilityKind, request: CapabilityIssueRequest
    ) -> IssuedCapability:
        self._validate_request(kind, request)
        unsigned = IssuedCapability(
            policy=request.policy,
            issued_at=request.issued_at,
            expires_at=request.expires_at,
            nonce=secrets.token_urlsafe(32),
            signature="unsigned",
        )
        _, signing_bytes = signed_capability_bytes(unsigned, request)
        return IssuedCapability(
            policy=request.policy,
            issued_at=request.issued_at,
            expires_at=request.expires_at,
            nonce=unsigned.nonce,
            signature=self._sign(kind, signing_bytes),
        )

    async def issue_dispatch(self, request: CapabilityIssueRequest) -> IssuedCapability:
        return await self._issue("dispatch", request)

    async def issue_media(self, request: CapabilityIssueRequest) -> IssuedCapability:
        return await self._issue("media", request)

    async def sign_dispatch_receipt(
        self, *, signing_bytes: bytes, policy: CapabilityPolicy
    ) -> str:
        if (
            policy.kind != "dispatch"
            or policy.key_id != self._key_ids["dispatch"]
            or policy.other_key_id != self._key_ids["media"]
            or policy.verification_domain != self._domains["dispatch"]
        ):
            raise SmokeCapabilityInvalidError()
        return self._sign("dispatch", signing_bytes)

    async def verify(
        self,
        kind: CapabilityKind,
        opaque_capability: bytes,
        signing_bytes: bytes,
        signature: str,
        binding: CapabilityBinding,
    ) -> VerifiedCapability:
        if kind == "dispatch" and json.loads(opaque_capability).get("verification_domain") == ROUTE_CHAIN_CAPABILITY_DOMAIN:
            parsed: Any = parse_route_chain_capability(opaque_capability)
        else:
            parsed = parse_dispatch_capability(opaque_capability) if kind == "dispatch" else parse_media_capability(opaque_capability)

        parsed_signature = parsed.signature.get_secret_value() if kind == "dispatch" else parsed["signature"]
        claims = parsed.claims if kind == "dispatch" else parsed["claims"]
        expires_at = parsed.expires_at if kind == "dispatch" else datetime.fromisoformat(parsed["expires_at"].replace("Z", "+00:00"))
        key_id = parsed.key_id if kind == "dispatch" else parsed["key_id"]
        issued_at = parsed.issued_at if kind == "dispatch" else datetime.fromisoformat(parsed["issued_at"].replace("Z", "+00:00"))
        expected_signing_bytes = canonical_signing_bytes(parsed, exclude={"signature"}) if isinstance(parsed, RouteChainCapability) else opaque_signing_bytes(opaque_capability, kind=kind)
        if (
            key_id != self._key_ids[kind]
            or signature != parsed_signature
            or signing_bytes != expected_signing_bytes
            or claims != binding.claims(authority_deadline=expires_at)
            or issued_at.astimezone(UTC) > datetime.now(UTC)
            or datetime.now(UTC) >= expires_at.astimezone(UTC)
        ):
            raise SmokeCapabilityInvalidError()
        raw = _b64url_decode(signature)
        if len(raw) != 64:
            raise SmokeCapabilityInvalidError()
        try:
            self._public_keys[kind].verify(
                encode_dss_signature(
                    int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
                ),
                signing_bytes,
                ec.ECDSA(hashes.SHA256()),
            )
        except (InvalidSignature, ValueError):
            raise SmokeCapabilityInvalidError() from None
        return VerifiedCapability(
            nonce_digest=sha256_hex(parsed.nonce if kind == "dispatch" else parsed["nonce"]),
            token_digest=sha256_hex(opaque_capability),
            receipt_digest=sha256_hex(signature),
        )


def _public_key_digest(key: ec.EllipticCurvePublicKey) -> str:
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_hex(der)


class PrivatePemExecutionEvidenceSigner:
    """Dedicated ES256 signer isolated from dispatch and media key identities."""

    def __init__(
        self,
        *,
        private_key_file: str,
        public_key_file: str,
        key_id: str,
        forbidden_key_ids: frozenset[str],
        forbidden_public_key_digests: frozenset[str],
    ) -> None:
        self._private_key = PrivatePemSmokeCapabilityIssuer._load_private(
            private_key_file
        )
        self._public_key = PrivatePemSmokeCapabilityIssuer._load_public(
            public_key_file
        )
        self._key_id = key_id
        self._public_key_digest = _public_key_digest(self._public_key)
        self._forbidden_key_ids = forbidden_key_ids
        self._forbidden_public_key_digests = forbidden_public_key_digests
        if (
            not key_id
            or key_id in forbidden_key_ids
            or self._public_key_digest in forbidden_public_key_digests
            or self._private_key.public_key().public_numbers()
            != self._public_key.public_numbers()
        ):
            raise RuntimeError(
                "onnuri_smoke_execution_evidence_signer_separation_invalid"
            )

    def configuration_ready(self) -> bool:
        return (
            self._key_id not in self._forbidden_key_ids
            and self._public_key_digest not in self._forbidden_public_key_digests
            and self._private_key.public_key().public_numbers()
            == self._public_key.public_numbers()
        )

    def key_ids(self) -> frozenset[str]:
        return frozenset({self._key_id})

    def public_key_digests(self) -> frozenset[str]:
        return frozenset({self._public_key_digest})

    async def sign(self, canonical_evidence: bytes) -> SignedExecutionEvidence:
        if not canonical_evidence or not self.configuration_ready():
            raise SmokeCapabilityInvalidError()
        der_signature = self._private_key.sign(
            canonical_evidence, ec.ECDSA(hashes.SHA256())
        )
        r, s = decode_dss_signature(der_signature)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return SignedExecutionEvidence(
            signature=signature,
            key_id=self._key_id,
            algorithm_policy_id=ECDSA_P256_SHA256_POLICY_ID,
            public_key_digest=self._public_key_digest,
        )


class AesGcmSmokeRecoverySealer:
    """Authenticated, expiring recovery records backed by an explicit key file."""

    def __init__(self, *, key_file: str) -> None:
        raw = _read_regular_file(key_file, error="onnuri_smoke_recovery_key_file_invalid")
        try:
            key = raw if len(raw) == 32 else _b64url_decode(raw.decode("ascii").strip())
        except (SmokeCapabilityInvalidError, UnicodeDecodeError):
            raise RuntimeError("onnuri_smoke_recovery_key_file_invalid") from None
        if len(key) != 32:
            raise RuntimeError("onnuri_smoke_recovery_key_file_invalid")
        self._cipher = AESGCM(key)

    def configuration_ready(self) -> bool:
        return True

    async def seal(self, *, plaintext: bytes, expires_at: datetime) -> str:
        if expires_at.tzinfo is None or expires_at <= datetime.now(UTC):
            raise SmokeCapabilityInvalidError()
        expires = expires_at.astimezone(UTC).isoformat()
        nonce = secrets.token_bytes(12)
        aad = _RECOVERY_AAD_PREFIX + expires.encode("ascii")
        encrypted = self._cipher.encrypt(nonce, plaintext, aad)
        return _b64url(
            canonical_json_bytes(
                {
                    "ciphertext": _b64url(encrypted),
                    "expires_at": expires,
                    "nonce": _b64url(nonce),
                    "version": _RECOVERY_VERSION,
                }
            )
        )

    async def unseal(self, *, ciphertext: str) -> bytes:
        try:
            envelope = json.loads(_b64url_decode(ciphertext))
            if (
                not isinstance(envelope, dict)
                or set(envelope) != {"ciphertext", "expires_at", "nonce", "version"}
                or envelope["version"] != _RECOVERY_VERSION
            ):
                raise ValueError
            expires = datetime.fromisoformat(envelope["expires_at"])
            if expires.tzinfo is None or datetime.now(UTC) >= expires.astimezone(UTC):
                raise ValueError
            nonce = _b64url_decode(envelope["nonce"])
            encrypted = _b64url_decode(envelope["ciphertext"])
            if len(nonce) != 12:
                raise ValueError
            aad = _RECOVERY_AAD_PREFIX + envelope["expires_at"].encode("ascii")
            return self._cipher.decrypt(nonce, encrypted, aad)
        except (InvalidTag, KeyError, TypeError, ValueError, UnicodeDecodeError):
            raise SmokeCapabilityInvalidError() from None


class UnavailableSmokeCapabilityIssuer:
    async def issue_dispatch(self, request: CapabilityIssueRequest) -> IssuedCapability:
        raise SmokeCapabilityUnavailableError()

    async def issue_media(self, request: CapabilityIssueRequest) -> IssuedCapability:
        raise SmokeCapabilityUnavailableError()

    async def sign_dispatch_receipt(
        self, *, signing_bytes: bytes, policy: CapabilityPolicy
    ) -> str:
        raise SmokeCapabilityUnavailableError()

    async def verify(
        self,
        kind: CapabilityKind,
        opaque_capability: bytes,
        signing_bytes: bytes,
        signature: str,
        binding: CapabilityBinding,
    ) -> VerifiedCapability:
        raise SmokeCapabilityUnavailableError()


class UnavailableExecutionEvidenceSigner:
    def configuration_ready(self) -> bool:
        return False

    def key_ids(self) -> frozenset[str]:
        return frozenset()

    def public_key_digests(self) -> frozenset[str]:
        return frozenset()

    async def sign(self, canonical_evidence: bytes) -> SignedExecutionEvidence:
        del canonical_evidence
        raise SmokeCapabilityUnavailableError()


class UnavailableSmokeRecoverySealer:
    async def seal(self, *, plaintext: bytes, expires_at: datetime) -> str:
        raise SmokeCapabilityUnavailableError()

    async def unseal(self, *, ciphertext: str) -> bytes:
        raise SmokeCapabilityUnavailableError()


UNAVAILABLE_ISSUER: SmokeCapabilityIssuer = UnavailableSmokeCapabilityIssuer()
UNAVAILABLE_EXECUTION_EVIDENCE_SIGNER: ExecutionEvidenceSigner = (
    UnavailableExecutionEvidenceSigner()
)
UNAVAILABLE_RECOVERY_SEALER: SmokeRecoverySealer = UnavailableSmokeRecoverySealer()
@dataclass(frozen=True)
class SmokeAuthorityRuntime:
    """Process-local authority dependencies; configuration performs no I/O."""

    issuer: SmokeCapabilityIssuer
    recovery_sealer: SmokeRecoverySealer
    execution_evidence_signer: ExecutionEvidenceSigner

    def configuration_ready(self) -> bool:
        issuer_ready = getattr(self.issuer, "configuration_ready", None)
        sealer_ready = getattr(self.recovery_sealer, "configuration_ready", None)
        evidence_signer_ready = getattr(
            self.execution_evidence_signer, "configuration_ready", None
        )
        return bool(
            callable(issuer_ready)
            and callable(sealer_ready)
            and callable(evidence_signer_ready)
            and issuer_ready()
            and sealer_ready()
            and evidence_signer_ready()
        )


_RUNTIME = SmokeAuthorityRuntime(
    issuer=UNAVAILABLE_ISSUER,
    recovery_sealer=UNAVAILABLE_RECOVERY_SEALER,
    execution_evidence_signer=UNAVAILABLE_EXECUTION_EVIDENCE_SIGNER,
)
_RUNTIME_CONFIGURED = False


def get_smoke_authority_runtime() -> SmokeAuthorityRuntime:
    return _RUNTIME


def configure_smoke_authority_runtime(
    *,
    issuer: SmokeCapabilityIssuer,
    recovery_sealer: SmokeRecoverySealer,
    execution_evidence_signer: ExecutionEvidenceSigner,
) -> SmokeAuthorityRuntime:
    """Install authority implementations exactly once in this process."""
    global _RUNTIME, _RUNTIME_CONFIGURED
    if _RUNTIME_CONFIGURED:
        raise RuntimeError("onnuri_smoke_authority_runtime_already_configured")
    if (
        not isinstance(issuer, SmokeCapabilityIssuer)
        or not isinstance(recovery_sealer, SmokeRecoverySealer)
        or not isinstance(execution_evidence_signer, ExecutionEvidenceSigner)
    ):
        raise TypeError("onnuri_smoke_authority_runtime_invalid")
    _RUNTIME = SmokeAuthorityRuntime(
        issuer=issuer,
        recovery_sealer=recovery_sealer,
        execution_evidence_signer=execution_evidence_signer,
    )
    _RUNTIME_CONFIGURED = True
    return _RUNTIME


def configure_smoke_authority_runtime_from_environment() -> SmokeAuthorityRuntime:
    """Load all authority material from explicit references or fail closed."""
    configured = {
        name: os.getenv(environment_name, "").strip()
        for name, environment_name in _RUNTIME_ENV.items()
    }
    missing = [
        _RUNTIME_ENV[name] for name, value in configured.items() if not value
    ]
    if missing:
        raise RuntimeError(
            "onnuri_smoke_authority_runtime_configuration_missing:"
            + ",".join(sorted(missing))
        )
    issuer = PrivatePemSmokeCapabilityIssuer(
        dispatch_private_key_file=configured["dispatch_private_key"],
        dispatch_public_key_file=configured["dispatch_public_key"],
        dispatch_key_id=configured["dispatch_key_id"],
        media_private_key_file=configured["media_private_key"],
        media_public_key_file=configured["media_public_key"],
        media_key_id=configured["media_key_id"],
    )
    evidence_signer = PrivatePemExecutionEvidenceSigner(
        private_key_file=configured["execution_evidence_private_key"],
        public_key_file=configured["execution_evidence_public_key"],
        key_id=configured["execution_evidence_key_id"],
        forbidden_key_ids=issuer.key_ids(),
        forbidden_public_key_digests=issuer.public_key_digests(),
    )
    sealer = AesGcmSmokeRecoverySealer(key_file=configured["recovery_key"])
    return configure_smoke_authority_runtime(
        issuer=issuer,
        recovery_sealer=sealer,
        execution_evidence_signer=evidence_signer,
    )


def reset_smoke_authority_runtime_for_tests() -> None:
    """Restore fail-closed defaults; intended only for test isolation."""
    global _RUNTIME, _RUNTIME_CONFIGURED
    _RUNTIME = SmokeAuthorityRuntime(
        issuer=UNAVAILABLE_ISSUER,
        recovery_sealer=UNAVAILABLE_RECOVERY_SEALER,
        execution_evidence_signer=UNAVAILABLE_EXECUTION_EVIDENCE_SIGNER,
    )
    _RUNTIME_CONFIGURED = False


def canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def sha256_hex(value: bytes | str) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def issued_digests(value: IssuedCapability, opaque: bytes) -> VerifiedCapability:
    """Derive persistence digests, including the capability signature audit digest."""
    return VerifiedCapability(
        nonce_digest=sha256_hex(value.nonce),
        token_digest=sha256_hex(opaque),
        receipt_digest=sha256_hex(value.signature),
    )


def _validate_issued(value: IssuedCapability, *, request: CapabilityIssueRequest) -> None:
    expected_domain = (
        DISPATCH_CAPABILITY_DOMAIN
        if request.policy.kind == "dispatch"
        else MEDIA_CAPABILITY_DOMAIN
    )
    duration = (value.expires_at - value.issued_at).total_seconds()
    if (
        value.policy != request.policy
        or value.issued_at != request.issued_at
        or value.expires_at != request.expires_at
        or value.policy.verification_domain != expected_domain
        or value.policy.key_id == value.policy.other_key_id
        or not value.policy.key_id
        or not value.policy.other_key_id
        or value.policy.algorithm_policy_id != ECDSA_P256_SHA256_POLICY_ID
        or not _is_sha256_hex(request.binding.request_digest)
        or not _is_sha256_hex(request.binding.candidate_digest)
        or not _is_sha256_hex(request.binding.gate_envelope_digest)
        or request.gate_envelope_digest != request.binding.gate_envelope_digest
        or value.issued_at.tzinfo is None
        or value.expires_at.tzinfo is None
        or not 1 <= duration <= MAX_CAPABILITY_SECONDS
        or not value.nonce
        or not value.signature
    ):
        raise SmokeCapabilityInvalidError()


def signed_capability_bytes(
    value: IssuedCapability, request: CapabilityIssueRequest
) -> tuple[bytes, bytes]:
    """Return exact wire JSON and the exact facade canonical ES256 signing bytes.

    Dispatch is validated by the facade's own ``SignedCapability`` model. Media
    intentionally uses the identical field shape with only the approved media
    verification domain changed; the backend/WSS verifier consumes this shape.
    """
    _validate_issued(value, request=request)
    payload = {
        "contract_version": CONTRACT_VERSION,
        "verification_domain": value.policy.verification_domain,
        "key_id": value.policy.key_id,
        "algorithm": SIGNING_ALGORITHM,
        "issued_at": value.issued_at.isoformat(),
        "expires_at": value.expires_at.isoformat(),
        "nonce": value.nonce,
        "claims": request.binding.claims(authority_deadline=value.expires_at),
        "signature": value.signature,
    }
    if value.policy.kind == "dispatch":
        try:
            facade_value = SignedCapability.model_validate(payload)
        except ValidationError as exc:
            raise SmokeCapabilityInvalidError() from exc
        wire_payload = facade_value.model_dump(
            mode="json", exclude={"signature"}, exclude_none=True
        )
        wire_payload["signature"] = value.signature
        wire = canonical_json_bytes(wire_payload)
    else:
        wire = canonical_json_bytes(payload)
    return wire, opaque_signing_bytes(wire, kind=value.policy.kind)


def parse_dispatch_capability(opaque: bytes) -> SignedCapability:
    """Parse the exact facade wire model; no alternate dispatch shape exists."""
    try:
        raw = json.loads(opaque)
        value = SignedCapability.model_validate(raw)
    except (ValidationError, ValueError, json.JSONDecodeError) as exc:
        raise SmokeCapabilityInvalidError() from exc
    if (value.expires_at - value.issued_at).total_seconds() > MAX_CAPABILITY_SECONDS:
        raise SmokeCapabilityInvalidError()
    canonical = value.model_dump(mode="json", exclude={"signature"}, exclude_none=True)
    canonical["signature"] = value.signature.get_secret_value()
    if canonical_json_bytes(canonical) != opaque:
        raise SmokeCapabilityInvalidError()
    return value


def parse_route_chain_capability(opaque: bytes) -> RouteChainCapability:
    """Parse the dedicated route-chain wire shape without accepting dispatch domain tokens."""
    try:
        raw = json.loads(opaque)
        value = RouteChainCapability.model_validate(raw)
    except (ValidationError, ValueError, json.JSONDecodeError) as exc:
        raise SmokeCapabilityInvalidError() from exc
    if (value.expires_at - value.issued_at).total_seconds() > MAX_CAPABILITY_SECONDS:
        raise SmokeCapabilityInvalidError()
    canonical = value.model_dump(mode="json", exclude={"signature"}, exclude_none=True)
    canonical["signature"] = value.signature.get_secret_value()
    if canonical_json_bytes(canonical) != opaque:
        raise SmokeCapabilityInvalidError()
    return value

def parse_media_capability(opaque: bytes) -> dict[str, Any]:
    """Parse the one documented media/WSS shape emitted by this module."""
    try:
        raw = json.loads(opaque)
    except (ValueError, json.JSONDecodeError) as exc:
        raise SmokeCapabilityInvalidError() from exc
    required = {
        "contract_version",
        "verification_domain",
        "key_id",
        "algorithm",
        "issued_at",
        "expires_at",
        "nonce",
        "claims",
        "signature",
    }
    if (
        not isinstance(raw, dict)
        or set(raw) != required
        or raw["contract_version"] != CONTRACT_VERSION
        or raw["verification_domain"] != MEDIA_CAPABILITY_DOMAIN
        or raw["algorithm"] != SIGNING_ALGORITHM
        or not isinstance(raw["claims"], dict)
        or canonical_json_bytes(raw) != opaque
    ):
        raise SmokeCapabilityInvalidError()
    try:
        issued_at = datetime.fromisoformat(raw["issued_at"].replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(raw["expires_at"].replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise SmokeCapabilityInvalidError() from exc
    if (
        issued_at.tzinfo is None
        or expires_at.tzinfo is None
        or not 1 <= (expires_at - issued_at).total_seconds() <= MAX_CAPABILITY_SECONDS
    ):
        raise SmokeCapabilityInvalidError()
    return raw


def opaque_signing_bytes(opaque: bytes, *, kind: CapabilityKind) -> bytes:
    """Canonical verifier input shared with issuer serialization."""
    if kind == "dispatch":
        value = parse_dispatch_capability(opaque)
        return canonical_signing_bytes(value, exclude={"signature"})
    value = parse_media_capability(opaque)
    return canonical_json_bytes({key: value[key] for key in value if key != "signature"})
