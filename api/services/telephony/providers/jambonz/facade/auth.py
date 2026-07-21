"""Pure verification boundaries for facade capabilities and signed receipts.

Key material resolution is deliberately supplied by the deployment layer. This
module performs no secret loading, network access, replay storage, or authority
consumption.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Protocol

from pydantic import BaseModel

from .models import (
    DISPATCH_VERIFICATION_DOMAIN,
    MEDIA_VERIFICATION_DOMAIN,
    ROUTE_CHAIN_CAPABILITY_DOMAIN,
    BoundCallContext,
    DispatchConsumeReceipt,
    DispatchSubmission,
    RouteChainCapability,
    RouteChainCapabilityRequest,
    SignedCapability,
)



class AuthenticationError(ValueError):
    """A fail-closed, safe-to-map authentication failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class SignatureVerifier(Protocol):
    """Verifies an ES256 signature with already-provisioned public key material."""

    def verify(
        self,
        *,
        key_id: str,
        algorithm: str,
        verification_domain: str,
        message: bytes,
        signature: str,
    ) -> bool: ...


class VerificationPolicy(BaseModel):
    """Immutable deployment policy; dispatch and media keys may never overlap."""

    dispatch_key_id: str
    media_key_id: str
    maximum_clock_skew_seconds: int = 30

    model_config = {"extra": "forbid", "frozen": True}

    def model_post_init(self, __context: object) -> None:
        if not self.dispatch_key_id or not self.media_key_id:
            raise ValueError("verification key IDs must be non-empty")
        if self.dispatch_key_id == self.media_key_id:
            raise ValueError("dispatch and media key IDs must be distinct")
        if not 0 <= self.maximum_clock_skew_seconds <= 300:
            raise ValueError("maximum clock skew must be between zero and 300 seconds")


class VerifiedDispatch(BaseModel):
    submission: DispatchSubmission
    capability_nonce: str

    model_config = {"extra": "forbid", "frozen": True}


def canonical_signing_bytes(model: BaseModel, *, exclude: set[str]) -> bytes:
    payload = model.model_dump(mode="json", exclude=exclude, exclude_none=True)
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def validate_key_domains(policy: VerificationPolicy) -> None:
    if policy.dispatch_key_id == policy.media_key_id:
        raise AuthenticationError("key_domain_confusion")


def validate_dispatch_capability(
    submission: DispatchSubmission,
    *,
    policy: VerificationPolicy,
    verifier: SignatureVerifier,
    now: datetime,
) -> VerifiedDispatch:
    """Validate dispatch authenticity and exact binding without consuming it."""

    validate_key_domains(policy)
    capability = submission.capability
    now = _aware_utc(now)
    skew = timedelta(seconds=policy.maximum_clock_skew_seconds)

    if capability.verification_domain != DISPATCH_VERIFICATION_DOMAIN:
        raise AuthenticationError("wrong_verification_domain")
    if capability.key_id != policy.dispatch_key_id:
        raise AuthenticationError("wrong_dispatch_key")
    if capability.key_id == policy.media_key_id:
        raise AuthenticationError("key_domain_confusion")
    if capability.algorithm != "ES256":
        raise AuthenticationError("unsupported_algorithm")
    if capability.issued_at > now + skew:
        raise AuthenticationError("not_yet_valid")
    if capability.expires_at <= now - skew:
        raise AuthenticationError("expired")
    if capability.expires_at > submission.context.authority_deadline + skew:
        raise AuthenticationError("capability_exceeds_authority_deadline")

    expected_claims = {
        "organization_id": submission.context.organization_id,
        "account_id": submission.context.account_id,
        "application_id": submission.context.application_id,
        "run_id": submission.context.run_id,
        "attempt_id": submission.context.attempt_id,
        "direction": submission.context.direction.value,
        "authority_deadline": submission.context.authority_deadline.isoformat(),
        "idempotency_key": submission.idempotency_key,
        "request_digest": submission.request_digest,
        "candidate_digest": submission.context.candidate_digest,
        "gate_envelope_digest": submission.context.gate_envelope_digest,
        "contract_version": submission.context.contract_version,
    }
    if capability.claims != expected_claims:
        raise AuthenticationError("claim_binding_mismatch")

    if not verifier.verify(
        key_id=capability.key_id,
        algorithm=capability.algorithm,
        verification_domain=capability.verification_domain,
        message=canonical_signing_bytes(capability, exclude={"signature"}),
        signature=capability.signature.get_secret_value(),
    ):
        raise AuthenticationError("invalid_signature")

    return VerifiedDispatch(
        submission=submission,
        capability_nonce=capability.nonce,
    )


def route_chain_capability_claims(
    request: RouteChainCapabilityRequest,
    *,
    provider_fact_packet_id: str,
    provider_fact_packet_sha256: str,
    route_decision_id: str,
    route_decision_sha256: str,
    route_conformance_id: str,
    route_conformance_sha256: str,
    adapter_entries_digest: str,
    keyset_sha256: str,
    revocations_sha256: str,
) -> dict[str, object]:
    """Return the only accepted dedicated route-capability claim projection."""
    context = request.context
    return {
        "organization_id": context.organization_id,
        "account_id": context.account_id,
        "application_id": context.application_id,
        "run_id": context.run_id,
        "attempt_id": context.attempt_id,
        "direction": context.direction.value,
        "authority_deadline": context.authority_deadline.isoformat(),
        "idempotency_key": request.idempotency_key,
        "request_digest": request.request_digest,
        "candidate_digest": context.candidate_digest,
        "gate_envelope_digest": context.gate_envelope_digest,
        "contract_version": context.contract_version,
        "route_profile_digest": request.route_profile_digest,
        "provider_fact_packet_id": provider_fact_packet_id,
        "provider_fact_packet_sha256": provider_fact_packet_sha256,
        "route_decision_id": route_decision_id,
        "route_decision_sha256": route_decision_sha256,
        "route_conformance_id": route_conformance_id,
        "route_conformance_sha256": route_conformance_sha256,
        "adapter_entries_digest": adapter_entries_digest,
        "keyset_sha256": keyset_sha256,
        "revocations_sha256": revocations_sha256,
    }


def _route_chain_claims_from_capability(
    request: RouteChainCapabilityRequest, claims: dict[str, object]
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
        raise AuthenticationError("route_claim_binding_mismatch")
    if any(
        not isinstance(claims.get(name), str)
        or len(claims[name]) != 64
        or any(char not in "0123456789abcdef" for char in claims[name])
        for name in digests
    ):
        raise AuthenticationError("route_claim_binding_mismatch")
    return route_chain_capability_claims(
        request,
        **{name: claims[name] for name in (*identifiers, *digests)},
    )  # type: ignore[arg-type]


def validate_route_chain_capability(
    capability: RouteChainCapability,
    request: RouteChainCapabilityRequest,
    *,
    policy: VerificationPolicy,
    verifier: SignatureVerifier,
    now: datetime,
) -> None:
    """Validate opaque route authority without raw route facts at the facade."""
    validate_key_domains(policy)
    skew = timedelta(seconds=policy.maximum_clock_skew_seconds)
    now = _aware_utc(now)
    if capability.verification_domain != ROUTE_CHAIN_CAPABILITY_DOMAIN:
        raise AuthenticationError("wrong_route_verification_domain")
    if capability.key_id != policy.dispatch_key_id or capability.key_id == policy.media_key_id:
        raise AuthenticationError("wrong_route_key")
    if capability.algorithm != "ES256":
        raise AuthenticationError("unsupported_algorithm")
    if capability.issued_at > now + skew or capability.expires_at <= now - skew:
        raise AuthenticationError("route_capability_expired")
    if capability.expires_at > request.context.authority_deadline + skew:
        raise AuthenticationError("capability_exceeds_authority_deadline")
    if capability.claims != _route_chain_claims_from_capability(request, capability.claims):
        raise AuthenticationError("route_claim_binding_mismatch")
    if not verifier.verify(
        key_id=capability.key_id,
        algorithm=capability.algorithm,
        verification_domain=capability.verification_domain,
        message=canonical_signing_bytes(capability, exclude={"signature"}),
        signature=capability.signature.get_secret_value(),
    ):
        raise AuthenticationError("invalid_route_signature")


def validate_dispatch_receipt(
    receipt: DispatchConsumeReceipt,
    submission: DispatchSubmission,
    *,
    policy: VerificationPolicy,
    verifier: SignatureVerifier,
) -> None:
    """Validate that F12 committed this exact dispatch before stock creation."""

    validate_key_domains(policy)
    if receipt.verification_domain != DISPATCH_VERIFICATION_DOMAIN:
        raise AuthenticationError("wrong_receipt_domain")
    if receipt.dispatch_key_id != policy.dispatch_key_id:
        raise AuthenticationError("wrong_receipt_key")
    if receipt.dispatch_key_id == policy.media_key_id:
        raise AuthenticationError("key_domain_confusion")
    if receipt.context != submission.context:
        raise AuthenticationError("receipt_context_mismatch")
    if receipt.idempotency_key != submission.idempotency_key:
        raise AuthenticationError("receipt_idempotency_mismatch")
    if receipt.request_digest != submission.request_digest:
        raise AuthenticationError("receipt_digest_mismatch")
    if not verifier.verify(
        key_id=receipt.dispatch_key_id,
        algorithm="ES256",
        verification_domain=receipt.verification_domain,
        message=canonical_signing_bytes(receipt, exclude={"signature"}),
        signature=receipt.signature.get_secret_value(),
    ):
        raise AuthenticationError("invalid_receipt_signature")


def validate_media_receipt_domain(
    *,
    media_key_id: str,
    media_verification_domain: str,
    policy: VerificationPolicy,
) -> None:
    """Check F12 response metadata while keeping the media token opaque."""

    validate_key_domains(policy)
    if media_verification_domain != MEDIA_VERIFICATION_DOMAIN:
        raise AuthenticationError("wrong_media_domain")
    if media_key_id != policy.media_key_id:
        raise AuthenticationError("wrong_media_key")
    if media_key_id == policy.dispatch_key_id:
        raise AuthenticationError("key_domain_confusion")


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise AuthenticationError("naive_clock")
    return value.astimezone(timezone.utc)
