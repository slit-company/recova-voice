"""Typed, provider-local contracts for the DB-less Jambonz facade."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    StringConstraints,
    field_validator,
    model_validator,
)

CONTRACT_VERSION = "recova-jambonz-facade-v1"
DISPATCH_VERIFICATION_DOMAIN = "recova.onnuri.smoke.dispatch.v1"
ROUTE_CHAIN_CAPABILITY_DOMAIN = "recova.onnuri.route-chain-capability.v1"

MEDIA_VERIFICATION_DOMAIN = "recova.onnuri.smoke.media.v1"
SIGNING_ALGORITHM = "ES256"
MEDIA_USERNAME = "recova-media"

Identifier = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]
IdempotencyKey = Annotated[str, StringConstraints(strip_whitespace=True, min_length=16, max_length=255)]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
OrganizationId = Annotated[int, Field(gt=0)]


class FacadeModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class Direction(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
StockCallStatus = Literal[
    "trying",
    "ringing",
    "early-media",
    "in-progress",
    "completed",
    "failed",
    "busy",
    "no-answer",
    "queued",
]



class CallStatus(StrEnum):
    ALLOCATED = "allocated"
    DISPATCH_CONSUMED = "dispatch_consumed"
    STOCK_REQUESTED = "stock_requested"
    STOCK_BOUND = "stock_bound"
    ANSWER_AUTHORITY_COMMITTED = "answer_authority_committed"
    MEDIA_ISSUED = "media_issued"
    MEDIA_CONSUMED = "media_consumed"
    RUNNING = "running"
    COMPLETED = "completed"
    BUSY = "busy"
    NO_ANSWER = "no_answer"
    FAILED = "failed"
    CANCELED = "canceled"
    CONTAINED = "contained"


class FailureCategory(StrEnum):
    AUTHENTICATION_REJECTED = "authentication_rejected"
    CONTRACT_MISMATCH = "contract_mismatch"
    EXPIRED = "expired"
    REPLAY = "replay"
    IDEMPOTENCY_MISMATCH = "idempotency_mismatch"
    AUTHORITY_UNAVAILABLE = "authority_unavailable"
    STOCK_REJECTED = "stock_rejected"
    STOCK_UNAVAILABLE = "stock_unavailable"
    INVALID_STOCK_EVENT = "invalid_stock_event"
    CONTAINMENT_REQUIRED = "containment_required"


class BoundCallContext(FacadeModel):
    contract_version: Literal["recova-jambonz-facade-v1"] = CONTRACT_VERSION
    organization_id: OrganizationId
    account_id: Identifier
    application_id: Identifier
    run_id: Identifier
    attempt_id: Identifier
    direction: Direction
    stock_call_id: Identifier | None = None
    authority_deadline: datetime
    candidate_digest: Digest
    gate_envelope_digest: Digest

    @field_validator("authority_deadline")
    @classmethod
    def require_aware_deadline(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("authority_deadline must be timezone-aware")
        return value.astimezone(timezone.utc)


class SignedCapability(FacadeModel):
    contract_version: Literal["recova-jambonz-facade-v1"] = CONTRACT_VERSION
    verification_domain: Literal["recova.onnuri.smoke.dispatch.v1"] = DISPATCH_VERIFICATION_DOMAIN
    key_id: Identifier
    algorithm: Literal["ES256"] = SIGNING_ALGORITHM
    issued_at: datetime
    expires_at: datetime
    nonce: Identifier
    claims: dict[str, Any]
    signature: SecretStr

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("capability times must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def require_positive_lifetime(self) -> SignedCapability:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be later than issued_at")
        return self

class RouteChainCapabilityRequest(FacadeModel):
    """Opaque F12-owned route evidence request; raw evidence never enters the facade."""

    context: BoundCallContext
    idempotency_key: IdempotencyKey
    request_digest: Digest
    route_profile_digest: Digest
    route_evidence_handle: Identifier

    @field_validator("route_evidence_handle")
    @classmethod
    def require_opaque_handle(cls, value: str) -> str:
        if re.fullmatch(r"[0-9a-f]{64}", value) or re.fullmatch(
            r"[0-9a-f]{64}", value.lower()
        ):
            raise ValueError("route evidence handle must not be a digest")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._~-]{15,254}", value) is None:
            raise ValueError("route evidence handle is malformed")
        return value



class RouteChainCapability(FacadeModel):
    """F12-signed route-chain authorization with a distinct cryptographic domain."""

    contract_version: Literal["recova-jambonz-facade-v1"] = CONTRACT_VERSION
    verification_domain: Literal["recova.onnuri.route-chain-capability.v1"] = ROUTE_CHAIN_CAPABILITY_DOMAIN
    key_id: Identifier
    algorithm: Literal["ES256"] = SIGNING_ALGORITHM
    issued_at: datetime
    expires_at: datetime
    nonce: Identifier
    claims: dict[str, Any]
    signature: SecretStr

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("capability times must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def require_bounded_lifetime(self) -> RouteChainCapability:
        lifetime = (self.expires_at - self.issued_at).total_seconds()
        if not 1 <= lifetime <= 60:
            raise ValueError("route capability lifetime must be between one and sixty seconds")
        return self


class DispatchSubmission(FacadeModel):
    context: BoundCallContext
    idempotency_key: IdempotencyKey
    request_digest: Digest
    capability: SignedCapability | RouteChainCapability


class DispatchConsumeReceipt(FacadeModel):
    context: BoundCallContext
    idempotency_key: IdempotencyKey
    request_digest: Digest
    receipt_id: Identifier
    consumed_at: datetime
    dispatch_key_id: Identifier
    verification_domain: Literal["recova.onnuri.smoke.dispatch.v1"] = DISPATCH_VERIFICATION_DOMAIN
    signature: SecretStr

    @field_validator("consumed_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("consumed_at must be timezone-aware")
        return value.astimezone(timezone.utc)


class OuterCallCreateRequest(FacadeModel):
    contract_version: Literal["recova-jambonz-facade-v1"] = CONTRACT_VERSION
    organization_id: OrganizationId
    application_id: Identifier
    run_id: Identifier
    attempt_id: Identifier
    direction: Literal[Direction.OUTBOUND] = Direction.OUTBOUND
    authority_deadline: datetime
    idempotency_key: IdempotencyKey
    candidate_digest: Digest
    gate_envelope_digest: Digest
    dispatch_capability: SignedCapability | None = None
    from_address: SecretStr
    to_address: SecretStr
    answer_hook_url: str
    status_hook_url: str
    ring_timeout_seconds: Annotated[int, Field(ge=1, le=30)] = 30
    time_limit_seconds: Literal[60] = 60
    request_mode: Literal["legacy", "diagnostic"] = "legacy"
    route_profile_digest: Digest | None = None
    route_evidence_handle: Identifier | None = None

    @model_validator(mode="after")
    def require_exact_request_authority(self) -> OuterCallCreateRequest:
        has_diagnostic_authority = (
            self.route_profile_digest is not None
            and self.route_evidence_handle is not None
        )
        if self.request_mode == "diagnostic":
            if self.dispatch_capability is not None or not has_diagnostic_authority:
                raise ValueError("diagnostic requests require opaque route evidence only")
            RouteChainCapabilityRequest.model_validate(
                {
                    "context": {
                        "organization_id": self.organization_id,
                        "account_id": "opaque-diagnostic-binding",
                        "application_id": self.application_id,
                        "run_id": self.run_id,
                        "attempt_id": self.attempt_id,
                        "direction": "outbound",
                        "authority_deadline": self.authority_deadline,
                        "candidate_digest": self.candidate_digest,
                        "gate_envelope_digest": self.gate_envelope_digest,
                    },
                    "idempotency_key": self.idempotency_key,
                    "request_digest": "0" * 64,
                    "route_profile_digest": self.route_profile_digest,
                    "route_evidence_handle": self.route_evidence_handle,
                }
            )
        elif self.dispatch_capability is None or has_diagnostic_authority:
            raise ValueError("legacy requests require dispatch capability only")
        return self

    @field_validator("authority_deadline")
    @classmethod
    def require_aware_deadline(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("authority_deadline must be timezone-aware")
        return value.astimezone(timezone.utc)


class StockCallCreateRequest(FacadeModel):
    context: BoundCallContext
    idempotency_key: IdempotencyKey
    dispatch_receipt_id: Identifier
    from_address: SecretStr
    to_address: SecretStr
    answer_hook_url: str
    status_hook_url: str
    ring_timeout_seconds: Annotated[int, Field(ge=1, le=30)]
    time_limit_seconds: Literal[60] = 60


class StockCallCreateResult(FacadeModel):
    organization_id: OrganizationId
    stock_call_id: Identifier
    stock_status: Identifier
    idempotency_key: IdempotencyKey
    request_digest: Digest


class StockCallBindRequest(FacadeModel):
    context: BoundCallContext
    stock_call_id: Identifier
    idempotency_key: IdempotencyKey
    request_digest: Digest
    dispatch_receipt_id: Identifier | None = None
    source_account_id: Identifier | None = None
    source_application_id: Identifier | None = None
    did_digest: Digest | None = None
    caller_mobile_digest: Digest | None = None
    candidate_digest: Digest | None = None
    @model_validator(mode="after")
    def require_direction_specific_authority(self) -> StockCallBindRequest:
        inbound_fields = (
            self.source_account_id,
            self.source_application_id,
            self.did_digest,
            self.caller_mobile_digest,
            self.candidate_digest,
        )
        if self.context.direction == Direction.INBOUND:
            if self.dispatch_receipt_id is not None or any(
                value is None for value in inbound_fields
            ):
                raise ValueError("inbound bind authority is incomplete")
            if self.source_account_id != self.context.account_id:
                raise ValueError("source account does not match bound context")
            if self.source_application_id != self.context.application_id:
                raise ValueError("source application does not match bound context")
        elif self.dispatch_receipt_id is None or any(
            value is not None for value in inbound_fields
        ):
            raise ValueError("outbound bind authority is incomplete")
        return self


class StockCallBindReceipt(FacadeModel):
    context: BoundCallContext
    stock_call_id: Identifier
    idempotency_key: IdempotencyKey
    request_digest: Digest
    bind_receipt_id: Identifier
    bound_at: datetime
    media_capability_issued: Literal[False] = False

    @field_validator("bound_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("bound_at must be timezone-aware")
        return value.astimezone(timezone.utc)


class OuterCallCreateResponse(FacadeModel):
    context: BoundCallContext
    stock_call_id: Identifier
    status: CallStatus
    dispatch_receipt_id: Identifier
    bind_receipt_id: Identifier
    idempotency_key: IdempotencyKey
    request_digest: Digest


class CallStatusResponse(FacadeModel):
    context: BoundCallContext
    status: CallStatus
    updated_at: datetime
    terminal: bool
    failure_category: FailureCategory | None = None
    idempotency_key: IdempotencyKey | None = Field(default=None, exclude=True)
    request_digest: Digest | None = Field(default=None, exclude=True)
    candidate_digest: Digest | None = Field(default=None, exclude=True)

    @field_validator("updated_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("updated_at must be timezone-aware")
        return value.astimezone(timezone.utc)


class AnswerAuthorityRequest(FacadeModel):
    organization_id: OrganizationId
    context: BoundCallContext
    stock_call_id: Identifier
    idempotency_key: IdempotencyKey
    request_digest: Digest
    event_nonce: Identifier
    observed_wall_time: datetime
    proposed_deadline: datetime
    candidate_digest: Digest

    @field_validator("observed_wall_time", "proposed_deadline")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("authority times must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def require_exact_binding_and_deadline(self) -> AnswerAuthorityRequest:
        if self.organization_id != self.context.organization_id:
            raise ValueError("organization_id must match bound context")
        if self.context.stock_call_id != self.stock_call_id:
            raise ValueError("stock_call_id must match bound context")
        if self.proposed_deadline != self.observed_wall_time + timedelta(seconds=60):
            raise ValueError("proposed_deadline must be exactly 60 seconds")
        return self


class MediaAuthorityReceipt(FacadeModel):
    context: BoundCallContext
    stock_call_id: Identifier
    idempotency_key: IdempotencyKey
    request_digest: Digest
    authority_receipt_id: Identifier
    committed_at: datetime
    authority_deadline: datetime
    media_verification_domain: Literal["recova.onnuri.smoke.media.v1"] = MEDIA_VERIFICATION_DOMAIN
    media_key_id: Identifier
    opaque_media_capability: SecretStr

    @field_validator("committed_at", "authority_deadline")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("authority times must be timezone-aware")
        return value.astimezone(timezone.utc)


class StockCallWebhook(FacadeModel):
    """Current public jambonz call-hook/call-status wire envelope."""

    call_sid: Identifier
    call_id: Identifier
    application_sid: Identifier
    account_sid: Identifier
    direction: Direction
    from_address: SecretStr = Field(alias="from")
    to_address: SecretStr = Field(alias="to")
    caller_name: str
    sip_status: Annotated[int, Field(ge=100, le=699)]
    sip_reason: str
    call_status: StockCallStatus
    parent_call_sid: Identifier | None = None
    sbc_callid: Identifier | None = None
    originating_sip_ip: str | None = None
    originating_sip_trunk_name: str | None = None
    local_sip_address: str | None = None
    service_provider_sid: Identifier | None = None
    trace_id: Identifier | None = None
    sip: dict[str, Any] | None = None
    env_vars: dict[str, Any] | None = None


class StockCdrWebhook(FacadeModel):
    """Public jambonz completed-call representation used as a CDR callback."""

    call_sid: Identifier
    call_status: StockCallStatus
    application_sid: Identifier
    account_sid: Identifier
    direction: Direction
    from_address: SecretStr = Field(alias="from")
    to_address: SecretStr = Field(alias="to")
    duration: Annotated[int, Field(ge=0, le=3600)]
    call_id: Identifier | None = None
    sip_status: Annotated[int, Field(ge=100, le=699)] | None = None
    sip_reason: str | None = None

class OutboundAnswerHookRequest(AnswerAuthorityRequest):
    direction: Literal[Direction.OUTBOUND] = Direction.OUTBOUND
    observed_answer: Literal[True] = True

    @model_validator(mode="after")
    def require_outbound_context(self) -> OutboundAnswerHookRequest:
        if self.context.direction != Direction.OUTBOUND:
            raise ValueError("outbound hook requires outbound context")
        return self


class InboundInitialHookRequest(AnswerAuthorityRequest):
    direction: Literal[Direction.INBOUND] = Direction.INBOUND
    source_account_id: Identifier
    source_application_id: Identifier
    did_digest: Digest
    caller_mobile_digest: Digest
    optional_pause_milliseconds: Literal[0] = 0

    @model_validator(mode="after")
    def require_inbound_context(self) -> InboundInitialHookRequest:
        if self.context.direction != Direction.INBOUND:
            raise ValueError("inbound hook requires inbound context")
        if self.source_account_id != self.context.account_id:
            raise ValueError("source account does not match bound context")
        if self.source_application_id != self.context.application_id:
            raise ValueError("source application does not match bound context")
        return self





class WsAuth(FacadeModel):
    username: Literal["recova-media"] = MEDIA_USERNAME
    password: SecretStr


class BidirectionalAudio(FacadeModel):
    enabled: Literal[True] = True
    streaming: Literal[True] = True
    sample_rate: Literal[8000] = Field(default=8000, serialization_alias="sampleRate")


class AnswerVerb(FacadeModel):
    verb: Literal["answer"] = "answer"



class ListenVerb(FacadeModel):
    verb: Literal["listen"] = "listen"
    url: str
    sample_rate: Literal[8000] = Field(default=8000, serialization_alias="sampleRate")
    mix_type: Literal["mono"] = Field(default="mono", serialization_alias="mixType")
    ws_auth: WsAuth = Field(serialization_alias="wsAuth")
    bidirectional_audio: BidirectionalAudio = Field(
        default_factory=BidirectionalAudio,
        serialization_alias="bidirectionalAudio",
    )


class HangupVerb(FacadeModel):
    verb: Literal["hangup"] = "hangup"


JambonzVerb = AnswerVerb | ListenVerb | HangupVerb


class HookResponse(FacadeModel):
    organization_id: OrganizationId
    verbs: tuple[JambonzVerb, ...]
    authority_receipt_id: Identifier | None = None
    idempotency_key: IdempotencyKey
    request_digest: Digest
    containment_requested: bool = False

    @model_validator(mode="after")
    def enforce_verb_safety(self) -> HookResponse:
        names = [verb.verb for verb in self.verbs]
        if "listen" in names and self.authority_receipt_id is None:
            raise ValueError("listen requires committed authority receipt")
        if self.containment_requested and ("answer" in names or "listen" in names):
            raise ValueError("containment response cannot answer or listen")
        return self


class StockEventType(StrEnum):
    STATUS = "status"
    CDR = "cdr"


class StockStatusEvent(FacadeModel):
    organization_id: OrganizationId
    context: BoundCallContext
    stock_call_id: Identifier
    status: Identifier
    event_time: datetime
    event_nonce: Identifier
    idempotency_key: IdempotencyKey
    request_digest: Digest
    duration_seconds: Annotated[int, Field(ge=0, le=3600)] | None = None
    failure_code: Identifier | None = None

    @field_validator("event_time")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event_time must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def require_bound_call(self) -> StockStatusEvent:
        if self.organization_id != self.context.organization_id:
            raise ValueError("organization_id must match bound context")
        if self.context.stock_call_id != self.stock_call_id:
            raise ValueError("stock_call_id must match bound context")
        return self


class StockCdrEvent(FacadeModel):
    organization_id: OrganizationId
    context: BoundCallContext
    stock_call_id: Identifier
    started_at: datetime
    answered_at: datetime | None = None
    ended_at: datetime
    event_nonce: Identifier
    idempotency_key: IdempotencyKey
    request_digest: Digest
    duration_seconds: Annotated[int, Field(ge=0, le=3600)]
    hangup_code: Identifier | None = None

    @field_validator("started_at", "answered_at", "ended_at")
    @classmethod
    def require_aware_time(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event times must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def require_bound_call_and_ordered_times(self) -> StockCdrEvent:
        if self.organization_id != self.context.organization_id:
            raise ValueError("organization_id must match bound context")
        if self.context.stock_call_id != self.stock_call_id:
            raise ValueError("stock_call_id must match bound context")
        if self.ended_at < self.started_at:
            raise ValueError("ended_at cannot precede started_at")
        if self.answered_at is not None and not (
            self.started_at <= self.answered_at <= self.ended_at
        ):
            raise ValueError("answered_at must be inside the call interval")
        return self


class NormalizedCallEvent(FacadeModel):
    organization_id: OrganizationId
    context: BoundCallContext
    stock_call_id: Identifier
    event_type: StockEventType
    normalized_status: CallStatus
    occurred_at: datetime
    event_nonce: Identifier
    idempotency_key: IdempotencyKey
    request_digest: Digest
    duration_seconds: int | None = None
    redacted_cause_category: FailureCategory | None = None

    @field_validator("occurred_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def require_exact_binding(self) -> NormalizedCallEvent:
        if self.organization_id != self.context.organization_id:
            raise ValueError("organization_id must match bound context")
        if self.stock_call_id != self.context.stock_call_id:
            raise ValueError("stock_call_id must match bound context")
        return self


class CallbackReceipt(FacadeModel):
    organization_id: OrganizationId
    event_nonce: Identifier
    idempotency_key: IdempotencyKey
    request_digest: Digest
    accepted_at: datetime
    status: CallStatus

    @field_validator("accepted_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("accepted_at must be timezone-aware")
        return value.astimezone(timezone.utc)


class ContainmentRequest(FacadeModel):
    organization_id: OrganizationId
    context: BoundCallContext
    stock_call_id: Identifier
    category: FailureCategory
    bounded_hangup_seconds: Annotated[int, Field(ge=1, le=5)] = 5

    @model_validator(mode="after")
    def require_exact_binding(self) -> ContainmentRequest:
        if self.organization_id != self.context.organization_id:
            raise ValueError("organization_id must match bound context")
        if self.stock_call_id != self.context.stock_call_id:
            raise ValueError("stock_call_id must match bound context")
        return self


class RedactedEvent(FacadeModel):
    category: FailureCategory
    operation: Literal[
        "create",
        "bind",
        "outbound_answer",
        "inbound_initial",
        "status",
        "cdr",
        "containment",
    ]
    direction: Direction | None = None
    contract_version: Literal["recova-jambonz-facade-v1"] = CONTRACT_VERSION
