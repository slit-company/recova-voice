"""Strict, secret-redacted contracts for the internal Onnuri F12 API."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

from api.services.telephony.providers.jambonz.facade.models import (
    BoundCallContext,
    CallStatus,
    DispatchConsumeReceipt,
    FailureCategory,
    MediaAuthorityReceipt,
    StockCallBindReceipt,
    StockCallBindRequest,
    StockEventType,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


Digest = str
Identifier = str


def _canonical_uuid(value: object) -> object:
    if value is None:
        return value
    if isinstance(value, UUID):
        return value
    if not isinstance(value, str):
        raise ValueError("identifier must be a canonical UUID")
    try:
        parsed = UUID(value)
    except ValueError:
        raise ValueError("identifier must be a canonical UUID") from None
    if str(parsed) != value:
        raise ValueError("identifier must be a canonical UUID")
    return value


class ConsumeDispatchRequest(_StrictModel):
    organization_id: int = Field(gt=0)
    account_id: Identifier = Field(min_length=1, max_length=255)
    application_id: Identifier = Field(min_length=1, max_length=255)
    run_id: Identifier = Field(min_length=1, max_length=255)
    attempt_uuid: Identifier = Field(min_length=1, max_length=64)
    idempotency_key: Identifier = Field(min_length=16, max_length=255)
    request_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    opaque_capability: SecretStr = Field(min_length=1, max_length=16_384, repr=False)




class _MintMediaRequest(_StrictModel):
    organization_id: int = Field(gt=0)
    account_id: Identifier = Field(min_length=1, max_length=255)
    application_id: Identifier = Field(min_length=1, max_length=255)
    run_id: Identifier = Field(min_length=1, max_length=255)
    attempt_uuid: Identifier = Field(min_length=1, max_length=64)
    stock_call_id: Identifier = Field(min_length=1, max_length=255)
    idempotency_key: Identifier = Field(min_length=16, max_length=255)
    request_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    event_nonce: Identifier = Field(min_length=1, max_length=255)
    candidate_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    gate_envelope_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    observed_wall_time: datetime
    proposed_deadline: datetime

    @field_validator("observed_wall_time", "proposed_deadline")
    @classmethod
    def require_aware_authority_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("authority times must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def require_exact_deadline(self) -> _MintMediaRequest:
        if self.proposed_deadline != self.observed_wall_time + timedelta(seconds=60):
            raise ValueError("proposed_deadline must be exactly 60 seconds")
        return self


class RecordAnswerAndMintMediaRequest(_MintMediaRequest):
    observed_answer: Literal[True] = True



class CommitInboundAnswerIntentAndMintMediaRequest(_MintMediaRequest):
    source_account_id: Identifier = Field(min_length=1, max_length=255)
    source_application_id: Identifier = Field(min_length=1, max_length=255)
    did_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    caller_mobile_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    approved_pause_milliseconds: int = Field(default=0, ge=0, le=5000)


class ConsumeMediaRequest(_StrictModel):
    organization_id: int = Field(gt=0)
    account_id: Identifier = Field(min_length=1, max_length=255)
    application_id: Identifier = Field(min_length=1, max_length=255)
    run_id: Identifier = Field(min_length=1, max_length=255)
    attempt_uuid: Identifier = Field(min_length=1, max_length=64)
    stock_call_id: Identifier = Field(min_length=1, max_length=255)
    idempotency_key: Identifier = Field(min_length=16, max_length=255)
    request_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    direction: Literal["outbound", "inbound"]
    opaque_capability: SecretStr = Field(min_length=1, max_length=16_384, repr=False)
    event_nonce: Identifier = Field(min_length=1, max_length=255)
    candidate_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    gate_envelope_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    observed_wall_time: datetime | None = None

    @field_validator("observed_wall_time")
    @classmethod
    def require_aware_optional_wall_time(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_wall_time must be timezone-aware")
        return value.astimezone(timezone.utc)


class SetTerminalRequest(_StrictModel):
    organization_id: int = Field(gt=0)
    attempt_uuid: str = Field(min_length=1, max_length=64)
    terminal_class: str = Field(min_length=1, max_length=64)
    terminal_reason: str = Field(min_length=1, max_length=256)
    contain: bool = False


class FacadeAuthorityReadiness(_StrictModel):
    ready: bool


class FacadeBoundCallStatusRequest(_StrictModel):
    organization_id: int = Field(gt=0)
    account_id: Identifier = Field(min_length=1, max_length=255)
    stock_call_id_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")


class FacadeBoundCallStatusResponse(_StrictModel):
    context: BoundCallContext
    status: CallStatus
    idempotency_key: Identifier = Field(min_length=16, max_length=255)
    request_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    allocated_at: datetime
    stock_bound_at: datetime | None = None
    authority_deadline: datetime | None = None
    terminal_at: datetime | None = None
    contained_at: datetime | None = None


class AcceptFacadeCallbackRequest(_StrictModel):
    context: BoundCallContext
    event_nonce_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    idempotency_key: Identifier = Field(min_length=16, max_length=255)
    request_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    event_type: StockEventType
    normalized_status: CallStatus
    occurred_at: datetime
    duration_seconds: int | None = Field(default=None, ge=0, le=3600)
    redacted_cause_category: FailureCategory | None = None


class RequestFacadeContainment(_StrictModel):
    context: BoundCallContext
    category: FailureCategory

class ExecutionNonceConsumeRequest(_StrictModel):
    organization_id: int = Field(gt=0)
    execution_seal_uuid: UUID
    execution_nonce_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    gate_envelope_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_keyset_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("execution_seal_uuid", mode="before")
    @classmethod
    def require_canonical_uuid(cls, value: object) -> object:
        return _canonical_uuid(value)


class ExecutionNonceConsumePayload(ExecutionNonceConsumeRequest):
    kind: Literal["nonce_consumption"]
    state: Literal["consumed"]
    pre_existing: Literal[False]


class G008AuthoritySignature(_StrictModel):
    algorithm: Literal["Ed25519"]
    key_id: Literal["recova-g008-authority-v1"]
    value: str = Field(pattern=r"^[A-Za-z0-9+/]{86}==$", repr=False)


class ExecutionNonceConsumeReceipt(_StrictModel):
    payload: ExecutionNonceConsumePayload
    signature: G008AuthoritySignature

class G008AuthorityReceipt(_StrictModel):
    payload: dict[str, object]
    signature: G008AuthoritySignature



class EmergencyUnregisterRequest(_StrictModel):
    organization_id: int = Field(gt=0)
    envelope_uuid: UUID
    request_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    gate_envelope_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    nonce_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    execution_seal_uuid: UUID
    execution_nonce_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    execution_stage_uuid: UUID
    prior_register_gate_id: int = Field(gt=0)
    prior_register_operation_uuid: UUID

    @field_validator(
        "envelope_uuid",
        "execution_seal_uuid",
        "execution_stage_uuid",
        "prior_register_operation_uuid",
        mode="before",
    )
    @classmethod
    def require_canonical_uuid(cls, value: object) -> object:
        return _canonical_uuid(value)

class RegistrationBeginRequest(_StrictModel):
    organization_id: int = Field(gt=0)
    envelope_uuid: UUID
    operation_kind: Literal["register", "unregister"]
    request_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    gate_envelope_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    nonce_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    execution_seal_uuid: UUID
    execution_nonce_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    execution_stage_uuid: UUID
    execution_stage: Literal["register", "unregister"]
    execution_stage_ordinal: Literal[1, 4]
    prior_register_gate_id: int | None = Field(default=None, gt=0)
    prior_register_operation_uuid: UUID | None = None

    @field_validator(
        "envelope_uuid",
        "execution_seal_uuid",
        "execution_stage_uuid",
        "prior_register_operation_uuid",
        mode="before",
    )
    @classmethod
    def require_canonical_uuid(cls, value: object) -> object:
        return _canonical_uuid(value)

    @model_validator(mode="after")
    def require_exact_unregister_linkage(self) -> RegistrationBeginRequest:
        linked = (
            self.prior_register_gate_id is not None
            and self.prior_register_operation_uuid is not None
        )
        if (self.operation_kind == "unregister") != linked:
            raise ValueError("prior register identity is required only for unregister")
        expected_stage = (
            ("register", 1)
            if self.operation_kind == "register"
            else ("unregister", 4)
        )
        if (self.execution_stage, self.execution_stage_ordinal) != expected_stage:
            raise ValueError("execution stage must match registration operation")
        return self


class RegistrationAuthorization(_StrictModel):
    registration_gate_id: int = Field(gt=0)
    operation_uuid: UUID
    operation_kind: Literal["register", "unregister"]
    envelope_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    expires_at: datetime
    opaque_authorization: str = Field(
        min_length=1, max_length=16_384, repr=False
    )

class RegistrationConsumeRequest(_StrictModel):
    opaque_authorization: SecretStr = Field(
        min_length=1, max_length=16_384, repr=False
    )
    organization_id: int = Field(gt=0)
    registration_gate_id: int = Field(gt=0)
    operation_uuid: UUID
    operation_kind: Literal["register", "unregister"]
    request_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    gate_envelope_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    nonce_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    prior_register_gate_id: int | None = Field(default=None, gt=0)
    prior_register_operation_uuid: UUID | None = None

    @field_validator("operation_uuid", "prior_register_operation_uuid", mode="before")
    @classmethod
    def require_canonical_uuid(cls, value: object) -> object:
        return _canonical_uuid(value)

    @model_validator(mode="after")
    def require_exact_unregister_linkage(self) -> RegistrationConsumeRequest:
        linked = (
            self.prior_register_gate_id is not None
            and self.prior_register_operation_uuid is not None
        )
        if (self.operation_kind == "unregister") != linked:
            raise ValueError("prior register identity is required only for unregister")
        return self


class RegistrationConsumeResponse(_StrictModel):
    registration_gate_id: int = Field(gt=0)
    operation_uuid: UUID
    operation_kind: Literal["register", "unregister"]
    request_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    gate_envelope_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    nonce_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    prior_register_gate_id: int | None = Field(default=None, gt=0)
    prior_register_operation_uuid: UUID | None = None
    state: Literal["started"]
    challenged: Literal[True]
    transaction_count: Literal[1]
    retry_count: Literal[0]
    concurrency_count: Literal[1]



class RegistrationFinalizeRequest(_StrictModel):
    opaque_execution_attestation: SecretStr = Field(min_length=1, max_length=32768)


class RegistrationTerminalReceipt(_StrictModel):
    registration_gate_id: int = Field(gt=0)
    operation_uuid: UUID
    operation_kind: Literal["register", "unregister"]
    outcome: Literal["succeeded", "failed", "contained"]
    recovered: bool


class SmokeReceipt(_StrictModel):
    attempt_uuid: str
    state: str


class RedactedAttemptStatus(_StrictModel):
    attempt_uuid: str
    ordinal: int = Field(ge=1, le=3)
    direction: Literal["outbound", "inbound"]
    state: str
    terminal_class: str | None = None


class RedactedSmokeStatus(_StrictModel):
    envelope_uuid: str
    state: str
    current: bool
    remaining_attempts: int = Field(ge=0, le=3)
    max_duration_seconds: Literal[60]
    attempts: list[RedactedAttemptStatus] = Field(max_length=3)
ExecutionMode = Literal["legacy_registration", "ip_to_ip_no_register"]
ExecutionStage = Literal[
    "register",
    "peer_attach",
    "outbound_call",
    "inbound_call",
    "unregister",
    "peer_detach",
]
ExecutionState = Literal[
    "sealed",
    "running",
    "cleanup_required",
    "residue_blocked",
    "contained",
    "completed",
    "failed",
]
ExecutionStageState = Literal[
    "pending", "started", "succeeded", "failed", "contained"
]
_STAGE_ORDINALS = {
    "register": 1,
    "peer_attach": 1,
    "outbound_call": 2,
    "inbound_call": 3,
    "unregister": 4,
    "peer_detach": 4,
}
RedactedTerminalClass = Literal[
    "authority_unavailable",
    "call_completed",
    "call_failed",
    "contract_mismatch",
    "expired",
    "inbound_bound",
    "peer_attached",
    "peer_detached",
    "registered",
    "replay",
    "stock_unavailable",
    "stage_failed",
    "unregistered",
]


class _ExecutionBinding(_StrictModel):
    organization_id: int = Field(gt=0)
    execution_seal_uuid: UUID
    execution_nonce_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    gate_envelope_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_keyset_digest: Digest = Field(
        default="00645f3af8230c742951c12f17a713afde209de12182cd6e3722ac59445507aa",
        pattern=r"^[0-9a-f]{64}$",
    )


    @field_validator("execution_seal_uuid", mode="before")
    @classmethod
    def require_canonical_execution_uuid(cls, value: object) -> object:
        return _canonical_uuid(value)



class ExecutionSealRequest(_ExecutionBinding):
    schema_version: Literal["recova-g008-execution-seal-v1"]
    execution_mode: ExecutionMode = "legacy_registration"
    destination_hmac_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    owned_target_digest: Digest | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source_external_ipv4: str | None = None
    peer_signaling_ipv4_cidr: str | None = None
    peer_signaling_udp_port: int | None = Field(default=None, ge=1, le=65535)
    stages: tuple[ExecutionStage, ExecutionStage, ExecutionStage, ExecutionStage]
    live_window_starts_at: datetime
    live_window_expires_at: datetime
    retry_count: Literal[0]
    concurrency_count: Literal[1]
    call_deadline_seconds: Literal[60]
    stage_deadline_seconds: Literal[60] = 60

    reserved_inbound_did_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    reserved_inbound_caller_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    policy_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("live_window_starts_at", "live_window_expires_at")
    @classmethod
    def require_aware_live_window(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("live window must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def require_mode_binding(self) -> ExecutionSealRequest:
        if self.live_window_expires_at <= self.live_window_starts_at:
            raise ValueError("live window expiry must follow its start")
        expected_stages = (
            ("register", "outbound_call", "inbound_call", "unregister")
            if self.execution_mode == "legacy_registration"
            else ("peer_attach", "outbound_call", "inbound_call", "peer_detach")
        )
        if self.stages != expected_stages:
            raise ValueError("execution stages must match execution mode")
        network_values = (
            self.source_external_ipv4,
            self.peer_signaling_ipv4_cidr,
            self.peer_signaling_udp_port,
            self.owned_target_digest,
        )
        if self.execution_mode == "legacy_registration":
            if any(value is not None for value in network_values):
                raise ValueError("IP-to-IP binding is invalid for legacy registration")
            return self
        import ipaddress

        if any(value is None for value in network_values):
            raise ValueError("IP-to-IP mode requires exact source, peer, and owned target")
        source = ipaddress.ip_address(self.source_external_ipv4)
        peer = ipaddress.ip_network(self.peer_signaling_ipv4_cidr, strict=True)
        if source.version != 4 or peer.version != 4 or peer.prefixlen != 32:
            raise ValueError("IP-to-IP mode requires canonical IPv4 and peer /32")
        if self.source_external_ipv4 != str(source) or self.peer_signaling_ipv4_cidr != str(peer):
            raise ValueError("IP-to-IP addresses must be canonical")
        if self.peer_signaling_udp_port != 5060:
            raise ValueError("IP-to-IP peer signaling port must be 5060/UDP")
        return self


class ExecutionSealReceipt(_ExecutionBinding):
    schema_version: Literal["recova-g008-execution-seal-v1"]
    execution_mode: ExecutionMode = "legacy_registration"
    destination_hmac_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    owned_target_digest: Digest | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source_external_ipv4: str | None = None
    peer_signaling_ipv4_cidr: str | None = None
    peer_signaling_udp_port: int | None = Field(default=None, ge=1, le=65535)
    stages: tuple[ExecutionStage, ExecutionStage, ExecutionStage, ExecutionStage]
    live_window_starts_at: datetime
    live_window_expires_at: datetime
    retry_count: Literal[0]
    concurrency_count: Literal[1]
    call_deadline_seconds: Literal[60]
    stage_deadline_at: datetime | None = None
    reserved_inbound_did_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    reserved_inbound_caller_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    policy_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    state: ExecutionState
    sealed_at: datetime
    completed_at: datetime | None = None
    contained_at: datetime | None = None
    terminal_class: RedactedTerminalClass | None = None
    final_evidence_digest: Digest | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    final_evidence_signature_digest: Digest | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    final_evidence_key_digest: Digest | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    final_evidence_key_id: Identifier | None = None
    containment_evidence_digest: Digest | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    containment_evidence_signature_digest: Digest | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    containment_evidence_key_digest: Digest | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    containment_evidence_key_id: Identifier | None = None

class ExecutionStageStartRequest(_ExecutionBinding):
    stage: ExecutionStage
    ordinal: int = Field(ge=1, le=4)
    stage_deadline_seconds: Literal[60] = 60

    @model_validator(mode="after")
    def require_stage_ordinal(self) -> ExecutionStageStartRequest:
        if _STAGE_ORDINALS[self.stage] != self.ordinal:
            raise ValueError("stage ordinal mismatch")
        return self


class ExecutionStageStatusRequest(ExecutionStageStartRequest):
    pass


class ExecutionStageFinalizeRequest(ExecutionStageStartRequest):
    stage_state: Literal["succeeded", "failed", "contained"]
    terminal_class: RedactedTerminalClass

    @model_validator(mode="after")
    def require_generic_stage(self) -> ExecutionStageFinalizeRequest:
        if self.stage in {"register", "unregister"}:
            raise ValueError("terminal registration stages require signed attestation")
        return self

    @model_validator(mode="after")
    def require_stage_terminal_class(self) -> ExecutionStageFinalizeRequest:
        succeeded_classes = {
            "peer_attach": "peer_attached",
            "outbound_call": "call_completed",
            "inbound_call": "inbound_bound",
            "peer_detach": "peer_detached",
        }
        if self.stage_state == "succeeded":
            if self.terminal_class != succeeded_classes[self.stage]:
                raise ValueError("stage terminal class mismatch")
        elif self.terminal_class in succeeded_classes.values():
            raise ValueError("stage failure cannot use a success terminal class")
        return self


class ExecutionStageReceipt(_ExecutionBinding):
    stage_uuid: UUID
    stage: ExecutionStage
    ordinal: int = Field(ge=1, le=4)
    state: ExecutionStageState
    stage_deadline_at: datetime | None = None
    started_at: datetime | None = None
    terminal_at: datetime | None = None
    terminal_class: RedactedTerminalClass | None = None
    evidence_digest: Digest | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    evidence_signature_digest: Digest | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    evidence_key_digest: Digest | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    evidence_key_id: Identifier | None = None
    registration_gate_id: int | None = Field(default=None, gt=0)
    registration_operation_uuid: UUID | None = None
    prior_register_gate_id: int | None = Field(default=None, gt=0)
    recovered: bool

    @field_validator("stage_uuid", "registration_operation_uuid", mode="before")
    @classmethod
    def require_canonical_stage_uuid(cls, value: object) -> object:
        return _canonical_uuid(value)

    @model_validator(mode="after")
    def require_terminal_registration_linkage(self) -> ExecutionStageReceipt:
        linked = (
            self.registration_gate_id is not None
            and self.registration_operation_uuid is not None
        )
        partially_linked = (
            self.registration_gate_id is not None
            or self.registration_operation_uuid is not None
        )
        is_terminal_registration = (
            self.stage in {"register", "unregister"}
            and self.state in {"succeeded", "failed", "contained"}
        )
        if _STAGE_ORDINALS[self.stage] != self.ordinal:
            raise ValueError("stage ordinal mismatch")
        if partially_linked != linked or (is_terminal_registration and not linked):
            raise ValueError("terminal registration stage identity is incomplete")
        if self.prior_register_gate_id is not None and self.stage != "unregister":
            raise ValueError("prior register identity is valid only for unregister")
        if (
            self.stage == "unregister"
            and self.state in {"succeeded", "failed", "contained"}
            and self.prior_register_gate_id is None
        ):
            raise ValueError("terminal unregister stage requires prior register identity")
        if self.recovered and self.state not in {"succeeded", "failed", "contained"}:
            raise ValueError("only a terminal stage status can be recovered")
        return self


class ExecutionEvidenceFinalizeRequest(_ExecutionBinding):
    stage_receipts: list[G008AuthorityReceipt] = Field(default_factory=list, max_length=4)
    containment_receipt: G008AuthorityReceipt | None = None
    containment_verified: Literal[True] = True




class ExecutionContainRequest(_ExecutionBinding):
    containment_class: Literal[
        "authority_unavailable",
        "contract_mismatch",
        "expired",
        "replay",
        "stage_failed",
        "stock_unavailable",
        "verified_terminal",
    ]


class ClaimReservedInboundAndBindRequest(_StrictModel):
    organization_id: int = Field(gt=0)
    account_id: UUID
    application_id: UUID
    stock_call_id: UUID
    did_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    caller_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "account_id",
        "application_id",
        "stock_call_id",
        mode="before",
    )
    @classmethod
    def require_canonical_identifiers(cls, value: object) -> object:
        return _canonical_uuid(value)


class G008BoundCallContext(_StrictModel):
    organization_id: int = Field(gt=0)
    execution_seal_uuid: UUID
    stage_uuid: UUID
    stage: Literal["inbound_call"]
    ordinal: Literal[3]
    account_id: UUID
    application_id: UUID
    run_uuid: UUID
    attempt_uuid: UUID
    idempotency_key: UUID
    bind_receipt_uuid: UUID
    stock_call_id_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    direction: Literal["inbound"]
    authority_deadline_at: datetime
    did_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    caller_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    request_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    gate_envelope_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    bound_at: datetime
    bind_receipt_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    bind_receipt_signature_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    bind_receipt_key_fingerprint: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    bind_receipt_key_id: Identifier = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")


class G008InboundBindClaims(_StrictModel):
    claim_schema: Literal["recova-g008-inbound-bind-receipt-v1"] = Field(
        alias="schema"
    )
    domain: Literal["recova.onnuri.smoke.g008.inbound-bind.v1"]
    algorithm: Literal["ES256"]
    organization_id: int = Field(gt=0)
    execution_seal_uuid: UUID
    execution_stage_uuid: UUID
    account_uuid: UUID
    application_uuid: UUID
    stock_call_uuid: UUID
    stock_call_id_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    did_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    caller_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    direction: Literal["inbound"]
    run_uuid: UUID
    attempt_uuid: UUID
    idempotency_uuid: UUID
    bind_receipt_uuid: UUID
    request_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    gate_envelope_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: datetime
    authority_deadline_at: datetime

    @field_validator(
        "execution_seal_uuid",
        "execution_stage_uuid",
        "account_uuid",
        "application_uuid",
        "stock_call_uuid",
        "run_uuid",
        "attempt_uuid",
        "idempotency_uuid",
        "bind_receipt_uuid",
        mode="before",
    )
    @classmethod
    def require_canonical_identifiers(cls, value: object) -> object:
        return _canonical_uuid(value)

    @model_validator(mode="after")
    def require_exact_authority_window(self) -> "G008InboundBindClaims":
        if (
            self.issued_at.tzinfo is None
            or self.authority_deadline_at.tzinfo is None
            or self.authority_deadline_at - self.issued_at != timedelta(seconds=60)
        ):
            raise ValueError("authority deadline must be exactly 60 seconds")
        return self


class G008InboundBindReceipt(_StrictModel):
    schema_version: Literal["recova-g008-inbound-bind-receipt-v1"]
    algorithm: Literal["ES256"]
    verification_domain: Literal["recova.onnuri.smoke.g008.inbound-bind.v1"]
    key_id: Identifier = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")
    claims: G008InboundBindClaims
    signature: str = Field(pattern=r"^[A-Za-z0-9_-]{86}$", repr=False)


class ClaimReservedInboundAndBindResponse(_StrictModel):
    context: G008BoundCallContext
    bind_receipt: G008InboundBindReceipt
    recovered: bool


from functools import lru_cache
from pathlib import Path
import json


@lru_cache(maxsize=1)
def load_onnuri_outbound_diagnostic_contract() -> dict[str, object]:
    """Load the closed, versioned outbound diagnostic state contract."""
    fixture = (
        Path(__file__).resolve().parents[2]
        / "deploy/onnuri-jambonz-oss/fixtures/onnuri_outbound_diagnostic_v1_contract.json"
    )
    contract = json.loads(fixture.read_text(encoding="utf-8"))
    if contract.get("schema_version") != "recova-onnuri-outbound-diagnostic-v1":
        raise RuntimeError("onnuri_outbound_diagnostic_contract_version_invalid")
    return contract


ONNURI_OUTBOUND_DIAGNOSTIC_CONTRACT = load_onnuri_outbound_diagnostic_contract()
ONNURI_OUTBOUND_DIAGNOSTIC_FIXTURE_DIGEST = __import__("hashlib").sha256(
    json.dumps(ONNURI_OUTBOUND_DIAGNOSTIC_CONTRACT, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
ONNURI_OUTBOUND_DIAGNOSTIC_OPERATIONS = frozenset(
    edge["operation"] for edge in ONNURI_OUTBOUND_DIAGNOSTIC_CONTRACT["edges"]
) | frozenset(ONNURI_OUTBOUND_DIAGNOSTIC_CONTRACT["open_terminal_operations"])


class OutboundDiagnosticState(_StrictModel):
    dispatch: Literal["not_submitted", "submission_reserved", "submitted", "stock_accepted", "ambiguous_submission", "dispatch_denied"]
    signaling: Literal["unknown", "no_final_response", "provisional_only", "final_2xx", "final_3xx_6xx"]
    answer: Literal["unknown", "answered", "not_answered"]
    media: Literal["unknown", "not_applicable", "none", "rtp_one_way", "rtp_bidirectional"]
    terminal: Literal["open", "dispatch_denied", "provisional_timeout", "event_unavailable", "answered_no_matching_rtp", "answered_rtp_one_way", "completed", "carrier_rejected", "ambiguous_submission", "authority_expired", "contained"]

    @model_validator(mode="after")
    def require_listed_product(self) -> "OutboundDiagnosticState":
        product = [self.dispatch, self.signaling, self.answer, self.media, self.terminal]
        if product not in ONNURI_OUTBOUND_DIAGNOSTIC_CONTRACT["nodes"]:
            raise ValueError("onnuri_outbound_diagnostic_state_unlisted")
        return self


class OutboundDiagnosticTransitionRequest(_StrictModel):
    attempt_uuid: str = Field(min_length=1, max_length=64)
    organization_id: int = Field(gt=0)
    operation: str = Field(min_length=1, max_length=64)
    expected: OutboundDiagnosticState
    provenance_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    event_idempotency_key: str = Field(min_length=16, max_length=255)

    @field_validator("operation")
    @classmethod
    def require_named_operation(cls, value: str) -> str:
        if value not in ONNURI_OUTBOUND_DIAGNOSTIC_OPERATIONS:
            raise ValueError("onnuri_outbound_diagnostic_operation_unlisted")
        return value


class OutboundDiagnosticLateEvidenceRequest(_StrictModel):
    attempt_uuid: str = Field(min_length=1, max_length=64)
    organization_id: int = Field(gt=0)
    evidence_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_kind: str = Field(min_length=1, max_length=64)
__all__ = [
    "ONNURI_OUTBOUND_DIAGNOSTIC_CONTRACT",
    "ONNURI_OUTBOUND_DIAGNOSTIC_FIXTURE_DIGEST",
    "ONNURI_OUTBOUND_DIAGNOSTIC_OPERATIONS",
    "OutboundDiagnosticLateEvidenceRequest",
    "OutboundDiagnosticState",
    "OutboundDiagnosticTransitionRequest",
    "ClaimReservedInboundAndBindRequest",
    "ClaimReservedInboundAndBindResponse",
    "G008BoundCallContext",
    "G008InboundBindClaims",
    "G008InboundBindReceipt",
    "EmergencyUnregisterRequest",
    "ExecutionNonceConsumeReceipt",
    "ExecutionNonceConsumeRequest",
    "ExecutionContainRequest",
    "ExecutionEvidenceFinalizeRequest",
    "ExecutionSealReceipt",
    "ExecutionSealRequest",
    "ExecutionStageFinalizeRequest",
    "ExecutionStageReceipt",
    "ExecutionStageStatusRequest",
    "ExecutionStageStartRequest",
    "RegistrationAuthorization",
    "RegistrationBeginRequest",
    "RegistrationConsumeRequest",
    "RegistrationConsumeResponse",
    "RegistrationFinalizeRequest",
    "RegistrationTerminalReceipt",
    "StockCallBindReceipt",
    "StockCallBindRequest",
    "CommitInboundAnswerIntentAndMintMediaRequest",
    "ConsumeDispatchRequest",
    "ConsumeMediaRequest",
    "DispatchConsumeReceipt",
    "MediaAuthorityReceipt",
    "RecordAnswerAndMintMediaRequest",
    "RedactedSmokeStatus",
    "SetTerminalRequest",
    "SmokeReceipt",
    "AcceptFacadeCallbackRequest",
    "BoundCallContext",
    "CallStatus",
    "FacadeAuthorityReadiness",
    "FacadeBoundCallStatusRequest",
    "FacadeBoundCallStatusResponse",
    "RequestFacadeContainment",
]
