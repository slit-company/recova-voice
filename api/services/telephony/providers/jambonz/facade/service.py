"""Fail-closed orchestration for the DB-less Recova/Jambonz facade."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

if TYPE_CHECKING:
    from api.schemas.onnuri_smoke import (
        ClaimReservedInboundAndBindRequest,
        ClaimReservedInboundAndBindResponse,
    )

from .auth import (
    AuthenticationError,
    SignatureVerifier,
    VerificationPolicy,
    canonical_signing_bytes,
    validate_dispatch_capability,
    validate_dispatch_receipt,
    validate_media_receipt_domain,
    validate_route_chain_capability,
)
from .models import (
    AnswerVerb,
    BoundCallContext,
    CallStatus,
    CallStatusResponse,
    CallbackReceipt,
    ContainmentRequest,
    Direction,
    DispatchConsumeReceipt,
    DispatchSubmission,
    FailureCategory,
    HookResponse,
    InboundInitialHookRequest,
    ListenVerb,
    MediaAuthorityReceipt,
    NormalizedCallEvent,
    OuterCallCreateRequest,
    OuterCallCreateResponse,
    OutboundAnswerHookRequest,
    RouteChainCapability,
    RouteChainCapabilityRequest,
    StockCallBindReceipt,
    StockCallBindRequest,
    StockCallCreateRequest,
    StockCallCreateResult,
    StockCallWebhook,
    StockCdrWebhook,
    StockCdrEvent,
    StockEventType,
    StockStatusEvent,
    WsAuth,
)


class G008Binding(BaseModel):
    """Non-secret identity binding carried by every fixed G008 control request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    organization_id: int = Field(gt=0)
    execution_seal_uuid: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    execution_nonce_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    gate_envelope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class G008InboundArmRequest(G008Binding):
    execution_stage_uuid: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    destination_hmac_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    reserved_inbound_did_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    reserved_inbound_caller_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    retry_count: Literal[0]
    concurrency_count: Literal[1]
    call_deadline_seconds: Literal[60]


class G008InboundArmContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    direction: Literal["inbound"] = "inbound"
    context_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class G008InboundArmReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    context: G008InboundArmContext
    state: Literal["armed"] = "armed"
    retry_count: Literal[0] = 0
    concurrency_count: Literal[1] = 1
    call_deadline_seconds: Literal[60] = 60


class G008HangupRequest(G008Binding):
    context: dict[str, object]
    deadline_seconds: Literal[5]

    @model_validator(mode="after")
    def require_context_object(self) -> "G008HangupRequest":
        if not self.context:
            raise ValueError("context must not be empty")
        return self


class G008HangupReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    context_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: Literal["terminated"] = "terminated"
    containment_requested: bool


class _InboundArm:
    def __init__(
        self,
        *,
        request: G008InboundArmRequest,
        context_digest: str,
        expires_at: datetime,
    ) -> None:
        self.request = request
        self.context_digest = context_digest
        self.expires_at = expires_at
        self.consumed = False
        self.bound_context: BoundCallContext | None = None


class AuthorityClientError(RuntimeError):
    """F12 rejected, replayed, mismatched, or could not commit an operation."""

    def __init__(self, category: FailureCategory):
        super().__init__(category.value)
        self.category = category


class StockClientError(RuntimeError):
    """Stock Jambonz rejected or could not prove an operation."""

    def __init__(self, category: FailureCategory):
        super().__init__(category.value)
        self.category = category


class FacadeError(RuntimeError):
    """Stable public failure carrying no sensitive identifiers."""

    def __init__(
        self,
        category: FailureCategory,
        *,
        http_status: int,
        containment_requested: bool = False,
    ):
        super().__init__(category.value)
        self.category = category
        self.http_status = http_status
        self.containment_requested = containment_requested


class F12AuthorityClient(Protocol):
    """Narrow internal Recova API. Its implementation alone may use PostgreSQL."""

    async def mint_route_chain_capability(
        self, request: RouteChainCapabilityRequest
    ) -> RouteChainCapability: ...

    async def consume_dispatch(
        self, submission: DispatchSubmission
    ) -> DispatchConsumeReceipt: ...

    async def bind_stock_call(
        self, request: StockCallBindRequest
    ) -> StockCallBindReceipt: ...

    async def claim_reserved_inbound_and_bind(
        self, request: ClaimReservedInboundAndBindRequest
    ) -> ClaimReservedInboundAndBindResponse: ...

    async def record_answer_and_mint_media(
        self, request: OutboundAnswerHookRequest
    ) -> MediaAuthorityReceipt: ...

    async def commit_inbound_answer_intent_and_mint_media(
        self, request: InboundInitialHookRequest
    ) -> MediaAuthorityReceipt: ...

    async def get_call_status(
        self,
        *,
        organization_id: int,
        account_id: str,
        stock_call_id: str,
    ) -> CallStatusResponse: ...

    async def submit_call_event(
        self, event: NormalizedCallEvent
    ) -> CallbackReceipt: ...

    async def request_containment(self, request: ContainmentRequest) -> None: ...

    async def ready(self) -> bool: ...

class StockJambonzClient(Protocol):
    """Candidate-specific one-shot localhost stock API; no retries or fan-out."""

    async def create_call(
        self, request: StockCallCreateRequest
    ) -> StockCallCreateResult: ...

    async def request_bounded_hangup(
        self,
        *,
        stock_call_id: str,
        timeout_seconds: int,
    ) -> None: ...

    async def ready(self) -> bool: ...


class FacadeService:
    def __init__(
        self,
        *,
        f12: F12AuthorityClient,
        stock: StockJambonzClient,
        verifier: SignatureVerifier,
        verification_policy: VerificationPolicy,
        media_websocket_url: str,
    ):
        if not media_websocket_url.startswith("wss://"):
            raise ValueError("media_websocket_url must use wss")
        self._f12 = f12
        self._stock = stock
        self._verifier = verifier
        self._policy = verification_policy
        self._media_websocket_url = media_websocket_url
        self._control_lock = asyncio.Lock()
        self._inbound_arms: dict[int, _InboundArm] = {}
        self._hangup_receipts: dict[str, G008HangupReceipt] = {}
        self._outbound_nonce_digests: dict[str, str] = {}

    async def ready(self) -> bool:
        try:
            return await self._f12.ready() and await self._stock.ready()
        except Exception:
            return False

    async def arm_g008_inbound(
        self,
        *,
        request: G008InboundArmRequest,
        now: datetime,
    ) -> G008InboundArmReceipt:
        """Arm one exact inbound reservation; retries and replacement are forbidden."""

        context_digest = _digest_payload(
            request.model_dump(mode="json", exclude_none=True)
        )
        async with self._control_lock:
            if request.organization_id in self._inbound_arms:
                raise FacadeError(FailureCategory.REPLAY, http_status=409)
            self._inbound_arms[request.organization_id] = _InboundArm(
                request=request,
                context_digest=context_digest,
                expires_at=now + timedelta(seconds=60),
            )
        return G008InboundArmReceipt(
            context=G008InboundArmContext(context_digest=context_digest)
        )

    async def hangup_g008(
        self,
        *,
        request: G008HangupRequest,
    ) -> G008HangupReceipt:
        """Contain one exactly bound active call, once, within the fixed budget."""

        if set(request.context) == {"direction", "context_digest"}:
            request_context_digest = _digest_payload(request.context)
        else:
            try:
                request_context_digest = _digest(
                    BoundCallContext.model_validate(request.context)
                )
            except Exception as exc:
                raise FacadeError(
                    FailureCategory.CONTRACT_MISMATCH, http_status=409
                ) from exc
        operation_digest = _digest_payload(
            request.model_dump(mode="json", exclude_none=True)
        )
        async with self._control_lock:
            recovered = self._hangup_receipts.get(operation_digest)
            if recovered is not None:
                return recovered
            try:
                async with asyncio.timeout(5):
                    bound_context = self._resolve_g008_hangup_context(
                        request=request,
                        context_digest=request_context_digest,
                    )
                    status = await self.get_call_status(
                        organization_id=request.organization_id,
                        account_id=bound_context.account_id,
                        stock_call_id=bound_context.stock_call_id or "",
                    )
                    if (
                        status.context != bound_context
                        or status.context.organization_id
                        != request.organization_id
                        or status.context.candidate_digest
                        != request.candidate_digest
                        or status.context.gate_envelope_digest
                        != request.gate_envelope_digest
                    ):
                        raise FacadeError(
                            FailureCategory.CONTRACT_MISMATCH,
                            http_status=409,
                        )

                    if not status.terminal:
                        containment = ContainmentRequest(
                            organization_id=request.organization_id,
                            context=bound_context,
                            stock_call_id=bound_context.stock_call_id or "",
                            category=FailureCategory.CONTAINMENT_REQUIRED,
                            bounded_hangup_seconds=5,
                        )
                        await asyncio.gather(
                            self._f12.request_containment(containment),
                            self._stock.request_bounded_hangup(
                                stock_call_id=containment.stock_call_id,
                                timeout_seconds=5,
                            ),
                        )
            except FacadeError:
                raise
            except Exception as exc:
                raise FacadeError(
                    FailureCategory.CONTAINMENT_REQUIRED,
                    http_status=503,
                    containment_requested=True,
                ) from exc

            receipt = G008HangupReceipt(
                context_digest=request_context_digest,
                containment_requested=not status.terminal,
            )
            self._hangup_receipts[operation_digest] = receipt
            return receipt

    def _resolve_g008_hangup_context(
        self,
        *,
        request: G008HangupRequest,
        context_digest: str,
    ) -> BoundCallContext:
        if set(request.context) == {"direction", "context_digest"}:
            arm = self._inbound_arms.get(request.organization_id)
            if (
                arm is None
                or not arm.consumed
                or arm.bound_context is None
                or arm.context_digest != request.context.get("context_digest")
                or not _binding_matches_arm(request, arm.request)
            ):
                raise FacadeError(
                    FailureCategory.CONTRACT_MISMATCH, http_status=409
                )
            return arm.bound_context

        try:
            context = BoundCallContext.model_validate(request.context)
        except Exception as exc:
            raise FacadeError(
                FailureCategory.CONTRACT_MISMATCH, http_status=409
            ) from exc
        if (
            context.direction != Direction.OUTBOUND
            or context.stock_call_id is None
            or context.organization_id != request.organization_id
            or context.run_id != request.execution_seal_uuid
            or self._outbound_nonce_digests.get(context_digest)
            != request.execution_nonce_digest
            or context.candidate_digest != request.candidate_digest
            or context.gate_envelope_digest != request.gate_envelope_digest
        ):
            raise FacadeError(FailureCategory.CONTRACT_MISMATCH, http_status=409)
        return context

    async def create_outbound_call(
        self,
        *,
        account_id: str,
        request: OuterCallCreateRequest,
        now: datetime,
    ) -> OuterCallCreateResponse:
        context = BoundCallContext(
            organization_id=request.organization_id,
            account_id=account_id,
            application_id=request.application_id,
            run_id=request.run_id,
            attempt_id=request.attempt_id,
            direction=Direction.OUTBOUND,
            authority_deadline=request.authority_deadline,
            candidate_digest=request.candidate_digest,
            gate_envelope_digest=request.gate_envelope_digest,
        )
        request_digest = _create_request_digest(account_id, request)
        if request.request_mode == "diagnostic":
            try:
                capability = await self._f12.mint_route_chain_capability(
                    RouteChainCapabilityRequest(
                        context=context,
                        idempotency_key=request.idempotency_key,
                        request_digest=request_digest,
                        route_profile_digest=request.route_profile_digest or "",
                        route_evidence_handle=request.route_evidence_handle or "",
                    )
                )
                validate_route_chain_capability(
                    capability,
                    RouteChainCapabilityRequest(
                        context=context,
                        idempotency_key=request.idempotency_key,
                        request_digest=request_digest,
                        route_profile_digest=request.route_profile_digest or "",
                        route_evidence_handle=request.route_evidence_handle or "",
                    ),
                    policy=self._policy,
                    verifier=self._verifier,
                    now=now,
                )
            except AuthenticationError as exc:
                raise FacadeError(_auth_category(exc), http_status=403) from exc
            except AuthorityClientError as exc:
                raise FacadeError(exc.category, http_status=409) from exc
            except Exception as exc:
                raise FacadeError(
                    FailureCategory.AUTHORITY_UNAVAILABLE, http_status=503
                ) from exc
        else:
            capability = request.dispatch_capability
            assert capability is not None
        submission = DispatchSubmission(
            context=context,
            idempotency_key=request.idempotency_key,
            request_digest=request_digest,
            capability=capability,
        )
        try:
            if request.request_mode == "legacy":
                validate_dispatch_capability(
                    submission,
                    policy=self._policy,
                    verifier=self._verifier,
                    now=now,
                )
            receipt = await self._f12.consume_dispatch(submission)
            validate_dispatch_receipt(
                receipt,
                submission,
                policy=self._policy,
                verifier=self._verifier,
            )
        except AuthenticationError as exc:
            raise FacadeError(
                _auth_category(exc), http_status=403
            ) from exc
        except AuthorityClientError as exc:
            raise FacadeError(exc.category, http_status=409) from exc
        except Exception as exc:
            raise FacadeError(
                FailureCategory.AUTHORITY_UNAVAILABLE, http_status=503
            ) from exc

        stock_request = StockCallCreateRequest(
            context=context,
            idempotency_key=request.idempotency_key,
            dispatch_receipt_id=receipt.receipt_id,
            from_address=request.from_address,
            to_address=request.to_address,
            answer_hook_url=request.answer_hook_url,
            status_hook_url=request.status_hook_url,
            ring_timeout_seconds=request.ring_timeout_seconds,
            time_limit_seconds=request.time_limit_seconds,
        )
        try:
            stock_result = await self._stock.create_call(stock_request)
        except StockClientError as exc:
            raise FacadeError(exc.category, http_status=502) from exc
        except Exception as exc:
            raise FacadeError(
                FailureCategory.STOCK_UNAVAILABLE, http_status=503
            ) from exc
        if (
            stock_result.organization_id != context.organization_id
            or stock_result.idempotency_key != request.idempotency_key
            or stock_result.request_digest != _digest(stock_request)
        ):
            await self._contain_best_effort(
                context=context.model_copy(
                    update={"stock_call_id": stock_result.stock_call_id}
                ),
                stock_call_id=stock_result.stock_call_id,
                category=FailureCategory.IDEMPOTENCY_MISMATCH,
            )
            raise FacadeError(
                FailureCategory.IDEMPOTENCY_MISMATCH,
                http_status=409,
                containment_requested=True,
            )

        bound_context = context.model_copy(
            update={"stock_call_id": stock_result.stock_call_id}
        )
        bind_request = StockCallBindRequest(
            context=bound_context,
            stock_call_id=stock_result.stock_call_id,
            idempotency_key=request.idempotency_key,
            request_digest=request_digest,
            dispatch_receipt_id=receipt.receipt_id,
        )
        try:
            bind = await self._f12.bind_stock_call(bind_request)
            _validate_bind(bind, bind_request)
        except Exception as exc:
            await self._contain_best_effort(
                context=bound_context,
                stock_call_id=stock_result.stock_call_id,
                category=FailureCategory.CONTAINMENT_REQUIRED,
            )
            category = (
                exc.category
                if isinstance(exc, AuthorityClientError)
                else FailureCategory.AUTHORITY_UNAVAILABLE
            )
            raise FacadeError(
                category,
                http_status=503,
                containment_requested=True,
            ) from exc

        self._outbound_nonce_digests[_digest(bound_context)] = _digest_text(
            capability.nonce
        )
        return OuterCallCreateResponse(
            context=bound_context,
            stock_call_id=stock_result.stock_call_id,
            status=CallStatus.STOCK_BOUND,
            dispatch_receipt_id=receipt.receipt_id,
            bind_receipt_id=bind.bind_receipt_id,
            idempotency_key=request.idempotency_key,
            request_digest=request_digest,
        )

    async def get_call_status(
        self, *, organization_id: int, account_id: str, stock_call_id: str
    ) -> CallStatusResponse:
        try:
            response = await self._f12.get_call_status(
                organization_id=organization_id,
                account_id=account_id,
                stock_call_id=stock_call_id,
            )
        except AuthorityClientError as exc:
            raise FacadeError(exc.category, http_status=404) from exc
        except Exception as exc:
            raise FacadeError(
                FailureCategory.AUTHORITY_UNAVAILABLE, http_status=503
            ) from exc
        if (
            response.context.organization_id != organization_id
            or response.context.account_id != account_id
            or response.context.stock_call_id != stock_call_id
        ):
            raise FacadeError(FailureCategory.CONTRACT_MISMATCH, http_status=409)
        return response
    async def stock_outbound_answer(
        self,
        *,
        organization_id: int,
        event: StockCallWebhook,
        now: datetime,
    ) -> HookResponse:
        binding = await self._resolve_stock_callback(
            organization_id=organization_id,
            event=event,
            expected_direction=Direction.OUTBOUND,
        )
        if event.call_status != "in-progress" or not 200 <= event.sip_status < 300:
            await self._contain_best_effort(
                context=binding.context,
                stock_call_id=event.call_sid,
                category=FailureCategory.INVALID_STOCK_EVENT,
            )
            raise FacadeError(
                FailureCategory.INVALID_STOCK_EVENT,
                http_status=409,
                containment_requested=True,
            )
        request = OutboundAnswerHookRequest(
            organization_id=organization_id,
            context=binding.context,
            stock_call_id=event.call_sid,
            idempotency_key=binding.idempotency_key,
            request_digest=binding.request_digest,
            event_nonce=_stock_event_nonce("answer", event),
            observed_wall_time=now,
            proposed_deadline=now + timedelta(seconds=60),
            candidate_digest=binding.context.candidate_digest,
        )
        return await self.outbound_answer_hook(request)

    async def stock_inbound_initial(
        self,
        *,
        organization_id: int,
        event: StockCallWebhook,
        now: datetime,
    ) -> HookResponse:
        claim = None
        bound_context = None
        persisted_stock_call_id = None
        arm = None
        try:
            if event.call_status != "trying" or event.direction != Direction.INBOUND:
                raise AuthenticationError("invalid_inbound_initial_event")

            from api.schemas.onnuri_smoke import ClaimReservedInboundAndBindRequest

            validated_identifiers = ClaimReservedInboundAndBindRequest(
                organization_id=organization_id,
                account_id=event.account_sid,
                application_id=event.application_sid,
                stock_call_id=event.call_sid,
                did_digest="0" * 64,
                caller_digest="0" * 64,
            )
            claim_request = validated_identifiers.model_copy(
                update={
                    "did_digest": _digest_text(
                        event.to_address.get_secret_value()
                    ),
                    "caller_digest": _digest_text(
                        event.from_address.get_secret_value()
                    ),
                }
            )
            async with self._control_lock:
                arm = self._inbound_arms.get(organization_id)
                if (
                    arm is None
                    or arm.consumed
                    or now >= arm.expires_at
                    or arm.request.reserved_inbound_did_digest
                    != claim_request.did_digest
                    or arm.request.reserved_inbound_caller_digest
                    != claim_request.caller_digest
                ):
                    raise AuthenticationError("inbound_arm_binding_mismatch")
                arm.consumed = True
            claim = await self._f12.claim_reserved_inbound_and_bind(claim_request)
            self._validate_inbound_claim(
                claim,
                request=claim_request,
                now=now,
            )
            persisted = claim.context
            persisted_stock_call_id = str(
                claim.bind_receipt.claims.stock_call_uuid
            )
            bound_context = BoundCallContext(
                organization_id=persisted.organization_id,
                account_id=str(persisted.account_id),
                application_id=str(persisted.application_id),
                run_id=str(persisted.run_uuid),
                attempt_id=str(persisted.attempt_uuid),
                direction=Direction.INBOUND,
                stock_call_id=persisted_stock_call_id,
                authority_deadline=persisted.authority_deadline_at,
                candidate_digest=persisted.candidate_digest,
                gate_envelope_digest=persisted.gate_envelope_digest,
            )
            if (
                arm is None
                or persisted.organization_id != arm.request.organization_id
                or str(persisted.execution_seal_uuid)
                != arm.request.execution_seal_uuid
                or str(persisted.stage_uuid) != arm.request.execution_stage_uuid
                or persisted.candidate_digest != arm.request.candidate_digest
                or persisted.gate_envelope_digest
                != arm.request.gate_envelope_digest
                or persisted.did_digest
                != arm.request.reserved_inbound_did_digest
                or persisted.caller_digest
                != arm.request.reserved_inbound_caller_digest
                or persisted.authority_deadline_at
                != persisted.bound_at + timedelta(seconds=60)
            ):
                raise AuthenticationError("inbound_arm_authority_binding_mismatch")
            arm.bound_context = bound_context
            request = InboundInitialHookRequest(
                organization_id=persisted.organization_id,
                context=bound_context,
                stock_call_id=persisted_stock_call_id,
                idempotency_key=str(persisted.idempotency_key),
                request_digest=persisted.request_digest,
                event_nonce=persisted.request_digest,
                observed_wall_time=persisted.bound_at,
                proposed_deadline=persisted.authority_deadline_at,
                candidate_digest=persisted.candidate_digest,
                source_account_id=str(persisted.account_id),
                source_application_id=str(persisted.application_id),
                did_digest=persisted.did_digest,
                caller_mobile_digest=persisted.caller_digest,
            )
            receipt = await self._f12.commit_inbound_answer_intent_and_mint_media(
                request
            )
            self._validate_media_receipt(receipt, request)
        except Exception:
            if (
                bound_context is not None
                and claim is not None
                and persisted_stock_call_id is not None
            ):
                await self._contain_best_effort(
                    context=bound_context,
                    stock_call_id=persisted_stock_call_id,
                    category=FailureCategory.CONTAINMENT_REQUIRED,
                )
            return HookResponse(
                organization_id=organization_id,
                verbs=(),
                idempotency_key=(
                    str(claim.context.idempotency_key)
                    if claim is not None and bound_context is not None
                    else "rejected-000000000"
                ),
                request_digest=(
                    claim.context.request_digest
                    if claim is not None and bound_context is not None
                    else "0" * 64
                ),
                containment_requested=bound_context is not None,
            )
        return self._listen_response(receipt, answer=True)

    async def stock_status(
        self,
        *,
        organization_id: int,
        event: StockCallWebhook,
        now: datetime,
    ) -> CallbackReceipt:
        binding = await self._resolve_stock_callback(
            organization_id=organization_id,
            event=event,
            expected_direction=event.direction,
        )
        normalized_status, category = _normalize_status(event.call_status)
        return await self._submit_event(
            NormalizedCallEvent(
                organization_id=organization_id,
                context=binding.context,
                stock_call_id=event.call_sid,
                event_type=StockEventType.STATUS,
                normalized_status=normalized_status,
                occurred_at=now,
                event_nonce=_stock_event_nonce("status", event),
                idempotency_key=binding.idempotency_key,
                request_digest=binding.request_digest,
                redacted_cause_category=category,
            )
        )

    async def stock_cdr(
        self,
        *,
        organization_id: int,
        event: StockCdrWebhook,
        now: datetime,
    ) -> CallbackReceipt:
        binding = await self._resolve_stock_callback(
            organization_id=organization_id,
            event=event,
            expected_direction=event.direction,
        )
        normalized_status, category = _normalize_status(event.call_status)
        if normalized_status not in _TERMINAL_STATUSES:
            raise FacadeError(
                FailureCategory.INVALID_STOCK_EVENT, http_status=409
            )
        return await self._submit_event(
            NormalizedCallEvent(
                organization_id=organization_id,
                context=binding.context,
                stock_call_id=event.call_sid,
                event_type=StockEventType.CDR,
                normalized_status=normalized_status,
                occurred_at=now,
                event_nonce=_stock_event_nonce("cdr", event),
                idempotency_key=binding.idempotency_key,
                request_digest=binding.request_digest,
                duration_seconds=event.duration,
                redacted_cause_category=category,
            )
        )

    async def _resolve_stock_callback(
        self,
        *,
        organization_id: int,
        event: StockCallWebhook | StockCdrWebhook,
        expected_direction: Direction,
    ) -> CallStatusResponse:
        binding = await self.get_call_status(
            organization_id=organization_id,
            account_id=event.account_sid,
            stock_call_id=event.call_sid,
        )
        if (
            binding.context.application_id != event.application_sid
            or binding.context.direction != event.direction
            or binding.context.direction != expected_direction
            or binding.terminal
            or binding.idempotency_key is None
            or binding.request_digest is None
            or binding.candidate_digest is None
            or binding.candidate_digest != binding.context.candidate_digest
        ):
            if not binding.terminal:
                await self._contain_best_effort(
                    context=binding.context,
                    stock_call_id=event.call_sid,
                    category=FailureCategory.CONTRACT_MISMATCH,
                )
            raise FacadeError(
                FailureCategory.CONTRACT_MISMATCH,
                http_status=409,
                containment_requested=not binding.terminal,
            )
        return binding


    async def outbound_answer_hook(
        self, request: OutboundAnswerHookRequest
    ) -> HookResponse:
        try:
            receipt = await self._f12.record_answer_and_mint_media(request)
            self._validate_media_receipt(receipt, request)
        except Exception as exc:
            await self._contain_best_effort(
                context=request.context,
                stock_call_id=request.stock_call_id,
                category=FailureCategory.CONTAINMENT_REQUIRED,
            )
            category = (
                exc.category
                if isinstance(exc, AuthorityClientError)
                else FailureCategory.AUTHORITY_UNAVAILABLE
            )
            raise FacadeError(
                category,
                http_status=503,
                containment_requested=True,
            ) from exc
        return self._listen_response(receipt, answer=False)

    def _validate_inbound_claim(
        self,
        claim: ClaimReservedInboundAndBindResponse,
        *,
        request: ClaimReservedInboundAndBindRequest,
        now: datetime,
    ) -> None:
        context = claim.context
        receipt = claim.bind_receipt
        claims = receipt.claims
        expected_claims = {
            "schema": receipt.schema_version,
            "domain": receipt.verification_domain,
            "algorithm": receipt.algorithm,
            "organization_id": context.organization_id,
            "execution_seal_uuid": context.execution_seal_uuid,
            "execution_stage_uuid": context.stage_uuid,
            "account_uuid": context.account_id,
            "application_uuid": context.application_id,
            "stock_call_uuid": request.stock_call_id,
            "stock_call_id_digest": context.stock_call_id_digest,
            "did_digest": context.did_digest,
            "caller_digest": context.caller_digest,
            "direction": context.direction,
            "run_uuid": context.run_uuid,
            "attempt_uuid": context.attempt_uuid,
            "idempotency_uuid": context.idempotency_key,
            "bind_receipt_uuid": context.bind_receipt_uuid,
            "request_digest": context.request_digest,
            "candidate_digest": context.candidate_digest,
            "gate_envelope_digest": context.gate_envelope_digest,
            "issued_at": context.bound_at,
            "authority_deadline_at": context.authority_deadline_at,
        }
        signing_bytes = canonical_signing_bytes(receipt, exclude={"signature"})
        signature_bytes = _decode_base64url_signature(receipt.signature)
        key_fingerprint = getattr(self._verifier, "key_fingerprint", None)
        configured_fingerprint = (
            key_fingerprint(receipt.key_id) if callable(key_fingerprint) else None
        )
        if (
            context.organization_id != request.organization_id
            or context.account_id != request.account_id
            or context.application_id != request.application_id
            or context.stock_call_id_digest != _digest_text(str(request.stock_call_id))
            or context.did_digest != request.did_digest
            or context.caller_digest != request.caller_digest
            or context.direction != Direction.INBOUND.value
            or context.stage != "inbound_call"
            or context.ordinal != 3
            or context.authority_deadline_at
            != context.bound_at + timedelta(seconds=60)
            or now >= context.authority_deadline_at
            or receipt.schema_version != "recova-g008-inbound-bind-receipt-v1"
            or receipt.algorithm != "ES256"
            or receipt.verification_domain
            != "recova.onnuri.smoke.g008.inbound-bind.v1"
            or receipt.key_id != self._policy.dispatch_key_id
            or context.bind_receipt_key_id != receipt.key_id
            or configured_fingerprint is None
            or context.bind_receipt_key_fingerprint != configured_fingerprint
            or claims.model_dump(mode="python", by_alias=True) != expected_claims
            or context.bind_receipt_digest
            != hashlib.sha256(signing_bytes).hexdigest()
            or context.bind_receipt_signature_digest
            != hashlib.sha256(signature_bytes).hexdigest()
            or not self._verifier.verify(
                key_id=receipt.key_id,
                algorithm=receipt.algorithm,
                verification_domain=receipt.verification_domain,
                message=signing_bytes,
                signature=receipt.signature,
            )
        ):
            raise AuthenticationError("inbound_bind_receipt_mismatch")

    async def accept_status(self, event: StockStatusEvent) -> CallbackReceipt:
        _require_request_digest(event)
        normalized = normalize_stock_status(event)
        return await self._submit_event(normalized)

    async def accept_cdr(self, event: StockCdrEvent) -> CallbackReceipt:
        _require_request_digest(event)
        normalized = normalize_stock_cdr(event)
        return await self._submit_event(normalized)

    async def _submit_event(
        self, event: NormalizedCallEvent
    ) -> CallbackReceipt:
        try:
            receipt = await self._f12.submit_call_event(event)
        except AuthorityClientError as exc:
            raise FacadeError(exc.category, http_status=409) from exc
        except Exception as exc:
            raise FacadeError(
                FailureCategory.AUTHORITY_UNAVAILABLE, http_status=503
            ) from exc
        if (
            receipt.organization_id != event.organization_id
            or receipt.organization_id != event.context.organization_id
            or receipt.event_nonce != event.event_nonce
            or receipt.idempotency_key != event.idempotency_key
            or receipt.request_digest != event.request_digest
        ):
            raise FacadeError(FailureCategory.CONTRACT_MISMATCH, http_status=409)
        return receipt

    def _validate_media_receipt(
        self,
        receipt: MediaAuthorityReceipt,
        request: OutboundAnswerHookRequest | InboundInitialHookRequest,
    ) -> None:
        validate_media_receipt_domain(
            media_key_id=receipt.media_key_id,
            media_verification_domain=receipt.media_verification_domain,
            policy=self._policy,
        )
        if (
            receipt.context != request.context
            or receipt.stock_call_id != request.stock_call_id
            or receipt.idempotency_key != request.idempotency_key
            or receipt.request_digest != request.request_digest
            or receipt.authority_deadline != request.proposed_deadline
        ):
            raise AuthenticationError("media_receipt_binding_mismatch")

    def _listen_response(
        self,
        receipt: MediaAuthorityReceipt,
        *,
        answer: bool,
    ) -> HookResponse:
        verbs: list[AnswerVerb | ListenVerb] = []
        if answer:
            verbs.append(AnswerVerb())
        verbs.append(
            ListenVerb(
                url=self._media_websocket_url,
                ws_auth=WsAuth(password=receipt.opaque_media_capability),
            )
        )
        return HookResponse(
            organization_id=receipt.context.organization_id,
            verbs=tuple(verbs),
            authority_receipt_id=receipt.authority_receipt_id,
            idempotency_key=receipt.idempotency_key,
            request_digest=receipt.request_digest,
        )

    async def _contain_best_effort(
        self,
        *,
        context: BoundCallContext,
        stock_call_id: str,
        category: FailureCategory,
    ) -> None:
        containment = ContainmentRequest(
            organization_id=context.organization_id,
            context=context,
            stock_call_id=stock_call_id,
            category=category,
        )
        try:
            await self._f12.request_containment(containment)
        except Exception:
            pass
        try:
            await self._stock.request_bounded_hangup(
                stock_call_id=stock_call_id,
                timeout_seconds=containment.bounded_hangup_seconds,
            )
        except Exception:
            pass


def _binding_matches_arm(
    request: G008HangupRequest, arm: G008InboundArmRequest
) -> bool:
    return (
        request.organization_id == arm.organization_id
        and request.execution_seal_uuid == arm.execution_seal_uuid
        and request.execution_nonce_digest == arm.execution_nonce_digest
        and request.candidate_digest == arm.candidate_digest
        and request.gate_envelope_digest == arm.gate_envelope_digest
    )

def outbound_create_request_digest(
    account_id: str, request: OuterCallCreateRequest
) -> str:
    """Canonical digest adapters must bind into a dispatch capability."""

    return _create_request_digest(account_id, request)


def canonical_model_digest(model: BaseModel) -> str:
    """Canonical digest for stock adapter idempotency acknowledgements."""

    return _digest(model)


def _create_request_digest(account_id: str, request: OuterCallCreateRequest) -> str:
    excluded = {"dispatch_capability"}
    if request.request_mode == "legacy":
        excluded.add("request_mode")
    payload = _model_payload(request, exclude=excluded)
    payload["account_id"] = account_id
    return _digest_payload(payload)


def _digest(model: BaseModel) -> str:
    return _digest_payload(_model_payload(model))


def _digest_payload(payload: object) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _model_payload(
    model: BaseModel, *, exclude: set[str] | None = None
) -> dict[str, object]:
    excluded = exclude or set()
    return {
        name: _json_value(value)
        for name, value in model.__dict__.items()
        if name not in excluded and value is not None
    }


def _json_value(value: object) -> object:
    if isinstance(value, SecretStr):
        return value.get_secret_value()
    if isinstance(value, BaseModel):
        return _model_payload(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _require_request_digest(model: BaseModel) -> None:
    supplied = getattr(model, "request_digest")
    calculated = _digest_payload(
        _model_payload(model, exclude={"request_digest"})
    )
    if supplied != calculated:
        raise FacadeError(FailureCategory.CONTRACT_MISMATCH, http_status=409)


def _validate_bind(
    receipt: StockCallBindReceipt,
    request: StockCallBindRequest,
) -> None:
    if (
        receipt.context != request.context
        or receipt.stock_call_id != request.stock_call_id
        or receipt.idempotency_key != request.idempotency_key
        or receipt.request_digest != request.request_digest
        or receipt.media_capability_issued is not False
    ):
        raise AuthorityClientError(FailureCategory.CONTRACT_MISMATCH)


def _auth_category(error: AuthenticationError) -> FailureCategory:
    if error.code == "expired":
        return FailureCategory.EXPIRED
    if "replay" in error.code:
        return FailureCategory.REPLAY
    if "mismatch" in error.code or "confusion" in error.code:
        return FailureCategory.CONTRACT_MISMATCH
    return FailureCategory.AUTHENTICATION_REJECTED


_STATUS_MAP = {
    "trying": CallStatus.STOCK_REQUESTED,
    "early-media": CallStatus.STOCK_BOUND,
    "queued": CallStatus.STOCK_REQUESTED,
    "initiated": CallStatus.STOCK_BOUND,
    "ringing": CallStatus.STOCK_BOUND,
    "answered": CallStatus.ANSWER_AUTHORITY_COMMITTED,
    "in-progress": CallStatus.RUNNING,
    "completed": CallStatus.COMPLETED,
    "busy": CallStatus.BUSY,
    "no-answer": CallStatus.NO_ANSWER,
    "failed": CallStatus.FAILED,
    "canceled": CallStatus.CANCELED,
}
_TERMINAL_STATUSES = frozenset(
    {
        CallStatus.COMPLETED,
        CallStatus.BUSY,
        CallStatus.NO_ANSWER,
        CallStatus.FAILED,
        CallStatus.CANCELED,
        CallStatus.CONTAINED,
    }
)


def _normalize_status(
    stock_status: str,
) -> tuple[CallStatus, FailureCategory | None]:
    normalized = _STATUS_MAP.get(stock_status.lower())
    if normalized is None:
        return CallStatus.FAILED, FailureCategory.INVALID_STOCK_EVENT
    return normalized, None


def _stock_event_nonce(
    operation: str, event: StockCallWebhook | StockCdrWebhook
) -> str:
    return _digest_payload(
        {
            "operation": operation,
            "event": _model_payload(event),
        }
    )


def _decode_base64url_signature(signature: str) -> bytes:
    try:
        encoded = signature.encode("ascii")
        decoded = base64.b64decode(encoded + b"==", altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise AuthenticationError("malformed_inbound_bind_signature") from exc
    if (
        len(decoded) != 64
        or b"=" in encoded
        or base64.urlsafe_b64encode(decoded).rstrip(b"=") != encoded
    ):
        raise AuthenticationError("malformed_inbound_bind_signature")
    return decoded

def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_stock_status(event: StockStatusEvent) -> NormalizedCallEvent:
    normalized = _STATUS_MAP.get(event.status.lower())
    category = None
    if normalized is None:
        normalized = CallStatus.FAILED
        category = FailureCategory.INVALID_STOCK_EVENT
    return NormalizedCallEvent(
        organization_id=event.organization_id,
        context=event.context,
        stock_call_id=event.stock_call_id,
        event_type=StockEventType.STATUS,
        normalized_status=normalized,
        occurred_at=event.event_time,
        event_nonce=event.event_nonce,
        idempotency_key=event.idempotency_key,
        request_digest=event.request_digest,
        duration_seconds=event.duration_seconds,
        redacted_cause_category=category,
    )


def normalize_stock_cdr(event: StockCdrEvent) -> NormalizedCallEvent:
    status = CallStatus.COMPLETED
    category = None
    if event.hangup_code:
        code = event.hangup_code.lower()
        if code in {"busy", "user_busy"}:
            status = CallStatus.BUSY
        elif code in {"no-answer", "no_answer"}:
            status = CallStatus.NO_ANSWER
        elif code not in {"normal", "normal_clearing", "completed"}:
            status = CallStatus.FAILED
            category = FailureCategory.INVALID_STOCK_EVENT
    return NormalizedCallEvent(
        organization_id=event.organization_id,
        context=event.context,
        stock_call_id=event.stock_call_id,
        event_type=StockEventType.CDR,
        normalized_status=status,
        occurred_at=event.ended_at,
        event_nonce=event.event_nonce,
        idempotency_key=event.idempotency_key,
        request_digest=event.request_digest,
        duration_seconds=event.duration_seconds,
        redacted_cause_category=category,
    )
