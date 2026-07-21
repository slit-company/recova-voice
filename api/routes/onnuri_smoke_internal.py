"""Non-public facade/runtime routes for the Onnuri classified smoke flow.

The deployment contract requires the trusted proxy to remove all incoming F12
identity headers and re-inject them only after successful client-certificate
verification. This router must never be exposed directly to external traffic.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from api.schemas.onnuri_smoke import (
    AcceptFacadeCallbackRequest,
    ClaimReservedInboundAndBindRequest,
    ClaimReservedInboundAndBindResponse,
    CommitInboundAnswerIntentAndMintMediaRequest,
    ConsumeDispatchRequest,
    ConsumeMediaRequest,
    FacadeAuthorityReadiness,
    EmergencyUnregisterRequest,
    ExecutionContainRequest,
    ExecutionEvidenceFinalizeRequest,
    ExecutionSealReceipt,
    ExecutionNonceConsumeReceipt,
    G008AuthorityReceipt,

    ExecutionNonceConsumeRequest,
    ExecutionSealRequest,
    ExecutionStageFinalizeRequest,
    ExecutionStageReceipt,
    ExecutionStageStatusRequest,
    ExecutionStageStartRequest,
    FacadeBoundCallStatusRequest,
    FacadeBoundCallStatusResponse,
    MediaAuthorityReceipt,
    RecordAnswerAndMintMediaRequest,
    RegistrationAuthorization,
    RegistrationBeginRequest,
    RegistrationConsumeRequest,
    RegistrationConsumeResponse,
    RegistrationFinalizeRequest,
    RegistrationTerminalReceipt,
    RedactedSmokeStatus,
    RequestFacadeContainment,
    SetTerminalRequest,
    SmokeReceipt,
    StockCallBindReceipt,
    StockCallBindRequest,
)
from api.services.telephony.providers.jambonz.facade.models import (
    CallbackReceipt,
    DispatchConsumeReceipt,
    RouteChainCapability,
    RouteChainCapabilityRequest,
)
from api.services import onnuri_smoke_f12

onnuri_smoke_f12.validate_startup_configuration()

router = APIRouter(
    prefix="/internal/onnuri-smoke",
    tags=["internal-onnuri-smoke"],
    include_in_schema=False,
)

_IDENTITY_HEADER = b"x-recova-verified-mtls-identity"
_ISSUER_HEADER = b"x-recova-verified-mtls-issuer"
_CREDENTIAL_HEADER = b"x-recova-onnuri-endpoint-credential"
_FORBIDDEN_HEADERS = {b"authorization", b"cookie", b"x-api-key"}


def _single_header(request: Request, name: bytes) -> str:
    values = [value for key, value in request.scope.get("headers", ()) if key.lower() == name]
    if len(values) != 1:
        raise HTTPException(status_code=401, detail="onnuri_smoke_f12_unauthorized")
    value = values[0].decode("latin-1").strip()
    if not value:
        raise HTTPException(status_code=401, detail="onnuri_smoke_f12_unauthorized")
    return value


def require_f12_caller(request: Request) -> onnuri_smoke_f12.F12Caller:
    if any(key.lower() in _FORBIDDEN_HEADERS for key, _ in request.scope.get("headers", ())):
        raise HTTPException(status_code=401, detail="onnuri_smoke_f12_unauthorized")
    try:
        return onnuri_smoke_f12.authenticate(
            identity=_single_header(request, _IDENTITY_HEADER),
            issuer=_single_header(request, _ISSUER_HEADER),
            credential=_single_header(request, _CREDENTIAL_HEADER),
        )
    except onnuri_smoke_f12.F12ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc


def _raise_f12(exc: onnuri_smoke_f12.F12ServiceError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc


def _authorize_payload(
    caller: onnuri_smoke_f12.F12Caller, payload: object
) -> None:
    organization_id = getattr(payload, "organization_id", None)
    context = getattr(payload, "context", None)
    if organization_id is None and context is not None:
        organization_id = getattr(context, "organization_id", None)
    try:
        caller.authorize(organization_id)
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.post("/route-chain/capability", response_model=RouteChainCapability)
async def mint_route_chain_capability(
    payload: RouteChainCapabilityRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> RouteChainCapability:
    _authorize_payload(_caller, payload.context)
    try:
        return await onnuri_smoke_f12.mint_route_chain_capability(
            **payload.model_dump(mode="python")
        )
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


def _dispatch_wire_response(receipt: DispatchConsumeReceipt) -> JSONResponse:
    content = receipt.model_dump(mode="json", exclude={"signature"})
    content["signature"] = receipt.signature.get_secret_value()
    return JSONResponse(content=content)


def _media_wire_response(receipt: MediaAuthorityReceipt) -> JSONResponse:
    content = receipt.model_dump(mode="json", exclude={"opaque_media_capability"})
    content["opaque_media_capability"] = (
        receipt.opaque_media_capability.get_secret_value()
    )
    return JSONResponse(content=content)



@router.post("/execution/nonce/consume", response_model=ExecutionNonceConsumeReceipt)
async def consume_execution_nonce(
    payload: ExecutionNonceConsumeRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> ExecutionNonceConsumeReceipt:
    _authorize_payload(_caller, payload)
    try:
        return ExecutionNonceConsumeReceipt.model_validate(
            await onnuri_smoke_f12.consume_execution_nonce(
                **payload.model_dump(mode="python")
            )
        )
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.post(
    "/execution/seal",
    response_model=G008AuthorityReceipt | ExecutionSealReceipt,
)
async def create_execution_seal(
    payload: ExecutionSealRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> dict[str, object]:
    _authorize_payload(_caller, payload)
    try:
        return await onnuri_smoke_f12.create_execution_seal(**payload.model_dump())
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.post(
    "/execution/stage/start",
    response_model=G008AuthorityReceipt | ExecutionStageReceipt,
)
async def start_execution_stage(
    payload: ExecutionStageStartRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> dict[str, object]:
    _authorize_payload(_caller, payload)
    try:
        return await onnuri_smoke_f12.start_execution_stage(**payload.model_dump())
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.post(
    "/execution/stage/finalize",
    response_model=G008AuthorityReceipt | ExecutionStageReceipt,
)
async def finalize_execution_stage(
    payload: ExecutionStageFinalizeRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> dict[str, object]:
    _authorize_payload(_caller, payload)
    try:
        return await onnuri_smoke_f12.finalize_execution_stage(**payload.model_dump())
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.post(
    "/execution/stage/status",
    response_model=G008AuthorityReceipt | ExecutionStageReceipt,
)
async def execution_stage_status(
    payload: ExecutionStageStatusRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> dict[str, object]:
    _authorize_payload(_caller, payload)
    try:
        return await onnuri_smoke_f12.execution_stage_status(**payload.model_dump())
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.post(
    "/execution/finalize-evidence",
    response_model=G008AuthorityReceipt | ExecutionSealReceipt,
)
async def finalize_execution_evidence(
    payload: ExecutionEvidenceFinalizeRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> dict[str, object]:
    _authorize_payload(_caller, payload)
    try:
        return await onnuri_smoke_f12.finalize_execution_evidence(**payload.model_dump())
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.post(
    "/execution/contain",
    response_model=G008AuthorityReceipt | ExecutionSealReceipt,
)
async def contain_execution(
    payload: ExecutionContainRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> dict[str, object]:
    _authorize_payload(_caller, payload)
    try:
        return await onnuri_smoke_f12.contain_execution(**payload.model_dump())
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.post(
    "/claim-reserved-inbound-and-bind",
    response_model=ClaimReservedInboundAndBindResponse,
)
async def claim_reserved_inbound_and_bind(
    payload: ClaimReservedInboundAndBindRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> ClaimReservedInboundAndBindResponse:
    _authorize_payload(_caller, payload)
    try:
        return ClaimReservedInboundAndBindResponse.model_validate(
            await onnuri_smoke_f12.claim_reserved_inbound_and_bind(
                organization_id=payload.organization_id,
                account_uuid=payload.account_id,
                application_uuid=payload.application_id,
                stock_call_uuid=payload.stock_call_id,
                did_digest=payload.did_digest,
                caller_digest=payload.caller_digest,
            )
        )
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)

@router.post(
    "/registration/emergency-unregister",
    response_model=RegistrationAuthorization,
)
async def emergency_unregister(
    payload: EmergencyUnregisterRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> RegistrationAuthorization:
    _authorize_payload(_caller, payload)
    try:
        return RegistrationAuthorization.model_validate(
            await onnuri_smoke_f12.emergency_unregister(
                **payload.model_dump(mode="python")
            )
        )
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)

@router.post("/registration/begin", response_model=RegistrationAuthorization)
async def begin_registration(
    payload: RegistrationBeginRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> RegistrationAuthorization:
    _authorize_payload(_caller, payload)
    try:
        return RegistrationAuthorization.model_validate(
            await onnuri_smoke_f12.begin_registration(**payload.model_dump())
        )
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)

@router.post("/registration/consume", response_model=RegistrationConsumeResponse)
async def consume_registration(
    payload: RegistrationConsumeRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> RegistrationConsumeResponse:
    _authorize_payload(_caller, payload)
    try:
        return RegistrationConsumeResponse.model_validate(
            await onnuri_smoke_f12.consume_registration(**payload.model_dump())
        )
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.post("/registration/finalize", response_model=RegistrationTerminalReceipt)
async def finalize_registration(
    payload: RegistrationFinalizeRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> RegistrationTerminalReceipt:
    try:
        return RegistrationTerminalReceipt.model_validate(
            await onnuri_smoke_f12.finalize_registration(
                opaque_execution_attestation=payload.opaque_execution_attestation,
                caller=_caller,
            )
        )
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)
@router.post("/ready", response_model=FacadeAuthorityReadiness)
async def ready(
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> FacadeAuthorityReadiness:
    return FacadeAuthorityReadiness(ready=await onnuri_smoke_f12.authority_ready())


@router.post("/bound-call-status", response_model=FacadeBoundCallStatusResponse)
async def bound_call_status(
    payload: FacadeBoundCallStatusRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> FacadeBoundCallStatusResponse:
    _authorize_payload(_caller, payload)
    try:
        return await onnuri_smoke_f12.get_bound_call_status(**payload.model_dump())
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.post("/normalized-event", response_model=CallbackReceipt)
async def normalized_event(
    payload: AcceptFacadeCallbackRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> CallbackReceipt:
    _authorize_payload(_caller, payload)
    try:
        return await onnuri_smoke_f12.accept_call_event(
            context=payload.context,
            event_nonce_digest=payload.event_nonce_digest,
            idempotency_key=payload.idempotency_key,
            request_digest=payload.request_digest,
            event_type=payload.event_type.value,
            normalized_status=payload.normalized_status.value,
            occurred_at=payload.occurred_at,
            duration_seconds=payload.duration_seconds,
            redacted_cause_category=(
                payload.redacted_cause_category.value
                if payload.redacted_cause_category is not None
                else None
            ),
        )
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.post("/containment", response_model=SmokeReceipt)
async def containment(
    payload: RequestFacadeContainment,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> SmokeReceipt:
    _authorize_payload(_caller, payload)
    try:
        return SmokeReceipt.model_validate(
            await onnuri_smoke_f12.request_call_containment(
                context=payload.context, category=payload.category
            )
        )
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)



@router.post("/consume-dispatch", response_model=DispatchConsumeReceipt)
async def consume_dispatch(
    payload: ConsumeDispatchRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> JSONResponse:
    _authorize_payload(_caller, payload)
    try:
        receipt = DispatchConsumeReceipt.model_validate(
            await onnuri_smoke_f12.consume_dispatch(**payload.model_dump())
        )
        return _dispatch_wire_response(receipt)
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.post("/bind-stock-call", response_model=StockCallBindReceipt)
async def bind_stock_call(
    payload: StockCallBindRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> StockCallBindReceipt:
    _authorize_payload(_caller, payload)
    try:
        return await onnuri_smoke_f12.bind_stock_call(payload)
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.post("/record-answer-and-mint-media", response_model=MediaAuthorityReceipt)
async def record_answer_and_mint_media(
    payload: RecordAnswerAndMintMediaRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> JSONResponse:
    _authorize_payload(_caller, payload)
    try:
        receipt = MediaAuthorityReceipt.model_validate(
            await onnuri_smoke_f12.record_answer_and_mint_media(**payload.model_dump())
        )
        return _media_wire_response(receipt)
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.post(
    "/commit-inbound-answer-intent-and-mint-media",
    response_model=MediaAuthorityReceipt,
)
async def commit_inbound_answer_intent_and_mint_media(
    payload: CommitInboundAnswerIntentAndMintMediaRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> JSONResponse:
    _authorize_payload(_caller, payload)
    try:
        receipt = MediaAuthorityReceipt.model_validate(
            await onnuri_smoke_f12.commit_inbound_answer_intent_and_mint_media(
                **payload.model_dump()
            )
        )
        return _media_wire_response(receipt)
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.post("/consume-media", response_model=SmokeReceipt)
async def consume_media(
    payload: ConsumeMediaRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> SmokeReceipt:
    _authorize_payload(_caller, payload)
    try:
        return SmokeReceipt.model_validate(
            await onnuri_smoke_f12.consume_media(**payload.model_dump())
        )
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.post("/terminal", response_model=SmokeReceipt)
async def set_terminal(
    payload: SetTerminalRequest,
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> SmokeReceipt:
    _authorize_payload(_caller, payload)
    try:
        return SmokeReceipt.model_validate(
            await onnuri_smoke_f12.set_terminal(**payload.model_dump())
        )
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)


@router.get("/status/{envelope_uuid}", response_model=RedactedSmokeStatus)
async def redacted_status(
    envelope_uuid: str,
    organization_id: int = Query(gt=0),
    _caller: onnuri_smoke_f12.F12Caller = Depends(require_f12_caller),
) -> RedactedSmokeStatus:
    try:
        _caller.authorize(organization_id)
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)
    try:
        return RedactedSmokeStatus.model_validate(
            await onnuri_smoke_f12.redacted_status(
                envelope_uuid, organization_id=organization_id
            )
        )
    except onnuri_smoke_f12.F12ServiceError as exc:
        _raise_f12(exc)
