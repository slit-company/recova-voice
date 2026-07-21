from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from api.db.models import UserModel
from api.services.auth.depends import get_user
from api.services.phone_preview.service import phone_preview_service

router = APIRouter(prefix="/phone-preview")


async def get_phone_preview_user(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> UserModel:
    """Phone preview is an interactive canvas flow, not an API-key surface."""

    if request.headers.get("X-API-Key"):
        raise HTTPException(
            status_code=403, detail="phone_preview_requires_user_session"
        )
    return await get_user(authorization=authorization)


class PhonePreviewStartRequest(BaseModel):
    workflow_id: int
    phone_number: str = Field(..., min_length=3, max_length=40)
    display_name: str | None = Field(default=None, max_length=120)


class PhonePreviewVerifyRequest(BaseModel):
    session_id: int
    otp_code: str = Field(..., min_length=4, max_length=12)


class PhonePreviewCallRequest(BaseModel):
    session_id: int
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=200)
    manual_acknowledgement: str | None = Field(default=None, max_length=500)


class PhonePreviewContainRequest(BaseModel):
    session_id: int
    terminal_class: str = Field(..., min_length=1, max_length=100)
    terminal_reason: str = Field(..., min_length=1, max_length=500)


class PhonePreviewLatencySummary(BaseModel):
    workflow_run_id: int
    latency_profile: str | None = None
    user_stop_to_bot_started_ms: float | None = None
    stt_final_ms: float | None = None
    llm_ttfb_ms: float | None = None
    tts_ttfb_ms: float | None = None
    first_response_ms: float | None = None
    updated_at: str | None = None


class PhonePreviewResponse(BaseModel):
    session_id: int
    status: str
    otp_required: bool = False
    masked_phone: str
    expires_at: datetime
    workflow_run_id: int | None = None
    failure_reason: str | None = None
    dev_otp_code: str | None = None
    inbound_phone_number: str | None = None
    latency_summary: PhonePreviewLatencySummary | None = None
    gate_states: dict[str, bool] | None = None
    remaining_attempts: int | None = None
    proof_current: bool | None = None
    registration_fresh: bool | None = None
    media_fresh: bool | None = None
    contained: bool | None = None
    terminal_class: str | None = None


@router.post("/start", response_model=PhonePreviewResponse)
async def start_phone_preview(
    request: PhonePreviewStartRequest,
    user: UserModel = Depends(get_phone_preview_user),
):
    result = await phone_preview_service.start(
        user=user,
        workflow_id=request.workflow_id,
        phone_number=request.phone_number,
        display_name=request.display_name,
    )
    return result.as_dict()


@router.post("/verify", response_model=PhonePreviewResponse)
async def verify_phone_preview(
    request: PhonePreviewVerifyRequest,
    user: UserModel = Depends(get_phone_preview_user),
):
    result = await phone_preview_service.verify(
        user=user,
        session_id=request.session_id,
        otp_code=request.otp_code,
    )
    return result.as_dict()


@router.post("/call", response_model=PhonePreviewResponse)
async def call_phone_preview(
    request: PhonePreviewCallRequest,
    user: UserModel = Depends(get_phone_preview_user),
):
    result = await phone_preview_service.call(
        user=user,
        session_id=request.session_id,
        idempotency_key=request.idempotency_key,
        manual_acknowledgement=request.manual_acknowledgement,
    )
    return result.as_dict()


@router.post("/contain", response_model=PhonePreviewResponse)
async def contain_phone_preview(
    request: PhonePreviewContainRequest,
    user: UserModel = Depends(get_phone_preview_user),
):
    result = await phone_preview_service.contain(
        user=user,
        session_id=request.session_id,
        terminal_class=request.terminal_class,
        terminal_reason=request.terminal_reason,
    )
    return result.as_dict()

@router.post("/wait-inbound", response_model=PhonePreviewResponse)
async def wait_for_inbound_phone_preview(
    request: PhonePreviewCallRequest,
    user: UserModel = Depends(get_phone_preview_user),
):
    result = await phone_preview_service.wait_for_inbound(
        user=user, session_id=request.session_id
    )
    return result.as_dict()


@router.get("/status/{session_id}", response_model=PhonePreviewResponse)
async def get_phone_preview_status_by_status_path(
    session_id: int,
    user: UserModel = Depends(get_phone_preview_user),
):
    result = await phone_preview_service.status(user=user, session_id=session_id)
    return result.as_dict()


@router.get("/{session_id}", response_model=PhonePreviewResponse)
async def get_phone_preview_status(
    session_id: int,
    user: UserModel = Depends(get_phone_preview_user),
):
    result = await phone_preview_service.status(user=user, session_id=session_id)
    return result.as_dict()
