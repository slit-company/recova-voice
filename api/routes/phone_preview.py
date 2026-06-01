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
    result = await phone_preview_service.call(user=user, session_id=request.session_id)
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
