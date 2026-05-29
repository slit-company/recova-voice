from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from api.db.models import UserModel
from api.services.auth.depends import get_user
from api.services.phone_preview.service import phone_preview_service

router = APIRouter(prefix="/phone-preview")


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
    provider_call_id: str | None = None
    failure_reason: str | None = None
    dev_otp_code: str | None = None


@router.post("/start", response_model=PhonePreviewResponse)
async def start_phone_preview(
    request: PhonePreviewStartRequest,
    user: UserModel = Depends(get_user),
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
    user: UserModel = Depends(get_user),
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
    user: UserModel = Depends(get_user),
):
    result = await phone_preview_service.call(user=user, session_id=request.session_id)
    return result.as_dict()


@router.get("/status/{session_id}", response_model=PhonePreviewResponse)
async def get_phone_preview_status_by_status_path(
    session_id: int,
    user: UserModel = Depends(get_user),
):
    result = await phone_preview_service.status(user=user, session_id=session_id)
    return result.as_dict()


@router.get("/{session_id}", response_model=PhonePreviewResponse)
async def get_phone_preview_status(
    session_id: int,
    user: UserModel = Depends(get_user),
):
    result = await phone_preview_service.status(user=user, session_id=session_id)
    return result.as_dict()
