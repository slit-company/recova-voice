"""Amazon Connect telephony configuration schemas."""

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class AWSConnectConfigurationRequest(BaseModel):
    """Request schema for Amazon Connect outbound configuration."""

    provider: Literal["aws_connect"] = Field(default="aws_connect")
    region: str = Field(..., description="AWS region for the Amazon Connect instance")
    instance_id: str = Field(..., description="Amazon Connect instance ID")
    contact_flow_id: str = Field(
        ..., description="Published CONTACT_FLOW ID used by StartOutboundVoiceContact"
    )
    queue_id: Optional[str] = Field(
        default=None,
        description=(
            "Optional Amazon Connect queue ID. Recova preview calls prefer an "
            "explicit SourcePhoneNumber from the selected phone number row."
        ),
    )
    ring_timeout_seconds: Optional[int] = Field(
        default=None,
        ge=15,
        le=60,
        description=(
            "Optional ring timeout. Leave blank for the Amazon Connect default; "
            "some accounts require CAMPAIGN traffic to set a custom timer."
        ),
    )
    from_numbers: List[str] = Field(
        default_factory=list,
        description="E.164 Amazon Connect phone numbers managed by this config.",
    )


class AWSConnectConfigurationResponse(BaseModel):
    """Response schema for Amazon Connect configuration."""

    provider: Literal["aws_connect"] = Field(default="aws_connect")
    region: str
    instance_id: str
    contact_flow_id: str
    queue_id: Optional[str] = None
    ring_timeout_seconds: Optional[int] = None
    from_numbers: List[str] = Field(default_factory=list)
