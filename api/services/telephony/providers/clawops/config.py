"""ClawOps telephony configuration schemas."""

from typing import List, Literal

from pydantic import BaseModel, Field


class ClawOpsConfigurationRequest(BaseModel):
    """Request schema for ClawOps configuration."""

    provider: Literal["clawops"] = Field(default="clawops")
    account_id: str = Field(..., description="ClawOps Account ID")
    api_key: str = Field(..., description="ClawOps API key")
    signing_key: str = Field(
        ...,
        description="ClawOps webhook signing key from dashboard settings",
    )
    from_numbers: List[str] = Field(
        default_factory=list,
        description="List of ClawOps-owned Korean 070 numbers",
    )


class ClawOpsConfigurationResponse(BaseModel):
    """Response schema for ClawOps configuration with masked sensitive fields."""

    provider: Literal["clawops"] = Field(default="clawops")
    account_id: str
    api_key: str
    signing_key: str
    from_numbers: List[str]
