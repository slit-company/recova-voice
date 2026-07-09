"""Jambonz telephony configuration schemas."""

from typing import List, Literal

from pydantic import BaseModel, Field


class JambonzConfigurationRequest(BaseModel):
    """Request schema for Recova-owned Jambonz configuration."""

    provider: Literal["jambonz"] = Field(default="jambonz")
    base_url: str = Field(..., description="Jambonz REST API base URL")
    account_id: str = Field(..., description="Jambonz account identifier")
    application_id: str = Field(..., description="Jambonz application identifier")
    api_key: str = Field(..., description="Jambonz REST API key")
    webhook_secret: str = Field(..., description="Shared secret for signed callbacks")
    outbound_profile_id: str | None = Field(
        default=None, description="Optional Jambonz outbound SIP profile identifier"
    )
    from_numbers: List[str] = Field(
        default_factory=list,
        description="Assigned Recova 070 caller IDs managed by operators",
    )


class JambonzConfigurationResponse(BaseModel):
    """Response schema for Jambonz configuration with masked sensitive fields."""

    provider: Literal["jambonz"] = Field(default="jambonz")
    base_url: str
    account_id: str
    application_id: str
    api_key: str
    webhook_secret: str
    outbound_profile_id: str | None = None
    from_numbers: List[str]
