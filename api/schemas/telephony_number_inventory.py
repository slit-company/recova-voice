"""Schemas for Recova-managed telephony number inventory."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TelephonyNumberInventoryStatus(str, Enum):
    AVAILABLE = "available"
    RESERVED = "reserved"
    ASSIGNED = "assigned"
    QUARANTINED = "quarantined"
    RETIRED = "retired"


class TelephonyNumberInventoryImportItem(BaseModel):
    address: str = Field(..., min_length=1, max_length=255)
    provider: str = Field(default="jambonz", min_length=1, max_length=32)
    country_code: str | None = Field(default="KR", min_length=2, max_length=2)
    label: str | None = Field(default=None, max_length=64)
    trunk_group: str | None = Field(default=None, max_length=64)
    extra_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("provider")
    @classmethod
    def _normalize_provider(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("country_code")
    @classmethod
    def _normalize_country_code(cls, value: str | None) -> str | None:
        return value.upper() if value else None


class TelephonyNumberInventoryImportRequest(BaseModel):
    numbers: list[TelephonyNumberInventoryImportItem] = Field(..., min_length=1)


class TelephonyNumberInventorySkippedItem(BaseModel):
    provider: str
    address_masked: str
    reason: str
    inventory_id: int | None = None


class TelephonyNumberInventoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    provider: str
    trunk_group: str | None = None
    organization_id: int | None = None
    telephony_configuration_id: int | None = None
    telephony_phone_number_id: int | None = None
    address_masked: str | None = None
    address_type: str
    country_code: str | None = None
    label: str | None = None
    status: TelephonyNumberInventoryStatus
    reservation_expires_at: datetime | None = None
    quarantined_reason: str | None = None
    retired_reason: str | None = None
    extra_metadata: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class TelephonyNumberInventoryImportResponse(BaseModel):
    imported: list[TelephonyNumberInventoryResponse]
    skipped: list[TelephonyNumberInventorySkippedItem]


class TelephonyNumberInventoryListResponse(BaseModel):
    numbers: list[TelephonyNumberInventoryResponse]
    total_count: int
    limit: int
    offset: int


class TelephonyNumberInventoryReserveRequest(BaseModel):
    organization_id: int
    reservation_expires_at: datetime | None = None
    note: str | None = Field(default=None, max_length=500)


class TelephonyNumberInventoryAssignRequest(BaseModel):
    organization_id: int
    telephony_configuration_id: int | None = None
    inbound_workflow_id: int | None = None
    label: str | None = Field(default=None, max_length=64)
    set_default_caller_id: bool = False
    note: str | None = Field(default=None, max_length=500)


class TelephonyNumberInventoryStateChangeRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=500)


class TelephonyNumberInventoryAuditResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    inventory_id: int
    actor_user_id: int | None = None
    organization_id: int | None = None
    action: str
    from_status: str | None = None
    to_status: str | None = None
    details: dict[str, Any]
    created_at: datetime


class TelephonyNumberInventoryAuditListResponse(BaseModel):
    audit: list[TelephonyNumberInventoryAuditResponse]


class CustomerAssignedNumberResponse(BaseModel):
    inventory_id: int
    provider: str
    address_masked: str | None = None
    address_type: str
    country_code: str | None = None
    label: str | None = None
    status: TelephonyNumberInventoryStatus
    telephony_configuration_id: int | None = None
    telephony_phone_number_id: int | None = None
    inbound_workflow_id: int | None = None
    inbound_workflow_name: str | None = None
    is_active: bool
    is_default_caller_id: bool
    created_at: datetime
    updated_at: datetime


class CustomerAssignedNumberListResponse(BaseModel):
    numbers: list[CustomerAssignedNumberResponse]


class CustomerAssignedNumberBindRequest(BaseModel):
    workflow_id: int
