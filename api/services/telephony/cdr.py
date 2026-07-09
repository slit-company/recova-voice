"""First-class telephony event/CDR persistence and redaction helpers."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from loguru import logger

from api.db import db_client
from api.utils.phone_security import hash_phone_number, mask_phone_number


class TelephonyEventType(StrEnum):
    ADMISSION_ACQUIRED = "admission_acquired"
    ADMISSION_DENIED = "admission_denied"
    ADMISSION_RELEASED = "admission_released"
    INBOUND_REJECTED = "inbound_rejected"
    OUTBOUND_INITIATED = "outbound_initiated"
    INITIATE_FAILED = "initiate_failed"
    MEDIA_STARTED = "media_started"
    MEDIA_FAILED = "media_failed"
    STATUS_CALLBACK = "status_callback"
    TERMINAL_CDR = "terminal_cdr"
    ARTIFACT_MARKER = "artifact_marker"
    SLOT_LEAK = "slot_leak"


class TelephonyFailureCategory(StrEnum):
    NONE = "none"
    ADMISSION_CAPACITY = "admission_capacity"
    PROVIDER_INITIATE_FAILED = "provider_initiate_failed"
    PROVIDER_STATUS_FAILED = "provider_status_failed"
    SIGNATURE_FAILED = "signature_failed"
    ROUTE_NOT_FOUND = "route_not_found"
    WORKFLOW_NOT_BOUND = "workflow_not_bound"
    WORKFLOW_NOT_FOUND = "workflow_not_found"
    QUOTA_EXCEEDED = "quota_exceeded"
    MEDIA_STREAM_FAILED = "media_stream_failed"
    SLOT_LEAK = "slot_leak"
    SYSTEM_UNAVAILABLE = "system_unavailable"


TERMINAL_STATUSES = {"completed", "failed", "busy", "no-answer", "canceled", "error"}
FAILURE_STATUSES = {"failed", "error"}
NOT_CONNECTED_STATUSES = {"busy", "no-answer", "canceled"}


@dataclass(frozen=True)
class TelephonyEventRecord:
    provider: str
    direction: str
    event_type: TelephonyEventType
    status: str | None = None
    organization_id: int | None = None
    telephony_configuration_id: int | None = None
    telephony_phone_number_id: int | None = None
    inventory_id: int | None = None
    workflow_id: int | None = None
    workflow_run_id: int | None = None
    campaign_id: int | None = None
    queued_run_id: int | None = None
    call_attempt_id: str | None = None
    event_id: str | None = None
    provider_call_id: str | None = None
    from_number: str | None = None
    to_number: str | None = None
    failure_category: TelephonyFailureCategory | str | None = None
    release_reason: str | None = None
    admission_slot_id: str | None = None
    duration_seconds: int | None = None
    provider_payload: dict[str, Any] = field(default_factory=dict)
    artifact_payload: dict[str, Any] = field(default_factory=dict)
    contract_version: str | None = None
    is_contract_fixture: bool = False
    live_trunk_validated: bool = False
    occurred_at: datetime | None = None


@dataclass(frozen=True)
class TelephonyTerminalCDR:
    provider: str
    direction: str
    terminal_status: str
    organization_id: int | None = None
    telephony_configuration_id: int | None = None
    telephony_phone_number_id: int | None = None
    inventory_id: int | None = None
    workflow_id: int | None = None
    workflow_run_id: int | None = None
    campaign_id: int | None = None
    queued_run_id: int | None = None
    call_attempt_id: str | None = None
    provider_call_id: str | None = None
    from_number: str | None = None
    to_number: str | None = None
    failure_category: TelephonyFailureCategory | str | None = None
    release_reason: str | None = None
    admission_slot_id: str | None = None
    started_at: datetime | None = None
    answered_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: int | None = None
    provider_payload: dict[str, Any] = field(default_factory=dict)
    artifact_payload: dict[str, Any] = field(default_factory=dict)
    artifact_recording_expected: bool = False
    artifact_recording_present: bool = False
    artifact_transcript_expected: bool = False
    artifact_transcript_present: bool = False
    contract_version: str | None = None
    is_contract_fixture: bool = False
    live_trunk_validated: bool = False


def build_call_attempt_id(
    *,
    direction: str,
    provider: str | None = None,
    workflow_run_id: int | None = None,
    call_attempt_id: str | None = None,
    provider_call_id: str | None = None,
    event_id: str | None = None,
) -> str:
    if call_attempt_id:
        return call_attempt_id
    if workflow_run_id:
        return f"{direction}:workflow_run:{workflow_run_id}"
    if provider and provider_call_id:
        return f"{direction}:{provider}:{_sha256(provider_call_id)[:24]}"
    if event_id:
        return f"{direction}:event:{_sha256(event_id)[:24]}"
    return f"{direction}:pre_workflow:{uuid.uuid4().hex}"


def call_attempt_from_workflow_run(workflow_run) -> str:
    initial_context = getattr(workflow_run, "initial_context", None) or {}
    return build_call_attempt_id(
        direction=str(initial_context.get("direction") or getattr(workflow_run, "call_type", "outbound")),
        provider=str(initial_context.get("provider") or getattr(workflow_run, "mode", "unknown")),
        workflow_run_id=getattr(workflow_run, "id", None),
        call_attempt_id=initial_context.get("telephony_call_attempt_id"),
        provider_call_id=(getattr(workflow_run, "gathered_context", None) or {}).get("call_id"),
    )


async def record_telephony_event(record: TelephonyEventRecord):
    call_attempt_id = build_call_attempt_id(
        direction=record.direction,
        provider=record.provider,
        workflow_run_id=record.workflow_run_id,
        call_attempt_id=record.call_attempt_id,
        provider_call_id=record.provider_call_id,
        event_id=record.event_id,
    )
    event_id = record.event_id or _event_id(record, call_attempt_id)
    idempotency_key = f"event:{event_id}"
    payload = _shared_payload(record, call_attempt_id)
    return await db_client.record_telephony_call_event(
        **payload,
        event_id=event_id,
        event_type=record.event_type.value,
        status=record.status,
        occurred_at=record.occurred_at or datetime.now(UTC),
        idempotency_key=idempotency_key,
    )


async def record_terminal_cdr(cdr: TelephonyTerminalCDR):
    call_attempt_id = build_call_attempt_id(
        direction=cdr.direction,
        provider=cdr.provider,
        workflow_run_id=cdr.workflow_run_id,
        call_attempt_id=cdr.call_attempt_id,
        provider_call_id=cdr.provider_call_id,
    )
    idempotency_key = f"cdr:{call_attempt_id}:terminal"
    number_fields = _number_fields(cdr.from_number, cdr.to_number)
    return await db_client.upsert_telephony_cdr(
        call_attempt_id=call_attempt_id,
        idempotency_key=idempotency_key,
        organization_id=cdr.organization_id,
        telephony_configuration_id=cdr.telephony_configuration_id,
        telephony_phone_number_id=cdr.telephony_phone_number_id,
        inventory_id=cdr.inventory_id,
        workflow_id=cdr.workflow_id,
        workflow_run_id=cdr.workflow_run_id,
        campaign_id=cdr.campaign_id,
        queued_run_id=cdr.queued_run_id,
        provider=cdr.provider,
        provider_call_id_hash=_sha256(cdr.provider_call_id) if cdr.provider_call_id else None,
        direction=cdr.direction,
        terminal_status=cdr.terminal_status,
        failure_category=_failure_value(cdr.failure_category),
        release_reason=cdr.release_reason,
        admission_slot_id=cdr.admission_slot_id,
        started_at=cdr.started_at,
        answered_at=cdr.answered_at,
        completed_at=cdr.completed_at or datetime.now(UTC),
        duration_seconds=cdr.duration_seconds,
        artifact_recording_expected=cdr.artifact_recording_expected,
        artifact_recording_present=cdr.artifact_recording_present,
        artifact_transcript_expected=cdr.artifact_transcript_expected,
        artifact_transcript_present=cdr.artifact_transcript_present,
        artifact_payload=cdr.artifact_payload,
        provider_payload_redacted=redact_provider_payload(cdr.provider_payload),
        contract_version=cdr.contract_version,
        is_contract_fixture=cdr.is_contract_fixture,
        live_trunk_validated=cdr.live_trunk_validated,
        schema_version=1,
        **number_fields,
    )


async def record_status_event_and_terminal_cdr(workflow_run, status) -> None:
    initial_context = getattr(workflow_run, "initial_context", None) or {}
    gathered_context = getattr(workflow_run, "gathered_context", None) or {}
    provider = str(initial_context.get("provider") or getattr(workflow_run, "mode", "unknown"))
    direction = str(initial_context.get("direction") or getattr(workflow_run, "call_type", "outbound"))
    workflow_run_id = getattr(workflow_run, "id", None)
    call_attempt_id = call_attempt_from_workflow_run(workflow_run)
    terminal = status.status in TERMINAL_STATUSES
    failure_category = _category_for_status(status.status)
    is_contract_fixture = bool(initial_context.get("is_contract_fixture"))
    contract_version = initial_context.get("contract_version") or initial_context.get(
        "jambonz_contract_version"
    )
    live_trunk_validated = bool(initial_context.get("live_trunk_validated"))

    await record_telephony_event(
        TelephonyEventRecord(
            provider=provider,
            direction=direction,
            event_type=TelephonyEventType.TERMINAL_CDR if terminal else TelephonyEventType.STATUS_CALLBACK,
            status=status.status,
            organization_id=_workflow_org_id(workflow_run),
            telephony_configuration_id=initial_context.get("telephony_configuration_id"),
            telephony_phone_number_id=initial_context.get("from_phone_number_id"),
            workflow_id=getattr(workflow_run, "workflow_id", None),
            workflow_run_id=workflow_run_id,
            campaign_id=getattr(workflow_run, "campaign_id", None),
            queued_run_id=getattr(workflow_run, "queued_run_id", None),
            call_attempt_id=call_attempt_id,
            event_id=f"status:{workflow_run_id}:{status.call_id}:{status.status}:{status.duration or ''}",
            provider_call_id=status.call_id,
            from_number=status.from_number or initial_context.get("caller_number"),
            to_number=status.to_number or initial_context.get("called_number"),
            duration_seconds=_parse_duration(status.duration),
            failure_category=failure_category,
            provider_payload=status.extra,
            contract_version=contract_version,
            is_contract_fixture=is_contract_fixture,
            live_trunk_validated=live_trunk_validated,
        )
    )

    if terminal:
        expect_artifacts = status.status == "completed"
        await record_terminal_cdr(
            TelephonyTerminalCDR(
                provider=provider,
                direction=direction,
                terminal_status=status.status,
                organization_id=_workflow_org_id(workflow_run),
                telephony_configuration_id=initial_context.get("telephony_configuration_id"),
                telephony_phone_number_id=initial_context.get("from_phone_number_id"),
                workflow_id=getattr(workflow_run, "workflow_id", None),
                workflow_run_id=workflow_run_id,
                campaign_id=getattr(workflow_run, "campaign_id", None),
                queued_run_id=getattr(workflow_run, "queued_run_id", None),
                call_attempt_id=call_attempt_id,
                provider_call_id=status.call_id,
                from_number=status.from_number or initial_context.get("caller_number"),
                to_number=status.to_number or initial_context.get("called_number"),
                duration_seconds=_parse_duration(status.duration),
                failure_category=failure_category,
                provider_payload=status.extra,
                artifact_recording_expected=expect_artifacts,
                artifact_transcript_expected=expect_artifacts,
                contract_version=contract_version,
                is_contract_fixture=is_contract_fixture,
                live_trunk_validated=live_trunk_validated,
            )
        )


async def record_rejected_call(
    *,
    provider: str,
    direction: str,
    failure_category: TelephonyFailureCategory,
    status: str = "failed",
    organization_id: int | None = None,
    telephony_configuration_id: int | None = None,
    telephony_phone_number_id: int | None = None,
    workflow_id: int | None = None,
    workflow_run_id: int | None = None,
    campaign_id: int | None = None,
    queued_run_id: int | None = None,
    call_attempt_id: str | None = None,
    provider_call_id: str | None = None,
    from_number: str | None = None,
    to_number: str | None = None,
    provider_payload: dict[str, Any] | None = None,
    admission_slot_id: str | None = None,
    release_reason: str | None = None,
    contract_version: str | None = None,
    is_contract_fixture: bool = False,
) -> None:
    resolved_attempt_id = build_call_attempt_id(
        direction=direction,
        provider=provider,
        workflow_run_id=workflow_run_id,
        call_attempt_id=call_attempt_id,
        provider_call_id=provider_call_id,
    )
    await record_telephony_event(
        TelephonyEventRecord(
            provider=provider,
            direction=direction,
            event_type=TelephonyEventType.INBOUND_REJECTED
            if direction == "inbound"
            else TelephonyEventType.INITIATE_FAILED,
            status=status,
            organization_id=organization_id,
            telephony_configuration_id=telephony_configuration_id,
            telephony_phone_number_id=telephony_phone_number_id,
            workflow_id=workflow_id,
            workflow_run_id=workflow_run_id,
            campaign_id=campaign_id,
            queued_run_id=queued_run_id,
            call_attempt_id=resolved_attempt_id,
            event_id=f"rejected:{resolved_attempt_id}:{failure_category.value}:{status}",
            provider_call_id=provider_call_id,
            from_number=from_number,
            to_number=to_number,
            failure_category=failure_category,
            release_reason=release_reason,
            admission_slot_id=admission_slot_id,
            provider_payload=provider_payload or {},
            contract_version=contract_version,
            is_contract_fixture=is_contract_fixture,
        )
    )
    await record_terminal_cdr(
        TelephonyTerminalCDR(
            provider=provider,
            direction=direction,
            terminal_status=status,
            organization_id=organization_id,
            telephony_configuration_id=telephony_configuration_id,
            telephony_phone_number_id=telephony_phone_number_id,
            workflow_id=workflow_id,
            workflow_run_id=workflow_run_id,
            campaign_id=campaign_id,
            queued_run_id=queued_run_id,
            call_attempt_id=resolved_attempt_id,
            provider_call_id=provider_call_id,
            from_number=from_number,
            to_number=to_number,
            failure_category=failure_category,
            release_reason=release_reason,
            admission_slot_id=admission_slot_id,
            provider_payload=provider_payload or {},
            contract_version=contract_version,
            is_contract_fixture=is_contract_fixture,
        )
    )


async def mark_telephony_artifact(
    *, workflow_run_id: int, artifact_type: str, present: bool = True, expected: bool = True
) -> None:
    await db_client.mark_telephony_artifact(
        workflow_run_id=workflow_run_id,
        artifact_type=artifact_type,
        present=present,
        expected=expected,
    )


def live_readiness_eligible(cdr_row) -> bool:
    return bool(
        not getattr(cdr_row, "is_contract_fixture", True)
        and getattr(cdr_row, "live_trunk_validated", False)
    )


def redact_provider_payload(value: Any, *, key: object | None = None):
    if key is not None:
        key_text = str(key).lower()
        if key_text in _SENSITIVE_EXACT_KEYS or any(
            fragment in key_text for fragment in _SENSITIVE_FRAGMENTS
        ):
            return "[redacted]"
    if isinstance(value, dict):
        return {
            item_key: redact_provider_payload(item_value, key=item_key)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [redact_provider_payload(item) for item in value]
    return value


_SENSITIVE_EXACT_KEYS = {
    "account_sid",
    "accountsid",
    "authorization",
    "call_id",
    "call_sid",
    "callsid",
    "from",
    "provider_call_id",
    "proxy-authorization",
    "to",
}
_SENSITIVE_FRAGMENTS = (
    "account",
    "auth",
    "credential",
    "phone",
    "number",
    "destination",
    "caller",
    "called",
    "secret",
    "signature",
    "token",
)


def _shared_payload(record: TelephonyEventRecord, call_attempt_id: str) -> dict[str, Any]:
    return {
        "call_attempt_id": call_attempt_id,
        "organization_id": record.organization_id,
        "telephony_configuration_id": record.telephony_configuration_id,
        "telephony_phone_number_id": record.telephony_phone_number_id,
        "inventory_id": record.inventory_id,
        "workflow_id": record.workflow_id,
        "workflow_run_id": record.workflow_run_id,
        "campaign_id": record.campaign_id,
        "queued_run_id": record.queued_run_id,
        "provider": record.provider,
        "provider_call_id_hash": _sha256(record.provider_call_id)
        if record.provider_call_id
        else None,
        "direction": record.direction,
        "failure_category": _failure_value(record.failure_category),
        "release_reason": record.release_reason,
        "admission_slot_id": record.admission_slot_id,
        "duration_seconds": record.duration_seconds,
        "artifact_payload": record.artifact_payload,
        "provider_payload_redacted": redact_provider_payload(record.provider_payload),
        "contract_version": record.contract_version,
        "is_contract_fixture": record.is_contract_fixture,
        "live_trunk_validated": record.live_trunk_validated,
        "schema_version": 1,
        **_number_fields(record.from_number, record.to_number),
    }


def _number_fields(from_number: str | None, to_number: str | None) -> dict[str, str | None]:
    return {
        "from_number_masked": _mask(from_number),
        "from_number_hash": _hash_number(from_number),
        "to_number_masked": _mask(to_number),
        "to_number_hash": _hash_number(to_number),
    }


def _mask(number: str | None) -> str | None:
    if not number:
        return None
    return mask_phone_number(str(number))


def _hash_number(number: str | None) -> str | None:
    if not number:
        return None
    return hash_phone_number(str(number).strip())


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _failure_value(value: TelephonyFailureCategory | str | None) -> str | None:
    if value is None or value == TelephonyFailureCategory.NONE:
        return None
    return value.value if isinstance(value, TelephonyFailureCategory) else str(value)


def _category_for_status(status: str) -> TelephonyFailureCategory | None:
    if status in FAILURE_STATUSES:
        return TelephonyFailureCategory.PROVIDER_STATUS_FAILED
    if status in NOT_CONNECTED_STATUSES:
        return TelephonyFailureCategory.NONE
    return None


def _event_id(record: TelephonyEventRecord, call_attempt_id: str) -> str:
    parts = [
        record.event_type.value,
        call_attempt_id,
        record.provider_call_id or "no-provider-call-id",
        record.status or "no-status",
        str(record.occurred_at.timestamp()) if record.occurred_at else "no-ts",
    ]
    return _sha256(":".join(parts))


def _parse_duration(duration: Any) -> int | None:
    if duration in (None, ""):
        return None
    try:
        return int(float(duration))
    except (TypeError, ValueError):
        logger.debug(f"Unable to parse telephony duration: {duration}")
        return None


def _workflow_org_id(workflow_run) -> int | None:
    workflow = getattr(workflow_run, "workflow", None)
    if workflow is not None:
        return getattr(workflow, "organization_id", None)
    return None
