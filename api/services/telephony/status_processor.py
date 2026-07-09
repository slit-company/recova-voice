"""Provider-agnostic call status processing.

Extracted from ``api/routes/telephony.py`` so that per-provider route
modules can import the processor and normalized request type without
introducing a circular import on the routes module.
"""

from datetime import UTC, datetime
from typing import Optional

from loguru import logger
from pydantic import BaseModel

from api.db import db_client
from api.enums import WorkflowRunState
from api.services.campaign.campaign_call_dispatcher import campaign_call_dispatcher
from api.services.campaign.campaign_event_publisher import (
    get_campaign_event_publisher,
)
from api.services.campaign.circuit_breaker import circuit_breaker
from api.services.telephony.admission import telephony_admission_controller
from api.services.telephony.cdr import record_status_event_and_terminal_cdr
from api.services.telephony.ops_alerts import (
    TelephonyOpsAlert,
    TelephonyOpsAlertSeverity,
    TelephonyOpsAlertType,
    telephony_ops_alert_sink,
)

_PREVIEW_CALLBACK_SENSITIVE_EXACT_KEYS = {
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
_PREVIEW_CALLBACK_SENSITIVE_FRAGMENTS = (
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

_TELEPHONY_LOG_SENSITIVE_EXACT_KEYS = {
    *(_PREVIEW_CALLBACK_SENSITIVE_EXACT_KEYS),
    "authorization",
    "proxy-authorization",
}
_TELEPHONY_LOG_SENSITIVE_FRAGMENTS = (
    *(_PREVIEW_CALLBACK_SENSITIVE_FRAGMENTS),
    "account",
    "auth",
    "secret",
    "signature",
)


def _is_preview_run(workflow_run) -> bool:
    initial_context = getattr(workflow_run, "initial_context", None) or {}
    if not isinstance(initial_context, dict):
        return False
    return bool(
        initial_context.get("telephony_preview")
        or initial_context.get("preview_session_id")
    )


def _callback_key_is_sensitive(key: object) -> bool:
    key_text = str(key).lower()
    return key_text in _PREVIEW_CALLBACK_SENSITIVE_EXACT_KEYS or any(
        fragment in key_text for fragment in _PREVIEW_CALLBACK_SENSITIVE_FRAGMENTS
    )


def _redact_preview_callback_extra(value, *, key: object | None = None):
    if key is not None and _callback_key_is_sensitive(key):
        return "[redacted]"
    if isinstance(value, dict):
        return {
            item_key: _redact_preview_callback_extra(item_value, key=item_key)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_preview_callback_extra(item) for item in value]
    return value


def redact_telephony_payload_for_logs(value, *, key: object | None = None):
    """Return a log-safe copy of provider webhook payload/header data.

    Provider callback routes may log payloads before signature verification, so
    logging redaction cannot depend on knowing whether the run is a Recova
    preview. Keep durable DB audit behavior in ``_process_status_update``
    unchanged, but never emit raw caller/called numbers or credentials to app
    logs from webhook entrypoints.
    """

    if key is not None:
        key_text = str(key).lower()
        if key_text in _TELEPHONY_LOG_SENSITIVE_EXACT_KEYS or any(
            fragment in key_text for fragment in _TELEPHONY_LOG_SENSITIVE_FRAGMENTS
        ):
            return "[redacted]"
    if isinstance(value, dict):
        return {
            item_key: redact_telephony_payload_for_logs(item_value, key=item_key)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [redact_telephony_payload_for_logs(item) for item in value]
    return value


async def _update_preview_session_from_status(
    workflow_run_id: int, *, preview_status: str, failure_reason: str | None = None
) -> None:
    preview_session = await db_client.get_phone_preview_session_for_run(workflow_run_id)
    if not preview_session:
        return
    await db_client.update_phone_preview_session_status(
        preview_session.id,
        status=preview_status,
        failure_reason=failure_reason,
        completed=preview_status == "completed",
    )


class StatusCallbackRequest(BaseModel):
    """Normalized status callback shape used across all telephony providers.

    Per-provider converters live as classmethods (``from_twilio``, ``from_plivo``,
    ``from_vonage``, ``from_cloudonix_cdr``) so the route handler for each
    provider can map raw webhook payloads into this shape and hand off to
    :func:`_process_status_update`.
    """

    call_id: str
    status: str
    from_number: Optional[str] = None
    to_number: Optional[str] = None
    direction: Optional[str] = None
    duration: Optional[str] = None

    extra: dict = {}

    @classmethod
    def from_twilio(cls, data: dict):
        """Convert Twilio callback to generic format."""
        return cls(
            call_id=data.get("CallSid", ""),
            status=data.get("CallStatus", ""),
            from_number=data.get("From"),
            to_number=data.get("To"),
            direction=data.get("Direction"),
            duration=data.get("CallDuration") or data.get("Duration"),
            extra=data,
        )

    @classmethod
    def from_plivo(cls, data: dict):
        """Convert Plivo callback to generic format."""
        status_map = {
            "in-progress": "answered",
            "ringing": "ringing",
            "ring": "ringing",
            "completed": "completed",
            "hangup": "completed",
            "stopstream": "completed",
            "busy": "busy",
            "no-answer": "no-answer",
            "cancel": "canceled",
            "cancelled": "canceled",
            "timeout": "no-answer",
        }
        call_status = (data.get("CallStatus") or data.get("Event") or "").lower()
        return cls(
            call_id=data.get("CallUUID", "") or data.get("RequestUUID", ""),
            status=status_map.get(call_status, call_status),
            from_number=data.get("From"),
            to_number=data.get("To"),
            direction=data.get("Direction"),
            duration=data.get("Duration"),
            extra=data,
        )

    @classmethod
    def from_vonage(cls, data: dict):
        """Convert Vonage event to generic format."""
        status_map = {
            "started": "initiated",
            "ringing": "ringing",
            "answered": "answered",
            "complete": "completed",
            "failed": "failed",
            "busy": "busy",
            "timeout": "no-answer",
            "rejected": "busy",
        }

        return cls(
            call_id=data.get("uuid", ""),
            status=status_map.get(data.get("status", ""), data.get("status", "")),
            from_number=data.get("from"),
            to_number=data.get("to"),
            direction=data.get("direction"),
            duration=data.get("duration"),
            extra=data,
        )

    @classmethod
    def from_cloudonix_cdr(cls, data: dict):
        """Convert Cloudonix CDR to generic format."""
        disposition_map = {
            "ANSWER": "completed",
            "BUSY": "busy",
            "CANCEL": "canceled",
            "FAILED": "failed",
            "CONGESTION": "failed",
            "NOANSWER": "no-answer",
        }

        disposition = data.get("disposition", "")
        status = disposition_map.get(disposition.upper(), disposition.lower())

        return cls(
            call_id=data.get("session").get("token"),
            status=status,
            from_number=data.get("from"),
            to_number=data.get("to"),
            duration=str(data.get("billsec") or data.get("duration") or 0),
            extra=data,
        )


async def _process_status_update(workflow_run_id: int, status: StatusCallbackRequest):
    """Process status updates from telephony providers.

    Idempotent: handles repeated callbacks (e.g. from both webhook and CDR).
    """
    workflow_run = await db_client.get_workflow_run_by_id(workflow_run_id)
    if not workflow_run:
        logger.warning(
            f"[run {workflow_run_id}] Workflow run not found in status update"
        )
        return

    telephony_callback_logs = workflow_run.logs.get("telephony_status_callbacks", [])
    telephony_callback_log = {
        "status": status.status,
        "timestamp": datetime.now(UTC).isoformat(),
        "call_id": "[redacted]" if _is_preview_run(workflow_run) else status.call_id,
        "duration": status.duration,
        **(
            _redact_preview_callback_extra(status.extra)
            if _is_preview_run(workflow_run)
            else status.extra
        ),
    }
    telephony_callback_logs.append(telephony_callback_log)

    await db_client.update_workflow_run(
        run_id=workflow_run_id,
        logs={"telephony_status_callbacks": telephony_callback_logs},
    )
    try:
        await record_status_event_and_terminal_cdr(workflow_run, status)
    except Exception as e:
        logger.error(
            f"[run {workflow_run_id}] Failed to persist telephony status/CDR: {e}"
        )

    if status.status in ["completed", "failed", "busy", "no-answer", "canceled", "error"]:
        try:
            await telephony_admission_controller.release(
                workflow_run_id=workflow_run_id,
                reason=status.status,
            )
        except Exception as e:
            logger.error(
                f"[run {workflow_run_id}] Failed to release telephony admission slot: {e}"
            )


    if status.status == "completed":
        logger.info(
            f"[run {workflow_run_id}] Call completed with duration: {status.duration}s"
        )

        if workflow_run.campaign_id:
            await campaign_call_dispatcher.release_call_slot(workflow_run_id)
            await circuit_breaker.record_and_evaluate(
                workflow_run.campaign_id, is_failure=False
            )

        if workflow_run.state != WorkflowRunState.COMPLETED.value:
            await db_client.update_workflow_run(
                run_id=workflow_run_id,
                is_completed=True,
                state=WorkflowRunState.COMPLETED.value,
            )
        await _update_preview_session_from_status(
            workflow_run_id, preview_status="completed"
        )

    elif status.status in ["failed", "busy", "no-answer", "canceled", "error"]:
        logger.warning(
            f"[run {workflow_run_id}] Call failed with status: {status.status}"
        )
        if status.status in ("error", "failed"):
            initial_context = workflow_run.initial_context or {}
            await telephony_ops_alert_sink.emit(
                TelephonyOpsAlert(
                    alert_type=TelephonyOpsAlertType.PROVIDER_STATUS_FAILURE,
                    severity=TelephonyOpsAlertSeverity.WARNING,
                    summary="Telephony provider reported terminal call failure",
                    organization_id=getattr(workflow_run.workflow, "organization_id", None),
                    provider=initial_context.get("provider") or workflow_run.mode,
                    source="contract_simulator"
                    if initial_context.get("is_contract_fixture")
                    else "runtime",
                    is_contract_fixture=bool(initial_context.get("is_contract_fixture")),
                    details={
                        "workflow_run_id": workflow_run_id,
                        "campaign_id": workflow_run.campaign_id,
                        "queued_run_id": workflow_run.queued_run_id,
                        "status": status.status,
                        "call_id": status.call_id,
                    },
                    dedupe_components=(status.status,),
                )
            )

        if workflow_run.campaign_id:
            await campaign_call_dispatcher.release_call_slot(workflow_run_id)
            is_failure = status.status in ("error", "failed")
            await circuit_breaker.record_and_evaluate(
                workflow_run.campaign_id,
                is_failure=is_failure,
                workflow_run_id=workflow_run_id if is_failure else None,
                reason=status.status if is_failure else None,
            )

        if status.status in ["busy", "no-answer"] and workflow_run.campaign_id:
            publisher = await get_campaign_event_publisher()
            await publisher.publish_retry_needed(
                workflow_run_id=workflow_run_id,
                reason=status.status.replace("-", "_"),
                campaign_id=workflow_run.campaign_id,
                queued_run_id=workflow_run.queued_run_id,
            )

        call_tags = (
            workflow_run.gathered_context.get("call_tags", [])
            if workflow_run.gathered_context
            else []
        )
        call_tags.extend(["not_connected", f"telephony_{status.status.lower()}"])

        await db_client.update_workflow_run(
            run_id=workflow_run_id,
            is_completed=True,
            state=WorkflowRunState.COMPLETED.value,
            gathered_context={"call_tags": call_tags},
        )
        await _update_preview_session_from_status(
            workflow_run_id,
            preview_status="failed",
            failure_reason=f"telephony_{status.status.lower()}",
        )
    elif status.status in ["in-progress", "initiated", "ringing"]:
        # No-op while the call is in flight.
        pass
    else:
        logger.warning(
            f"[run {workflow_run_id}] Unexpected status update: {status.status}"
        )
