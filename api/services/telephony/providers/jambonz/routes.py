"""Jambonz telephony routes (answer, status, CDR callbacks)."""

from __future__ import annotations

import json
import base64
import binascii
import re
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, WebSocket
from fastapi.responses import JSONResponse
from loguru import logger
from pipecat.utils.run_context import set_current_run_id

from api.db import db_client
from api.enums import WorkflowRunState
from api.services import onnuri_smoke_f12
from api.services.onnuri_smoke_capabilities import parse_media_capability
from api.services.telephony.factory import get_telephony_provider_for_run
from api.services.telephony.evidence_markers import (
    extract_telephony_evidence_markers,
    strip_untrusted_evidence_fields,
)
from api.services.telephony.status_processor import (
    StatusCallbackRequest,
    _process_status_update,
    redact_telephony_payload_for_logs,
)

router = APIRouter()
_MEDIA_CLAIM_KEYS = {
    "account_id",
    "application_id",
    "attempt_id",
    "authority_deadline",
    "callback_event_nonce",
    "candidate_digest",
    "contract_version",
    "direction",
    "gate_envelope_digest",
    "idempotency_key",
    "observed_event_wall_time",
    "organization_id",
    "request_digest",
    "run_id",
    "stock_call_id",
}
_POSITIVE_RUN_ID = re.compile(r"^[1-9][0-9]*$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


async def _reject_media(websocket: WebSocket, *, code: int = 4403) -> None:
    try:
        await websocket.close(code=code, reason="Jambonz media authority rejected")
    except RuntimeError:
        pass


def _basic_media_capability(websocket: WebSocket) -> bytes | None:
    authorization_values = [
        value
        for name, value in websocket.scope.get("headers", ())
        if name.lower() == b"authorization"
    ]
    if len(authorization_values) != 1:
        return None
    try:
        authorization = authorization_values[0].decode("ascii")
        scheme, encoded = authorization.split(" ", 1)
        if scheme.lower() != "basic" or not encoded or encoded.strip() != encoded:
            return None
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
        username, capability = decoded.split(":", 1)
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    if username != "recova-media" or not capability:
        return None
    return capability.encode("utf-8")


def _media_consume_values(opaque_capability: bytes) -> tuple[dict, dict] | None:
    try:
        parsed = parse_media_capability(opaque_capability)
        claims = parsed["claims"]
        if set(claims) != _MEDIA_CLAIM_KEYS:
            return None
        organization_id = claims["organization_id"]
        run_id = claims["run_id"]
        if (
            isinstance(organization_id, bool)
            or not isinstance(organization_id, int)
            or organization_id <= 0
            or not isinstance(run_id, str)
            or _POSITIVE_RUN_ID.fullmatch(run_id) is None
            or claims["direction"] not in {"inbound", "outbound"}
            or any(
                not isinstance(claims[key], str) or not claims[key]
                for key in (
                    "account_id",
                    "application_id",
                    "attempt_id",
                    "authority_deadline",
                    "callback_event_nonce",
                    "idempotency_key",
                    "observed_event_wall_time",
                    "stock_call_id",
                )
            )
            or any(
                not isinstance(claims[key], str)
                or _DIGEST.fullmatch(claims[key]) is None
                for key in (
                    "candidate_digest",
                    "gate_envelope_digest",
                    "request_digest",
                )
            )
        ):
            return None
        expires_at = datetime.fromisoformat(
            parsed["expires_at"].replace("Z", "+00:00")
        )
        observed_at = datetime.fromisoformat(
            claims["observed_event_wall_time"].replace("Z", "+00:00")
        )
        if (
            expires_at.tzinfo is None
            or expires_at.utcoffset() is None
            or observed_at.tzinfo is None
            or observed_at.utcoffset() is None
            or expires_at <= datetime.now(timezone.utc)
        ):
            return None
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    return claims, {
        "opaque_capability": opaque_capability,
        "attempt_uuid": claims["attempt_id"],
        "organization_id": organization_id,
        "account_id": claims["account_id"],
        "application_id": claims["application_id"],
        "run_id": run_id,
        "direction": claims["direction"],
        "idempotency_key": claims["idempotency_key"],
        "request_digest": claims["request_digest"],
        "stock_call_id": claims["stock_call_id"],
        "event_nonce": claims["callback_event_nonce"],
        "candidate_digest": claims["candidate_digest"],
        "gate_envelope_digest": claims["gate_envelope_digest"],
        "observed_wall_time": observed_at,
    }


def _stock_metadata_call_id(message: object) -> str | None:
    if not isinstance(message, dict):
        return None
    call_sid = message.get("callSid")
    if not isinstance(call_sid, str) or not call_sid:
        return None
    return call_sid


async def _run_media_pipeline(websocket: WebSocket, **kwargs) -> None:
    from api.services.pipecat.run_pipeline import run_pipeline_telephony

    await run_pipeline_telephony(websocket, **kwargs)


@router.websocket("/jambonz/onnuri-smoke/media")
async def handle_jambonz_onnuri_smoke_media(websocket: WebSocket) -> None:
    opaque_capability = _basic_media_capability(websocket)
    if opaque_capability is None:
        await _reject_media(websocket)
        return
    media = _media_consume_values(opaque_capability)
    if media is None:
        await _reject_media(websocket, code=4408)
        return
    claims, consume_values = media

    await websocket.accept()
    try:
        metadata = json.loads(await websocket.receive_text())
    except (json.JSONDecodeError, RuntimeError):
        await _reject_media(websocket)
        return
    call_id = _stock_metadata_call_id(metadata)
    if call_id != claims["stock_call_id"]:
        await _reject_media(websocket)
        return

    try:
        await onnuri_smoke_f12.consume_media(**consume_values)
    except Exception:
        await _reject_media(websocket)
        return

    workflow_run_id = int(claims["run_id"])
    workflow_run = await db_client.get_workflow_run_by_id(workflow_run_id)
    if workflow_run is None:
        await _reject_media(websocket)
        return
    workflow = await db_client.get_workflow_by_id(workflow_run.workflow_id)
    run_state = getattr(workflow_run.state, "value", workflow_run.state)
    call_type = getattr(workflow_run.call_type, "value", workflow_run.call_type)
    gathered_context = workflow_run.gathered_context or {}
    if (
        workflow is None
        or workflow_run.id != workflow_run_id
        or workflow_run.workflow_id != workflow.id
        or workflow.organization_id != claims["organization_id"]
        or workflow.user_id is None
        or workflow_run.is_completed
        or run_state != WorkflowRunState.INITIALIZED.value
        or str(call_type).lower() != claims["direction"]
        or str(gathered_context.get("call_id")) != call_id
    ):
        await _reject_media(websocket)
        return

    provider = await get_telephony_provider_for_run(
        workflow_run, workflow.organization_id
    )
    if (
        provider.PROVIDER_NAME != "jambonz"
        or provider.account_id != claims["account_id"]
        or provider.application_id != claims["application_id"]
    ):
        await _reject_media(websocket)
        return

    expires_at = datetime.fromisoformat(
        claims["authority_deadline"].replace("Z", "+00:00")
    ).astimezone(timezone.utc)
    remaining_seconds = min(
        60, int((expires_at - datetime.now(timezone.utc)).total_seconds())
    )
    if remaining_seconds <= 0:
        await _reject_media(websocket, code=4408)
        return
    await db_client.update_workflow_run(
        run_id=workflow_run_id, state=WorkflowRunState.RUNNING.value
    )
    set_current_run_id(workflow_run_id)
    await _run_media_pipeline(
        websocket,
        provider_name="jambonz",
        workflow_id=workflow.id,
        workflow_run_id=workflow_run_id,
        user_id=workflow.user_id,
        call_id=call_id,
        transport_kwargs={
            "stream_id": call_id,
            "call_id": call_id,
            "jambonz_sample_rate": 8000,
            "strict_authority": True,
            "authority_deadline": claims["authority_deadline"],
            "remaining_seconds": remaining_seconds,
        },
    )


async def _json_body_and_raw(request: Request) -> tuple[dict, str]:
    raw_body = (await request.body()).decode("utf-8", errors="replace")
    try:
        data = json.loads(raw_body) if raw_body else {}
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object")
    return data, raw_body
def _require_authority_binding(
    event_data: dict,
    *,
    workflow_run,
    provider,
    require_callback_nonce: bool,
) -> None:
    envelope = (
        event_data.get("data")
        if isinstance(event_data.get("data"), dict)
        else event_data
    )
    context = envelope.get("context")
    classified = isinstance(context, dict) or any(
        envelope.get(key)
        for key in (
            "run_id",
            "attempt_id",
            "event_nonce",
            "request_digest",
            "authority_receipt_id",
        )
    )
    if not classified:
        if envelope.get("is_contract_fixture") is True:
            return
        raise HTTPException(status_code=403, detail="jambonz_live_authority_required")

    if not isinstance(context, dict):
        context = envelope
    initial_context = workflow_run.initial_context or {}
    gathered_context = workflow_run.gathered_context or {}
    expected_attempt_id = (
        initial_context.get("telephony_call_attempt_id")
        or initial_context.get("smoke_attempt_uuid")
        or initial_context.get("application_attempt_id")
    )
    expected_call_id = gathered_context.get("call_id")
    expected_run_id = workflow_run.id
    direction_value = (
        initial_context.get("direction")
        or getattr(workflow_run, "call_type", "")
    )
    expected_direction = str(
        getattr(direction_value, "value", direction_value)
    ).lower()
    values = {
        "account_id": context.get("account_id"),
        "application_id": context.get("application_id"),
        "run_id": context.get("run_id"),
        "attempt_id": context.get("attempt_id"),
        "direction": context.get("direction"),
        "call_id": envelope.get("stock_call_id")
        or context.get("stock_call_id")
        or envelope.get("call_id"),
        "idempotency_key": envelope.get("idempotency_key"),
        "request_digest": envelope.get("request_digest"),
    }
    if require_callback_nonce:
        values["event_nonce"] = envelope.get("event_nonce")
    if any(not value for value in values.values()):
        raise HTTPException(
            status_code=403, detail="jambonz_authority_binding_incomplete"
        )
    if (
        values["account_id"] != provider.account_id
        or values["application_id"] != provider.application_id
        or str(values["run_id"]) != str(expected_run_id)
        or not expected_attempt_id
        or str(values["attempt_id"]) != str(expected_attempt_id)
        or not expected_call_id
        or str(values["call_id"]) != str(expected_call_id)
        or not expected_direction
        or str(values["direction"]).lower() != expected_direction
    ):
        raise HTTPException(
            status_code=403, detail="jambonz_authority_binding_mismatch"
        )



@router.post("/jambonz/answer", include_in_schema=False)
async def handle_jambonz_answer(
    workflow_id: int,
    user_id: int,
    workflow_run_id: int,
    organization_id: int,
    request: Request,
):
    """Answer URL for outbound Jambonz calls."""
    set_current_run_id(workflow_run_id)
    event_data, raw_body = await _json_body_and_raw(request)
    logger.info(
        f"[run {workflow_run_id}] Received Jambonz answer callback: "
        f"{json.dumps(redact_telephony_payload_for_logs(event_data))}"
    )

    workflow_run = await db_client.get_workflow_run_by_id(workflow_run_id)
    if not workflow_run:
        raise HTTPException(status_code=404, detail="Workflow run not found")
    if workflow_run.workflow_id != workflow_id:
        raise HTTPException(status_code=400, detail="workflow_run_workflow_mismatch")

    provider = await get_telephony_provider_for_run(workflow_run, organization_id)
    if provider.PROVIDER_NAME != "jambonz":
        raise HTTPException(status_code=400, detail="provider_mismatch")
    _require_authority_binding(
        event_data,
        workflow_run=workflow_run,
        provider=provider,
        require_callback_nonce=True,
    )

    is_valid = await provider.verify_inbound_signature(
        str(request.url), event_data, dict(request.headers), raw_body
    )
    if not is_valid:
        logger.warning(f"[run {workflow_run_id}] Invalid Jambonz answer signature")
        return provider.generate_error_response(
            "invalid_signature", "Invalid webhook signature."
        )

    markers = extract_telephony_evidence_markers(
        event_data,
        trusted_context={
            "provider": "jambonz",
            "telephony_configuration_id": (
                workflow_run.initial_context or {}
            ).get("telephony_configuration_id"),
            "telephony_phone_number_id": (
                workflow_run.initial_context or {}
            ).get("telephony_phone_number_id")
            or (workflow_run.initial_context or {}).get("from_phone_number_id"),
            "call_attempt_id": (workflow_run.initial_context or {}).get(
                "telephony_call_attempt_id"
            ),
        },
    )
    call_id = event_data.get("call_id") or event_data.get("callSid")
    stream_id = event_data.get("stream_id") or event_data.get("streamSid")
    if call_id or stream_id:
        gathered_context = dict(workflow_run.gathered_context or {})
        if call_id:
            gathered_context["call_id"] = call_id
        if stream_id:
            gathered_context["stream_id"] = stream_id
        gathered_context = {
            **strip_untrusted_evidence_fields(gathered_context),
            **markers.as_context(),
        }
        await db_client.update_workflow_run(
            run_id=workflow_run_id, gathered_context=gathered_context
        )

    response_content = await provider.get_webhook_response(
        workflow_id, user_id, workflow_run_id
    )
    return JSONResponse(content=response_content, media_type="application/json")


@router.post("/jambonz/status/{workflow_run_id}")
@router.post("/jambonz/cdr/{workflow_run_id}")
async def handle_jambonz_status(workflow_run_id: int, request: Request):
    """Handle Jambonz status and CDR callbacks."""
    set_current_run_id(workflow_run_id)
    event_data, raw_body = await _json_body_and_raw(request)
    logger.info(
        f"[run {workflow_run_id}] Received Jambonz status callback: "
        f"{json.dumps(redact_telephony_payload_for_logs(event_data))}"
    )

    workflow_run = await db_client.get_workflow_run_by_id(workflow_run_id)
    if not workflow_run:
        raise HTTPException(status_code=404, detail="Workflow run not found")

    workflow = await db_client.get_workflow_by_id(workflow_run.workflow_id)
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    provider = await get_telephony_provider_for_run(
        workflow_run, workflow.organization_id
    )
    if provider.PROVIDER_NAME != "jambonz":
        raise HTTPException(status_code=400, detail="provider_mismatch")
    _require_authority_binding(
        event_data,
        workflow_run=workflow_run,
        provider=provider,
        require_callback_nonce=True,
    )

    is_valid = await provider.verify_inbound_signature(
        str(request.url), event_data, dict(request.headers), raw_body
    )
    if not is_valid:
        logger.warning(f"[run {workflow_run_id}] Invalid Jambonz status signature")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    parsed_data = provider.parse_status_callback(event_data)
    status_update = StatusCallbackRequest(
        call_id=parsed_data["call_id"],
        status=parsed_data["status"],
        from_number=parsed_data.get("from_number"),
        to_number=parsed_data.get("to_number"),
        direction=parsed_data.get("direction"),
        duration=parsed_data.get("duration"),
        extra=parsed_data.get("extra", {}),
    )
    await _process_status_update(workflow_run_id, status_update)
    return {"status": "success"}
