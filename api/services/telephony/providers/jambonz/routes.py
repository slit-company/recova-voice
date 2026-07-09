"""Jambonz telephony routes (answer, status, CDR callbacks)."""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from loguru import logger
from pipecat.utils.run_context import set_current_run_id

from api.db import db_client
from api.services.telephony.factory import get_telephony_provider_for_run
from api.services.telephony.status_processor import (
    StatusCallbackRequest,
    _process_status_update,
    redact_telephony_payload_for_logs,
)

router = APIRouter()


async def _json_body_and_raw(request: Request) -> tuple[dict, str]:
    raw_body = (await request.body()).decode("utf-8", errors="replace")
    try:
        data = json.loads(raw_body) if raw_body else {}
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object")
    return data, raw_body


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

    is_valid = await provider.verify_inbound_signature(
        str(request.url), event_data, dict(request.headers), raw_body
    )
    if not is_valid:
        logger.warning(f"[run {workflow_run_id}] Invalid Jambonz answer signature")
        return provider.generate_error_response(
            "invalid_signature", "Invalid webhook signature."
        )

    call_id = event_data.get("call_id") or event_data.get("callSid")
    stream_id = event_data.get("stream_id") or event_data.get("streamSid")
    if call_id or stream_id:
        gathered_context = dict(workflow_run.gathered_context or {})
        if call_id:
            gathered_context["call_id"] = call_id
        if stream_id:
            gathered_context["stream_id"] = stream_id
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
