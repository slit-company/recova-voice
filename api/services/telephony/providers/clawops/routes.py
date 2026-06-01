"""ClawOps telephony routes (VoiceML answer URL and status callbacks)."""

import json

from fastapi import APIRouter, HTTPException, Request
from loguru import logger
from pipecat.utils.run_context import set_current_run_id
from starlette.responses import HTMLResponse

from api.db import db_client
from api.services.telephony.factory import get_telephony_provider_for_run
from api.services.telephony.status_processor import (
    StatusCallbackRequest,
    _process_status_update,
    redact_telephony_payload_for_logs,
)
from api.utils.telephony_helper import parse_webhook_request

router = APIRouter()


@router.post("/clawops-voiceml", include_in_schema=False)
async def handle_clawops_voiceml_webhook(
    workflow_id: int,
    user_id: int,
    workflow_run_id: int,
    organization_id: int,
    request: Request,
):
    """Return VoiceML that connects an answered ClawOps call to Recova."""
    set_current_run_id(workflow_run_id)
    callback_data, raw_body = await parse_webhook_request(request)

    workflow_run = await db_client.get_workflow_run_by_id(workflow_run_id)
    if not workflow_run:
        raise HTTPException(status_code=404, detail="workflow_run_not_found")

    provider = await get_telephony_provider_for_run(workflow_run, organization_id)
    if provider.PROVIDER_NAME != "clawops":
        raise HTTPException(status_code=400, detail="provider_mismatch")

    is_valid = await provider.verify_inbound_signature(
        str(request.url), callback_data, dict(request.headers), raw_body
    )
    if not is_valid:
        logger.warning(
            f"[run {workflow_run_id}] Invalid ClawOps signature on VoiceML webhook"
        )
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    response_content = await provider.get_webhook_response(
        workflow_id, user_id, workflow_run_id
    )
    return HTMLResponse(content=response_content, media_type="application/xml")


@router.post("/clawops/status-callback/{workflow_run_id}")
async def handle_clawops_status_callback(
    workflow_run_id: int,
    request: Request,
):
    """Handle ClawOps status callbacks."""
    set_current_run_id(workflow_run_id)
    callback_data, raw_body = await parse_webhook_request(request)

    logger.info(
        f"[run {workflow_run_id}] Received ClawOps status callback: "
        f"{json.dumps(redact_telephony_payload_for_logs(callback_data))}"
    )

    workflow_run = await db_client.get_workflow_run_by_id(workflow_run_id)
    if not workflow_run:
        logger.warning(f"Workflow run {workflow_run_id} not found for ClawOps callback")
        return {"status": "ignored", "reason": "workflow_run_not_found"}

    workflow = await db_client.get_workflow_by_id(workflow_run.workflow_id)
    if not workflow:
        logger.warning(f"Workflow {workflow_run.workflow_id} not found")
        return {"status": "ignored", "reason": "workflow_not_found"}

    provider = await get_telephony_provider_for_run(
        workflow_run, workflow.organization_id
    )
    is_valid = await provider.verify_inbound_signature(
        str(request.url), callback_data, dict(request.headers), raw_body
    )
    if not is_valid:
        logger.warning(f"Invalid ClawOps status signature for run {workflow_run_id}")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    parsed_data = provider.parse_status_callback(callback_data)
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
