from __future__ import annotations

from typing import Any

from loguru import logger

from api.db import db_client
from api.services.phone_preview.config import get_preview_telephony_settings


def _int_value(value: Any, name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc


async def resolve_preview_system_telephony_scope(
    workflow_run,
    workflow_organization_id: int,
) -> tuple[int, int] | None:
    """Return allowlisted ``(org_id, config_id)`` for a preview run.

    A preview marker is privileged: when present it must fully verify against
    the server allowlist and persisted preview session. Any mismatch fails
    closed instead of falling back to the user's organization default.
    """

    context = workflow_run.initial_context or {}
    if not context.get("telephony_preview"):
        return None

    settings = get_preview_telephony_settings()
    if not settings.is_configured:
        raise ValueError("preview_telephony_not_configured")

    session_id = _int_value(context.get("preview_session_id"), "preview_session_id")

    session = await db_client.get_phone_preview_session_for_run(workflow_run.id)
    if not session:
        raise ValueError("preview_session_not_found")

    expected = {
        "session_id": session_id,
        "workflow_run_id": workflow_run.id,
        "workflow_id": workflow_run.workflow_id,
        "organization_id": workflow_organization_id,
    }
    actual = {
        "session_id": session.id,
        "workflow_run_id": session.workflow_run_id,
        "workflow_id": session.workflow_id,
        "organization_id": session.organization_id,
    }
    if actual != expected:
        logger.warning(
            "Preview session mismatch for run {}: expected {}, actual {}",
            workflow_run.id,
            expected,
            actual,
        )
        raise ValueError("preview_session_mismatch")

    if session.status not in {"calling", "active", "completed"}:
        raise ValueError("preview_session_not_calling")

    return settings.organization_id, settings.configuration_id
