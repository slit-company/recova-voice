from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException
from loguru import logger
from pipecat.utils.enums import RealtimeFeedbackType

from api.db import db_client
from api.db.models import UserModel
from api.enums import CallType, WorkflowRunMode
from api.services.phone_preview.config import (
    get_preview_telephony_settings,
    should_expose_dev_otp,
)
from api.services.phone_preview.otp import (
    generate_otp_code,
    generate_otp_salt,
    hash_otp_code,
    otp_matches,
)
from api.services.phone_preview.privacy import (
    decrypt_phone,
    encrypt_phone,
    global_phone_hash,
    mask_phone,
    normalize_preview_phone,
    phone_hash,
)
from api.services.phone_preview.otp_delivery import (
    PhonePreviewOtpDeliveryError,
    deliver_otp_code,
)
from api.services.configuration.resolve import resolve_effective_config
from api.services.quota_service import check_dograh_quota_by_user_id
from api.services.telephony.registry import get_optional as get_provider_spec
from api.utils.common import get_backend_endpoints

_PREVIEW_METADATA_SENSITIVE_EXACT_KEYS = {"from", "to"}
_PREVIEW_METADATA_SENSITIVE_FRAGMENTS = (
    "phone",
    "number",
    "destination",
    "caller",
    "called",
    "account",
    "sid",
    "secret",
    "token",
    "api_key",
    "credential",
)
_PREVIEW_RUNTIME_LATENCY_PROFILE = "speed_demo"
_PREVIEW_LATENCY_EVENT_TYPE = RealtimeFeedbackType.LATENCY_MEASURED.value
_PREVIEW_LATENCY_EVENT_KIND = "voice_latency_breakdown"


def _log_preview_latency_profile(
    *,
    session_id: int,
    workflow_run_id: int,
    direction: str,
) -> None:
    logger.info(
        "Phone preview latency profile "
        f"phone_preview_session_id={session_id} "
        f"workflow_run_id={workflow_run_id} "
        f"direction={direction} "
        f"latency_profile={_PREVIEW_RUNTIME_LATENCY_PROFILE}"
    )


async def _get_preview_telephony_provider_by_id(config_id: int, organization_id: int):
    from api.services.telephony.factory import get_telephony_provider_by_id

    return await get_telephony_provider_by_id(config_id, organization_id)


def _preview_metadata_key_is_sensitive(key: object) -> bool:
    key_text = str(key).lower()
    return key_text in _PREVIEW_METADATA_SENSITIVE_EXACT_KEYS or any(
        fragment in key_text for fragment in _PREVIEW_METADATA_SENSITIVE_FRAGMENTS
    )


def _redact_preview_metadata(value: Any, *, key: object | None = None) -> Any:
    if key is not None and _preview_metadata_key_is_sensitive(key):
        return "[redacted]"
    if isinstance(value, dict):
        return {
            item_key: _redact_preview_metadata(item_value, key=item_key)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_preview_metadata(item) for item in value]
    return value


def _preview_config_has_service(config: Any, field_name: str) -> bool:
    """Return whether an effective user configuration has a usable service slot.

    The concrete provider validators own provider-specific credential validation.
    This guard intentionally checks only that the pipeline-critical section is
    present, preventing the known no-configuration crash before a PSTN call is
    dispatched.
    """

    return getattr(config, field_name, None) is not None


@dataclass
class PhonePreviewLatencySummaryData:
    workflow_run_id: int
    latency_profile: str | None
    user_stop_to_bot_started_ms: float | None
    stt_final_ms: float | None
    llm_ttfb_ms: float | None
    tts_ttfb_ms: float | None
    first_response_ms: float | None
    updated_at: str | None

    def as_dict(self) -> dict[str, int | float | str | None]:
        return {
            "workflow_run_id": self.workflow_run_id,
            "latency_profile": self.latency_profile,
            "user_stop_to_bot_started_ms": self.user_stop_to_bot_started_ms,
            "stt_final_ms": self.stt_final_ms,
            "llm_ttfb_ms": self.llm_ttfb_ms,
            "tts_ttfb_ms": self.tts_ttfb_ms,
            "first_response_ms": self.first_response_ms,
            "updated_at": self.updated_at,
        }


@dataclass
class PhonePreviewResult:
    session_id: int
    status: str
    otp_required: bool
    masked_phone: str
    expires_at: datetime
    workflow_run_id: int | None = None
    provider_call_id: str | None = None
    failure_reason: str | None = None
    dev_otp_code: str | None = None
    inbound_phone_number: str | None = None
    latency_summary: PhonePreviewLatencySummaryData | None = None

    def as_dict(self) -> dict[str, Any]:
        data = {
            "session_id": self.session_id,
            "status": self.status,
            "otp_required": self.otp_required,
            "masked_phone": self.masked_phone,
            "expires_at": self.expires_at,
            "workflow_run_id": self.workflow_run_id,
            "failure_reason": self.failure_reason,
        }
        if self.dev_otp_code:
            data["dev_otp_code"] = self.dev_otp_code
        if self.inbound_phone_number:
            data["inbound_phone_number"] = self.inbound_phone_number
        if self.latency_summary is not None:
            data["latency_summary"] = self.latency_summary.as_dict()
        return data


class PhonePreviewService:
    async def start(
        self,
        *,
        user: UserModel,
        workflow_id: int,
        phone_number: str,
        display_name: str | None = None,
    ) -> PhonePreviewResult:
        organization_id = self._selected_org(user)
        workflow = await db_client.get_workflow(
            workflow_id, organization_id=organization_id
        )
        if not workflow:
            raise HTTPException(status_code=404, detail="workflow_not_found")

        try:
            normalized = normalize_preview_phone(phone_number)
        except ValueError:
            raise HTTPException(status_code=422, detail="invalid_phone_number")

        settings = get_preview_telephony_settings()
        now = datetime.now(UTC)
        masked = mask_phone(normalized)
        hashed = phone_hash(
            normalized, organization_id=organization_id, user_id=user.id
        )
        global_hashed = global_phone_hash(normalized)

        await self._enforce_start_rate_limits(
            organization_id=organization_id,
            user_id=user.id,
            phone_number_global_hash=global_hashed,
            now=now,
            settings=settings,
        )

        verified = await db_client.get_recent_verified_phone_preview_verification(
            organization_id=organization_id,
            user_id=user.id,
            phone_number_hash=hashed,
            now=now,
        )

        if verified:
            session = await db_client.create_phone_preview_session(
                organization_id=organization_id,
                user_id=user.id,
                workflow_id=workflow_id,
                verification_id=verified.id,
                phone_number_hash=hashed,
                phone_number_global_hash=global_hashed,
                phone_number_masked=masked,
                destination_phone_encrypted=encrypt_phone(normalized),
                display_name=display_name,
                status="verified",
                expires_at=now + timedelta(seconds=settings.session_ttl_seconds),
                max_duration_seconds=settings.max_duration_seconds,
            )
            return self._session_result(session, otp_required=False)

        code = generate_otp_code()
        salt = generate_otp_salt()
        verification = await db_client.create_phone_preview_verification(
            organization_id=organization_id,
            user_id=user.id,
            phone_number_hash=hashed,
            phone_number_masked=masked,
            code_hash=hash_otp_code(code, salt),
            code_salt=salt,
            expires_at=now + timedelta(seconds=settings.otp_ttl_seconds),
        )
        session = await db_client.create_phone_preview_session(
            organization_id=organization_id,
            user_id=user.id,
            workflow_id=workflow_id,
            verification_id=verification.id,
            phone_number_hash=hashed,
            phone_number_global_hash=global_hashed,
            phone_number_masked=masked,
            destination_phone_encrypted=encrypt_phone(normalized),
            display_name=display_name,
            status="pending_verification",
            expires_at=now + timedelta(seconds=settings.session_ttl_seconds),
            max_duration_seconds=settings.max_duration_seconds,
        )

        if not should_expose_dev_otp():
            try:
                await deliver_otp_code(
                    phone_number=normalized,
                    code=code,
                    masked_phone=masked,
                    settings=settings,
                )
            except PhonePreviewOtpDeliveryError as exc:
                await db_client.set_phone_preview_verification_status(
                    verification.id, status="delivery_failed"
                )
                await db_client.update_phone_preview_session_status(
                    session.id, status="failed", failure_reason=str(exc)
                )
                raise HTTPException(
                    status_code=503, detail="otp_delivery_failed"
                ) from exc

        result = self._session_result(session, otp_required=True)
        if should_expose_dev_otp():
            result.dev_otp_code = code
        return result

    async def verify(
        self,
        *,
        user: UserModel,
        session_id: int,
        otp_code: str,
    ) -> PhonePreviewResult:
        organization_id = self._selected_org(user)
        session = await self._get_user_session(session_id, organization_id, user.id)
        session = await self._expire_session_if_stale(
            session,
            expirable_statuses={"verified"},
        )
        if session.status == "expired":
            raise HTTPException(
                status_code=400, detail=session.failure_reason or "expired"
            )
        if session.status in {"verified", "calling", "active", "completed"}:
            return self._session_result(session, otp_required=False)
        if session.status != "pending_verification" or not session.verification_id:
            raise HTTPException(status_code=400, detail="preview_not_verifiable")

        verification = await db_client.get_phone_preview_verification(
            session.verification_id
        )
        if (
            not verification
            or verification.organization_id != organization_id
            or verification.user_id != user.id
            or verification.phone_number_hash != session.phone_number_hash
        ):
            raise HTTPException(status_code=400, detail="verification_not_found")

        settings = get_preview_telephony_settings()
        now = datetime.now(UTC)
        if verification.status == "locked":
            await db_client.update_phone_preview_session_status(
                session.id, status="failed", failure_reason="otp_locked"
            )
            raise HTTPException(status_code=400, detail="otp_locked")
        if verification.expires_at <= now:
            await db_client.increment_phone_preview_verification_attempts(
                verification.id, status="expired"
            )
            await db_client.update_phone_preview_session_status(
                session.id, status="expired", failure_reason="otp_expired"
            )
            raise HTTPException(status_code=400, detail="otp_expired")
        if (verification.attempts or 0) >= settings.max_otp_attempts:
            await db_client.increment_phone_preview_verification_attempts(
                verification.id, status="locked"
            )
            raise HTTPException(status_code=400, detail="otp_locked")
        if not otp_matches(otp_code, verification.code_salt, verification.code_hash):
            status = (
                "locked"
                if (verification.attempts or 0) + 1 >= settings.max_otp_attempts
                else None
            )
            await db_client.increment_phone_preview_verification_attempts(
                verification.id, status=status
            )
            if status == "locked":
                await db_client.update_phone_preview_session_status(
                    session.id, status="failed", failure_reason="otp_locked"
                )
            raise HTTPException(status_code=400, detail="otp_invalid")

        await db_client.mark_phone_preview_verification_verified(
            verification.id,
            verified_until=now + timedelta(seconds=settings.verified_ttl_seconds),
        )
        session = await db_client.mark_phone_preview_session_verified(
            session.id, verification_id=verification.id
        )
        return self._session_result(session, otp_required=False)

    async def call(self, *, user: UserModel, session_id: int) -> PhonePreviewResult:
        organization_id = self._selected_org(user)
        settings = get_preview_telephony_settings()
        if not settings.is_configured:
            raise HTTPException(status_code=400, detail="telephony_not_configured")

        session, should_start = await db_client.begin_phone_preview_call(
            session_id, organization_id=organization_id, user_id=user.id
        )
        if not session:
            raise HTTPException(status_code=404, detail="preview_session_not_found")
        if not should_start:
            if session.status == "pending_verification":
                raise HTTPException(status_code=400, detail="phone_not_verified")
            if session.status in {"calling", "active", "completed"}:
                return self._session_result(session, otp_required=False)
            raise HTTPException(
                status_code=400, detail=session.failure_reason or session.status
            )

        try:
            return await self._start_provider_call(user=user, session=session)
        except HTTPException as exc:
            await db_client.update_phone_preview_session_status(
                session.id, status="failed", failure_reason=str(exc.detail)
            )
            raise
        except Exception as exc:
            await db_client.update_phone_preview_session_status(
                session.id, status="failed", failure_reason="call_failed"
            )
            raise HTTPException(status_code=500, detail="call_failed") from exc

    async def wait_for_inbound(
        self, *, user: UserModel, session_id: int
    ) -> PhonePreviewResult:
        """Prepare a verified preview session for "user calls Recova" testing."""
        organization_id = self._selected_org(user)
        settings = get_preview_telephony_settings()
        if not settings.is_configured or settings.from_phone_number_id is None:
            raise HTTPException(status_code=400, detail="telephony_not_configured")

        provider = await _get_preview_telephony_provider_by_id(
            settings.configuration_id, settings.organization_id
        )
        if not provider.validate_config():
            raise HTTPException(status_code=400, detail="telephony_not_configured")
        self._require_preview_provider(provider.PROVIDER_NAME, inbound=True)

        phone_row = await db_client.get_phone_number_for_config(
            settings.from_phone_number_id, settings.configuration_id
        )
        if not phone_row or not phone_row.is_active:
            raise HTTPException(
                status_code=400, detail="preview_from_phone_number_not_found"
            )
        if getattr(phone_row, "inbound_workflow_id", None):
            raise HTTPException(
                status_code=400, detail="preview_from_phone_number_must_be_unassigned"
            )

        session, is_waiting = await db_client.begin_phone_preview_inbound_wait(
            session_id,
            organization_id=organization_id,
            user_id=user.id,
            provider=provider.PROVIDER_NAME,
            telephony_configuration_id=settings.configuration_id,
            from_phone_number_id=phone_row.id,
        )
        if not session:
            raise HTTPException(status_code=404, detail="preview_session_not_found")
        if not is_waiting:
            if session.status == "pending_verification":
                raise HTTPException(status_code=400, detail="phone_not_verified")
            if session.status in {"calling", "active", "completed"}:
                return self._session_result(
                    session,
                    otp_required=False,
                    inbound_phone_number=phone_row.address,
                )
            raise HTTPException(
                status_code=400, detail=session.failure_reason or session.status
            )

        try:
            workflow = await db_client.get_workflow(
                session.workflow_id, organization_id=session.organization_id
            )
            if not workflow:
                raise HTTPException(status_code=404, detail="workflow_not_found")
            if workflow.user_id is None:
                raise HTTPException(status_code=409, detail="workflow_has_no_owner")
            draft = await db_client.get_draft_version(session.workflow_id)
            if not draft:
                raise HTTPException(status_code=400, detail="draft_not_ready")
            await self._require_preview_model_configuration(
                user_id=workflow.user_id,
                workflow_configurations=getattr(draft, "workflow_configurations", None),
            )
        except HTTPException as exc:
            await db_client.update_phone_preview_session_status(
                session.id, status="failed", failure_reason=str(exc.detail)
            )
            raise

        return self._session_result(
            session,
            otp_required=False,
            inbound_phone_number=phone_row.address,
        )

    async def answer_inbound_preview(
        self,
        *,
        provider_instance,
        normalized_data,
        organization_id: int,
        telephony_configuration_id: int,
        from_phone_number_id: int,
    ):
        """Answer an inbound call if it matches a verified preview reservation.

        This path is for the Recova-owned representative number: the logged-in
        user first verifies their own phone number in the canvas, then calls the
        representative number. The inbound webhook carries only telephony data,
        so matching is by the previously verified caller-number hash.
        """
        now = datetime.now(UTC)
        caller_hash = global_phone_hash(normalized_data.from_number)
        session = await db_client.claim_phone_preview_inbound_session(
            organization_id=organization_id,
            phone_number_global_hash=caller_hash,
            provider=provider_instance.PROVIDER_NAME,
            telephony_configuration_id=telephony_configuration_id,
            from_phone_number_id=from_phone_number_id,
            now=now,
        )
        if not session:
            return None

        try:
            return await self._start_inbound_preview_stream(
                provider_instance=provider_instance,
                session=session,
                normalized_data=normalized_data,
            )
        except Exception as exc:
            await db_client.update_phone_preview_session_status(
                session.id,
                status="failed",
                failure_reason="inbound_preview_failed",
            )
            logger.error(
                "Failed to start inbound preview session "
                f"{session.id}: {exc.__class__.__name__}"
            )
            raise

    async def status(self, *, user: UserModel, session_id: int) -> PhonePreviewResult:
        organization_id = self._selected_org(user)
        session = await self._get_user_session(session_id, organization_id, user.id)
        session = await self._expire_session_if_stale(
            session,
            expirable_statuses={
                "pending_verification",
                "verified",
                "awaiting_inbound",
                "calling",
                "active",
            },
        )
        workflow_run = None
        if session.workflow_run_id and session.status in {"calling", "active"}:
            workflow_run = await db_client.get_workflow_run(
                session.workflow_run_id, organization_id=organization_id
            )
            if workflow_run and workflow_run.is_completed:
                updated_session = await db_client.update_phone_preview_session_status(
                    session.id, status="completed", completed=True
                )
                session = updated_session or session
            elif workflow_run and session.provider == WorkflowRunMode.AWS_CONNECT.value:
                session = await self._refresh_aws_connect_preview_status(
                    session=session,
                    workflow_run=workflow_run,
                    organization_id=organization_id,
                )
        inbound_phone_number = None
        if session.status == "awaiting_inbound":
            inbound_phone_number = await self._preview_inbound_phone_number(session)
        return self._session_result(
            session,
            otp_required=session.status == "pending_verification",
            inbound_phone_number=inbound_phone_number,
            latency_summary=self._latency_summary_from_workflow_run(workflow_run),
        )

    async def _start_inbound_preview_stream(
        self,
        *,
        provider_instance,
        session,
        normalized_data,
    ):
        workflow = await db_client.get_workflow(
            session.workflow_id, organization_id=session.organization_id
        )
        if not workflow:
            raise HTTPException(status_code=404, detail="workflow_not_found")
        if workflow.user_id is None:
            raise HTTPException(status_code=409, detail="workflow_has_no_owner")

        draft = await db_client.get_draft_version(session.workflow_id)
        if not draft:
            raise HTTPException(status_code=400, detail="draft_not_ready")
        await self._require_preview_model_configuration(
            user_id=workflow.user_id,
            workflow_configurations=getattr(draft, "workflow_configurations", None),
        )

        quota_result = await check_dograh_quota_by_user_id(
            workflow.user_id, workflow_id=workflow.id
        )
        if not quota_result.has_quota:
            raise HTTPException(status_code=402, detail=quota_result.error_message)

        numeric_suffix = int(str(uuid.uuid4()).replace("-", "")[:8], 16) % 100000000
        workflow_run_name = f"WR-PREVIEW-IN-{numeric_suffix:08d}"
        initial_context = {
            **(draft.template_context_variables or {}),
            "phone_number": session.phone_number_masked,
            "caller_number_masked": session.phone_number_masked,
            "called_number": mask_phone(normalized_data.to_number),
            "called_number_masked": mask_phone(normalized_data.to_number),
            "direction": "inbound",
            "telephony_preview": True,
            "runtime_latency_profile": _PREVIEW_RUNTIME_LATENCY_PROFILE,
            "preview_session_id": session.id,
            "max_duration_seconds": session.max_duration_seconds,
        }
        if session.display_name:
            initial_context["preview_display_name"] = session.display_name

        workflow_run = await db_client.create_workflow_run(
            workflow_run_name,
            workflow.id,
            provider_instance.PROVIDER_NAME,
            user_id=workflow.user_id,
            call_type=CallType.INBOUND,
            initial_context=initial_context,
            gathered_context={
                "provider": provider_instance.PROVIDER_NAME,
                "preview_session_id": session.id,
                "call_id": normalized_data.call_id,
            },
            use_draft=True,
            organization_id=session.organization_id,
        )
        _log_preview_latency_profile(
            session_id=session.id,
            workflow_run_id=workflow_run.id,
            direction="inbound",
        )

        session = await db_client.attach_phone_preview_call(
            session.id,
            workflow_run_id=workflow_run.id,
            provider=provider_instance.PROVIDER_NAME,
            provider_call_id=normalized_data.call_id,
            clear_destination_phone=True,
        )
        if not session:
            raise HTTPException(status_code=404, detail="preview_session_not_found")

        backend_endpoint, wss_backend_endpoint = await get_backend_endpoints()
        websocket_url = (
            f"{wss_backend_endpoint}/api/v1/telephony/ws/"
            f"{workflow.id}/{workflow.user_id}/{workflow_run.id}"
        )
        return await provider_instance.start_inbound_stream(
            websocket_url=websocket_url,
            workflow_run_id=workflow_run.id,
            normalized_data=normalized_data,
            backend_endpoint=backend_endpoint,
        )

    async def _refresh_aws_connect_preview_status(
        self,
        *,
        session,
        workflow_run,
        organization_id: int,
    ):
        """Poll Amazon Connect smoke-call status for preview sessions.

        Amazon Connect contact flows do not connect back to Recova's WebSocket
        transport, so no Pipecat runtime marks the workflow run complete. Poll
        DescribeContact and close the preview session when the Connect contact
        has disconnected.
        """
        if not session.provider_call_id:
            return session

        try:
            from api.services.telephony.factory import get_telephony_provider_for_run

            provider = await get_telephony_provider_for_run(
                workflow_run, organization_id
            )
            status_payload = await provider.get_call_status(session.provider_call_id)
        except Exception as exc:
            logger.warning(
                "Failed to refresh Amazon Connect preview status: "
                f"{exc.__class__.__name__}"
            )
            await db_client.update_workflow_run(
                run_id=workflow_run.id,
                is_completed=True,
                gathered_context={
                    "provider_status": "failed",
                    "provider_error": "aws_connect_status_unavailable",
                },
            )
            return (
                await db_client.update_phone_preview_session_status(
                    session.id,
                    status="failed",
                    failure_reason="aws_connect_status_unavailable",
                )
                or session
            )

        provider_status = str(status_payload.get("status") or "").lower()
        if provider_status not in {
            "completed",
            "failed",
            "busy",
            "no-answer",
            "canceled",
        }:
            return session

        await db_client.update_workflow_run(
            run_id=workflow_run.id,
            is_completed=True,
            gathered_context={
                "provider_status": provider_status,
                "provider_disconnect_reason": status_payload.get("disconnect_reason"),
            },
        )
        status = "completed" if provider_status == "completed" else "failed"
        return (
            await db_client.update_phone_preview_session_status(
                session.id,
                status=status,
                failure_reason=None if status == "completed" else provider_status,
                completed=status == "completed",
            )
            or session
        )

    async def _expire_session_if_stale(
        self,
        session,
        *,
        expirable_statuses: set[str] | None = None,
    ):
        statuses = expirable_statuses or {"pending_verification", "verified"}
        if session.status not in statuses or session.expires_at > datetime.now(UTC):
            return session
        return (
            await db_client.update_phone_preview_session_status(
                session.id, status="expired", failure_reason="expired"
            )
            or session
        )

    async def _start_provider_call(
        self, *, user: UserModel, session
    ) -> PhonePreviewResult:
        settings = get_preview_telephony_settings()
        assert settings.organization_id is not None
        assert settings.configuration_id is not None

        workflow = await db_client.get_workflow(
            session.workflow_id, organization_id=session.organization_id
        )
        if not workflow:
            raise HTTPException(status_code=404, detail="workflow_not_found")
        if workflow.user_id is None:
            raise HTTPException(status_code=409, detail="workflow_has_no_owner")

        draft = await db_client.get_draft_version(session.workflow_id)
        if not draft:
            raise HTTPException(status_code=400, detail="draft_not_ready")
        await self._require_preview_model_configuration(
            user_id=workflow.user_id,
            workflow_configurations=getattr(draft, "workflow_configurations", None),
        )

        quota_result = await check_dograh_quota_by_user_id(
            workflow.user_id, workflow_id=workflow.id
        )
        if not quota_result.has_quota:
            raise HTTPException(status_code=402, detail=quota_result.error_message)

        since = datetime.now(UTC) - timedelta(days=1)
        user_count = await db_client.count_phone_preview_sessions_since(
            organization_id=session.organization_id,
            user_id=session.user_id,
            since=since,
        )
        if user_count > settings.daily_user_call_limit:
            raise HTTPException(status_code=429, detail="preview_rate_limited")

        org_count = await db_client.count_phone_preview_sessions_since(
            organization_id=session.organization_id,
            since=since,
        )
        if org_count > settings.daily_org_call_limit:
            raise HTTPException(status_code=429, detail="preview_org_rate_limited")

        phone_count = await self._count_recent_phone_sessions(session, since)
        if phone_count > settings.daily_phone_call_limit:
            raise HTTPException(status_code=429, detail="preview_phone_rate_limited")

        provider = await _get_preview_telephony_provider_by_id(
            settings.configuration_id, settings.organization_id
        )
        if not provider.validate_config():
            raise HTTPException(status_code=400, detail="telephony_not_configured")
        self._require_preview_provider(provider.PROVIDER_NAME, inbound=False)

        destination = self._decrypt_destination(session)
        from_number = None
        if settings.from_phone_number_id is not None:
            phone_row = await db_client.get_phone_number_for_config(
                settings.from_phone_number_id, settings.configuration_id
            )
            if not phone_row or not phone_row.is_active:
                raise HTTPException(
                    status_code=400, detail="preview_from_phone_number_not_found"
                )
            from_number = phone_row.address_normalized
        if provider.PROVIDER_NAME == WorkflowRunMode.AWS_CONNECT.value:
            if not from_number:
                raise HTTPException(
                    status_code=400, detail="preview_from_phone_number_required"
                )
            available_numbers = await provider.get_available_phone_numbers()
            if from_number not in available_numbers:
                raise HTTPException(
                    status_code=400, detail="preview_from_phone_number_not_configured"
                )

        numeric_suffix = int(str(uuid.uuid4()).replace("-", "")[:8], 16) % 100000000
        workflow_run_name = f"WR-PREVIEW-{numeric_suffix:08d}"
        initial_context = {
            **(draft.template_context_variables or {}),
            "phone_number": session.phone_number_masked,
            "called_number": session.phone_number_masked,
            "phone_number_masked": session.phone_number_masked,
            "called_number_masked": session.phone_number_masked,
            "telephony_preview": True,
            "runtime_latency_profile": _PREVIEW_RUNTIME_LATENCY_PROFILE,
            "preview_session_id": session.id,
            "max_duration_seconds": session.max_duration_seconds,
        }
        if session.display_name:
            initial_context["preview_display_name"] = session.display_name

        workflow_run = await db_client.create_workflow_run(
            workflow_run_name,
            workflow.id,
            provider.PROVIDER_NAME,
            user_id=workflow.user_id,
            call_type=CallType.OUTBOUND,
            initial_context=initial_context,
            use_draft=True,
            organization_id=session.organization_id,
        )
        _log_preview_latency_profile(
            session_id=session.id,
            workflow_run_id=workflow_run.id,
            direction="outbound",
        )

        session = await db_client.attach_phone_preview_call(
            session.id,
            workflow_run_id=workflow_run.id,
            provider=provider.PROVIDER_NAME,
            provider_call_id=None,
            clear_destination_phone=True,
        )
        if not session:
            raise HTTPException(status_code=404, detail="preview_session_not_found")

        backend_endpoint, _ = await get_backend_endpoints()
        if provider.WEBHOOK_ENDPOINT:
            webhook_url = (
                f"{backend_endpoint}/api/v1/telephony/{provider.WEBHOOK_ENDPOINT}"
                f"?workflow_id={workflow.id}"
                f"&user_id={workflow.user_id}"
                f"&workflow_run_id={workflow_run.id}"
                f"&organization_id={session.organization_id}"
            )
        else:
            webhook_url = backend_endpoint

        try:
            call_result = await provider.initiate_call(
                to_number=destination,
                webhook_url=webhook_url,
                workflow_run_id=workflow_run.id,
                from_number=from_number,
                workflow_id=workflow.id,
                user_id=workflow.user_id,
            )
        except HTTPException as exc:
            raise HTTPException(
                status_code=502,
                detail="preview_call_failed",
            ) from exc

        provider_call_id = getattr(call_result, "call_id", None) or (
            getattr(call_result, "provider_metadata", {}) or {}
        ).get("call_id")
        provider_metadata = _redact_preview_metadata(
            getattr(call_result, "provider_metadata", {}) or {}
        )
        gathered_context = {
            "provider": provider.PROVIDER_NAME,
            "preview_session_id": session.id,
            **provider_metadata,
        }
        if provider_call_id:
            gathered_context["call_id"] = provider_call_id

        session = await db_client.attach_phone_preview_call(
            session.id,
            workflow_run_id=workflow_run.id,
            provider=provider.PROVIDER_NAME,
            provider_call_id=provider_call_id,
            clear_destination_phone=True,
        )
        if not session:
            raise HTTPException(status_code=404, detail="preview_session_not_found")

        updated_initial_context = {
            **(workflow_run.initial_context or initial_context),
            "phone_number": session.phone_number_masked,
            "called_number": session.phone_number_masked,
            "phone_number_masked": session.phone_number_masked,
            "called_number_masked": session.phone_number_masked,
            "telephony_preview": True,
            "runtime_latency_profile": _PREVIEW_RUNTIME_LATENCY_PROFILE,
            "preview_session_id": session.id,
        }
        caller_number = getattr(call_result, "caller_number", None)
        if caller_number:
            updated_initial_context["caller_number_masked"] = mask_phone(caller_number)

        await db_client.update_workflow_run(
            run_id=workflow_run.id,
            gathered_context=gathered_context,
            initial_context=updated_initial_context,
        )
        return self._session_result(session, otp_required=False)

    def _decrypt_destination(self, session) -> str:
        try:
            return decrypt_phone(session.destination_phone_encrypted)
        except Exception:
            raise HTTPException(
                status_code=400, detail="preview_destination_unavailable"
            )

    async def _enforce_start_rate_limits(
        self,
        *,
        organization_id: int,
        user_id: int,
        phone_number_global_hash: str,
        now: datetime,
        settings,
    ) -> None:
        since = now - timedelta(days=1)
        user_count = await db_client.count_phone_preview_sessions_since(
            organization_id=organization_id,
            user_id=user_id,
            since=since,
        )
        if user_count >= settings.daily_user_call_limit:
            raise HTTPException(status_code=429, detail="preview_rate_limited")

        org_count = await db_client.count_phone_preview_sessions_since(
            organization_id=organization_id,
            since=since,
        )
        if org_count >= settings.daily_org_call_limit:
            raise HTTPException(status_code=429, detail="preview_org_rate_limited")

        phone_count = await db_client.count_phone_preview_sessions_since(
            phone_number_global_hash=phone_number_global_hash,
            since=since,
        )
        if phone_count >= settings.daily_phone_call_limit:
            raise HTTPException(status_code=429, detail="preview_phone_rate_limited")

    async def _count_recent_phone_sessions(self, session, since: datetime) -> int:
        phone_number_global_hash = getattr(session, "phone_number_global_hash", None)
        if phone_number_global_hash:
            return await db_client.count_phone_preview_sessions_since(
                phone_number_global_hash=phone_number_global_hash,
                since=since,
            )
        return await db_client.count_phone_preview_sessions_since(
            phone_number_hash=session.phone_number_hash,
            since=since,
        )

    def _require_preview_provider(self, provider_name: str, *, inbound: bool) -> None:
        """Allow only providers explicitly approved for Recova-owned preview calls."""

        # Ensure provider modules have registered their ProviderSpec even in
        # unit tests that import this service directly.
        import api.services.telephony.providers  # noqa: F401

        spec = get_provider_spec(provider_name)
        if not spec or not spec.supports_preview_smoke:
            raise HTTPException(
                status_code=400,
                detail="telephony_provider_not_supported_for_preview",
            )
        if inbound and not spec.supports_media_transport:
            raise HTTPException(
                status_code=400,
                detail="telephony_provider_not_supported_for_inbound_preview",
            )

    def _latency_summary_from_workflow_run(
        self, workflow_run
    ) -> PhonePreviewLatencySummaryData | None:
        if workflow_run is None:
            return None
        logs = getattr(workflow_run, "logs", None)
        if not isinstance(logs, dict):
            return None
        events = logs.get("realtime_feedback_events")
        if not isinstance(events, list):
            return None

        workflow_run_id = self._workflow_run_id_from(workflow_run)
        if workflow_run_id is None:
            return None

        for event in reversed(events):
            if not isinstance(event, dict):
                continue
            if event.get("type") != _PREVIEW_LATENCY_EVENT_TYPE:
                continue
            payload = event.get("payload")
            if not isinstance(payload, dict):
                continue
            if payload.get("kind") != _PREVIEW_LATENCY_EVENT_KIND:
                continue
            return PhonePreviewLatencySummaryData(
                workflow_run_id=workflow_run_id,
                latency_profile=self._optional_string(payload.get("latency_profile")),
                user_stop_to_bot_started_ms=self._optional_float(
                    payload.get("user_stop_to_bot_started_ms")
                ),
                stt_final_ms=self._optional_float(payload.get("stt_final_ms")),
                llm_ttfb_ms=self._optional_float(payload.get("llm_ttfb_ms")),
                tts_ttfb_ms=self._optional_float(payload.get("tts_ttfb_ms")),
                first_response_ms=self._optional_float(
                    payload.get("first_response_ms")
                ),
                updated_at=self._optional_string(
                    event.get("updated_at")
                    or payload.get("updated_at")
                    or payload.get("bot_started_speaking_at")
                    or payload.get("initial_response_triggered_at")
                    or payload.get("user_turn_stopped_at")
                ),
            )
        return None

    def _workflow_run_id_from(self, workflow_run) -> int | None:
        workflow_run_id = getattr(workflow_run, "id", None)
        if isinstance(workflow_run_id, int) and not isinstance(workflow_run_id, bool):
            return workflow_run_id
        return None

    def _optional_float(self, value: Any) -> float | None:
        if isinstance(value, bool) or value is None:
            return None
        if isinstance(value, (int, float)):
            return float(value)
        return None

    def _optional_string(self, value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            return value
        return str(value)

    async def _preview_inbound_phone_number(self, session) -> str | None:
        configuration_id = getattr(session, "preview_telephony_configuration_id", None)
        phone_number_id = getattr(session, "preview_from_phone_number_id", None)
        if not configuration_id or not phone_number_id:
            return None
        phone_row = await db_client.get_phone_number_for_config(
            phone_number_id, configuration_id
        )
        if not phone_row or not getattr(phone_row, "is_active", False):
            return None
        return getattr(phone_row, "address", None)

    async def _require_preview_model_configuration(
        self,
        *,
        user_id: int,
        workflow_configurations: dict[str, Any] | None,
    ) -> None:
        """Fail before dialing when the workflow owner has no voice model config.

        Phone preview uses live PSTN calls. If the owner has no BYO model
        configuration, Pipecat can accept the telephony WebSocket and then crash
        while creating STT/TTS/LLM services. That burns a real call and produces
        a confusing failure. This preflight keeps the failure local and explicit.
        """

        user_config = await db_client.get_user_configurations(user_id)
        user_config = resolve_effective_config(
            user_config,
            (workflow_configurations or {}).get("model_overrides"),
        )

        if (
            getattr(user_config, "is_realtime", False)
            and getattr(user_config, "realtime", None) is not None
        ):
            # Realtime handles speech-to-speech, but the pipeline still creates
            # a side-channel text LLM for variable extraction and inference.
            required_fields = ("realtime", "llm")
        else:
            required_fields = ("stt", "tts", "llm")

        if not all(
            _preview_config_has_service(user_config, field_name)
            for field_name in required_fields
        ):
            raise HTTPException(
                status_code=400,
                detail="model_configuration_required",
            )

    def _selected_org(self, user: UserModel) -> int:
        if not getattr(user, "selected_organization_id", None):
            raise HTTPException(status_code=400, detail="no_organization_selected")
        return user.selected_organization_id

    async def _get_user_session(
        self, session_id: int, organization_id: int, user_id: int
    ):
        session = await db_client.get_phone_preview_session(
            session_id, organization_id=organization_id, user_id=user_id
        )
        if not session:
            raise HTTPException(status_code=404, detail="preview_session_not_found")
        return session

    def _session_result(
        self,
        session,
        *,
        otp_required: bool,
        inbound_phone_number: str | None = None,
        latency_summary: PhonePreviewLatencySummaryData | None = None,
    ) -> PhonePreviewResult:
        return PhonePreviewResult(
            session_id=session.id,
            status=session.status,
            otp_required=otp_required,
            masked_phone=session.phone_number_masked,
            expires_at=session.expires_at,
            workflow_run_id=session.workflow_run_id,
            provider_call_id=session.provider_call_id,
            failure_reason=session.failure_reason,
            inbound_phone_number=inbound_phone_number,
            latency_summary=latency_summary,
        )


phone_preview_service = PhonePreviewService()
