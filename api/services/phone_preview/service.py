from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from fastapi import HTTPException
from loguru import logger
from pipecat.utils.enums import RealtimeFeedbackType

from api.db import db_client
from api.db.models import UserModel
from api.enums import CallType, WorkflowRunMode
from api.services.onnuri_smoke_capabilities import (
    ECDSA_P256_SHA256_POLICY_ID,
    SmokeCapabilityIssuer,
    SmokeRecoverySealer,
    get_smoke_authority_runtime,
    parse_dispatch_capability,
)
from api.services.phone_preview.config import (
    PreviewTelephonySettings,
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
from api.services.telephony.jambonz_policy import (
    JAMBONZ_PROVIDER,
    is_current_jambonz_routable_phone_tuple,
    resolve_jambonz_outbound_caller,
)
from api.services.telephony.registry import is_dispatch_purpose_allowed
from api.services import onnuri_staging_preflight
from api.services.onnuri_smoke_f12 import (
    F12ServiceError,
    allocate_and_issue_dispatch,
)
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


_DESTINATION_HMAC_DOMAIN = "recova.onnuri.smoke.destination.v1"


class DestinationHmacProvider(Protocol):
    async def digest(
        self, *, canonical_payload: bytes, key_id: str, key_version: str
    ) -> str: ...


class UnavailableDestinationHmacProvider:
    async def digest(
        self, *, canonical_payload: bytes, key_id: str, key_version: str
    ) -> str:
        raise RuntimeError("classified_destination_hmac_provider_unavailable")



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
    gate_states: dict[str, bool] | None = None
    remaining_attempts: int | None = None
    proof_current: bool | None = None
    registration_fresh: bool | None = None
    media_fresh: bool | None = None
    contained: bool | None = None
    terminal_class: str | None = None
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
        if self.gate_states is not None:
            data["gate_states"] = self.gate_states
        if self.remaining_attempts is not None:
            data["remaining_attempts"] = self.remaining_attempts
        if self.proof_current is not None:
            data["proof_current"] = self.proof_current
        if self.registration_fresh is not None:
            data["registration_fresh"] = self.registration_fresh
        if self.media_fresh is not None:
            data["media_fresh"] = self.media_fresh
        if self.contained is not None:
            data["contained"] = self.contained
        if self.terminal_class is not None:
            data["terminal_class"] = self.terminal_class
        return data


class PhonePreviewService:
    def __init__(
        self,
        destination_hmac_provider: DestinationHmacProvider | None = None,
        smoke_capability_issuer: SmokeCapabilityIssuer | None = None,
        smoke_recovery_sealer: SmokeRecoverySealer | None = None,
    ) -> None:
        self.destination_hmac_provider = (
            destination_hmac_provider or UnavailableDestinationHmacProvider()
        )
        self.smoke_capability_issuer = smoke_capability_issuer
        self.smoke_recovery_sealer = smoke_recovery_sealer
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

    async def call(
        self,
        *,
        user: UserModel,
        session_id: int,
        idempotency_key: str | None = None,
        manual_acknowledgement: str | None = None,
    ) -> PhonePreviewResult:
        organization_id = self._selected_org(user)
        settings = get_preview_telephony_settings()
        if not settings.is_configured:
            raise HTTPException(status_code=400, detail="telephony_not_configured")
        if settings.is_classified_smoke:
            self._require_classified_gates(settings, "OUTBOUND_CALL")

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
            return await self._start_provider_call(
                user=user,
                session=session,
                idempotency_key=idempotency_key,
                manual_acknowledgement=manual_acknowledgement,
            )
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
        if settings.is_classified_smoke:
            self._require_classified_gates(settings, "INBOUND_CALL")

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
        if (
            provider.PROVIDER_NAME == JAMBONZ_PROVIDER
            and not await is_current_jambonz_routable_phone_tuple(
                organization_id=settings.organization_id,
                telephony_configuration_id=settings.configuration_id,
                telephony_phone_number_id=phone_row.id,
                address=phone_row.address_normalized,
            )
        ):
            raise HTTPException(
                status_code=400, detail="preview_jambonz_current_proof_required"
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

    def is_exact_classified_inbound(
        self,
        *,
        provider_name: str,
        normalized_data,
        organization_id: int,
        telephony_configuration_id: int,
        from_phone_number_id: int,
    ) -> bool:
        settings = get_preview_telephony_settings()
        if (
            not settings.is_classified_smoke
            or provider_name != JAMBONZ_PROVIDER
            or organization_id != settings.organization_id
            or telephony_configuration_id != settings.configuration_id
            or from_phone_number_id != settings.from_phone_number_id
        ):
            return False
        raw_data = normalized_data.raw_data or {}
        application_id = (
            raw_data.get("application_id")
            or raw_data.get("application_sid")
            or raw_data.get("applicationSid")
        )
        return bool(
            application_id
            and hmac.compare_digest(
                str(application_id), str(settings.smoke_application_id)
            )
        )
    async def handle_inbound_preview(
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
        settings = get_preview_telephony_settings()
        if settings.is_classified_smoke:
            self._require_classified_gates(settings, "INBOUND_CALL")
        if settings.is_classified_smoke and not self.is_exact_classified_inbound(
            provider_name=provider_instance.PROVIDER_NAME,
            normalized_data=normalized_data,
            organization_id=organization_id,
            telephony_configuration_id=telephony_configuration_id,
            from_phone_number_id=from_phone_number_id,
        ):
            return None
        if (
            provider_instance.PROVIDER_NAME == JAMBONZ_PROVIDER
            and not await is_current_jambonz_routable_phone_tuple(
                organization_id=organization_id,
                telephony_configuration_id=telephony_configuration_id,
                telephony_phone_number_id=from_phone_number_id,
                address=normalized_data.to_number,
            )
        ):
            return None
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
        if (
            provider_instance.PROVIDER_NAME == JAMBONZ_PROVIDER
            and not await is_current_jambonz_routable_phone_tuple(
                organization_id=organization_id,
                telephony_configuration_id=telephony_configuration_id,
                telephony_phone_number_id=from_phone_number_id,
                address=normalized_data.to_number,
            )
        ):
            await db_client.update_phone_preview_session_status(
                session.id,
                status="failed",
                failure_reason="inbound_preview_proof_required",
            )
            return None

        try:
            smoke_attempt = None
            settings = get_preview_telephony_settings()
            if settings.is_classified_smoke:
                smoke_attempt = await self._allocate_classified_inbound(
                    session=session,
                    normalized_data=normalized_data,
                    settings=settings,
                )
                return {
                    "authority_pending": True,
                    "attempt_id": smoke_attempt.attempt_uuid,
                    "idempotency_key": smoke_attempt.idempotency_key,
                    "direction": "inbound",
                    "max_duration_seconds": 60,
                }
            return await self._start_inbound_preview_stream(
                provider_instance=provider_instance,
                session=session,
                normalized_data=normalized_data,
                smoke_attempt=smoke_attempt,
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
        result = self._session_result(
            session,
            otp_required=session.status == "pending_verification",
            inbound_phone_number=inbound_phone_number,
            latency_summary=self._latency_summary_from_workflow_run(workflow_run),
        )
        settings = get_preview_telephony_settings()
        if (
            settings.is_classified_smoke
            and settings.organization_id == organization_id
        ):
            redacted = await onnuri_staging_preflight.get_smoke_redacted_status(
                settings.smoke_envelope_uuid,
                organization_id=settings.organization_id,
            )
            if redacted:
                result.gate_states = {
                    name.lower(): enabled for name, enabled in settings.smoke_gates
                }
                result.remaining_attempts = redacted.get("remaining_attempts")
                result.proof_current = bool(redacted.get("current"))
                result.registration_fresh = False
                result.media_fresh = False
                result.contained = redacted.get("state") == "contained"
                attempts = redacted.get("attempts") or ()
                if attempts:
                    result.terminal_class = attempts[-1].get("terminal_class")
        return result

    async def contain(
        self,
        *,
        user: UserModel,
        session_id: int,
        terminal_class: str,
        terminal_reason: str,
    ) -> PhonePreviewResult:
        organization_id = self._selected_org(user)
        session = await self._get_user_session(session_id, organization_id, user.id)
        attempt_uuid = None
        if session.workflow_run_id:
            workflow_run = await db_client.get_workflow_run(
                session.workflow_run_id, organization_id=organization_id
            )
            if workflow_run:
                attempt_uuid = (workflow_run.initial_context or {}).get(
                    "smoke_attempt_uuid"
                )
        settings = get_preview_telephony_settings()
        if (
            not attempt_uuid
            and settings.is_classified_smoke
            and settings.organization_id == organization_id
        ):
            redacted = await onnuri_staging_preflight.get_smoke_redacted_status(
                settings.smoke_envelope_uuid,
                organization_id=settings.organization_id,
            )
            attempts = (redacted or {}).get("attempts") or ()
            if attempts:
                attempt_uuid = attempts[-1].get("attempt_uuid")
        if not attempt_uuid:
            raise HTTPException(status_code=409, detail="classified_smoke_not_allocated")
        await onnuri_staging_preflight.set_smoke_terminal(
            attempt_uuid,
            organization_id=get_preview_telephony_settings().organization_id,
            terminal_class=terminal_class,
            terminal_reason=terminal_reason,
            contain=True,
        )
        return await self.status(user=user, session_id=session_id)

    async def _start_inbound_preview_stream(
        self,
        *,
        provider_instance,
        session,
        normalized_data,
        smoke_attempt=None,
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
        if smoke_attempt is not None:
            initial_context.update(
                {
                    "classified_smoke": True,
                    "smoke_attempt_uuid": smoke_attempt.attempt_uuid,
                }
            )
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
        application_attempt_id: str | None = None
        settings = get_preview_telephony_settings()
        if smoke_attempt is not None:
            application_attempt_id = smoke_attempt.attempt_uuid
        elif provider_instance.PROVIDER_NAME == JAMBONZ_PROVIDER:
            if not settings.is_configured:
                raise HTTPException(status_code=403, detail="telephony_not_configured")
            application_attempt_id = await self._consume_jambonz_application_smoke_lease(
                settings=settings,
                workflow=workflow,
                workflow_run=workflow_run,
                session=session,
                attempt_kind="inbound",
            )

        backend_endpoint, wss_backend_endpoint = await get_backend_endpoints()
        websocket_url = (
            f"{wss_backend_endpoint}/api/v1/telephony/ws/"
            f"{workflow.id}/{workflow.user_id}/{workflow_run.id}"
        )
        try:
            response = await provider_instance.start_inbound_stream(
                websocket_url=websocket_url,
                workflow_run_id=workflow_run.id,
                normalized_data=normalized_data,
                backend_endpoint=backend_endpoint,
            )
        except Exception:
            if application_attempt_id is not None and smoke_attempt is None:
                await onnuri_staging_preflight.mark_application_smoke_failed(
                    application_attempt_id,
                    organization_id=settings.organization_id,
                    reason="inbound_stream_start_failed",
                )
            raise
        if application_attempt_id is not None and smoke_attempt is None:
            await onnuri_staging_preflight.mark_application_smoke_dispatched(
                application_attempt_id,
                organization_id=settings.organization_id,
            )
        return response

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

    async def _consume_jambonz_application_smoke_lease(
        self,
        *,
        settings: PreviewTelephonySettings,
        workflow,
        workflow_run,
        session,
        attempt_kind: str,
    ) -> str:
        """Consume the one-use proof authorization immediately before dispatch."""
        if settings.from_phone_number_id is None:
            raise HTTPException(
                status_code=403,
                detail="jambonz_application_smoke_authorization_required",
            )

        phone = await db_client.get_phone_number_for_config(
            settings.from_phone_number_id, settings.configuration_id
        )
        if (
            phone is None
            or getattr(phone, "organization_id", None) != settings.organization_id
            or not getattr(phone, "is_active", False)
            or getattr(phone, "inbound_workflow_id", None) is not None
        ):
            raise HTTPException(
                status_code=403,
                detail="jambonz_application_smoke_authorization_required",
            )

        metadata = getattr(phone, "extra_metadata", None) or {}
        inventory_id = metadata.get("inventory_id") if isinstance(metadata, dict) else None
        if (
            isinstance(inventory_id, bool)
            or not isinstance(inventory_id, int)
            or inventory_id <= 0
        ):
            raise HTTPException(
                status_code=403,
                detail="jambonz_application_smoke_authorization_required",
            )

        inventory = await db_client.get_assigned_inventory_for_phone_number(
            inventory_id=inventory_id,
            organization_id=settings.organization_id,
            telephony_phone_number_id=phone.id,
            provider=JAMBONZ_PROVIDER,
            telephony_configuration_id=settings.configuration_id,
            address_normalized=phone.address_normalized,
        )
        proof_id = getattr(inventory, "onnuri_preflight_proof_id", None)
        if (
            inventory is None
            or isinstance(proof_id, bool)
            or not isinstance(proof_id, int)
            or proof_id <= 0
        ):
            raise HTTPException(
                status_code=403,
                detail="jambonz_application_smoke_authorization_required",
            )

        duration_seconds = getattr(session, "max_duration_seconds", None)
        if (
            isinstance(duration_seconds, bool)
            or not isinstance(duration_seconds, int)
            or duration_seconds <= 0
        ):
            raise HTTPException(
                status_code=403,
                detail="jambonz_application_smoke_authorization_required",
            )

        application_attempt_id = f"phone_preview:{attempt_kind}:{workflow_run.id}"
        lease = await onnuri_staging_preflight.acquire_application_smoke_lease(
            proof_id=proof_id,
            inventory_id=inventory.id,
            organization_id=settings.organization_id,
            attempt_kind=attempt_kind,
            duration_seconds=duration_seconds,
            actor_user_id=workflow.user_id,
            application_attempt_id=application_attempt_id,
        )
        attempt = await onnuri_staging_preflight.consume_application_smoke_lease(
            lease.lease_uuid,
            organization_id=settings.organization_id,
            application_attempt_id=application_attempt_id,
        )
        return attempt.application_attempt_id

    async def _start_provider_call(
        self,
        *,
        user: UserModel,
        session,
        idempotency_key: str | None,
        manual_acknowledgement: str | None,
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
        if not is_dispatch_purpose_allowed(
            provider.PROVIDER_NAME, "phone_preview_smoke"
        ):
            raise HTTPException(
                status_code=403,
                detail="telephony_provider_dispatch_not_permitted",
            )

        destination = self._decrypt_destination(session)
        from_number = None
        smoke_attempt = None
        dispatch_capability: bytes | None = None
        parsed_dispatch = None
        if settings.is_classified_smoke:
            if provider.PROVIDER_NAME != JAMBONZ_PROVIDER:
                raise HTTPException(
                    status_code=403,
                    detail="classified_smoke_provider_not_authorized",
                )
            caller = await resolve_jambonz_outbound_caller(
                telephony_configuration_id=settings.configuration_id,
                from_phone_number_id=settings.from_phone_number_id,
            )
            from_number = caller.from_number
        if provider.PROVIDER_NAME == JAMBONZ_PROVIDER and from_number is None:
            caller = await resolve_jambonz_outbound_caller(
                telephony_configuration_id=settings.configuration_id,
                from_phone_number_id=settings.from_phone_number_id,
            )
            from_number = caller.from_number
        elif settings.from_phone_number_id is not None:
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
        if settings.is_classified_smoke:
            smoke_attempt, dispatch_capability = (
                await self._allocate_classified_outbound(
                    user=user,
                    settings=settings,
                    workflow=workflow,
                    workflow_run=workflow_run,
                    session=session,
                    provider=provider,
                    destination=destination,
                    client_idempotency_key=idempotency_key,
                    manual_acknowledgement=manual_acknowledgement,
                )
            )
            parsed_dispatch = parse_dispatch_capability(dispatch_capability)
            initial_context.update(
                {
                    "classified_smoke": True,
                    "smoke_attempt_uuid": smoke_attempt.attempt_uuid,
                }
            )
            await db_client.update_workflow_run(
                run_id=workflow_run.id,
                initial_context=initial_context,
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

        application_attempt_id: str | None = None
        if smoke_attempt is not None:
            application_attempt_id = smoke_attempt.attempt_uuid
        elif provider.PROVIDER_NAME == JAMBONZ_PROVIDER:
            application_attempt_id = await self._consume_jambonz_application_smoke_lease(
                settings=settings,
                workflow=workflow,
                workflow_run=workflow_run,
                session=session,
                attempt_kind="outbound",
            )
        try:
            initiate_kwargs = {}
            if smoke_attempt is not None:
                assert dispatch_capability is not None
                assert parsed_dispatch is not None
                initiate_kwargs = {
                    "classified_smoke": True,
                    "run_id": str(workflow_run.id),
                    "attempt_id": smoke_attempt.attempt_uuid,
                    "application_attempt_id": smoke_attempt.attempt_uuid,
                    "direction": "outbound",
                    "idempotency_key": smoke_attempt.idempotency_key,
                    "dispatch_capability": dispatch_capability,
                    "dispatch_domain": parsed_dispatch.verification_domain,
                    "dispatch_key_id": parsed_dispatch.key_id,
                    "dispatch_algorithm_policy_id": ECDSA_P256_SHA256_POLICY_ID,
                    "authority_deadline": parsed_dispatch.expires_at,
                    "max_call_seconds": 60,
                }
            call_result = await provider.initiate_call(
                to_number=destination,
                webhook_url=webhook_url,
                workflow_run_id=workflow_run.id,
                from_number=from_number,
                workflow_id=workflow.id,
                user_id=workflow.user_id,
                **initiate_kwargs,
            )
        except HTTPException as exc:
            if application_attempt_id is not None and not settings.is_classified_smoke:
                await onnuri_staging_preflight.mark_application_smoke_failed(
                    application_attempt_id,
                    organization_id=settings.organization_id,
                    reason="outbound_provider_rejected",
                )
            raise HTTPException(
                status_code=502,
                detail="preview_call_failed",
            ) from exc
        except Exception:
            if application_attempt_id is not None and not settings.is_classified_smoke:
                await onnuri_staging_preflight.mark_application_smoke_failed(
                    application_attempt_id,
                    organization_id=settings.organization_id,
                    reason="outbound_provider_dispatch_failed",
                )
            raise
        if application_attempt_id is not None and not settings.is_classified_smoke:
            await onnuri_staging_preflight.mark_application_smoke_dispatched(
                application_attempt_id,
                organization_id=settings.organization_id,
            )

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
            **initial_context,
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

    async def _allocate_classified_inbound(
        self,
        *,
        session,
        normalized_data,
        settings: PreviewTelephonySettings,
    ):
        workflow = await db_client.get_workflow(
            session.workflow_id, organization_id=session.organization_id
        )
        if not workflow or workflow.user_id is None:
            raise HTTPException(status_code=404, detail="workflow_not_found")
        if (
            workflow.id != settings.smoke_workflow_id
            or session.organization_id != settings.organization_id
        ):
            raise HTTPException(
                status_code=403, detail="classified_smoke_tuple_mismatch"
            )
        canonical_destination = json.dumps(
            {
                "domain": _DESTINATION_HMAC_DOMAIN,
                "organization_id": settings.organization_id,
                "phone_e164": normalize_preview_phone(normalized_data.from_number),
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            destination_digest = await self.destination_hmac_provider.digest(
                canonical_payload=canonical_destination,
                key_id=settings.destination_hmac_key_id,
                key_version=settings.destination_hmac_key_version,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=503, detail="classified_destination_proof_unavailable"
            ) from exc
        idempotency_key = hashlib.sha256(
            f"inbound:{normalized_data.call_id}".encode("utf-8")
        ).hexdigest()
        request_digest = hashlib.sha256(
            json.dumps(
                {
                    "direction": "inbound",
                    "idempotency_key": idempotency_key,
                    "organization_id": settings.organization_id,
                    "workflow_id": workflow.id,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        try:
            return await onnuri_staging_preflight.allocate_smoke_attempt(
                envelope_uuid=settings.smoke_envelope_uuid,
                organization_id=settings.organization_id,
                proof_id=settings.smoke_proof_id,
                inventory_id=settings.smoke_inventory_id,
                telephony_configuration_id=settings.configuration_id,
                workflow_id=settings.smoke_workflow_id,
                direction="inbound",
                authenticated_operator_user_id=session.user_id,
                workflow_owner_user_id=workflow.user_id,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                destination_hmac_digest=destination_digest,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=403, detail="classified_smoke_allocation_denied"
            ) from exc
    async def _allocate_classified_outbound(
        self,
        *,
        user: UserModel,
        settings: PreviewTelephonySettings,
        workflow,
        workflow_run,
        session,
        provider,
        destination: str,
        client_idempotency_key: str | None,
        manual_acknowledgement: str | None,
    ):
        if (
            workflow.id != settings.smoke_workflow_id
            or user.selected_organization_id != settings.organization_id
            or session.organization_id != settings.organization_id
            or provider.account_id == ""
            or provider.application_id != settings.smoke_application_id
            or not destination.startswith("+8210")
            or not client_idempotency_key
        ):
            raise HTTPException(
                status_code=403, detail="classified_smoke_tuple_mismatch"
            )

        canonical_destination = json.dumps(
            {
                "domain": _DESTINATION_HMAC_DOMAIN,
                "organization_id": settings.organization_id,
                "phone_e164": destination,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            destination_digest = await self.destination_hmac_provider.digest(
                canonical_payload=canonical_destination,
                key_id=settings.destination_hmac_key_id,
                key_version=settings.destination_hmac_key_version,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=503, detail="classified_destination_proof_unavailable"
            ) from exc

        request_digest = hashlib.sha256(
            json.dumps(
                {
                    "application_id": settings.smoke_application_id,
                    "direction": "outbound",
                    "envelope_uuid": settings.smoke_envelope_uuid,
                    "idempotency_key": client_idempotency_key,
                    "inventory_id": settings.smoke_inventory_id,
                    "organization_id": settings.organization_id,
                    "proof_id": settings.smoke_proof_id,
                    "telephony_configuration_id": settings.configuration_id,
                    "workflow_id": workflow.id,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        authority_values = {
            "envelope_uuid": settings.smoke_envelope_uuid,
            "organization_id": settings.organization_id,
            "proof_id": settings.smoke_proof_id,
            "inventory_id": settings.smoke_inventory_id,
            "telephony_configuration_id": settings.configuration_id,
            "workflow_id": workflow.id,
            "authenticated_operator_user_id": user.id,
            "workflow_owner_user_id": workflow.user_id,
            "idempotency_key": client_idempotency_key,
            "request_digest": request_digest,
            "destination_hmac_digest": destination_digest,
            "account_id": provider.account_id,
            "application_id": provider.application_id,
            "run_id": str(workflow_run.id),
        }
        if manual_acknowledgement:
            authority_values.update(
                {
                    "manual_acknowledgement_digest": hashlib.sha256(
                        manual_acknowledgement.encode("utf-8")
                    ).hexdigest(),
                    "manual_acknowledged_at": datetime.now(UTC),
                }
            )
        runtime = get_smoke_authority_runtime()
        try:
            return await allocate_and_issue_dispatch(
                issuer=(
                    self.smoke_capability_issuer
                    if self.smoke_capability_issuer is not None
                    else runtime.issuer
                ),
                recovery_sealer=(
                    self.smoke_recovery_sealer
                    if self.smoke_recovery_sealer is not None
                    else runtime.recovery_sealer
                ),
                **authority_values,
            )
        except F12ServiceError as exc:
            detail = (
                "classified_dispatch_atomic_issuance_unavailable"
                if exc.status_code == 503
                else "classified_smoke_allocation_denied"
            )
            raise HTTPException(status_code=exc.status_code, detail=detail) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=403, detail="classified_smoke_allocation_denied"
            ) from exc
    @staticmethod
    def _require_classified_gates(
        settings: PreviewTelephonySettings, direction_gate: str
    ) -> None:
        gates = dict(settings.smoke_gates)
        required = {
            "DEPENDENCY_MANIFEST",
            "CANDIDATE",
            "ENDPOINT_IDENTITY",
            "COST",
            "LIVE_WINDOW",
            "SIP_REGISTER",
            "RTP",
            "OUTBOUND_CALL",
            "INBOUND_CALL",
        }
        if (
            direction_gate not in {"OUTBOUND_CALL", "INBOUND_CALL"}
            or set(gates) != required
            or any(gates.get(name) is not True for name in required)
        ):
            raise HTTPException(
                status_code=403, detail="classified_smoke_gates_closed"
            )
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
