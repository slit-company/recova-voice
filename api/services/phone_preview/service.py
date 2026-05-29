from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException

from api.db import db_client
from api.db.models import UserModel
from api.enums import CallType
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
    mask_phone,
    normalize_preview_phone,
    phone_hash,
)
from api.services.quota_service import check_dograh_quota_by_user_id
from api.utils.common import get_backend_endpoints


async def _get_preview_telephony_provider_by_id(config_id: int, organization_id: int):
    from api.services.telephony.factory import get_telephony_provider_by_id

    return await get_telephony_provider_by_id(config_id, organization_id)


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

    def as_dict(self) -> dict[str, Any]:
        data = {
            "session_id": self.session_id,
            "status": self.status,
            "otp_required": self.otp_required,
            "masked_phone": self.masked_phone,
            "expires_at": self.expires_at,
            "workflow_run_id": self.workflow_run_id,
            "provider_call_id": self.provider_call_id,
            "failure_reason": self.failure_reason,
        }
        if self.dev_otp_code:
            data["dev_otp_code"] = self.dev_otp_code
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
            phone_number_masked=masked,
            destination_phone_encrypted=encrypt_phone(normalized),
            display_name=display_name,
            status="pending_verification",
            expires_at=now + timedelta(seconds=settings.session_ttl_seconds),
            max_duration_seconds=settings.max_duration_seconds,
        )

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
            raise HTTPException(status_code=400, detail=session.failure_reason or session.status)

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

    async def status(self, *, user: UserModel, session_id: int) -> PhonePreviewResult:
        organization_id = self._selected_org(user)
        session = await self._get_user_session(session_id, organization_id, user.id)
        if session.workflow_run_id and session.status in {"calling", "active"}:
            workflow_run = await db_client.get_workflow_run(
                session.workflow_run_id, organization_id=organization_id
            )
            if workflow_run and workflow_run.is_completed:
                updated_session = await db_client.update_phone_preview_session_status(
                    session.id, status="completed", completed=True
                )
                session = updated_session or session
        return self._session_result(
            session, otp_required=session.status == "pending_verification"
        )

    async def _start_provider_call(self, *, user: UserModel, session) -> PhonePreviewResult:
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
        phone_count = await db_client.count_phone_preview_sessions_since(
            phone_number_hash=session.phone_number_hash,
            since=since,
        )
        if user_count > settings.daily_user_call_limit:
            raise HTTPException(status_code=429, detail="preview_rate_limited")
        if phone_count > settings.daily_phone_call_limit:
            raise HTTPException(status_code=429, detail="preview_phone_rate_limited")

        provider = await _get_preview_telephony_provider_by_id(
            settings.configuration_id, settings.organization_id
        )
        if not provider.validate_config():
            raise HTTPException(status_code=400, detail="telephony_not_configured")

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

        numeric_suffix = int(str(uuid.uuid4()).replace("-", "")[:8], 16) % 100000000
        workflow_run_name = f"WR-PREVIEW-{numeric_suffix:08d}"
        initial_context = {
            **(draft.template_context_variables or {}),
            "phone_number": destination,
            "called_number": destination,
            "called_number_masked": session.phone_number_masked,
            "provider": provider.PROVIDER_NAME,
            "telephony_preview": True,
            "preview_session_id": session.id,
            "preview_user_id": user.id,
            "telephony_configuration_id": settings.configuration_id,
            "telephony_configuration_organization_id": settings.organization_id,
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

        backend_endpoint, _ = await get_backend_endpoints()
        webhook_url = (
            f"{backend_endpoint}/api/v1/telephony/{provider.WEBHOOK_ENDPOINT}"
            f"?workflow_id={workflow.id}"
            f"&user_id={workflow.user_id}"
            f"&workflow_run_id={workflow_run.id}"
            f"&organization_id={session.organization_id}"
        )

        call_result = await provider.initiate_call(
            to_number=destination,
            webhook_url=webhook_url,
            workflow_run_id=workflow_run.id,
            from_number=from_number,
            workflow_id=workflow.id,
            user_id=workflow.user_id,
        )

        provider_call_id = getattr(call_result, "call_id", None) or (
            getattr(call_result, "provider_metadata", {}) or {}
        ).get("call_id")
        gathered_context = {
            "provider": provider.PROVIDER_NAME,
            "preview_session_id": session.id,
            **(getattr(call_result, "provider_metadata", {}) or {}),
        }
        if provider_call_id:
            gathered_context["call_id"] = provider_call_id

        updated_initial_context = {
            **(workflow_run.initial_context or initial_context),
            "called_number": destination,
            "called_number_masked": session.phone_number_masked,
            "telephony_configuration_id": settings.configuration_id,
            "telephony_configuration_organization_id": settings.organization_id,
            "telephony_preview": True,
            "preview_session_id": session.id,
        }
        caller_number = getattr(call_result, "caller_number", None)
        if caller_number:
            updated_initial_context["caller_number"] = caller_number

        await db_client.update_workflow_run(
            run_id=workflow_run.id,
            gathered_context=gathered_context,
            initial_context=updated_initial_context,
        )
        session = await db_client.attach_phone_preview_call(
            session.id,
            workflow_run_id=workflow_run.id,
            provider=provider.PROVIDER_NAME,
            provider_call_id=provider_call_id,
            clear_destination_phone=True,
        )
        return self._session_result(session, otp_required=False)

    def _decrypt_destination(self, session) -> str:
        try:
            return decrypt_phone(session.destination_phone_encrypted)
        except Exception:
            raise HTTPException(status_code=400, detail="preview_destination_unavailable")

    def _selected_org(self, user: UserModel) -> int:
        if not getattr(user, "selected_organization_id", None):
            raise HTTPException(status_code=400, detail="no_organization_selected")
        return user.selected_organization_id

    async def _get_user_session(self, session_id: int, organization_id: int, user_id: int):
        session = await db_client.get_phone_preview_session(
            session_id, organization_id=organization_id, user_id=user_id
        )
        if not session:
            raise HTTPException(status_code=404, detail="preview_session_not_found")
        return session

    def _session_result(self, session, *, otp_required: bool) -> PhonePreviewResult:
        return PhonePreviewResult(
            session_id=session.id,
            status=session.status,
            otp_required=otp_required,
            masked_phone=session.phone_number_masked,
            expires_at=session.expires_at,
            workflow_run_id=session.workflow_run_id,
            provider_call_id=session.provider_call_id,
            failure_reason=session.failure_reason,
        )


phone_preview_service = PhonePreviewService()
