from datetime import UTC, datetime
from typing import Optional

from sqlalchemy import delete, func, or_, update
from sqlalchemy.future import select

from api.db.base_client import BaseDBClient
from api.db.models import (
    PhonePreviewSessionModel,
    PhonePreviewVerificationModel,
)


class PhonePreviewClient(BaseDBClient):
    async def create_phone_preview_verification(
        self,
        *,
        organization_id: int,
        user_id: int,
        phone_number_hash: str,
        phone_number_masked: str,
        code_hash: str,
        code_salt: str,
        expires_at: datetime,
    ) -> PhonePreviewVerificationModel:
        async with self.async_session() as session:
            row = PhonePreviewVerificationModel(
                organization_id=organization_id,
                user_id=user_id,
                phone_number_hash=phone_number_hash,
                phone_number_masked=phone_number_masked,
                code_hash=code_hash,
                code_salt=code_salt,
                expires_at=expires_at,
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row

    async def get_recent_verified_phone_preview_verification(
        self,
        *,
        organization_id: int,
        user_id: int,
        phone_number_hash: str,
        now: datetime,
    ) -> Optional[PhonePreviewVerificationModel]:
        async with self.async_session() as session:
            result = await session.execute(
                select(PhonePreviewVerificationModel)
                .where(
                    PhonePreviewVerificationModel.organization_id == organization_id,
                    PhonePreviewVerificationModel.user_id == user_id,
                    PhonePreviewVerificationModel.phone_number_hash
                    == phone_number_hash,
                    PhonePreviewVerificationModel.status == "verified",
                    PhonePreviewVerificationModel.expires_at > now,
                )
                .order_by(PhonePreviewVerificationModel.verified_at.desc())
                .limit(1)
            )
            return result.scalars().first()

    async def get_phone_preview_verification(
        self, verification_id: int
    ) -> Optional[PhonePreviewVerificationModel]:
        async with self.async_session() as session:
            return await session.get(PhonePreviewVerificationModel, verification_id)

    async def increment_phone_preview_verification_attempts(
        self,
        verification_id: int,
        *,
        status: str | None = None,
    ) -> Optional[PhonePreviewVerificationModel]:
        async with self.async_session() as session:
            row = await session.get(PhonePreviewVerificationModel, verification_id)
            if not row:
                return None
            row.attempts = (row.attempts or 0) + 1
            if status:
                row.status = status
            row.updated_at = datetime.now(UTC)
            await session.commit()
            await session.refresh(row)
            return row

    async def set_phone_preview_verification_status(
        self,
        verification_id: int,
        *,
        status: str,
    ) -> Optional[PhonePreviewVerificationModel]:
        async with self.async_session() as session:
            row = await session.get(PhonePreviewVerificationModel, verification_id)
            if not row:
                return None
            row.status = status
            row.updated_at = datetime.now(UTC)
            await session.commit()
            await session.refresh(row)
            return row

    async def mark_phone_preview_verification_verified(
        self,
        verification_id: int,
        *,
        verified_until: datetime,
    ) -> Optional[PhonePreviewVerificationModel]:
        async with self.async_session() as session:
            row = await session.get(PhonePreviewVerificationModel, verification_id)
            if not row:
                return None
            row.status = "verified"
            row.verified_at = datetime.now(UTC)
            row.expires_at = verified_until
            row.updated_at = datetime.now(UTC)
            await session.commit()
            await session.refresh(row)
            return row

    async def create_phone_preview_session(
        self,
        *,
        organization_id: int,
        user_id: int,
        workflow_id: int,
        phone_number_hash: str,
        phone_number_global_hash: str | None,
        phone_number_masked: str,
        destination_phone_encrypted: str,
        status: str,
        expires_at: datetime,
        verification_id: int | None = None,
        display_name: str | None = None,
        max_duration_seconds: int = 300,
    ) -> PhonePreviewSessionModel:
        async with self.async_session() as session:
            row = PhonePreviewSessionModel(
                organization_id=organization_id,
                user_id=user_id,
                workflow_id=workflow_id,
                verification_id=verification_id,
                phone_number_hash=phone_number_hash,
                phone_number_global_hash=phone_number_global_hash,
                phone_number_masked=phone_number_masked,
                destination_phone_encrypted=destination_phone_encrypted,
                display_name=display_name,
                status=status,
                expires_at=expires_at,
                max_duration_seconds=max_duration_seconds,
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row

    async def get_phone_preview_session(
        self,
        session_id: int,
        *,
        organization_id: int | None = None,
        user_id: int | None = None,
    ) -> Optional[PhonePreviewSessionModel]:
        async with self.async_session() as session:
            query = select(PhonePreviewSessionModel).where(
                PhonePreviewSessionModel.id == session_id
            )
            if organization_id is not None:
                query = query.where(
                    PhonePreviewSessionModel.organization_id == organization_id
                )
            if user_id is not None:
                query = query.where(PhonePreviewSessionModel.user_id == user_id)
            result = await session.execute(query)
            return result.scalars().first()

    async def get_phone_preview_session_for_run(
        self, workflow_run_id: int
    ) -> Optional[PhonePreviewSessionModel]:
        async with self.async_session() as session:
            result = await session.execute(
                select(PhonePreviewSessionModel).where(
                    PhonePreviewSessionModel.workflow_run_id == workflow_run_id
                )
            )
            return result.scalars().first()

    async def mark_phone_preview_session_verified(
        self,
        session_id: int,
        *,
        verification_id: int,
    ) -> Optional[PhonePreviewSessionModel]:
        async with self.async_session() as session:
            row = await session.get(PhonePreviewSessionModel, session_id)
            if not row:
                return None
            row.status = "verified"
            row.verification_id = verification_id
            row.updated_at = datetime.now(UTC)
            await session.commit()
            await session.refresh(row)
            return row

    async def begin_phone_preview_call(
        self,
        session_id: int,
        *,
        organization_id: int,
        user_id: int,
    ) -> tuple[Optional[PhonePreviewSessionModel], bool]:
        """Atomically reserve a verified session for one provider call.

        Returns ``(session, should_start_provider_call)``. Already-started
        sessions are idempotent and return ``False``.
        """
        async with self.async_session() as session:
            result = await session.execute(
                select(PhonePreviewSessionModel)
                .where(
                    PhonePreviewSessionModel.id == session_id,
                    PhonePreviewSessionModel.organization_id == organization_id,
                    PhonePreviewSessionModel.user_id == user_id,
                )
                .with_for_update()
            )
            row = result.scalars().first()
            if not row:
                return None, False
            if row.workflow_run_id and row.status in {
                "calling",
                "active",
                "completed",
            }:
                return row, False
            now = datetime.now(UTC)
            if row.expires_at <= now:
                row.status = "expired"
                row.failure_reason = "expired"
                row.destination_phone_encrypted = None
                row.updated_at = now
                await session.commit()
                await session.refresh(row)
                return row, False
            if row.status != "verified":
                return row, False
            row.status = "calling"
            row.updated_at = now
            await session.commit()
            await session.refresh(row)
            return row, True

    async def attach_phone_preview_call(
        self,
        session_id: int,
        *,
        workflow_run_id: int,
        provider: str,
        provider_call_id: str | None,
        clear_destination_phone: bool = True,
    ) -> Optional[PhonePreviewSessionModel]:
        async with self.async_session() as session:
            row = await session.get(PhonePreviewSessionModel, session_id)
            if not row:
                return None
            row.status = "calling"
            row.workflow_run_id = workflow_run_id
            row.provider = provider
            row.provider_call_id = provider_call_id
            if clear_destination_phone:
                row.destination_phone_encrypted = None
            row.updated_at = datetime.now(UTC)
            await session.commit()
            await session.refresh(row)
            return row

    async def update_phone_preview_session_status(
        self,
        session_id: int,
        *,
        status: str,
        failure_reason: str | None = None,
        completed: bool = False,
    ) -> Optional[PhonePreviewSessionModel]:
        async with self.async_session() as session:
            row = await session.get(PhonePreviewSessionModel, session_id)
            if not row:
                return None
            row.status = status
            row.failure_reason = failure_reason
            row.updated_at = datetime.now(UTC)
            if completed:
                row.completed_at = datetime.now(UTC)
            if completed or status in {"completed", "failed", "expired"}:
                row.destination_phone_encrypted = None
            await session.commit()
            await session.refresh(row)
            return row

    async def count_phone_preview_sessions_since(
        self,
        *,
        organization_id: int | None = None,
        user_id: int | None = None,
        phone_number_hash: str | None = None,
        phone_number_global_hash: str | None = None,
        since: datetime,
    ) -> int:
        async with self.async_session() as session:
            query = select(func.count(PhonePreviewSessionModel.id)).where(
                PhonePreviewSessionModel.created_at >= since
            )
            if organization_id is not None:
                query = query.where(
                    PhonePreviewSessionModel.organization_id == organization_id
                )
            if user_id is not None:
                query = query.where(PhonePreviewSessionModel.user_id == user_id)
            if phone_number_hash is not None:
                query = query.where(
                    PhonePreviewSessionModel.phone_number_hash == phone_number_hash
                )
            if phone_number_global_hash is not None:
                query = query.where(
                    PhonePreviewSessionModel.phone_number_global_hash
                    == phone_number_global_hash
                )
            result = await session.execute(query)
            return int(result.scalar() or 0)

    async def expire_phone_preview_records(self, *, now: datetime) -> dict[str, int]:
        """Mark expired pending preview sessions/verifications without removing audit rows."""
        async with self.async_session() as session:
            verification_result = await session.execute(
                update(PhonePreviewVerificationModel)
                .where(
                    PhonePreviewVerificationModel.expires_at <= now,
                    PhonePreviewVerificationModel.status == "pending",
                )
                .values(status="expired", updated_at=now)
            )
            session_result = await session.execute(
                update(PhonePreviewSessionModel)
                .where(
                    PhonePreviewSessionModel.expires_at <= now,
                    PhonePreviewSessionModel.status.in_(
                        ("pending_verification", "verified")
                    ),
                )
                .values(
                    status="expired",
                    failure_reason="expired",
                    updated_at=now,
                    destination_phone_encrypted=None,
                )
            )
            await session.commit()
            return {
                "verifications": verification_result.rowcount or 0,
                "sessions": session_result.rowcount or 0,
            }

    async def purge_phone_preview_records_before(
        self, *, cutoff: datetime
    ) -> dict[str, int]:
        """Delete expired/completed preview records past the retention cutoff."""
        async with self.async_session() as session:
            session_result = await session.execute(
                delete(PhonePreviewSessionModel).where(
                    or_(
                        PhonePreviewSessionModel.expires_at < cutoff,
                        PhonePreviewSessionModel.completed_at < cutoff,
                    )
                )
            )
            verification_result = await session.execute(
                delete(PhonePreviewVerificationModel).where(
                    PhonePreviewVerificationModel.expires_at < cutoff
                )
            )
            await session.commit()
            return {
                "sessions": session_result.rowcount or 0,
                "verifications": verification_result.rowcount or 0,
            }
