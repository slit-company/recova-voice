"""Database access for first-class telephony call events, CDRs, and ops alerts."""

from datetime import UTC, datetime
from typing import Any, Optional

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from api.db.base_client import BaseDBClient
from api.db.models import (
    TelephonyCDRModel,
    TelephonyCallEventModel,
    TelephonyOpsAlertModel,
)


class TelephonyCallEventClient(BaseDBClient):
    async def record_telephony_call_event(
        self, **fields: Any
    ) -> TelephonyCallEventModel:
        """Insert one normalized telephony event idempotently."""

        idempotency_key = fields["idempotency_key"]
        async with self.async_session() as session:
            existing = await session.execute(
                select(TelephonyCallEventModel).where(
                    TelephonyCallEventModel.idempotency_key == idempotency_key
                )
            )
            row = existing.scalars().first()
            if row:
                return row

            row = TelephonyCallEventModel(**fields)
            session.add(row)
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                existing = await session.execute(
                    select(TelephonyCallEventModel).where(
                        TelephonyCallEventModel.idempotency_key == idempotency_key
                    )
                )
                row = existing.scalars().first()
                if row:
                    return row
                raise
            await session.refresh(row)
            return row

    async def upsert_telephony_cdr(self, **fields: Any) -> TelephonyCDRModel:
        """Create or update the single terminal CDR for a call attempt."""

        call_attempt_id = fields["call_attempt_id"]
        async with self.async_session() as session:
            result = await session.execute(
                select(TelephonyCDRModel)
                .where(TelephonyCDRModel.call_attempt_id == call_attempt_id)
                .with_for_update()
            )
            row = result.scalars().first()
            if row:
                for key, value in fields.items():
                    setattr(row, key, value)
                row.updated_at = datetime.now(UTC)
            else:
                row = TelephonyCDRModel(**fields)
                session.add(row)

            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                result = await session.execute(
                    select(TelephonyCDRModel).where(
                        TelephonyCDRModel.call_attempt_id == call_attempt_id
                    )
                )
                row = result.scalars().first()
                if row:
                    return row
                raise
            await session.refresh(row)
            return row

    async def mark_telephony_artifact(
        self,
        *,
        workflow_run_id: int,
        artifact_type: str,
        expected: bool = True,
        present: bool = True,
        artifact_payload: Optional[dict[str, Any]] = None,
    ) -> None:
        """Mark recording/transcript artifact expectations for events and CDRs."""

        if artifact_type not in {"recording", "transcript"}:
            raise ValueError(f"Unsupported telephony artifact type: {artifact_type}")

        values = {
            f"artifact_{artifact_type}_expected": expected,
            f"artifact_{artifact_type}_present": present,
            "updated_at": datetime.now(UTC),
        }
        if artifact_payload is not None:
            values["artifact_payload"] = artifact_payload
        async with self.async_session() as session:
            await session.execute(
                update(TelephonyCallEventModel)
                .where(TelephonyCallEventModel.workflow_run_id == workflow_run_id)
                .values(**values)
            )
            await session.execute(
                update(TelephonyCDRModel)
                .where(TelephonyCDRModel.workflow_run_id == workflow_run_id)
                .values(**values)
            )
            await session.commit()

    async def upsert_telephony_ops_alert(
        self,
        *,
        alert_type: str,
        severity: str,
        dedupe_key: str,
        summary: str,
        details_redacted: Optional[dict[str, Any]] = None,
        organization_id: Optional[int] = None,
        provider: Optional[str] = None,
        source: str = "runtime",
        is_contract_fixture: bool = False,
        should_page_live_ops: bool = False,
        escalation_threshold: int = 3,
    ) -> TelephonyOpsAlertModel:
        """Insert or update an ops alert under its dedupe key."""

        now = datetime.now(UTC)
        async with self.async_session() as session:
            result = await session.execute(
                select(TelephonyOpsAlertModel)
                .where(TelephonyOpsAlertModel.dedupe_key == dedupe_key)
                .with_for_update()
            )
            row = result.scalars().first()
            if row:
                row.occurrence_count += 1
                row.last_seen_at = now
                row.summary = summary
                row.details_redacted = details_redacted or {}
                row.should_page_live_ops = should_page_live_ops
                if row.occurrence_count >= escalation_threshold and not row.escalated_at:
                    row.escalated_at = now
                row.updated_at = now
            else:
                row = TelephonyOpsAlertModel(
                    alert_type=alert_type,
                    severity=severity,
                    dedupe_key=dedupe_key,
                    summary=summary,
                    details_redacted=details_redacted or {},
                    organization_id=organization_id,
                    provider=provider,
                    source=source,
                    is_contract_fixture=is_contract_fixture,
                    should_page_live_ops=should_page_live_ops,
                    occurrence_count=1,
                    first_seen_at=now,
                    last_seen_at=now,
                    escalated_at=now if escalation_threshold <= 1 else None,
                )
                session.add(row)

            await session.commit()
            await session.refresh(row)
            return row

    async def list_live_readiness_telephony_cdrs(
        self, *, organization_id: int | None = None
    ) -> list[TelephonyCDRModel]:
        """Return only CDRs that may count as live trunk readiness evidence."""

        async with self.async_session() as session:
            query = select(TelephonyCDRModel).where(
                TelephonyCDRModel.is_contract_fixture.is_(False),
                TelephonyCDRModel.live_trunk_validated.is_(True),
            )
            if organization_id is not None:
                query = query.where(TelephonyCDRModel.organization_id == organization_id)
            result = await session.execute(query.order_by(TelephonyCDRModel.created_at))
            return list(result.scalars().all())
