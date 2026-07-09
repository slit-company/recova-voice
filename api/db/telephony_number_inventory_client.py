"""Database access for Recova-managed telephony number inventory."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, func, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.future import select

from api.db.base_client import BaseDBClient
from api.db.models import (
    OrganizationModel,
    TelephonyConfigurationModel,
    TelephonyNumberInventoryAuditModel,
    TelephonyNumberInventoryModel,
    TelephonyPhoneNumberModel,
    WorkflowModel,
)
from api.utils.phone_security import build_stored_phone_number
from api.utils.telephony_address import normalize_telephony_address

INVENTORY_STATUS_AVAILABLE = "available"
INVENTORY_STATUS_RESERVED = "reserved"
INVENTORY_STATUS_ASSIGNED = "assigned"
INVENTORY_STATUS_QUARANTINED = "quarantined"
INVENTORY_STATUS_RETIRED = "retired"
MANAGED_INVENTORY_CREDENTIAL = "recova_number_inventory"


class TelephonyNumberInventoryError(Exception):
    status_code = 400

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class TelephonyNumberInventoryNotFoundError(TelephonyNumberInventoryError):
    status_code = 404


class TelephonyNumberInventoryConflictError(TelephonyNumberInventoryError):
    status_code = 409


class TelephonyNumberInventoryClient(BaseDBClient):
    async def import_telephony_number_inventory(
        self,
        items: list[dict[str, Any]],
        *,
        actor_user_id: int | None,
    ) -> tuple[list[TelephonyNumberInventoryModel], list[dict[str, Any]]]:
        imported: list[TelephonyNumberInventoryModel] = []
        skipped: list[dict[str, Any]] = []

        async with self.async_session() as session:
            for item in items:
                provider = str(item.get("provider") or "jambonz").strip().lower()
                country_code = item.get("country_code")
                address = str(item["address"])
                normalized = normalize_telephony_address(address, country_hint=country_code)
                stored_phone = build_stored_phone_number(
                    address,
                    country_code=country_code,
                )

                existing = (
                    await session.execute(
                        select(TelephonyNumberInventoryModel).where(
                            TelephonyNumberInventoryModel.provider == provider,
                            TelephonyNumberInventoryModel.address_normalized
                            == normalized.canonical,
                        )
                    )
                ).scalars().first()
                if existing:
                    skipped.append(
                        {
                            "provider": provider,
                            "address_masked": existing.address_masked or stored_phone.masked,
                            "reason": "already_imported",
                            "inventory_id": existing.id,
                        }
                    )
                    continue

                row = TelephonyNumberInventoryModel(
                    provider=provider,
                    trunk_group=item.get("trunk_group"),
                    address_normalized=normalized.canonical,
                    address_masked=stored_phone.masked,
                    address_hash=stored_phone.lookup_hash,
                    address_encrypted_raw=stored_phone.encrypted_raw,
                    address_type=normalized.address_type,
                    country_code=country_code or normalized.country_code,
                    label=item.get("label"),
                    status=INVENTORY_STATUS_AVAILABLE,
                    extra_metadata=item.get("extra_metadata") or {},
                )
                session.add(row)
                await session.flush()
                await self._write_inventory_audit(
                    session,
                    inventory_id=row.id,
                    actor_user_id=actor_user_id,
                    organization_id=None,
                    action="imported",
                    from_status=None,
                    to_status=row.status,
                    details={
                        "provider": provider,
                        "address_masked": row.address_masked,
                        "country_code": row.country_code,
                        "trunk_group": row.trunk_group,
                    },
                )
                imported.append(row)

            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_import_conflict"
                ) from exc

            for row in imported:
                await session.refresh(row)

        return imported, skipped

    async def list_telephony_number_inventory(
        self,
        *,
        status: str | None = None,
        provider: str | None = None,
        organization_id: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[TelephonyNumberInventoryModel], int]:
        async with self.async_session() as session:
            filters = []
            if status:
                filters.append(TelephonyNumberInventoryModel.status == status)
            if provider:
                filters.append(TelephonyNumberInventoryModel.provider == provider.lower())
            if organization_id is not None:
                filters.append(
                    TelephonyNumberInventoryModel.organization_id == organization_id
                )

            stmt = select(TelephonyNumberInventoryModel)
            count_stmt = select(func.count()).select_from(TelephonyNumberInventoryModel)
            if filters:
                stmt = stmt.where(*filters)
                count_stmt = count_stmt.where(*filters)

            total_count = int((await session.execute(count_stmt)).scalar_one())
            result = await session.execute(
                stmt.order_by(
                    TelephonyNumberInventoryModel.status,
                    TelephonyNumberInventoryModel.created_at.desc(),
                )
                .limit(limit)
                .offset(offset)
            )
            return list(result.scalars().all()), total_count

    async def reserve_telephony_number_inventory(
        self,
        inventory_id: int,
        *,
        organization_id: int,
        actor_user_id: int | None,
        reservation_expires_at: datetime | None = None,
        note: str | None = None,
    ) -> TelephonyNumberInventoryModel:
        async with self.async_session() as session:
            row = await self._get_inventory_for_update(session, inventory_id)
            if not row:
                raise TelephonyNumberInventoryNotFoundError(
                    "telephony_number_inventory_not_found"
                )
            await self._ensure_organization_exists(session, organization_id)
            if row.status not in (
                INVENTORY_STATUS_AVAILABLE,
                INVENTORY_STATUS_RESERVED,
            ):
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_not_reservable"
                )
            if row.organization_id not in (None, organization_id):
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_reserved_by_another_organization"
                )

            from_status = row.status
            row.status = INVENTORY_STATUS_RESERVED
            row.organization_id = organization_id
            row.reservation_expires_at = reservation_expires_at
            await self._write_inventory_audit(
                session,
                inventory_id=row.id,
                actor_user_id=actor_user_id,
                organization_id=organization_id,
                action="reserved",
                from_status=from_status,
                to_status=row.status,
                details={"note": note, "reservation_expires_at": _iso(reservation_expires_at)},
            )
            await session.commit()
            await session.refresh(row)
            return row

    async def assign_telephony_number_inventory(
        self,
        inventory_id: int,
        *,
        organization_id: int,
        actor_user_id: int | None,
        telephony_configuration_id: int | None = None,
        inbound_workflow_id: int | None = None,
        label: str | None = None,
        set_default_caller_id: bool = False,
        note: str | None = None,
    ) -> TelephonyNumberInventoryModel:
        async with self.async_session() as session:
            row = await self._get_inventory_for_update(session, inventory_id)
            if not row:
                raise TelephonyNumberInventoryNotFoundError(
                    "telephony_number_inventory_not_found"
                )
            await self._ensure_organization_exists(session, organization_id)
            if row.status == INVENTORY_STATUS_ASSIGNED and row.organization_id != organization_id:
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_assigned_to_another_organization"
                )
            if row.status == INVENTORY_STATUS_RESERVED and row.organization_id not in (
                None,
                organization_id,
            ):
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_reserved_by_another_organization"
                )
            if row.status in (
                INVENTORY_STATUS_QUARANTINED,
                INVENTORY_STATUS_RETIRED,
            ):
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_not_assignable"
                )

            if inbound_workflow_id is not None:
                await self._ensure_workflow_belongs_to_org(
                    session, inbound_workflow_id, organization_id
                )

            config = await self._resolve_assignment_config(
                session,
                provider=row.provider,
                organization_id=organization_id,
                telephony_configuration_id=telephony_configuration_id,
            )
            phone = await self._resolve_assignment_phone_number(
                session,
                row,
                organization_id=organization_id,
                config=config,
                label=label,
                inbound_workflow_id=inbound_workflow_id,
                set_default_caller_id=set_default_caller_id,
            )

            from_status = row.status
            row.status = INVENTORY_STATUS_ASSIGNED
            row.organization_id = organization_id
            row.telephony_configuration_id = config.id
            row.telephony_phone_number_id = phone.id
            row.label = label if label is not None else row.label
            row.reservation_expires_at = None
            row.quarantined_reason = None
            row.retired_reason = None
            await self._write_inventory_audit(
                session,
                inventory_id=row.id,
                actor_user_id=actor_user_id,
                organization_id=organization_id,
                action="assigned",
                from_status=from_status,
                to_status=row.status,
                details={
                    "telephony_configuration_id": config.id,
                    "telephony_phone_number_id": phone.id,
                    "inbound_workflow_id": inbound_workflow_id,
                    "note": note,
                },
            )
            await session.commit()
            await session.refresh(row)
            return row

    async def quarantine_telephony_number_inventory(
        self,
        inventory_id: int,
        *,
        actor_user_id: int | None,
        reason: str,
    ) -> TelephonyNumberInventoryModel:
        return await self._transition_inventory_state(
            inventory_id,
            actor_user_id=actor_user_id,
            status=INVENTORY_STATUS_QUARANTINED,
            action="quarantined",
            reason=reason,
        )

    async def retire_telephony_number_inventory(
        self,
        inventory_id: int,
        *,
        actor_user_id: int | None,
        reason: str,
    ) -> TelephonyNumberInventoryModel:
        return await self._transition_inventory_state(
            inventory_id,
            actor_user_id=actor_user_id,
            status=INVENTORY_STATUS_RETIRED,
            action="retired",
            reason=reason,
        )

    async def list_telephony_number_inventory_audit(
        self, inventory_id: int
    ) -> list[TelephonyNumberInventoryAuditModel]:
        async with self.async_session() as session:
            exists = await session.get(TelephonyNumberInventoryModel, inventory_id)
            if not exists:
                raise TelephonyNumberInventoryNotFoundError(
                    "telephony_number_inventory_not_found"
                )
            result = await session.execute(
                select(TelephonyNumberInventoryAuditModel)
                .where(TelephonyNumberInventoryAuditModel.inventory_id == inventory_id)
                .order_by(TelephonyNumberInventoryAuditModel.created_at.desc())
            )
            return list(result.scalars().all())

    async def list_customer_assigned_telephony_numbers(
        self, organization_id: int
    ) -> list[tuple[TelephonyNumberInventoryModel, TelephonyPhoneNumberModel | None, str | None]]:
        async with self.async_session() as session:
            result = await session.execute(
                select(
                    TelephonyNumberInventoryModel,
                    TelephonyPhoneNumberModel,
                    WorkflowModel.name,
                )
                .join(
                    TelephonyPhoneNumberModel,
                    and_(
                        TelephonyPhoneNumberModel.id
                        == TelephonyNumberInventoryModel.telephony_phone_number_id,
                        TelephonyPhoneNumberModel.organization_id == organization_id,
                    ),
                    isouter=True,
                )
                .join(
                    WorkflowModel,
                    and_(
                        WorkflowModel.id == TelephonyPhoneNumberModel.inbound_workflow_id,
                        WorkflowModel.organization_id == organization_id,
                    ),
                    isouter=True,
                )
                .where(
                    TelephonyNumberInventoryModel.organization_id == organization_id,
                    TelephonyNumberInventoryModel.status == INVENTORY_STATUS_ASSIGNED,
                )
                .order_by(TelephonyNumberInventoryModel.created_at.desc())
            )
            return [(row, phone, workflow_name) for row, phone, workflow_name in result.all()]

    async def bind_customer_assigned_telephony_number(
        self,
        inventory_id: int,
        *,
        organization_id: int,
        actor_user_id: int | None,
        workflow_id: int | None,
    ) -> tuple[TelephonyNumberInventoryModel, TelephonyPhoneNumberModel, str | None]:
        async with self.async_session() as session:
            row = await self._get_inventory_for_update(session, inventory_id)
            if not row or row.organization_id != organization_id:
                raise TelephonyNumberInventoryNotFoundError(
                    "telephony_number_inventory_not_found"
                )
            if row.status != INVENTORY_STATUS_ASSIGNED:
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_not_assigned"
                )
            if row.telephony_phone_number_id is None:
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_missing_phone_number"
                )
            phone = await session.get(
                TelephonyPhoneNumberModel, row.telephony_phone_number_id
            )
            if not phone or phone.organization_id != organization_id:
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_phone_number_mismatch"
                )

            workflow_name: str | None = None
            if workflow_id is not None:
                workflow = await self._ensure_workflow_belongs_to_org(
                    session, workflow_id, organization_id
                )
                workflow_name = workflow.name

            from_workflow_id = phone.inbound_workflow_id
            phone.inbound_workflow_id = workflow_id
            await self._write_inventory_audit(
                session,
                inventory_id=row.id,
                actor_user_id=actor_user_id,
                organization_id=organization_id,
                action="bound" if workflow_id is not None else "unbound",
                from_status=row.status,
                to_status=row.status,
                details={
                    "from_inbound_workflow_id": from_workflow_id,
                    "to_inbound_workflow_id": workflow_id,
                    "telephony_phone_number_id": phone.id,
                },
            )
            await session.commit()
            await session.refresh(row)
            await session.refresh(phone)
            return row, phone, workflow_name

    async def _transition_inventory_state(
        self,
        inventory_id: int,
        *,
        actor_user_id: int | None,
        status: str,
        action: str,
        reason: str,
    ) -> TelephonyNumberInventoryModel:
        async with self.async_session() as session:
            row = await self._get_inventory_for_update(session, inventory_id)
            if not row:
                raise TelephonyNumberInventoryNotFoundError(
                    "telephony_number_inventory_not_found"
                )
            if row.status == INVENTORY_STATUS_RETIRED and status != INVENTORY_STATUS_RETIRED:
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_retired"
                )
            from_status = row.status
            row.status = status
            if status == INVENTORY_STATUS_QUARANTINED:
                row.quarantined_reason = reason
            if status == INVENTORY_STATUS_RETIRED:
                row.retired_reason = reason
            if row.telephony_phone_number_id is not None:
                phone = await session.get(
                    TelephonyPhoneNumberModel, row.telephony_phone_number_id
                )
                if phone:
                    phone.is_active = False
                    phone.inbound_workflow_id = None
            await self._write_inventory_audit(
                session,
                inventory_id=row.id,
                actor_user_id=actor_user_id,
                organization_id=row.organization_id,
                action=action,
                from_status=from_status,
                to_status=status,
                details={"reason": reason},
            )
            await session.commit()
            await session.refresh(row)
            return row

    async def _resolve_assignment_config(
        self,
        session,
        *,
        provider: str,
        organization_id: int,
        telephony_configuration_id: int | None,
    ) -> TelephonyConfigurationModel:
        if telephony_configuration_id is not None:
            config = await session.get(TelephonyConfigurationModel, telephony_configuration_id)
            if not config or config.organization_id != organization_id:
                raise TelephonyNumberInventoryNotFoundError(
                    "telephony_configuration_not_found"
                )
            if config.provider != provider:
                raise TelephonyNumberInventoryConflictError(
                    "telephony_configuration_provider_mismatch"
                )
            return config

        result = await session.execute(
            select(TelephonyConfigurationModel)
            .where(
                TelephonyConfigurationModel.organization_id == organization_id,
                TelephonyConfigurationModel.provider == provider,
            )
            .order_by(TelephonyConfigurationModel.id)
        )
        for config in result.scalars().all():
            credentials = config.credentials or {}
            if credentials.get("managed_by") == MANAGED_INVENTORY_CREDENTIAL:
                return config

        config = TelephonyConfigurationModel(
            organization_id=organization_id,
            name=f"Recova Managed {provider.title()}",
            provider=provider,
            credentials={
                "managed_by": MANAGED_INVENTORY_CREDENTIAL,
                "hidden": True,
            },
            is_default_outbound=False,
        )
        session.add(config)
        await session.flush()
        return config

    async def _resolve_assignment_phone_number(
        self,
        session,
        row: TelephonyNumberInventoryModel,
        *,
        organization_id: int,
        config: TelephonyConfigurationModel,
        label: str | None,
        inbound_workflow_id: int | None,
        set_default_caller_id: bool,
    ) -> TelephonyPhoneNumberModel:
        phone: TelephonyPhoneNumberModel | None = None
        if row.telephony_phone_number_id is not None:
            phone = await session.get(TelephonyPhoneNumberModel, row.telephony_phone_number_id)
            if phone and phone.organization_id != organization_id:
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_phone_number_mismatch"
                )

        if phone is None:
            existing = (
                await session.execute(
                    select(TelephonyPhoneNumberModel).where(
                        TelephonyPhoneNumberModel.organization_id == organization_id,
                        TelephonyPhoneNumberModel.address_normalized
                        == row.address_normalized,
                    )
                )
            ).scalars().first()
            if existing:
                metadata = existing.extra_metadata or {}
                if metadata.get("inventory_id") not in (None, row.id):
                    raise TelephonyNumberInventoryConflictError(
                        "telephony_phone_number_already_bound_to_inventory"
                    )
                phone = existing
            else:
                phone = TelephonyPhoneNumberModel(
                    organization_id=organization_id,
                    telephony_configuration_id=config.id,
                    address=row.address_normalized,
                    address_normalized=row.address_normalized,
                    address_masked=row.address_masked,
                    address_hash=row.address_hash,
                    address_encrypted_raw=row.address_encrypted_raw,
                    address_type=row.address_type,
                    country_code=row.country_code,
                    label=label or row.label,
                    inbound_workflow_id=inbound_workflow_id,
                    is_active=True,
                    is_default_caller_id=False,
                    extra_metadata={
                        "inventory_id": row.id,
                        "managed_by": MANAGED_INVENTORY_CREDENTIAL,
                    },
                )
                session.add(phone)
                await session.flush()

        phone.telephony_configuration_id = config.id
        phone.label = label if label is not None else phone.label
        if inbound_workflow_id is not None:
            phone.inbound_workflow_id = inbound_workflow_id
        phone.is_active = True
        phone.extra_metadata = {
            **(phone.extra_metadata or {}),
            "inventory_id": row.id,
            "managed_by": MANAGED_INVENTORY_CREDENTIAL,
        }
        if set_default_caller_id:
            await session.execute(
                update(TelephonyPhoneNumberModel)
                .where(
                    TelephonyPhoneNumberModel.telephony_configuration_id == config.id,
                    TelephonyPhoneNumberModel.is_default_caller_id.is_(True),
                )
                .values(is_default_caller_id=False)
            )
            phone.is_default_caller_id = True
        await session.flush()
        return phone

    @staticmethod
    async def _get_inventory_for_update(session, inventory_id: int):
        result = await session.execute(
            select(TelephonyNumberInventoryModel)
            .where(TelephonyNumberInventoryModel.id == inventory_id)
            .with_for_update()
        )
        return result.scalars().first()

    @staticmethod
    async def _ensure_organization_exists(session, organization_id: int) -> OrganizationModel:
        organization = await session.get(OrganizationModel, organization_id)
        if not organization:
            raise TelephonyNumberInventoryNotFoundError("organization_not_found")
        return organization

    @staticmethod
    async def _ensure_workflow_belongs_to_org(
        session, workflow_id: int, organization_id: int
    ) -> WorkflowModel:
        workflow = await session.get(WorkflowModel, workflow_id)
        if not workflow or workflow.organization_id != organization_id:
            raise TelephonyNumberInventoryNotFoundError("workflow_not_found")
        return workflow

    @staticmethod
    async def _write_inventory_audit(
        session,
        *,
        inventory_id: int,
        actor_user_id: int | None,
        organization_id: int | None,
        action: str,
        from_status: str | None,
        to_status: str | None,
        details: dict[str, Any],
    ) -> None:
        session.add(
            TelephonyNumberInventoryAuditModel(
                inventory_id=inventory_id,
                actor_user_id=actor_user_id,
                organization_id=organization_id,
                action=action,
                from_status=from_status,
                to_status=to_status,
                details={k: v for k, v in details.items() if v is not None},
            )
        )


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.isoformat()
