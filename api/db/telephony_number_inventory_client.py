"""Database access for Recova-managed telephony number inventory."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Any, Awaitable, Callable
from uuid import UUID, uuid4

from sqlalchemy import and_, func, or_, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.future import select

from api.db.base_client import BaseDBClient
from api.db.models import (
    G008InboundBindingModel,
    G008ExecutionNonceConsumptionModel,
    G008OutboundBindingModel,
    G008ExecutionSealModel,
    G008ExecutionStageModel,
    OnnuriRegistrationGateModel,
    OnnuriSmokeAnswerAuthorizationModel,
    OnnuriSmokeAttemptModel,
    OnnuriSmokeCapabilityConsumptionModel,
    OnnuriSmokeCallbackEventModel,
    OnnuriSmokeEnvelopeModel,
    OnnuriStagingCandidateModel,
    OnnuriOutboundDiagnosticAttemptModel,
    OnnuriOutboundDiagnosticCapabilityModel,
    OnnuriOutboundDiagnosticEventModel,
    OnnuriOutboundDiagnosticLateEvidenceModel,
    OnnuriRouteAdapterReplayModel,
    OnnuriStagingPreflightAuthorizationLeaseModel,
    OnnuriStagingPreflightExpiryJobModel,
    OnnuriStagingPreflightProofModel,
    OnnuriStagingSmokeDispatchAttemptModel,
    OrganizationModel,
    TelephonyConfigurationModel,
    TelephonyNumberInventoryAuditModel,
    TelephonyNumberInventoryModel,
    TelephonyPhoneNumberModel,
    UserModel,
    WorkflowModel,
)
from api.services.telephony.onnuri_preflight_policy import (
    DISPATCH_CAPABILITY_DOMAIN,
    MEDIA_CAPABILITY_DOMAIN,
    OnnuriPreflightPolicyError,
    canonicalize_proof_input,
)
from api.utils.phone_security import build_stored_phone_number
from api.utils.telephony_address import normalize_telephony_address

INVENTORY_STATUS_AVAILABLE = "available"
INVENTORY_STATUS_RESERVED = "reserved"
INVENTORY_STATUS_ASSIGNED = "assigned"
INVENTORY_STATUS_QUARANTINED = "quarantined"
INVENTORY_STATUS_RETIRED = "retired"
MANAGED_INVENTORY_CREDENTIAL = "recova_number_inventory"
DESTINATION_HMAC_DOMAIN = "recova.onnuri.smoke.destination.v1"
CAPABILITY_ALGORITHM_POLICY_ID = "gcp-kms-ecdsa-p256-sha256-v1"
ONNURI_SMOKE_AUTHORITY_V2 = "recova_onnuri_smoke_authority_v2"
ONNURI_SMOKE_AUTHORITY_V3 = "recova_onnuri_smoke_authority_v3"
_ONNURI_V3_RECEIPT_FIELDS = (
    "provider_balance_currency_receipt_digest",
    "supplier_signaling_media_receipt_digest",
    "tenant_mapping_receipt_digest",
    "secret_version_manifest_receipt_digest",
    "gate_decision_receipt_digest",
)
RECOVA_INVENTORY_STATE_KEY = "recova_inventory_state"
INVENTORY_ID_METADATA_KEY = "inventory_id"
MANAGED_BY_METADATA_KEY = "managed_by"
TELEPHONY_PHONE_NUMBER_ID_METADATA_KEY = "telephony_phone_number_id"
CONTRACT_VERSION_METADATA_KEY = "contract_version"
IS_CONTRACT_FIXTURE_METADATA_KEY = "is_contract_fixture"
LIVE_TRUNK_VALIDATED_METADATA_KEY = "live_trunk_validated"
LIVE_VALIDATION_SOURCE_METADATA_KEY = "live_validation_source"
LIVE_VALIDATION_EVIDENCE_ID_METADATA_KEY = "live_validation_evidence_id"
PROVIDER_METADATA_KEY = "provider"
PROVIDER_CONFIG_ID_METADATA_KEY = "provider_config_id"
TELEPHONY_CONFIGURATION_ID_METADATA_KEY = "telephony_configuration_id"
PHONE_NUMBER_ID_METADATA_KEY = "phone_number_id"
CALL_ATTEMPT_ID_METADATA_KEY = "call_attempt_id"
LIVE_VALIDATION_TRUSTED_WRITER_METADATA_KEY = "live_validation_trusted_writer"
LIVE_VALIDATION_TRUSTED_WRITER = "recova_operator_live_validation_v1"
JAMBONZ_CONTRACT_VERSION = "jambonz_contract_v1"
MAX_ONNURI_REGISTRATION_APPLICATION_RETRIES = 2
MAX_ONNURI_REGISTRATION_PROTOCOL_RETRANSMISSIONS = 2
APPROVED_LIVE_VALIDATION_SOURCES = frozenset(
    {"live_validation_tool", "operator_attestation"}
)
_ONNURI_FACADE_CATALOG_FINGERPRINTS = {
    "onnuri_smoke_authority_row_guard": (
        "5313c83153a10f2cd206e981d425683fc176d4e38c4f74ba3f82331e0ecbd269"
    ),
    "onnuri_smoke_facade_context_guard": (
        "f29fc91c59ddb7c5cdc4bea9b089897a423bac15d380ded7037db34ba5933d63"
    ),
    "ck_onnuri_smoke_attempt_bound_context": (
        "4800c34b8bdfbb82c2a96c9344e9d5caf77b91ad41a7afbd5585b657d542e3b2"
    ),
    "uq_onnuri_smoke_callback_nonce": (
        "4bfb3639cb4897f0cc674e64133ed3812e27ca79e1fafd690d2da3723aa27e69"
    ),
    "ck_onnuri_smoke_callback_event_type": (
        "3009e9c9ecebd5a97123adcff2f868703b0c84d6e799ed1d4c69bd70348f4aef"
    ),
    "ck_onnuri_smoke_callback_duration": (
        "e0d9cbe63714b11f45bb01732363d8b3f413cce784370c90364afcac08d58cf6"
    ),
    "callback_attempt_fk": (
        "9d0d246808294568f60184f428dcf729e21f1288dee378ce224dc295cde626fe"
    ),
    "callback_events_primary_key": (
        "8c8464f42472e42ee190fc91ca8db79b5351d3a4609040516578d229c56f6fa5"
    ),
}


class TelephonyNumberInventoryError(Exception):
    status_code = 400

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class TelephonyNumberInventoryNotFoundError(TelephonyNumberInventoryError):
    status_code = 404


class TelephonyNumberInventoryConflictError(TelephonyNumberInventoryError):
    status_code = 409


def _digest_equal(left: str | None, right: str | None) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return left is None and right is None
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _is_lowercase_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_lowercase_attestation_key_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and value[0].isalnum()
        and value == value.lower()
        and all(
            character in "abcdefghijklmnopqrstuvwxyz0123456789._-"
            for character in value
        )
    )


def _onnuri_smoke_has_v3_prerequisites(
    envelope: OnnuriSmokeEnvelopeModel | None,
) -> bool:
    return (
        envelope is not None
        and envelope.evaluator_version == ONNURI_SMOKE_AUTHORITY_V3
        and envelope.sealed_at is not None
        and all(
            _is_lowercase_sha256(getattr(envelope, field))
            for field in _ONNURI_V3_RECEIPT_FIELDS
        )
    )


def _inbound_tuple_digest(values: tuple[str, str, str, str, str]) -> str:
    canonical = json.dumps(
        values,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _registration_binding_digest(
    *,
    organization_id: int,
    envelope_uuid: str,
    operation_kind: str,
    request_digest: str,
    candidate_digest: str,
    gate_envelope_digest: str,
    nonce_digest: str,
    prior_register_gate_id: int | None,
    prior_register_operation_uuid: str | None,
) -> str:
    payload = {
        "candidate_digest": candidate_digest,
        "envelope_uuid": envelope_uuid,
        "gate_envelope_digest": gate_envelope_digest,
        "nonce_digest": nonce_digest,
        "operation_kind": operation_kind,
        "organization_id": organization_id,
        "prior_register_gate_id": prior_register_gate_id,
        "prior_register_operation_uuid": prior_register_operation_uuid,
        "request_digest": request_digest,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _registration_receipt_digest(values: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(values, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
def _validated_onnuri_facade_context(
    account_id: str | None, application_id: str | None, run_id: str | None
) -> tuple[str, str, str]:
    values = (account_id, application_id, run_id)
    if not all(isinstance(value, str) and value.strip() for value in values):
        raise TelephonyNumberInventoryConflictError(
            "onnuri_smoke_facade_context_invalid"
        )
    return tuple(str(value).strip() for value in values)  # type: ignore[return-value]


def _onnuri_facade_context_matches(
    attempt: OnnuriSmokeAttemptModel, context: tuple[str, str, str]
) -> bool:
    return (
        _digest_equal(attempt.account_id, context[0])
        and _digest_equal(attempt.application_id, context[1])
        and _digest_equal(attempt.run_id, context[2])
    )

_ONNURI_FACADE_STATUS_RANK = {
    "allocated": 0, "dispatch_consumed": 1, "stock_requested": 2,
    "stock_bound": 3, "answer_authority_committed": 4, "media_issued": 5,
    "media_consumed": 6, "running": 7, "completed": 8, "busy": 8,
    "no_answer": 8, "failed": 8, "canceled": 8, "contained": 8,
}
_ONNURI_FACADE_TERMINAL = frozenset(
    {"completed", "busy", "no_answer", "failed", "canceled", "contained"}
)
_ONNURI_ATTEMPT_STATUS = {
    "dispatch_issued": "dispatch_consumed",
    "dispatch_issuing": "dispatch_consumed",
    "outbound_answer_recorded_media_issued": "media_issued",
    "inbound_answer_committed_media_issued": "media_issued",
    "outbound_answer_recorded_media_consumed": "media_consumed",
    "inbound_answer_committed_media_consumed": "media_consumed",
    "terminal": "failed",
}


def _onnuri_facade_status(attempt: OnnuriSmokeAttemptModel) -> str:
    if attempt.state == "terminal" and attempt.terminal_class in _ONNURI_FACADE_TERMINAL:
        return attempt.terminal_class
    return _ONNURI_ATTEMPT_STATUS.get(attempt.state, attempt.state)


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
                normalized = normalize_telephony_address(
                    address, country_hint=country_code
                )
                stored_phone = build_stored_phone_number(
                    address,
                    country_code=country_code,
                )

                existing = (
                    (
                        await session.execute(
                            select(TelephonyNumberInventoryModel).where(
                                TelephonyNumberInventoryModel.provider == provider,
                                TelephonyNumberInventoryModel.address_normalized
                                == normalized.canonical,
                                TelephonyNumberInventoryModel.status
                                != INVENTORY_STATUS_RETIRED,
                            )
                        )
                    )
                    .scalars()
                    .first()
                )
                if existing:
                    skipped.append(
                        {
                            "provider": provider,
                            "address_masked": existing.address_masked
                            or stored_phone.masked,
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
                    extra_metadata=_strip_live_validation_metadata(
                        item.get("extra_metadata") or {}
                    ),
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
                filters.append(
                    TelephonyNumberInventoryModel.provider == provider.lower()
                )
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
            if row.onnuri_staging_candidate_id is not None:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_candidate_requires_proof_bound_reservation"
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
                details={
                    "note": note,
                    "reservation_expires_at": _iso(reservation_expires_at),
                },
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
        onnuri_preflight_proof_id: int | None = None,
    ) -> TelephonyNumberInventoryModel:
        async with self.async_session() as session:
            proof = None
            if onnuri_preflight_proof_id is not None:
                proof = (
                    (
                        await session.execute(
                            select(OnnuriStagingPreflightProofModel)
                            .where(
                                OnnuriStagingPreflightProofModel.id
                                == onnuri_preflight_proof_id
                            )
                            .with_for_update()
                        )
                    )
                    .scalars()
                    .first()
                )
            if onnuri_preflight_proof_id is not None:
                if actor_user_id is None:
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_staging_privileged_actor_required"
                    )
                await self._require_superuser(session, actor_user_id)
            row = await self._get_inventory_for_update(session, inventory_id)
            if not row:
                raise TelephonyNumberInventoryNotFoundError(
                    "telephony_number_inventory_not_found"
                )
            if row.onnuri_staging_candidate_id is not None:
                database_now = (await session.execute(select(func.now()))).scalar_one()
                if proof is None or not self._proof_is_current_for_inventory(
                    proof, row, organization_id, database_now
                ):
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_staging_candidate_requires_proof_bound_assignment"
                    )
                if (
                    row.onnuri_preflight_proof_id != proof.id
                    or row.onnuri_preflight_proof_hash != proof.canonical_hash
                ):
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_staging_preflight_proof_linkage_mismatch"
                    )
            await self._ensure_organization_exists(session, organization_id)
            if (
                row.status == INVENTORY_STATUS_ASSIGNED
                and row.organization_id != organization_id
            ):
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
            row.extra_metadata = _with_assigned_inventory_metadata(
                _strip_live_validation_metadata(row.extra_metadata),
                inventory_id=row.id,
                telephony_phone_number_id=phone.id,
            )
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
    ) -> list[
        tuple[
            TelephonyNumberInventoryModel, TelephonyPhoneNumberModel | None, str | None
        ]
    ]:
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
                        WorkflowModel.id
                        == TelephonyPhoneNumberModel.inbound_workflow_id,
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
            return [
                (row, phone, workflow_name)
                for row, phone, workflow_name in result.all()
            ]

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
            if row.onnuri_staging_candidate_id is not None:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_candidate_requires_proof_bound_bind"
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

    async def attest_telephony_number_inventory_live_validation(
        self,
        inventory_id: int,
        *,
        actor_user_id: int | None,
        live_validation_source: str,
        live_validation_evidence_id: str,
        contract_version: str | None = None,
        call_attempt_id: str | None = None,
        note: str | None = None,
    ) -> TelephonyNumberInventoryModel:
        source = str(live_validation_source or "").strip()
        evidence_id = str(live_validation_evidence_id or "").strip()
        if source not in APPROVED_LIVE_VALIDATION_SOURCES or not evidence_id:
            raise TelephonyNumberInventoryConflictError(
                "telephony_number_inventory_invalid_live_validation_evidence"
            )

        async with self.async_session() as session:
            row = await self._get_inventory_for_update(session, inventory_id)
            if not row:
                raise TelephonyNumberInventoryNotFoundError(
                    "telephony_number_inventory_not_found"
                )
            if row.onnuri_staging_candidate_id is not None:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_candidate_attestation_forbidden"
                )
            if row.provider != "jambonz":
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_live_validation_provider_unsupported"
                )
            if (
                row.status != INVENTORY_STATUS_ASSIGNED
                or row.organization_id is None
                or row.telephony_configuration_id is None
                or row.telephony_phone_number_id is None
            ):
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_not_live_validation_ready"
                )

            phone = await session.get(
                TelephonyPhoneNumberModel, row.telephony_phone_number_id
            )
            if not phone or phone.organization_id != row.organization_id:
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_phone_number_mismatch"
                )
            if not phone.is_active:
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_phone_number_inactive"
                )

            contract = contract_version or JAMBONZ_CONTRACT_VERSION
            row.extra_metadata = _with_live_validation_metadata(
                _with_assigned_inventory_metadata(
                    _strip_live_validation_metadata(row.extra_metadata),
                    inventory_id=row.id,
                    telephony_phone_number_id=phone.id,
                ),
                row=row,
                live_validation_source=source,
                live_validation_evidence_id=evidence_id,
                contract_version=contract,
                call_attempt_id=call_attempt_id,
            )
            phone.extra_metadata = _with_live_validation_metadata(
                _with_assigned_inventory_metadata(
                    _strip_live_validation_metadata(phone.extra_metadata),
                    inventory_id=row.id,
                ),
                row=row,
                live_validation_source=source,
                live_validation_evidence_id=evidence_id,
                contract_version=contract,
                call_attempt_id=call_attempt_id,
            )
            await self._write_inventory_audit(
                session,
                inventory_id=row.id,
                actor_user_id=actor_user_id,
                organization_id=row.organization_id,
                action="live_validation_attested",
                from_status=row.status,
                to_status=row.status,
                details={
                    "live_validation_source": source,
                    "live_validation_evidence_id": evidence_id,
                    "contract_version": contract,
                    "call_attempt_id": call_attempt_id,
                    "telephony_configuration_id": row.telephony_configuration_id,
                    "telephony_phone_number_id": phone.id,
                    "note": note,
                },
            )
            await session.commit()
            await session.refresh(row)
            return row

    async def get_assigned_inventory_for_phone_number(
        self,
        *,
        inventory_id: int,
        organization_id: int,
        telephony_phone_number_id: int,
        provider: str,
        telephony_configuration_id: int | None = None,
        address_normalized: str | None = None,
    ) -> TelephonyNumberInventoryModel | None:
        async with self.async_session() as session:
            stmt = select(TelephonyNumberInventoryModel).where(
                TelephonyNumberInventoryModel.id == inventory_id,
                TelephonyNumberInventoryModel.provider == provider,
                TelephonyNumberInventoryModel.status == INVENTORY_STATUS_ASSIGNED,
                TelephonyNumberInventoryModel.organization_id == organization_id,
                TelephonyNumberInventoryModel.telephony_phone_number_id
                == telephony_phone_number_id,
            )
            if telephony_configuration_id is not None:
                stmt = stmt.where(
                    TelephonyNumberInventoryModel.telephony_configuration_id
                    == telephony_configuration_id
                )
            if address_normalized is not None:
                stmt = stmt.where(
                    TelephonyNumberInventoryModel.address_normalized
                    == address_normalized
                )
            result = await session.execute(stmt)
            return result.scalars().first()

    async def backfill_assigned_inventory_metadata(
        self,
        *,
        limit: int | None = None,
    ) -> int:
        async with self.async_session() as session:
            stmt = (
                select(TelephonyNumberInventoryModel, TelephonyPhoneNumberModel)
                .join(
                    TelephonyPhoneNumberModel,
                    and_(
                        TelephonyPhoneNumberModel.id
                        == TelephonyNumberInventoryModel.telephony_phone_number_id,
                        TelephonyPhoneNumberModel.organization_id
                        == TelephonyNumberInventoryModel.organization_id,
                        TelephonyPhoneNumberModel.address_normalized
                        == TelephonyNumberInventoryModel.address_normalized,
                    ),
                )
                .where(
                    TelephonyNumberInventoryModel.status == INVENTORY_STATUS_ASSIGNED,
                    TelephonyNumberInventoryModel.provider == "jambonz",
                    TelephonyNumberInventoryModel.telephony_phone_number_id.is_not(
                        None
                    ),
                )
                .order_by(TelephonyNumberInventoryModel.id)
            )
            if limit is not None:
                stmt = stmt.limit(limit)

            updated_count = 0
            result = await session.execute(stmt)
            for row, phone in result.all():
                next_phone_metadata = _with_assigned_inventory_metadata(
                    phone.extra_metadata,
                    inventory_id=row.id,
                )
                next_inventory_metadata = _with_assigned_inventory_metadata(
                    row.extra_metadata,
                    inventory_id=row.id,
                    telephony_phone_number_id=phone.id,
                )
                changed = False
                if next_phone_metadata != (phone.extra_metadata or {}):
                    phone.extra_metadata = next_phone_metadata
                    changed = True
                if next_inventory_metadata != (row.extra_metadata or {}):
                    row.extra_metadata = next_inventory_metadata
                    changed = True
                if changed:
                    updated_count += 1

            await session.commit()
            return updated_count

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
            if (
                status == INVENTORY_STATUS_RETIRED
                and row.onnuri_staging_candidate_id is not None
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_candidate_requires_dedicated_retirement"
                )
            if (
                row.status == INVENTORY_STATUS_RETIRED
                and status != INVENTORY_STATUS_RETIRED
            ):
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_retired"
                )
            from_status = row.status
            row.status = status
            if status == INVENTORY_STATUS_QUARANTINED:
                row.quarantined_reason = reason
            if status == INVENTORY_STATUS_RETIRED:
                row.retired_reason = reason
            database_now = (await session.execute(select(func.now()))).scalar_one()
            await session.execute(
                update(OnnuriStagingPreflightAuthorizationLeaseModel)
                .where(
                    OnnuriStagingPreflightAuthorizationLeaseModel.inventory_id
                    == row.id,
                    OnnuriStagingPreflightAuthorizationLeaseModel.state == "active",
                )
                .values(state="invalidated", invalidated_at=database_now)
            )
            phone_id = row.telephony_phone_number_id
            if phone_id is not None:
                phone = await session.get(TelephonyPhoneNumberModel, phone_id)
                if phone:
                    phone.is_active = False
                    phone.is_default_caller_id = False
                    phone.inbound_workflow_id = None
                    phone.extra_metadata = _strip_live_validation_metadata(
                        _strip_assigned_inventory_metadata(phone.extra_metadata)
                    )
            row.telephony_phone_number_id = None
            row.telephony_configuration_id = None
            row.extra_metadata = _strip_live_validation_metadata(
                _strip_assigned_inventory_metadata(row.extra_metadata)
            )
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

    async def import_onnuri_staging_candidates(
        self,
        items: list[dict[str, Any]],
        *,
        actor_user_id: int | None,
    ) -> list[OnnuriStagingCandidateModel]:
        if actor_user_id is None:
            raise TelephonyNumberInventoryConflictError(
                "onnuri_staging_privileged_actor_required"
            )
        candidates: list[OnnuriStagingCandidateModel] = []
        async with self.async_session() as session:
            await self._require_superuser(session, actor_user_id)
            for item in items:
                normalized = normalize_telephony_address(
                    str(item["address"]), country_hint=item.get("country_code") or "KR"
                )
                inventory = (
                    (
                        await session.execute(
                            select(TelephonyNumberInventoryModel)
                            .where(
                                TelephonyNumberInventoryModel.provider == "jambonz",
                                TelephonyNumberInventoryModel.address_normalized
                                == normalized.canonical,
                            )
                            .with_for_update()
                        )
                    )
                    .scalars()
                    .first()
                )
                if inventory is None:
                    raise TelephonyNumberInventoryNotFoundError(
                        "onnuri_staging_candidate_inventory_not_found"
                    )
                if inventory.status != INVENTORY_STATUS_AVAILABLE:
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_staging_candidate_inventory_not_available"
                    )
                if inventory.onnuri_staging_candidate_id is not None:
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_staging_candidate_already_classified"
                    )
                candidate = OnnuriStagingCandidateModel(
                    inventory_id=inventory.id,
                    provider="jambonz",
                    normalized_did=normalized.canonical,
                    created_by_user_id=actor_user_id,
                )
                session.add(candidate)
                await session.flush()
                inventory.onnuri_staging_candidate_id = candidate.id
                await self._write_inventory_audit(
                    session,
                    inventory_id=inventory.id,
                    actor_user_id=actor_user_id,
                    organization_id=None,
                    action="onnuri_staging_candidate_imported",
                    from_status=inventory.status,
                    to_status=inventory.status,
                    details={"candidate_uuid": candidate.candidate_uuid},
                )
                candidates.append(candidate)
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_candidate_import_conflict"
                ) from exc
            for candidate in candidates:
                await session.refresh(candidate)
        return candidates

    async def approve_onnuri_staging_preflight_proof(
        self,
        *,
        candidate_id: int,
        organization_id: int,
        predicate_class: str,
        canonical_input: dict[str, Any],
        expires_at: datetime,
        actor_user_id: int | None,
        evaluator: str | None,
        signer: str | None,
    ) -> OnnuriStagingPreflightProofModel:
        try:
            canonical_input, canonical_hash = canonicalize_proof_input(canonical_input)
        except OnnuriPreflightPolicyError as exc:
            raise TelephonyNumberInventoryConflictError(
                "onnuri_staging_preflight_invalid_canonical_input"
            ) from exc
        if (
            actor_user_id is None
            or evaluator != "recova_onnuri_staging_policy_v1"
            or signer != f"superuser:{actor_user_id}"
        ):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_staging_preflight_untrusted_approval_actor"
            )
        async with self.async_session() as session:
            await self._require_superuser(session, actor_user_id)
            candidate = (
                (
                    await session.execute(
                        select(OnnuriStagingCandidateModel)
                        .where(OnnuriStagingCandidateModel.id == candidate_id)
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            if candidate is None or candidate.state != "active":
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_staging_candidate_not_active"
                )
            await self._ensure_organization_exists(session, organization_id)
            scope_key = f"onnuri_staging:{organization_id}:{candidate.candidate_uuid}"
            database_now = (await session.execute(select(func.now()))).scalar_one()
            if expires_at <= database_now:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_preflight_expiry_must_be_future"
                )
            prior = (
                (
                    await session.execute(
                        select(OnnuriStagingPreflightProofModel)
                        .where(
                            OnnuriStagingPreflightProofModel.scope_key == scope_key,
                            OnnuriStagingPreflightProofModel.is_current.is_(True),
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            revision = 1 if prior is None else prior.revision + 1
            if prior is not None:
                prior.is_current = False
                prior.invalidated_at = database_now
                prior.invalidated_reason = "superseded"
                await session.execute(
                    update(OnnuriStagingPreflightExpiryJobModel)
                    .where(OnnuriStagingPreflightExpiryJobModel.proof_id == prior.id)
                    .values(state="completed", completed_at=database_now)
                )
                await session.execute(
                    update(OnnuriStagingPreflightAuthorizationLeaseModel)
                    .where(
                        OnnuriStagingPreflightAuthorizationLeaseModel.proof_id
                        == prior.id,
                        OnnuriStagingPreflightAuthorizationLeaseModel.state == "active",
                    )
                    .values(state="invalidated", invalidated_at=database_now)
                )
                if prior.inventory_id is not None:
                    inventory = await self._get_inventory_for_update(
                        session, prior.inventory_id
                    )
                    if (
                        inventory is not None
                        and inventory.onnuri_preflight_proof_id == prior.id
                        and inventory.onnuri_preflight_proof_hash
                        == prior.canonical_hash
                    ):
                        inventory.onnuri_preflight_proof_id = None
                        inventory.onnuri_preflight_proof_hash = None
                        if inventory.status in (
                            INVENTORY_STATUS_RESERVED,
                            INVENTORY_STATUS_ASSIGNED,
                        ):
                            inventory.status = INVENTORY_STATUS_QUARANTINED
                            inventory.quarantined_reason = (
                                "onnuri_staging_preflight_superseded"
                            )
                        if inventory.telephony_phone_number_id is not None:
                            phone = await session.get(
                                TelephonyPhoneNumberModel,
                                inventory.telephony_phone_number_id,
                                with_for_update=True,
                            )
                            if phone is not None:
                                phone.is_active = False
                                phone.is_default_caller_id = False
                                phone.inbound_workflow_id = None
                        inventory.telephony_phone_number_id = None
                        inventory.telephony_configuration_id = None
                        inventory.extra_metadata = _strip_live_validation_metadata(
                            _strip_assigned_inventory_metadata(inventory.extra_metadata)
                        )
                        await self._write_inventory_audit(
                            session,
                            inventory_id=inventory.id,
                            actor_user_id=actor_user_id,
                            organization_id=inventory.organization_id,
                            action="onnuri_staging_preflight_superseded",
                            from_status=None,
                            to_status=inventory.status,
                            details={
                                "proof_hash_prefix": prior.canonical_hash[:12],
                            },
                        )
            proof = OnnuriStagingPreflightProofModel(
                candidate_id=candidate.id,
                organization_id=organization_id,
                scope_key=scope_key,
                revision=revision,
                canonical_input=canonical_input,
                canonical_hash=canonical_hash,
                approved=True,
                passed=True,
                predicate_class=predicate_class,
                evaluator=evaluator,
                signer=signer,
                approved_at=database_now,
                expires_at=expires_at,
                created_by_user_id=actor_user_id,
            )
            session.add(proof)
            await session.flush()
            session.add(
                OnnuriStagingPreflightExpiryJobModel(
                    proof_id=proof.id, run_at=proof.expires_at
                )
            )
            await self._write_inventory_audit(
                session,
                inventory_id=candidate.inventory_id,
                actor_user_id=actor_user_id,
                organization_id=organization_id,
                action="onnuri_staging_preflight_approved",
                from_status=None,
                to_status=None,
                details={
                    "candidate_uuid": candidate.candidate_uuid,
                    "proof_hash_prefix": canonical_hash[:12],
                    "revision": revision,
                },
            )
            await session.commit()
            await session.refresh(proof)
            return proof

    async def reserve_onnuri_staging_inventory(
        self,
        inventory_id: int,
        *,
        proof_id: int,
        organization_id: int,
        actor_user_id: int | None,
        reservation_expires_at: datetime | None = None,
        note: str | None = None,
    ) -> TelephonyNumberInventoryModel:
        if actor_user_id is None:
            raise TelephonyNumberInventoryConflictError(
                "onnuri_staging_privileged_actor_required"
            )
        async with self.async_session() as session:
            await self._require_superuser(session, actor_user_id)
            proof = (
                (
                    await session.execute(
                        select(OnnuriStagingPreflightProofModel)
                        .where(OnnuriStagingPreflightProofModel.id == proof_id)
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            row = await self._get_inventory_for_update(session, inventory_id)
            if proof is None or row is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_staging_preflight_proof_or_inventory_not_found"
                )
            database_now = (await session.execute(select(func.now()))).scalar_one()
            if not self._proof_is_current_for_inventory(
                proof, row, organization_id, database_now
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_preflight_proof_not_current"
                )
            if row.status != INVENTORY_STATUS_AVAILABLE:
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_not_reservable"
                )
            row.status = INVENTORY_STATUS_RESERVED
            row.organization_id = organization_id
            row.reservation_expires_at = reservation_expires_at
            proof.inventory_id = row.id
            row.onnuri_preflight_proof_id = proof.id
            row.onnuri_preflight_proof_hash = proof.canonical_hash
            await self._write_inventory_audit(
                session,
                inventory_id=row.id,
                actor_user_id=actor_user_id,
                organization_id=organization_id,
                action="onnuri_staging_reserved",
                from_status=INVENTORY_STATUS_AVAILABLE,
                to_status=row.status,
                details={
                    "note": note,
                    "proof_hash_prefix": proof.canonical_hash[:12],
                    "reservation_expires_at": _iso(reservation_expires_at),
                },
            )
            await session.commit()
            await session.refresh(row)
            return row

    async def retire_onnuri_staging_candidate(
        self, candidate_id: int, *, actor_user_id: int | None, reason: str
    ) -> OnnuriStagingCandidateModel:
        if actor_user_id is None:
            raise TelephonyNumberInventoryConflictError(
                "onnuri_staging_privileged_actor_required"
            )
        async with self.async_session() as session:
            await self._require_superuser(session, actor_user_id)
            candidate = (
                (
                    await session.execute(
                        select(OnnuriStagingCandidateModel)
                        .where(OnnuriStagingCandidateModel.id == candidate_id)
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            if candidate is None or candidate.state != "active":
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_staging_candidate_not_active"
                )
            inventory = await self._get_inventory_for_update(
                session, candidate.inventory_id
            )
            if inventory is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_staging_candidate_inventory_not_found"
                )
            await session.execute(
                text("SET LOCAL recova.onnuri_candidate_lifecycle = 'retire'")
            )
            database_now = (await session.execute(select(func.now()))).scalar_one()
            candidate.state = "retired"
            candidate.retired_at = database_now
            candidate.retired_by_user_id = actor_user_id
            candidate.retired_reason = reason
            active_proofs = list(
                (
                    await session.execute(
                        select(
                            OnnuriStagingPreflightProofModel.id,
                            OnnuriStagingPreflightProofModel.organization_id,
                        )
                        .where(
                            OnnuriStagingPreflightProofModel.candidate_id
                            == candidate.id,
                            OnnuriStagingPreflightProofModel.is_current.is_(True),
                        )
                        .with_for_update()
                    )
                ).all()
            )
            if inventory.organization_id is not None and any(
                proof_organization_id != inventory.organization_id
                for _, proof_organization_id in active_proofs
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_preflight_tenant_link_mismatch"
                )
            active_proof_ids = [proof_id for proof_id, _ in active_proofs]
            if active_proof_ids:
                await session.execute(
                    update(OnnuriStagingPreflightProofModel)
                    .where(OnnuriStagingPreflightProofModel.id.in_(active_proof_ids))
                    .values(
                        is_current=False,
                        invalidated_at=database_now,
                        invalidated_reason="candidate_retired",
                    )
                )
                await session.execute(
                    update(OnnuriStagingPreflightExpiryJobModel)
                    .where(
                        OnnuriStagingPreflightExpiryJobModel.proof_id.in_(
                            active_proof_ids
                        )
                    )
                    .values(state="completed", completed_at=database_now)
                )
                await session.execute(
                    update(OnnuriStagingPreflightAuthorizationLeaseModel)
                    .where(
                        OnnuriStagingPreflightAuthorizationLeaseModel.proof_id.in_(
                            active_proof_ids
                        ),
                        OnnuriStagingPreflightAuthorizationLeaseModel.state == "active",
                    )
                    .values(state="invalidated", invalidated_at=database_now)
                )
            inventory.status = INVENTORY_STATUS_RETIRED
            inventory.retired_reason = reason
            inventory.onnuri_staging_candidate_id = None
            inventory.onnuri_preflight_proof_id = None
            inventory.onnuri_preflight_proof_hash = None
            if inventory.telephony_phone_number_id is not None:
                phone = await session.get(
                    TelephonyPhoneNumberModel,
                    inventory.telephony_phone_number_id,
                    with_for_update=True,
                )
                if phone is not None:
                    phone.is_active = False
                    phone.is_default_caller_id = False
                    phone.inbound_workflow_id = None
                    phone.extra_metadata = _strip_live_validation_metadata(
                        _strip_assigned_inventory_metadata(phone.extra_metadata)
                    )
            inventory.telephony_phone_number_id = None
            inventory.telephony_configuration_id = None
            inventory.extra_metadata = _strip_live_validation_metadata(
                _strip_assigned_inventory_metadata(inventory.extra_metadata)
            )
            await self._write_inventory_audit(
                session,
                inventory_id=inventory.id,
                actor_user_id=actor_user_id,
                organization_id=inventory.organization_id,
                action="onnuri_staging_candidate_retired",
                from_status=None,
                to_status=INVENTORY_STATUS_RETIRED,
                details={"candidate_uuid": candidate.candidate_uuid, "reason": reason},
            )
            await session.commit()
            await session.refresh(candidate)
            return candidate

    async def revoke_onnuri_staging_preflight_proof(
        self, proof_id: int, *, actor_user_id: int | None, reason: str
    ) -> OnnuriStagingPreflightProofModel:
        if actor_user_id is None:
            raise TelephonyNumberInventoryConflictError(
                "onnuri_staging_privileged_actor_required"
            )
        async with self.async_session() as session:
            await self._require_superuser(session, actor_user_id)
            proof = (
                (
                    await session.execute(
                        select(OnnuriStagingPreflightProofModel)
                        .where(OnnuriStagingPreflightProofModel.id == proof_id)
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            if proof is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_staging_preflight_proof_not_found"
                )
            if (
                not proof.is_current
                or proof.revoked_at is not None
                or proof.invalidated_at is not None
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_preflight_proof_already_terminal"
                )
            if proof.inventory_id is not None:
                linked_inventory = await self._get_inventory_for_update(
                    session, proof.inventory_id
                )
                if (
                    linked_inventory is not None
                    and linked_inventory.organization_id is not None
                    and linked_inventory.organization_id != proof.organization_id
                ):
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_staging_preflight_tenant_link_mismatch"
                    )
            database_now = (await session.execute(select(func.now()))).scalar_one()
            proof.revoked_at = database_now
            proof.revoked_by_user_id = actor_user_id
            proof.revoke_reason = reason
            proof.is_current = False
            await session.execute(
                update(OnnuriStagingPreflightExpiryJobModel)
                .where(OnnuriStagingPreflightExpiryJobModel.proof_id == proof.id)
                .values(state="completed", completed_at=database_now)
            )
            await session.execute(
                update(OnnuriStagingPreflightAuthorizationLeaseModel)
                .where(
                    OnnuriStagingPreflightAuthorizationLeaseModel.proof_id == proof.id,
                    OnnuriStagingPreflightAuthorizationLeaseModel.state == "active",
                )
                .values(state="invalidated", invalidated_at=database_now)
            )
            inventory = (
                await self._get_inventory_for_update(session, proof.inventory_id)
                if proof.inventory_id
                else None
            )
            if (
                inventory is not None
                and inventory.onnuri_preflight_proof_id == proof.id
                and inventory.onnuri_preflight_proof_hash == proof.canonical_hash
            ):
                inventory.onnuri_preflight_proof_id = None
                inventory.onnuri_preflight_proof_hash = None
                if inventory.status in (
                    INVENTORY_STATUS_RESERVED,
                    INVENTORY_STATUS_ASSIGNED,
                ):
                    inventory.status = INVENTORY_STATUS_QUARANTINED
                    inventory.quarantined_reason = "onnuri_staging_preflight_revoked"
                if inventory.telephony_phone_number_id is not None:
                    phone = await session.get(
                        TelephonyPhoneNumberModel,
                        inventory.telephony_phone_number_id,
                        with_for_update=True,
                    )
                    if phone is not None:
                        phone.is_active = False
                        phone.is_default_caller_id = False
                        phone.inbound_workflow_id = None
                        phone.extra_metadata = _strip_live_validation_metadata(
                            _strip_assigned_inventory_metadata(phone.extra_metadata)
                        )
                inventory.telephony_phone_number_id = None
                inventory.telephony_configuration_id = None
                inventory.extra_metadata = _strip_live_validation_metadata(
                    _strip_assigned_inventory_metadata(inventory.extra_metadata)
                )
                await self._write_inventory_audit(
                    session,
                    inventory_id=inventory.id,
                    actor_user_id=actor_user_id,
                    organization_id=inventory.organization_id,
                    action="onnuri_staging_preflight_revoked",
                    from_status=None,
                    to_status=inventory.status,
                    details={
                        "reason": reason,
                        "proof_hash_prefix": proof.canonical_hash[:12],
                    },
                )
            await session.commit()
            await session.refresh(proof)
            return proof

    @staticmethod
    def _proof_is_current_for_inventory(
        proof: OnnuriStagingPreflightProofModel,
        inventory: TelephonyNumberInventoryModel,
        organization_id: int,
        database_now: datetime,
    ) -> bool:
        return (
            proof.is_current
            and proof.approved
            and proof.passed
            and proof.revoked_at is None
            and proof.invalidated_at is None
            and proof.expires_at > database_now
            and proof.organization_id == organization_id
            and proof.candidate_id == inventory.onnuri_staging_candidate_id
            and proof.inventory_id in (None, inventory.id)
        )

    async def expire_due_onnuri_staging_preflight_proofs(
        self, *, limit: int = 50
    ) -> int:
        """Claim due jobs without trusting the controller for routability."""
        completed = 0
        async with self.async_session() as session:
            database_now = (await session.execute(select(func.now()))).scalar_one()
            jobs = (
                (
                    await session.execute(
                        select(OnnuriStagingPreflightExpiryJobModel)
                        .where(
                            OnnuriStagingPreflightExpiryJobModel.run_at <= database_now,
                            OnnuriStagingPreflightExpiryJobModel.state.in_(
                                ("scheduled", "leased")
                            ),
                        )
                        .order_by(OnnuriStagingPreflightExpiryJobModel.run_at)
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                    )
                )
                .scalars()
                .all()
            )
            for job in jobs:
                job.state = "leased"
                job.attempts += 1
                job.leased_at = database_now
                proof = (
                    (
                        await session.execute(
                            select(OnnuriStagingPreflightProofModel)
                            .where(OnnuriStagingPreflightProofModel.id == job.proof_id)
                            .with_for_update()
                        )
                    )
                    .scalars()
                    .first()
                )
                if proof is None:
                    job.state = "failed"
                    job.failed_at = database_now
                    job.error = "proof_not_found"
                    continue
                proof.is_current = False
                proof.invalidated_at = database_now
                proof.invalidated_reason = "expired"
                await session.execute(
                    update(OnnuriStagingPreflightAuthorizationLeaseModel)
                    .where(
                        OnnuriStagingPreflightAuthorizationLeaseModel.proof_id
                        == proof.id,
                        OnnuriStagingPreflightAuthorizationLeaseModel.state == "active",
                    )
                    .values(state="invalidated", invalidated_at=database_now)
                )
                if proof.inventory_id is not None:
                    inventory = await self._get_inventory_for_update(
                        session, proof.inventory_id
                    )
                    if (
                        inventory is not None
                        and inventory.onnuri_preflight_proof_id == proof.id
                        and inventory.onnuri_preflight_proof_hash
                        == proof.canonical_hash
                    ):
                        inventory.onnuri_preflight_proof_id = None
                        inventory.onnuri_preflight_proof_hash = None
                        if inventory.status in (
                            INVENTORY_STATUS_RESERVED,
                            INVENTORY_STATUS_ASSIGNED,
                        ):
                            inventory.status = INVENTORY_STATUS_QUARANTINED
                            inventory.quarantined_reason = (
                                "onnuri_staging_preflight_expired"
                            )
                        if inventory.telephony_phone_number_id is not None:
                            phone = await session.get(
                                TelephonyPhoneNumberModel,
                                inventory.telephony_phone_number_id,
                                with_for_update=True,
                            )
                            if phone is not None:
                                phone.is_active = False
                                phone.is_default_caller_id = False
                                phone.inbound_workflow_id = None
                                phone.extra_metadata = _strip_live_validation_metadata(
                                    _strip_assigned_inventory_metadata(
                                        phone.extra_metadata
                                    )
                                )
                        inventory.telephony_phone_number_id = None
                        inventory.telephony_configuration_id = None
                        inventory.extra_metadata = _strip_live_validation_metadata(
                            _strip_assigned_inventory_metadata(inventory.extra_metadata)
                        )
                        await self._write_inventory_audit(
                            session,
                            inventory_id=inventory.id,
                            actor_user_id=None,
                            organization_id=inventory.organization_id,
                            action="onnuri_staging_preflight_expired",
                            from_status=None,
                            to_status=inventory.status,
                            details={
                                "proof_hash_prefix": proof.canonical_hash[:12],
                            },
                        )
                job.state = "completed"
                job.completed_at = database_now
                job.lease_expires_at = None
                completed += 1
            await session.commit()
        return completed

    async def get_current_onnuri_staging_routable_inventory(
        self,
        inventory_id: int,
        candidate_id: int,
        proof_id: int,
        proof_hash: str,
        organization_id: int,
        telephony_phone_number_id: int,
        provider: str,
        telephony_configuration_id: int,
        address_normalized: str,
    ) -> TelephonyNumberInventoryModel | None:
        """Return an Onnuri row only when every proof-bound route invariant holds."""
        async with self.async_session() as session:
            result = await session.execute(
                select(TelephonyNumberInventoryModel)
                .join(
                    OnnuriStagingCandidateModel,
                    OnnuriStagingCandidateModel.id
                    == TelephonyNumberInventoryModel.onnuri_staging_candidate_id,
                )
                .join(
                    OnnuriStagingPreflightProofModel,
                    OnnuriStagingPreflightProofModel.id
                    == TelephonyNumberInventoryModel.onnuri_preflight_proof_id,
                )
                .join(
                    TelephonyPhoneNumberModel,
                    TelephonyPhoneNumberModel.id
                    == TelephonyNumberInventoryModel.telephony_phone_number_id,
                )
                .where(
                    TelephonyNumberInventoryModel.id == inventory_id,
                    TelephonyNumberInventoryModel.status == INVENTORY_STATUS_ASSIGNED,
                    TelephonyNumberInventoryModel.organization_id == organization_id,
                    TelephonyNumberInventoryModel.provider == provider,
                    TelephonyNumberInventoryModel.address_normalized
                    == address_normalized,
                    TelephonyNumberInventoryModel.onnuri_staging_candidate_id
                    == candidate_id,
                    TelephonyNumberInventoryModel.onnuri_preflight_proof_id == proof_id,
                    TelephonyNumberInventoryModel.onnuri_preflight_proof_hash
                    == proof_hash,
                    TelephonyNumberInventoryModel.telephony_phone_number_id
                    == telephony_phone_number_id,
                    TelephonyNumberInventoryModel.telephony_configuration_id
                    == telephony_configuration_id,
                    OnnuriStagingCandidateModel.inventory_id == inventory_id,
                    OnnuriStagingCandidateModel.provider == "jambonz",
                    OnnuriStagingCandidateModel.normalized_did == address_normalized,
                    OnnuriStagingCandidateModel.classification
                    == "onnuri_staging_candidate_v1",
                    OnnuriStagingCandidateModel.environment == "staging",
                    OnnuriStagingCandidateModel.state == "active",
                    OnnuriStagingPreflightProofModel.candidate_id == candidate_id,
                    OnnuriStagingPreflightProofModel.inventory_id == inventory_id,
                    OnnuriStagingPreflightProofModel.organization_id == organization_id,
                    OnnuriStagingPreflightProofModel.provider == provider,
                    OnnuriStagingPreflightProofModel.environment == "staging",
                    OnnuriStagingPreflightProofModel.canonical_hash == proof_hash,
                    OnnuriStagingPreflightProofModel.is_current.is_(True),
                    OnnuriStagingPreflightProofModel.approved.is_(True),
                    OnnuriStagingPreflightProofModel.passed.is_(True),
                    OnnuriStagingPreflightProofModel.revoked_at.is_(None),
                    OnnuriStagingPreflightProofModel.invalidated_at.is_(None),
                    OnnuriStagingPreflightProofModel.expires_at > func.now(),
                    TelephonyPhoneNumberModel.organization_id == organization_id,
                    TelephonyPhoneNumberModel.telephony_configuration_id
                    == telephony_configuration_id,
                    TelephonyPhoneNumberModel.address_normalized == address_normalized,
                    TelephonyPhoneNumberModel.is_active.is_(True),
                )
                .with_for_update()
            )
            return result.scalars().one_or_none()

    async def acquire_onnuri_application_smoke_lease(
        self,
        *,
        proof_id: int,
        inventory_id: int,
        organization_id: int,
        attempt_kind: str,
        duration_seconds: int,
        actor_user_id: int | None,
        application_attempt_id: str,
    ) -> OnnuriStagingPreflightAuthorizationLeaseModel:
        """Atomically allocate one bounded exception-waiting authorization."""
        if actor_user_id is None:
            raise TelephonyNumberInventoryConflictError("onnuri_staging_actor_required")
        if (
            not isinstance(application_attempt_id, str)
            or not application_attempt_id.strip()
            or len(application_attempt_id) > 128
        ):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_staging_preflight_invalid_application_attempt"
            )
        if attempt_kind not in {"inbound", "outbound"}:
            raise TelephonyNumberInventoryConflictError(
                "onnuri_staging_preflight_invalid_attempt_kind"
            )
        async with self.async_session() as session:
            await self._require_organization_member(
                session, actor_user_id, organization_id
            )
            proof = (
                (
                    await session.execute(
                        select(OnnuriStagingPreflightProofModel)
                        .where(OnnuriStagingPreflightProofModel.id == proof_id)
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            inventory = await self._get_inventory_for_update(session, inventory_id)
            database_now = (await session.execute(select(func.now()))).scalar_one()
            if (
                proof is None
                or inventory is None
                or not self._proof_is_current_for_inventory(
                    proof, inventory, organization_id, database_now
                )
                or proof.predicate_class != "exception_waiting"
                or inventory.onnuri_preflight_proof_id != proof.id
                or inventory.onnuri_preflight_proof_hash != proof.canonical_hash
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_preflight_lease_not_authorized"
                )
            try:
                controls, canonical_hash = canonicalize_proof_input(
                    proof.canonical_input
                )
            except OnnuriPreflightPolicyError as exc:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_preflight_lease_controls_invalid"
                ) from exc
            if (
                controls != proof.canonical_input
                or canonical_hash != proof.canonical_hash
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_preflight_lease_controls_invalid"
                )
            if (
                not isinstance(duration_seconds, int)
                or isinstance(duration_seconds, bool)
                or duration_seconds < 1
                or duration_seconds > controls["max_duration_seconds"]
                or controls["max_soak_spend"] != "0"
                or controls["retries"] != 0
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_preflight_lease_controls_invalid"
                )

            await session.execute(
                update(OnnuriStagingPreflightAuthorizationLeaseModel)
                .where(
                    OnnuriStagingPreflightAuthorizationLeaseModel.state == "active",
                    OnnuriStagingPreflightAuthorizationLeaseModel.expires_at
                    <= database_now,
                )
                .values(state="invalidated", invalidated_at=database_now)
            )
            active_count = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(OnnuriStagingPreflightAuthorizationLeaseModel)
                        .where(
                            OnnuriStagingPreflightAuthorizationLeaseModel.proof_id
                            == proof.id,
                            OnnuriStagingPreflightAuthorizationLeaseModel.state
                            == "active",
                        )
                    )
                ).scalar_one()
            )
            if active_count >= controls["max_concurrency"]:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_preflight_concurrency_exhausted"
                )
            attempt_count = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(OnnuriStagingPreflightAuthorizationLeaseModel)
                        .where(
                            OnnuriStagingPreflightAuthorizationLeaseModel.proof_id
                            == proof.id,
                            OnnuriStagingPreflightAuthorizationLeaseModel.attempt_kind
                            == attempt_kind,
                        )
                    )
                ).scalar_one()
            )
            attempt_limit = controls[f"max_{attempt_kind}_attempts"]
            if attempt_count >= attempt_limit:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_preflight_attempt_limit_exhausted"
                )
            recent_count = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(OnnuriStagingPreflightAuthorizationLeaseModel)
                        .where(
                            OnnuriStagingPreflightAuthorizationLeaseModel.proof_id
                            == proof.id,
                            OnnuriStagingPreflightAuthorizationLeaseModel.created_at
                            > database_now - timedelta(seconds=1),
                        )
                    )
                ).scalar_one()
            )
            if recent_count >= controls["cps"]:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_preflight_cps_exhausted"
                )
            lease = OnnuriStagingPreflightAuthorizationLeaseModel(
                proof_id=proof.id,
                inventory_id=inventory.id,
                organization_id=organization_id,
                attempt_kind=attempt_kind,
                expires_at=database_now + timedelta(seconds=duration_seconds),
                actor_user_id=actor_user_id,
                application_attempt_id=application_attempt_id.strip(),
            )
            session.add(lease)
            await session.commit()
            await session.refresh(lease)
            return lease

    async def consume_onnuri_application_smoke_lease(
        self,
        lease_uuid: str,
        *,
        organization_id: int,
        application_attempt_id: str,
    ) -> OnnuriStagingSmokeDispatchAttemptModel:
        """Consume a lease in the transaction that creates the routable use."""
        async with self.async_session() as session:
            lease = (
                (
                    await session.execute(
                        select(OnnuriStagingPreflightAuthorizationLeaseModel)
                        .where(
                            OnnuriStagingPreflightAuthorizationLeaseModel.lease_uuid
                            == lease_uuid,
                            OnnuriStagingPreflightAuthorizationLeaseModel.organization_id
                            == organization_id,
                            OnnuriStagingPreflightAuthorizationLeaseModel.application_attempt_id
                            == application_attempt_id,
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            if lease is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_staging_preflight_lease_not_found"
                )
            database_now = (await session.execute(select(func.now()))).scalar_one()
            if lease.state != "active" or lease.expires_at <= database_now:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_preflight_lease_not_active"
                )
            if (
                not isinstance(application_attempt_id, str)
                or not application_attempt_id.strip()
                or application_attempt_id != lease.application_attempt_id
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_preflight_attempt_mismatch"
                )
            proof = (
                (
                    await session.execute(
                        select(OnnuriStagingPreflightProofModel)
                        .where(OnnuriStagingPreflightProofModel.id == lease.proof_id)
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            inventory = await self._get_inventory_for_update(
                session, lease.inventory_id
            )
            phone = None
            if (
                inventory is not None
                and inventory.telephony_phone_number_id is not None
            ):
                phone = (
                    (
                        await session.execute(
                            select(TelephonyPhoneNumberModel)
                            .where(
                                TelephonyPhoneNumberModel.id
                                == inventory.telephony_phone_number_id
                            )
                            .with_for_update()
                        )
                    )
                    .scalars()
                    .first()
                )
            if (
                proof is None
                or inventory is None
                or phone is None
                or lease.proof_id != proof.id
                or lease.inventory_id != inventory.id
                or inventory.status != INVENTORY_STATUS_ASSIGNED
                or inventory.organization_id != organization_id
                or inventory.provider != "jambonz"
                or inventory.telephony_configuration_id is None
                or inventory.onnuri_preflight_proof_id != proof.id
                or inventory.onnuri_preflight_proof_hash != proof.canonical_hash
                or not phone.is_active
                or phone.organization_id != organization_id
                or phone.telephony_configuration_id
                != inventory.telephony_configuration_id
                or phone.address_normalized != inventory.address_normalized
                or phone.inbound_workflow_id is not None
                or not self._proof_is_current_for_inventory(
                    proof, inventory, organization_id, database_now
                )
            ):
                lease.state = "invalidated"
                lease.invalidated_at = database_now
                await session.commit()
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_staging_preflight_lease_not_authorized"
                )
            lease.state = "consumed"
            lease.consumed_at = database_now
            attempt = OnnuriStagingSmokeDispatchAttemptModel(
                application_attempt_id=lease.application_attempt_id,
                lease_id=lease.id,
                proof_id=proof.id,
                inventory_id=inventory.id,
                organization_id=organization_id,
                attempt_kind=lease.attempt_kind,
            )
            session.add(attempt)
            await session.commit()
            await session.refresh(attempt)
            return attempt

    async def mark_onnuri_smoke_dispatch_attempt_dispatched(
        self, application_attempt_id: str, *, organization_id: int
    ) -> OnnuriStagingSmokeDispatchAttemptModel:
        async with self.async_session() as session:
            attempt = (
                (
                    await session.execute(
                        select(OnnuriStagingSmokeDispatchAttemptModel)
                        .where(
                            OnnuriStagingSmokeDispatchAttemptModel.application_attempt_id
                            == application_attempt_id,
                            OnnuriStagingSmokeDispatchAttemptModel.organization_id
                            == organization_id,
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            if attempt is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_smoke_dispatch_attempt_not_found"
                )
            if attempt.state != "pending":
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_dispatch_attempt_not_pending"
                )
            attempt.state = "dispatched"
            attempt.dispatched_at = (
                await session.execute(select(func.now()))
            ).scalar_one()
            await session.commit()
            await session.refresh(attempt)
            return attempt

    async def mark_onnuri_smoke_dispatch_attempt_failed(
        self, application_attempt_id: str, *, organization_id: int, reason: str
    ) -> OnnuriStagingSmokeDispatchAttemptModel:
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
            raise TelephonyNumberInventoryConflictError(
                "onnuri_smoke_dispatch_failure_reason_invalid"
            )
        async with self.async_session() as session:
            attempt = (
                (
                    await session.execute(
                        select(OnnuriStagingSmokeDispatchAttemptModel)
                        .where(
                            OnnuriStagingSmokeDispatchAttemptModel.application_attempt_id
                            == application_attempt_id,
                            OnnuriStagingSmokeDispatchAttemptModel.organization_id
                            == organization_id,
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            if attempt is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_smoke_dispatch_attempt_not_found"
                )
            if attempt.state != "pending":
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_dispatch_attempt_not_pending"
                )
            attempt.state = "failed"
            attempt.failed_at = (await session.execute(select(func.now()))).scalar_one()
            attempt.failure_reason = reason.strip()
            await session.commit()
            await session.refresh(attempt)
            return attempt

    async def create_onnuri_smoke_envelope(
        self,
        *,
        evaluator_version: str,
        proof_id: int,
        inventory_id: int,
        organization_id: int,
        telephony_configuration_id: int,
        workflow_id: int,
        destination_hmac_key_id: str,
        destination_hmac_key_version: str,
        destination_hmac_digest: str,
        dispatch_key_id: str,
        dispatch_algorithm_policy_id: str,
        media_key_id: str,
        media_algorithm_policy_id: str,
        policy_digest: str,
        candidate_digest: str,
        phase_b_manifest_digest: str,
        phase_c_iac_digest: str,
        live_window_starts_at: datetime,
        live_window_expires_at: datetime,
        expires_at: datetime,
        destroy_deadline: datetime,
        provider_balance_currency_receipt_digest: str | None = None,
        supplier_signaling_media_receipt_digest: str | None = None,
        tenant_mapping_receipt_digest: str | None = None,
        secret_version_manifest_receipt_digest: str | None = None,
        gate_decision_receipt_digest: str | None = None,
    ) -> OnnuriSmokeEnvelopeModel:
        """Arm one immutable v2 compatibility or v3 live authority."""
        opaque_values = (
            destination_hmac_key_id,
            destination_hmac_key_version,
            destination_hmac_digest,
            dispatch_key_id,
            dispatch_algorithm_policy_id,
            media_key_id,
            media_algorithm_policy_id,
            policy_digest,
            candidate_digest,
            phase_b_manifest_digest,
            phase_c_iac_digest,
        )
        if any(
            not isinstance(value, str) or not value.strip() for value in opaque_values
        ):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_smoke_envelope_opaque_value_invalid"
            )
        receipt_digests = (
            provider_balance_currency_receipt_digest,
            supplier_signaling_media_receipt_digest,
            tenant_mapping_receipt_digest,
            secret_version_manifest_receipt_digest,
            gate_decision_receipt_digest,
        )
        if (
            evaluator_version
            not in {ONNURI_SMOKE_AUTHORITY_V2, ONNURI_SMOKE_AUTHORITY_V3}
            or (
                evaluator_version == ONNURI_SMOKE_AUTHORITY_V3
                and not all(_is_lowercase_sha256(value) for value in receipt_digests)
            )
            or (
                evaluator_version == ONNURI_SMOKE_AUTHORITY_V2
                and any(value is not None for value in receipt_digests)
            )
        ):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_smoke_prerequisite_receipts_invalid"
            )
        if dispatch_key_id == media_key_id:
            raise TelephonyNumberInventoryConflictError(
                "onnuri_smoke_capability_key_reuse"
            )
        if (
            dispatch_algorithm_policy_id != CAPABILITY_ALGORITHM_POLICY_ID
            or media_algorithm_policy_id != CAPABILITY_ALGORITHM_POLICY_ID
        ):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_smoke_capability_policy_invalid"
            )
        async with self.async_session() as session:
            await session.execute(
                select(
                    func.pg_advisory_xact_lock(
                        func.hashtext("onnuri-smoke-organization"), organization_id
                    )
                )
            )
            proof = (
                (
                    await session.execute(
                        select(OnnuriStagingPreflightProofModel)
                        .where(OnnuriStagingPreflightProofModel.id == proof_id)
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            inventory = await self._get_inventory_for_update(session, inventory_id)
            workflow = (
                (
                    await session.execute(
                        select(WorkflowModel)
                        .where(WorkflowModel.id == workflow_id)
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            database_now = (await session.execute(select(func.now()))).scalar_one()
            if (
                proof is None
                or inventory is None
                or workflow is None
                or not self._proof_is_current_for_inventory(
                    proof, inventory, organization_id, database_now
                )
                or proof.predicate_class != "exception_waiting"
                or inventory.organization_id != organization_id
                or inventory.telephony_configuration_id != telephony_configuration_id
                or inventory.onnuri_preflight_proof_id != proof.id
                or workflow.organization_id != organization_id
                or workflow.user_id is None
                or not (
                    database_now
                    <= live_window_starts_at
                    < live_window_expires_at
                    <= expires_at
                    <= destroy_deadline
                )
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_envelope_not_authorized"
                )
            duplicate_values = {
                "evaluator_version": evaluator_version,
                "proof_id": proof_id,
                "inventory_id": inventory_id,
                "organization_id": organization_id,
                "telephony_configuration_id": telephony_configuration_id,
                "workflow_id": workflow_id,
                "destination_hmac_key_id": destination_hmac_key_id.strip(),
                "destination_hmac_domain": DESTINATION_HMAC_DOMAIN,
                "destination_hmac_key_version": destination_hmac_key_version.strip(),
                "destination_hmac_digest": destination_hmac_digest.strip(),
                "dispatch_key_id": dispatch_key_id.strip(),
                "dispatch_algorithm_policy_id": dispatch_algorithm_policy_id.strip(),
                "dispatch_domain": DISPATCH_CAPABILITY_DOMAIN,
                "media_key_id": media_key_id.strip(),
                "media_algorithm_policy_id": media_algorithm_policy_id.strip(),
                "media_domain": MEDIA_CAPABILITY_DOMAIN,
                "policy_digest": policy_digest.strip(),
                "candidate_digest": candidate_digest.strip(),
                "phase_b_manifest_digest": phase_b_manifest_digest.strip(),
                "phase_c_iac_digest": phase_c_iac_digest.strip(),
                "provider_balance_currency_receipt_digest": provider_balance_currency_receipt_digest,
                "supplier_signaling_media_receipt_digest": supplier_signaling_media_receipt_digest,
                "tenant_mapping_receipt_digest": tenant_mapping_receipt_digest,
                "secret_version_manifest_receipt_digest": secret_version_manifest_receipt_digest,
                "gate_decision_receipt_digest": gate_decision_receipt_digest,
                "live_window_starts_at": live_window_starts_at,
                "live_window_expires_at": live_window_expires_at,
                "expires_at": expires_at,
                "destroy_deadline": destroy_deadline,
            }
            existing = (
                (
                    await session.execute(
                        select(OnnuriSmokeEnvelopeModel)
                        .where(
                            OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                            OnnuriSmokeEnvelopeModel.state == "armed",
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            if existing is not None:
                if all(
                    getattr(existing, field) == value
                    for field, value in duplicate_values.items()
                ):
                    return existing
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_active_envelope_mismatch"
                )
            envelope = OnnuriSmokeEnvelopeModel(
                evaluator_version=evaluator_version,
                proof_id=proof_id,
                inventory_id=inventory_id,
                organization_id=organization_id,
                telephony_configuration_id=telephony_configuration_id,
                workflow_id=workflow_id,
                destination_hmac_key_id=destination_hmac_key_id.strip(),
                destination_hmac_domain=DESTINATION_HMAC_DOMAIN,
                destination_hmac_key_version=destination_hmac_key_version.strip(),
                destination_hmac_digest=destination_hmac_digest.strip(),
                dispatch_key_id=dispatch_key_id.strip(),
                dispatch_algorithm_policy_id=dispatch_algorithm_policy_id.strip(),
                dispatch_domain=DISPATCH_CAPABILITY_DOMAIN,
                media_key_id=media_key_id.strip(),
                media_algorithm_policy_id=media_algorithm_policy_id.strip(),
                media_domain=MEDIA_CAPABILITY_DOMAIN,
                policy_digest=policy_digest.strip(),
                candidate_digest=candidate_digest.strip(),
                phase_b_manifest_digest=phase_b_manifest_digest.strip(),
                phase_c_iac_digest=phase_c_iac_digest.strip(),
                provider_balance_currency_receipt_digest=provider_balance_currency_receipt_digest,
                supplier_signaling_media_receipt_digest=supplier_signaling_media_receipt_digest,
                tenant_mapping_receipt_digest=tenant_mapping_receipt_digest,
                secret_version_manifest_receipt_digest=secret_version_manifest_receipt_digest,
                gate_decision_receipt_digest=gate_decision_receipt_digest,
                live_window_starts_at=live_window_starts_at,
                live_window_expires_at=live_window_expires_at,
                expires_at=expires_at,
                destroy_deadline=destroy_deadline,
            )
            session.add(envelope)
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_active_envelope_exists"
                ) from exc
            await session.refresh(envelope)
            return envelope

    async def _acquire_onnuri_smoke_envelope_mutex(
        self, session, *, envelope_uuid: str
    ) -> None:
        """Serialize authority mutations before taking any authority row lock."""
        key = int.from_bytes(
            hashlib.sha256(
                f"onnuri-smoke-envelope:{envelope_uuid}".encode("utf-8")
            ).digest()[:8],
            byteorder="big",
            signed=True,
        )
        await session.execute(select(func.pg_advisory_xact_lock(key)))

    async def _lock_onnuri_smoke_attempt_authority(
        self, session, *, attempt_uuid: str, organization_id: int
    ) -> tuple[OnnuriSmokeAttemptModel, OnnuriSmokeEnvelopeModel | None]:
        """Resolve the envelope unlocked, then mutex and lock attempt before envelope."""
        envelope_identity = (
            await session.execute(
                select(
                    OnnuriSmokeAttemptModel.envelope_id,
                    OnnuriSmokeEnvelopeModel.envelope_uuid,
                )
                .join(
                    OnnuriSmokeEnvelopeModel,
                    OnnuriSmokeEnvelopeModel.id
                    == OnnuriSmokeAttemptModel.envelope_id,
                )
                .where(
                    OnnuriSmokeAttemptModel.attempt_uuid == attempt_uuid,
                    OnnuriSmokeAttemptModel.organization_id == organization_id,
                    OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                )
            )
        ).one_or_none()
        if envelope_identity is None:
            raise TelephonyNumberInventoryNotFoundError(
                "onnuri_smoke_attempt_not_found"
            )
        envelope_id, envelope_uuid = envelope_identity
        await self._acquire_onnuri_smoke_envelope_mutex(
            session, envelope_uuid=envelope_uuid
        )
        attempt = (
            (
                await session.execute(
                    select(OnnuriSmokeAttemptModel)
                    .where(
                        OnnuriSmokeAttemptModel.attempt_uuid == attempt_uuid,
                        OnnuriSmokeAttemptModel.organization_id == organization_id,
                    )
                    .with_for_update()
                )
            )
            .scalars()
            .first()
        )
        if attempt is None:
            raise TelephonyNumberInventoryNotFoundError(
                "onnuri_smoke_attempt_not_found"
            )
        envelope = (
            (
                await session.execute(
                    select(OnnuriSmokeEnvelopeModel)
                    .where(
                        OnnuriSmokeEnvelopeModel.id == attempt.envelope_id,
                        OnnuriSmokeEnvelopeModel.id == envelope_id,
                        OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                    )
                    .with_for_update()
                )
            )
            .scalars()
            .first()
        )
        return attempt, envelope

    async def allocate_onnuri_smoke_attempt(
        self,
        *,
        envelope_uuid: str,
        organization_id: int,
        proof_id: int,
        inventory_id: int,
        telephony_configuration_id: int,
        workflow_id: int,
        direction: str,
        authenticated_operator_user_id: int,
        workflow_owner_user_id: int,
        idempotency_key: str,
        request_digest: str,
        destination_hmac_digest: str,
        manual_acknowledgement_digest: str | None = None,
        manual_acknowledged_at: datetime | None = None,
    ) -> OnnuriSmokeAttemptModel:
        """Irreversibly allocate one of the global ordinals; failures never refund."""
        if direction not in {"inbound", "outbound"}:
            raise TelephonyNumberInventoryConflictError(
                "onnuri_smoke_direction_invalid"
            )
        if any(
            not isinstance(value, str) or not value.strip()
            for value in (idempotency_key, request_digest, destination_hmac_digest)
        ):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_smoke_allocation_input_invalid"
            )
        async with self.async_session() as session:
            await self._require_organization_member(
                session, authenticated_operator_user_id, organization_id
            )
            envelope_uuid_row = (
                await session.execute(
                    select(OnnuriSmokeEnvelopeModel.envelope_uuid).where(
                        OnnuriSmokeEnvelopeModel.envelope_uuid == envelope_uuid,
                        OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                    )
                )
            ).scalar_one_or_none()
            if envelope_uuid_row is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_smoke_envelope_not_found"
                )
            await self._acquire_onnuri_smoke_envelope_mutex(
                session, envelope_uuid=envelope_uuid_row
            )
            envelope = (
                (
                    await session.execute(
                        select(OnnuriSmokeEnvelopeModel)
                        .where(
                            OnnuriSmokeEnvelopeModel.envelope_uuid == envelope_uuid,
                            OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            database_now = (await session.execute(select(func.now()))).scalar_one()
            if envelope is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_smoke_envelope_not_found"
                )
            if not _onnuri_smoke_has_v3_prerequisites(envelope):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_v3_prerequisites_required"
                )
            existing = (
                (
                    await session.execute(
                        select(OnnuriSmokeAttemptModel).where(
                            OnnuriSmokeAttemptModel.envelope_id == envelope.id,
                            OnnuriSmokeAttemptModel.idempotency_key == idempotency_key,
                        )
                    )
                )
                .scalars()
                .first()
            )
            if existing is not None:
                if (
                    _digest_equal(existing.allocation_request_digest, request_digest)
                    and existing.direction == direction
                    and existing.authenticated_operator_user_id
                    == authenticated_operator_user_id
                    and existing.workflow_owner_user_id == workflow_owner_user_id
                    and _digest_equal(
                        existing.manual_acknowledgement_digest,
                        manual_acknowledgement_digest,
                    )
                    and existing.manual_acknowledged_at == manual_acknowledged_at
                ):
                    return existing
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_allocation_replay"
                )
            workflow = await session.get(WorkflowModel, workflow_id)
            proof = await session.get(OnnuriStagingPreflightProofModel, proof_id)
            inventory = await session.get(TelephonyNumberInventoryModel, inventory_id)
            if (
                envelope.state != "armed"
                or envelope.revoked_at is not None
                or envelope.contained_at is not None
                or not (
                    envelope.live_window_starts_at
                    <= database_now
                    < envelope.live_window_expires_at
                    <= envelope.expires_at
                )
                or (
                    proof_id,
                    inventory_id,
                    telephony_configuration_id,
                    workflow_id,
                )
                != (
                    envelope.proof_id,
                    envelope.inventory_id,
                    envelope.telephony_configuration_id,
                    envelope.workflow_id,
                )
                or not hmac.compare_digest(
                    destination_hmac_digest.encode("utf-8"),
                    envelope.destination_hmac_digest.encode("utf-8"),
                )
                or workflow is None
                or workflow.organization_id != organization_id
                or workflow.user_id != workflow_owner_user_id
                or proof is None
                or inventory is None
                or not self._proof_is_current_for_inventory(
                    proof, inventory, organization_id, database_now
                )
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_allocation_not_authorized"
                )
            attempts = (
                (
                    await session.execute(
                        select(OnnuriSmokeAttemptModel)
                        .where(OnnuriSmokeAttemptModel.envelope_id == envelope.id)
                        .order_by(OnnuriSmokeAttemptModel.ordinal)
                        .with_for_update()
                    )
                )
                .scalars()
                .all()
            )
            if len(attempts) >= 3:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_global_attempts_exhausted"
                )
            if any(row.state not in {"terminal", "contained"} for row in attempts):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_concurrent_attempt"
                )
            repeated_direction = any(row.direction == direction for row in attempts)
            if repeated_direction:
                if (
                    len(attempts) != 2
                    or not isinstance(manual_acknowledgement_digest, str)
                    or not manual_acknowledgement_digest.strip()
                    or manual_acknowledged_at is None
                    or manual_acknowledged_at.tzinfo is None
                    or manual_acknowledged_at.utcoffset() is None
                    or manual_acknowledged_at > database_now
                    or manual_acknowledged_at < database_now - timedelta(minutes=10)
                ):
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_smoke_third_attempt_acknowledgement_required"
                    )
            elif (
                manual_acknowledgement_digest is not None
                or manual_acknowledged_at is not None
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_unexpected_attempt_acknowledgement"
                )
            attempt = OnnuriSmokeAttemptModel(
                envelope_id=envelope.id,
                proof_id=envelope.proof_id,
                organization_id=envelope.organization_id,
                inventory_id=envelope.inventory_id,
                telephony_configuration_id=envelope.telephony_configuration_id,
                workflow_id=envelope.workflow_id,
                ordinal=len(attempts) + 1,
                direction=direction,
                state="allocated",
                authenticated_operator_user_id=authenticated_operator_user_id,
                workflow_owner_user_id=workflow_owner_user_id,
                idempotency_key=idempotency_key.strip(),
                allocation_request_digest=request_digest.strip(),
                manual_acknowledgement_digest=(
                    manual_acknowledgement_digest.strip()
                    if manual_acknowledgement_digest is not None
                    else None
                ),
                manual_acknowledged_at=manual_acknowledged_at,
            )
            session.add(attempt)
            await session.commit()
            await session.refresh(attempt)
            return attempt

    async def consume_onnuri_route_adapter_replay(
        self,
        *,
        key_id: str,
        challenge_nonce: str,
        audience: str,
        signature_sha256: str,
        expires_at_utc: datetime,
    ) -> None:
        """Atomically consume a route-adapter response until its bounded expiry."""
        if (
            not isinstance(key_id, str)
            or not key_id
            or not isinstance(challenge_nonce, str)
            or len(challenge_nonce) != 43
            or not isinstance(audience, str)
            or not audience
            or not _is_lowercase_sha256(signature_sha256)
            or expires_at_utc.tzinfo is None
        ):
            raise TelephonyNumberInventoryConflictError("onnuri_route_adapter_replay_invalid")
        async with self.async_session() as session:
            database_now = (await session.execute(select(func.now()))).scalar_one()
            if expires_at_utc <= database_now:
                raise TelephonyNumberInventoryConflictError("onnuri_route_adapter_replay_expired")
            row = OnnuriRouteAdapterReplayModel(
                key_id=key_id,
                challenge_nonce=challenge_nonce,
                audience=audience,
                signature_sha256=signature_sha256,
                expires_at=expires_at_utc,
            )
            session.add(row)
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise TelephonyNumberInventoryConflictError("onnuri_route_adapter_replay") from exc

    async def persist_onnuri_outbound_diagnostic_capability(
        self,
        *,
        nonce_digest: str,
        organization_id: int,
        authorization_attempt_uuid: str,
        idempotency_key: str,
        request_digest: str,
        candidate_digest: str,
        gate_envelope_digest: str,
        route_profile_digest: str,
        route_digest: str,
        provider_digest: str,
        keyset_digest: str,
        token_digest: str,
        signature_digest: str,
        encrypted_capability_recovery: str,

        issued_at: datetime,
        expires_at: datetime,
    ) -> OnnuriOutboundDiagnosticCapabilityModel:
        """Persist a minted F12 route capability without consuming its nonce."""
        async with self.async_session() as session:
            attempt, envelope = await self._lock_onnuri_smoke_attempt_authority(
                session, attempt_uuid=authorization_attempt_uuid, organization_id=organization_id
            )
            if (
                envelope is None
                or attempt.direction != "outbound"
                or attempt.idempotency_key != idempotency_key
                or attempt.allocation_request_digest != request_digest
                or envelope.candidate_digest != candidate_digest
                or hashlib.sha256(str(envelope.envelope_uuid).encode("utf-8")).hexdigest()
                != gate_envelope_digest
            ):
                raise TelephonyNumberInventoryConflictError("onnuri_outbound_diagnostic_capability_binding_invalid")
            existing = (await session.execute(
                select(OnnuriOutboundDiagnosticCapabilityModel).where(
                    OnnuriOutboundDiagnosticCapabilityModel.authorization_attempt_id == attempt.id,
                    OnnuriOutboundDiagnosticCapabilityModel.idempotency_key == idempotency_key,
                ).with_for_update()
            )).scalars().first()
            if existing is not None:
                if (
                    existing.nonce_digest == nonce_digest
                    and existing.request_digest == request_digest
                    and existing.candidate_digest == candidate_digest
                    and existing.gate_envelope_digest == gate_envelope_digest
                    and existing.route_profile_digest == route_profile_digest
                    and existing.route_digest == route_digest
                    and existing.provider_digest == provider_digest
                    and existing.keyset_digest == keyset_digest
                    and existing.token_digest == token_digest
                    and existing.signature_digest == signature_digest
                    and existing.issued_at == issued_at
                    and existing.expires_at == expires_at
                ):
                    return existing
                raise TelephonyNumberInventoryConflictError("onnuri_outbound_diagnostic_capability_replay")
            row = OnnuriOutboundDiagnosticCapabilityModel(
                nonce_digest=nonce_digest, organization_id=organization_id, envelope_id=envelope.id,
                authorization_attempt_id=attempt.id,
                authenticated_operator_user_id=attempt.authenticated_operator_user_id,
                idempotency_key=idempotency_key, request_digest=request_digest,
                candidate_digest=candidate_digest, gate_envelope_digest=gate_envelope_digest,
                route_profile_digest=route_profile_digest, route_digest=route_digest,
                provider_digest=provider_digest, keyset_digest=keyset_digest,
                token_digest=token_digest, signature_digest=signature_digest,
                encrypted_capability_recovery=encrypted_capability_recovery,
                issued_at=issued_at, expires_at=expires_at,
            )
            session.add(row)
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise TelephonyNumberInventoryConflictError("onnuri_outbound_diagnostic_capability_replay") from exc
            await session.refresh(row)
            return row

    async def recover_onnuri_outbound_diagnostic_capability(
        self,
        *,
        organization_id: int,
        authorization_attempt_uuid: str,
        idempotency_key: str,
        request_digest: str,
        candidate_digest: str,
        gate_envelope_digest: str,
        route_profile_digest: str,
    ) -> OnnuriOutboundDiagnosticCapabilityModel | None:
        """Lock and return an exact F12 mint replay without invoking route authority."""
        async with self.async_session() as session:
            attempt, envelope = await self._lock_onnuri_smoke_attempt_authority(
                session,
                attempt_uuid=authorization_attempt_uuid,
                organization_id=organization_id,
            )
            if (
                envelope is None
                or attempt.direction != "outbound"
                or attempt.idempotency_key != idempotency_key
                or not _digest_equal(attempt.allocation_request_digest, request_digest)
                or not _digest_equal(envelope.candidate_digest, candidate_digest)
                or not _digest_equal(
                    hashlib.sha256(str(envelope.envelope_uuid).encode("utf-8")).hexdigest(),
                    gate_envelope_digest,
                )
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_outbound_diagnostic_capability_binding_invalid"
                )
            row = (
                (
                    await session.execute(
                        select(OnnuriOutboundDiagnosticCapabilityModel)
                        .where(
                            OnnuriOutboundDiagnosticCapabilityModel.authorization_attempt_id
                            == attempt.id,
                            OnnuriOutboundDiagnosticCapabilityModel.idempotency_key
                            == idempotency_key,
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            if row is None:
                return None
            if (
                row.organization_id != organization_id
                or row.envelope_id != envelope.id
                or not _digest_equal(row.request_digest, request_digest)
                or not _digest_equal(row.candidate_digest, candidate_digest)
                or not _digest_equal(row.gate_envelope_digest, gate_envelope_digest)
                or not _digest_equal(row.route_profile_digest, route_profile_digest)
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_outbound_diagnostic_capability_replay"
                )
            return row

    async def consume_onnuri_outbound_route_capability(
        self,
        *,
        nonce_digest: str,
        token_digest: str,
        signature_digest: str,
        organization_id: int,
        authorization_attempt_uuid: str,
        idempotency_key: str,
        request_digest: str,
        candidate_digest: str,
        gate_envelope_digest: str,
        route_profile_digest: str,
        route_digest: str,
        provider_digest: str,
        keyset_digest: str,
        builder: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]],
        key_id: str,
        other_key_id: str,
        domain: str,
        algorithm_policy_id: str,
    ) -> tuple[OnnuriOutboundDiagnosticAttemptModel, bytes]:
        """Consume a dedicated route capability and persist its receipt in one transaction."""
        from api.schemas.onnuri_smoke import ONNURI_OUTBOUND_DIAGNOSTIC_FIXTURE_DIGEST

        for retry_attempt in range(3):
            builder_invoked = False
            try:
                async with self.async_session() as session:
                    await session.connection(execution_options={"isolation_level": "SERIALIZABLE"})
                    authorization_attempt, envelope = await self._lock_onnuri_smoke_attempt_authority(
                        session, attempt_uuid=authorization_attempt_uuid, organization_id=organization_id
                    )
                    capability = (await session.execute(
                        select(OnnuriOutboundDiagnosticCapabilityModel).where(
                            OnnuriOutboundDiagnosticCapabilityModel.nonce_digest == nonce_digest
                        ).with_for_update()
                    )).scalars().first()
                    database_now = (await session.execute(select(func.clock_timestamp()))).scalar_one()
                    if capability is None or envelope is None:
                        raise TelephonyNumberInventoryConflictError("onnuri_outbound_diagnostic_capability_not_found")
                    binding = (authorization_attempt.id, organization_id, envelope.id, idempotency_key, request_digest, candidate_digest, gate_envelope_digest, route_profile_digest, route_digest, provider_digest, keyset_digest, token_digest, signature_digest)
                    persisted = (capability.authorization_attempt_id, capability.organization_id, capability.envelope_id, capability.idempotency_key, capability.request_digest, capability.candidate_digest, capability.gate_envelope_digest, capability.route_profile_digest, capability.route_digest, capability.provider_digest, capability.keyset_digest, capability.token_digest, capability.signature_digest)
                    if binding != persisted:
                        raise TelephonyNumberInventoryConflictError("onnuri_outbound_diagnostic_capability_binding_invalid")
                    if capability.diagnostic_attempt_id is not None:
                        replay = await session.get(OnnuriOutboundDiagnosticAttemptModel, capability.diagnostic_attempt_id)
                        if (
                            replay is not None
                            and replay.idempotency_key == idempotency_key
                            and replay.request_digest == request_digest
                            and capability.encrypted_consume_recovery is not None
                            and capability.consume_response_digest is not None
                        ):
                            builder_invoked = True
                            built = await builder({"duplicate": True, "encrypted_consume_recovery": capability.encrypted_consume_recovery})
                            response = built.get("response")
                            if isinstance(response, bytes) and _digest_equal(capability.consume_response_digest, hashlib.sha256(response).hexdigest()):
                                return replay, response
                        raise TelephonyNumberInventoryConflictError("onnuri_outbound_diagnostic_capability_reused")
                    if (
                        capability.consumed_at is not None
                        or capability.revoked_at is not None
                        or capability.expires_at <= database_now
                        or authorization_attempt.direction != "outbound"
                        or authorization_attempt.state in {"terminal", "contained"}
                        or not await self._onnuri_smoke_envelope_is_current(session, envelope, database_now)
                    ):
                        raise TelephonyNumberInventoryConflictError("onnuri_outbound_diagnostic_capability_not_authorized")
                    attempts = (await session.execute(select(OnnuriOutboundDiagnosticAttemptModel).where(
                        OnnuriOutboundDiagnosticAttemptModel.envelope_id == envelope.id
                    ).with_for_update())).scalars().all()
                    if len(attempts) >= 3:
                        raise TelephonyNumberInventoryConflictError("onnuri_outbound_diagnostic_attempts_exhausted")
                    if any(row.terminal == "open" for row in attempts):
                        raise TelephonyNumberInventoryConflictError("onnuri_outbound_diagnostic_concurrent_attempt")
                    row = OnnuriOutboundDiagnosticAttemptModel(
                        organization_id=organization_id, envelope_id=envelope.id, inventory_id=envelope.inventory_id,
                        telephony_configuration_id=envelope.telephony_configuration_id,
                        authenticated_operator_user_id=authorization_attempt.authenticated_operator_user_id, ordinal=len(attempts) + 1,
                        idempotency_key=idempotency_key, fixture_digest=ONNURI_OUTBOUND_DIAGNOSTIC_FIXTURE_DIGEST,
                        destination_hmac_digest=envelope.destination_hmac_digest,
                        destination_hmac_key_version=envelope.destination_hmac_key_version,
                        caller_digest=hashlib.sha256(str(envelope.inventory_id).encode("utf-8")).hexdigest(),
                        operator_role="f12", operator_credential_digest=hashlib.sha256(str(authorization_attempt.authenticated_operator_user_id).encode("utf-8")).hexdigest(),
                        candidate_digest=candidate_digest, provider_digest=provider_digest, route_digest=route_digest,
                        nat_firewall_digest=route_digest, keyset_digest=keyset_digest, request_digest=request_digest,
                        dispatch="submission_reserved", reconciliation_cutoff_at=min(capability.expires_at, database_now + timedelta(seconds=60)),
                    )
                    session.add(row)
                    await session.flush()
                    builder_invoked = True
                    try:
                        built = await builder({
                            "duplicate": False, "consumed_at": database_now, "attempt_uuid": row.attempt_uuid,
                            "idempotency_key": idempotency_key, "request_digest": request_digest,
                            "key_id": key_id, "other_key_id": other_key_id, "domain": domain, "algorithm_policy_id": algorithm_policy_id,
                            "expires_at": capability.expires_at,
                        })
                    except Exception:
                        await session.rollback()
                        raise
                    response = built.get("response")
                    encrypted_recovery = built.get("encrypted_consume_recovery")
                    if not isinstance(response, bytes) or not isinstance(encrypted_recovery, str):
                        raise TelephonyNumberInventoryConflictError("onnuri_outbound_diagnostic_receipt_invalid")
                    capability.diagnostic_attempt_id = row.id
                    capability.consumed_at = database_now
                    capability.encrypted_consume_recovery = encrypted_recovery
                    capability.consume_response_digest = hashlib.sha256(response).hexdigest()
                    session.add(OnnuriOutboundDiagnosticEventModel(
                        attempt_id=row.id, sequence=1, operation="reserve_submission", provenance_digest=nonce_digest,
                        idempotency_key=f"{idempotency_key}:reserve", expected_dispatch="not_submitted",
                        expected_signaling="unknown", expected_answer="unknown", expected_media="unknown",
                        expected_terminal="open",
                    ))
                    row.event_sequence = 1
                    try:
                        await session.commit()
                    except IntegrityError as exc:
                        await session.rollback()
                        raise TelephonyNumberInventoryConflictError("onnuri_outbound_diagnostic_reservation_conflict") from exc
                    await session.refresh(row)
                    return row, response
            except DBAPIError as exc:
                sqlstate = getattr(exc.orig, "sqlstate", None) or getattr(exc.orig, "pgcode", None)
                if builder_invoked or sqlstate not in {"40001", "40P01"}:
                    raise
                if retry_attempt == 2:
                    raise TelephonyNumberInventoryConflictError("onnuri_outbound_diagnostic_serialization_conflict") from exc
        raise AssertionError("unreachable")

    async def transition_onnuri_outbound_diagnostic(
        self, *, attempt_uuid: str, organization_id: int, operation: str,
        expected: tuple[str, str, str, str, str], provenance_digest: str,
        event_idempotency_key: str,
    ) -> OnnuriOutboundDiagnosticAttemptModel:
        """Apply exactly one fixture-listed transition under the attempt row lock."""
        from api.schemas.onnuri_smoke import ONNURI_OUTBOUND_DIAGNOSTIC_CONTRACT

        edges = {(edge["operation"], tuple(edge["from"])): tuple(edge["to"])
                 for edge in ONNURI_OUTBOUND_DIAGNOSTIC_CONTRACT["edges"]}
        async with self.async_session() as session:
            attempt = (await session.execute(select(OnnuriOutboundDiagnosticAttemptModel).where(
                OnnuriOutboundDiagnosticAttemptModel.attempt_uuid == attempt_uuid,
                OnnuriOutboundDiagnosticAttemptModel.organization_id == organization_id,
            ).with_for_update())).scalars().first()
            if attempt is None:
                raise TelephonyNumberInventoryNotFoundError("onnuri_outbound_diagnostic_attempt_not_found")
            current = (attempt.dispatch, attempt.signaling, attempt.answer, attempt.media, attempt.terminal)
            duplicate = (await session.execute(select(OnnuriOutboundDiagnosticEventModel).where(
                OnnuriOutboundDiagnosticEventModel.attempt_id == attempt.id,
                OnnuriOutboundDiagnosticEventModel.idempotency_key == event_idempotency_key,
            ))).scalars().first()
            if duplicate is not None:
                binding = (
                    duplicate.operation,
                    duplicate.expected_dispatch,
                    duplicate.expected_signaling,
                    duplicate.expected_answer,
                    duplicate.expected_media,
                    duplicate.expected_terminal,
                    duplicate.provenance_digest,
                )
                if binding == (operation, *expected, provenance_digest):
                    return attempt
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_outbound_diagnostic_transition_replay"
                )
            if current != expected:
                raise TelephonyNumberInventoryConflictError("onnuri_outbound_diagnostic_expected_state_mismatch")
            target = edges.get((operation, current))
            if target is None:
                if operation == "terminate_authority_expired" and current[-1] == "open":
                    target = (*current[:4], "authority_expired")
                elif operation == "terminate_contained" and current[-1] == "open":
                    target = (*current[:4], "contained")
                else:
                    raise TelephonyNumberInventoryConflictError("onnuri_outbound_diagnostic_transition_invalid")
            attempt.dispatch, attempt.signaling, attempt.answer, attempt.media, attempt.terminal = target
            attempt.event_sequence += 1
            if target[-1] != "open":
                attempt.terminal_at = (await session.execute(select(func.now()))).scalar_one()
            session.add(OnnuriOutboundDiagnosticEventModel(
                attempt_id=attempt.id, sequence=attempt.event_sequence, operation=operation,
                provenance_digest=provenance_digest, idempotency_key=event_idempotency_key,
                expected_dispatch=expected[0], expected_signaling=expected[1],
                expected_answer=expected[2], expected_media=expected[3],
                expected_terminal=expected[4],
            ))
            await session.commit()
            await session.refresh(attempt)
            return attempt

    async def record_onnuri_outbound_diagnostic_late_evidence(
        self, *, attempt_uuid: str, organization_id: int, evidence_digest: str, evidence_kind: str,
    ) -> OnnuriOutboundDiagnosticLateEvidenceModel:
        """Append redacted evidence without reopening or changing the terminal product."""
        async with self.async_session() as session:
            attempt = (await session.execute(select(OnnuriOutboundDiagnosticAttemptModel).where(
                OnnuriOutboundDiagnosticAttemptModel.attempt_uuid == attempt_uuid,
                OnnuriOutboundDiagnosticAttemptModel.organization_id == organization_id,
            ).with_for_update())).scalars().first()
            if attempt is None:
                raise TelephonyNumberInventoryNotFoundError("onnuri_outbound_diagnostic_attempt_not_found")
            row = OnnuriOutboundDiagnosticLateEvidenceModel(
                attempt_id=attempt.id, evidence_digest=evidence_digest, evidence_kind=evidence_kind
            )
            session.add(row)
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise TelephonyNumberInventoryConflictError("onnuri_outbound_diagnostic_late_evidence_replay") from exc
            await session.refresh(row)
            return row

    async def issue_onnuri_smoke_dispatch(
        self,
        attempt_uuid: str,
        *,
        organization_id: int,
        builder: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]],
    ) -> tuple[OnnuriSmokeAttemptModel, bytes]:
        """Issue once after allocation; signer failure leaves the allocation burned."""
        async with self.async_session() as session:
            attempt, envelope = await self._lock_onnuri_smoke_attempt_authority(
                session,
                attempt_uuid=attempt_uuid,
                organization_id=organization_id,
            )
            database_now = (await session.execute(select(func.now()))).scalar_one()
            capability = (
                (
                    await session.execute(
                        select(OnnuriSmokeCapabilityConsumptionModel)
                        .where(
                            OnnuriSmokeCapabilityConsumptionModel.attempt_id
                            == attempt.id,
                            OnnuriSmokeCapabilityConsumptionModel.kind == "dispatch",
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            if (
                not await self._onnuri_smoke_envelope_is_current(
                    session, envelope, database_now
                )
                or attempt.direction != "outbound"
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_dispatch_issue_not_authorized"
                )
            if capability is not None:
                if (
                    attempt.state != "dispatch_issued"
                    or capability.expires_at <= database_now
                    or capability.recovery_erased_at is not None
                    or capability.encrypted_issue_recovery is None
                ):
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_smoke_dispatch_issue_replay"
                    )
                recovered = await builder(
                    {
                        "duplicate": True,
                        "encrypted_issue_recovery": capability.encrypted_issue_recovery,
                        "expires_at": capability.expires_at,
                        "attempt_uuid": attempt.attempt_uuid,
                        "request_digest": attempt.allocation_request_digest,
                        "idempotency_key": attempt.idempotency_key,
                        "candidate_digest": envelope.candidate_digest,
                        "gate_envelope_digest": hashlib.sha256(
                            str(envelope.envelope_uuid).encode("utf-8")
                        ).hexdigest(),
                    }
                )
                response = recovered.get("response")
                if not isinstance(response, bytes) or not _digest_equal(
                    capability.token_digest,
                    hashlib.sha256(response).hexdigest(),
                ):
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_smoke_dispatch_recovery_invalid"
                    )
                return attempt, response
            if attempt.state != "allocated":
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_dispatch_issue_not_authorized"
                )
            authority_expires_at = min(
                database_now + timedelta(seconds=60),
                envelope.live_window_expires_at,
            )
            if (authority_expires_at - database_now).total_seconds() < 1:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_dispatch_issue_not_authorized"
                )
            issuance_context = {
                "duplicate": False,
                "issued_at": database_now,
                "attempt_uuid": attempt.attempt_uuid,
                "request_digest": attempt.allocation_request_digest,
                "idempotency_key": attempt.idempotency_key,
                "candidate_digest": envelope.candidate_digest,
                "gate_envelope_digest": hashlib.sha256(
                    str(envelope.envelope_uuid).encode("utf-8")
                ).hexdigest(),
                "domain": envelope.dispatch_domain,
                "key_id": envelope.dispatch_key_id,
                "other_key_id": envelope.media_key_id,
                "algorithm_policy_id": envelope.dispatch_algorithm_policy_id,
                "live_window_expires_at": envelope.live_window_expires_at,
                "expires_at": authority_expires_at,
            }
            attempt.state = "dispatch_issuing"
            await session.commit()
            built = await builder(issuance_context)
            session.expire_all()
            attempt, envelope = await self._lock_onnuri_smoke_attempt_authority(
                session,
                attempt_uuid=attempt_uuid,
                organization_id=organization_id,
            )
            finalized_at = (await session.execute(select(func.now()))).scalar_one()
            if (
                attempt.state != "dispatch_issuing"
                or attempt.direction != "outbound"
                or not await self._onnuri_smoke_envelope_is_current(
                    session, envelope, finalized_at
                )
                or finalized_at >= authority_expires_at
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_dispatch_issue_not_authorized"
                )
            response = built.get("response")
            issued_at = built.get("issued_at")
            expires_at = built.get("expires_at")
            required = (
                built.get("nonce_digest"),
                built.get("token_digest"),
                built.get("receipt_digest"),
                built.get("encrypted_issue_recovery"),
            )
            if (
                not isinstance(response, bytes)
                or any(not isinstance(value, str) or not value for value in required)
                or issued_at != database_now
                or expires_at != authority_expires_at
                or not _digest_equal(
                    built.get("token_digest"), hashlib.sha256(response).hexdigest()
                )
                or built.get("domain") != envelope.dispatch_domain
                or built.get("key_id") != envelope.dispatch_key_id
                or built.get("algorithm_policy_id")
                != envelope.dispatch_algorithm_policy_id
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_dispatch_issue_material_invalid"
                )
            capability = OnnuriSmokeCapabilityConsumptionModel(
                attempt_id=attempt.id,
                kind="dispatch",
                domain=envelope.dispatch_domain,
                key_id=envelope.dispatch_key_id,
                algorithm_policy_id=envelope.dispatch_algorithm_policy_id,
                nonce_digest=built["nonce_digest"],
                token_digest=built["token_digest"],
                request_digest=attempt.allocation_request_digest,
                receipt_digest=built["receipt_digest"],
                issued_at=issued_at,
                expires_at=expires_at,
                encrypted_issue_recovery=built["encrypted_issue_recovery"],
            )
            session.add(capability)
            attempt.dispatch_receipt_digest = built["receipt_digest"]
            attempt.state = "dispatch_issued"
            await session.commit()
            await session.refresh(attempt)
            return attempt, response

    async def _onnuri_smoke_envelope_is_current(
        self, session, envelope: OnnuriSmokeEnvelopeModel | None, database_now: datetime
    ) -> bool:
        if (
            envelope is None
            or not _onnuri_smoke_has_v3_prerequisites(envelope)
            or envelope.state != "armed"
            or envelope.revoked_at is not None
            or envelope.contained_at is not None
            or not (
                envelope.live_window_starts_at
                <= database_now
                < envelope.live_window_expires_at
                <= envelope.expires_at
            )
        ):
            return False
        proof = await session.get(OnnuriStagingPreflightProofModel, envelope.proof_id)
        inventory = await session.get(
            TelephonyNumberInventoryModel, envelope.inventory_id
        )
        return (
            proof is not None
            and inventory is not None
            and inventory.organization_id == envelope.organization_id
            and inventory.telephony_configuration_id
            == envelope.telephony_configuration_id
            and inventory.onnuri_preflight_proof_id == envelope.proof_id
            and self._proof_is_current_for_inventory(
                proof, inventory, envelope.organization_id, database_now
            )
        )

    async def consume_onnuri_smoke_dispatch(
        self,
        attempt_uuid: str,
        *,
        organization_id: int,
        nonce_digest: str,
        token_digest: str,
        request_digest: str,
        receipt_digest: str,
        builder: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]],
        account_id: str | None = None,
        application_id: str | None = None,
        run_id: str | None = None,
    ) -> tuple[OnnuriSmokeAttemptModel, bytes]:
        """Consume and persist the exact facade receipt before stock creation."""
        context = _validated_onnuri_facade_context(
            account_id, application_id, run_id
        )
        async with self.async_session() as session:
            attempt, envelope = await self._lock_onnuri_smoke_attempt_authority(
                session,
                attempt_uuid=attempt_uuid,
                organization_id=organization_id,
            )
            capability = (
                (
                    await session.execute(
                        select(OnnuriSmokeCapabilityConsumptionModel)
                        .where(
                            OnnuriSmokeCapabilityConsumptionModel.attempt_id
                            == attempt.id,
                            OnnuriSmokeCapabilityConsumptionModel.kind == "dispatch",
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            database_now = (await session.execute(select(func.now()))).scalar_one()
            if (
                not await self._onnuri_smoke_envelope_is_current(
                    session, envelope, database_now
                )
                or capability is None
                or capability.expires_at <= database_now
                or capability.domain != envelope.dispatch_domain
                or capability.key_id != envelope.dispatch_key_id
                or not _digest_equal(capability.nonce_digest, nonce_digest)
                or not _digest_equal(capability.token_digest, token_digest)
                or not _digest_equal(capability.request_digest, request_digest)
                or not _digest_equal(capability.receipt_digest, receipt_digest)
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_dispatch_not_authorized"
                )
            if attempt.account_id is None:
                attempt.account_id, attempt.application_id, attempt.run_id = context
            elif not _onnuri_facade_context_matches(attempt, context):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_dispatch_context_mismatch"
                )
            if capability.consumed_at is not None:
                if (
                    attempt.state != "dispatch_consumed"
                    or capability.encrypted_consume_recovery is None
                    or capability.consume_response_digest is None
                    or capability.recovery_erased_at is not None
                ):
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_smoke_dispatch_replay"
                    )
                recovered = await builder(
                    {
                        "duplicate": True,
                        "encrypted_consume_recovery": capability.encrypted_consume_recovery,
                    }
                )
                response = recovered.get("response")
                if not isinstance(response, bytes) or not _digest_equal(
                    capability.consume_response_digest,
                    hashlib.sha256(response).hexdigest(),
                ):
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_smoke_dispatch_recovery_invalid"
                    )
                return attempt, response
            if attempt.state != "dispatch_issued":
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_dispatch_not_authorized"
                )
            built = await builder(
                {
                    "duplicate": False,
                    "consumed_at": database_now,
                    "attempt_uuid": attempt.attempt_uuid,
                    "idempotency_key": attempt.idempotency_key,
                    "request_digest": attempt.allocation_request_digest,
                    "direction": attempt.direction,
                    "key_id": envelope.dispatch_key_id,
                    "domain": envelope.dispatch_domain,
                    "other_key_id": envelope.media_key_id,
                    "algorithm_policy_id": envelope.dispatch_algorithm_policy_id,
                    "expires_at": capability.expires_at,
                }
            )
            response = built.get("response")
            encrypted_recovery = built.get("encrypted_consume_recovery")
            if (
                not isinstance(response, bytes)
                or not isinstance(encrypted_recovery, str)
                or not encrypted_recovery
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_dispatch_receipt_invalid"
                )
            capability.consumed_at = database_now
            capability.encrypted_consume_recovery = encrypted_recovery
            capability.consume_response_digest = hashlib.sha256(response).hexdigest()
            attempt.state = "dispatch_consumed"
            await session.commit()
            await session.refresh(attempt)
            return attempt, response

    async def onnuri_smoke_authority_ready(self) -> bool:
        contract_probe = text("""
            WITH expected_columns(table_name, column_name, type_name, is_nullable,
                                  default_expression) AS (
              VALUES
                ('onnuri_staging_smoke_attempts', 'account_id',
                 'character varying(255)', true, NULL),
                ('onnuri_staging_smoke_attempts', 'application_id',
                 'character varying(255)', true, NULL),
                ('onnuri_staging_smoke_attempts', 'run_id',
                 'character varying(255)', true, NULL),
                ('onnuri_staging_smoke_callback_events', 'id',
                 'integer', false, 'nextval(''onnuri_staging_smoke_callback_events_id_seq''::regclass)'),
                ('onnuri_staging_smoke_callback_events', 'attempt_id',
                 'integer', false, NULL),
                ('onnuri_staging_smoke_callback_events', 'event_nonce_digest',
                 'character varying(128)', false, NULL),
                ('onnuri_staging_smoke_callback_events', 'idempotency_key',
                 'character varying(255)', false, NULL),
                ('onnuri_staging_smoke_callback_events', 'request_digest',
                 'character varying(128)', false, NULL),
                ('onnuri_staging_smoke_callback_events', 'event_type',
                 'character varying(16)', false, NULL),
                ('onnuri_staging_smoke_callback_events', 'normalized_status',
                 'character varying(64)', false, NULL),
                ('onnuri_staging_smoke_callback_events', 'occurred_at',
                 'timestamp with time zone', false, NULL),
                ('onnuri_staging_smoke_callback_events', 'accepted_at',
                 'timestamp with time zone', false, 'now()'),
                ('onnuri_staging_smoke_callback_events', 'duration_seconds',
                 'integer', true, NULL),
                ('onnuri_staging_smoke_callback_events', 'redacted_cause_category',
                 'character varying(64)', true, NULL),
                ('g008_execution_nonce_consumptions', 'organization_id',
                 'integer', false, NULL),
                ('g008_execution_nonce_consumptions', 'execution_seal_uuid',
                 'character varying(36)', false, NULL),
                ('g008_execution_nonce_consumptions', 'execution_nonce_digest',
                 'character varying(64)', false, NULL),
                ('g008_execution_nonce_consumptions', 'candidate_digest',
                 'character varying(64)', false, NULL),
                ('g008_execution_nonce_consumptions', 'gate_envelope_digest',
                 'character varying(64)', false, NULL),
                ('g008_execution_nonce_consumptions', 'trusted_keyset_digest',
                 'character varying(64)', false, NULL),
                ('g008_execution_nonce_consumptions', 'consumed_at',
                 'timestamp with time zone', false, 'clock_timestamp()')
            ),
            expected_triggers(trigger_name, function_name) AS (
              VALUES
                ('trg_onnuri_smoke_attempt_facade_context',
                 'onnuri_smoke_facade_context_guard'),
                ('trg_onnuri_staging_smoke_attempts_authority_immutable',
                 'onnuri_smoke_authority_row_guard'),
                ('trg_onnuri_registration_attempt_terminal_guard',
                 'onnuri_registration_attempt_terminal_guard')
            ),
            expected_constraints(constraint_name, table_name, constraint_type,
                                 column_names) AS (
              VALUES
                ('ck_onnuri_smoke_attempt_bound_context',
                 'onnuri_staging_smoke_attempts', 'c', NULL::text[]),
                ('uq_onnuri_smoke_callback_nonce',
                 'onnuri_staging_smoke_callback_events', 'u',
                 ARRAY['attempt_id', 'event_nonce_digest']),
                ('ck_onnuri_smoke_callback_event_type',
                 'onnuri_staging_smoke_callback_events', 'c', NULL::text[]),
                ('ck_onnuri_smoke_callback_duration',
                 'onnuri_staging_smoke_callback_events', 'c', NULL::text[]),
                ('ck_g008_execution_nonce_consumption_digests',
                 'g008_execution_nonce_consumptions', 'c', NULL::text[]),
                ('uq_g008_execution_nonce_digest',
                 'g008_execution_nonce_consumptions', 'u',
                 ARRAY['execution_nonce_digest']),
                ('uq_g008_execution_nonce_seal',
                 'g008_execution_nonce_consumptions', 'u',
                 ARRAY['execution_seal_uuid'])
            )
            SELECT
              NOT EXISTS (
                SELECT 1
                FROM expected_columns required
                WHERE NOT EXISTS (
                  SELECT 1
                  FROM pg_class relation
                  JOIN pg_namespace namespace
                    ON namespace.oid = relation.relnamespace
                  JOIN pg_attribute attribute
                    ON attribute.attrelid = relation.oid
                   AND attribute.attname = required.column_name
                   AND attribute.attnum > 0
                   AND NOT attribute.attisdropped
                  LEFT JOIN pg_attrdef default_definition
                    ON default_definition.adrelid = relation.oid
                   AND default_definition.adnum = attribute.attnum
                  WHERE relation.relname = required.table_name
                    AND namespace.nspname = current_schema()
                    AND format_type(attribute.atttypid, attribute.atttypmod)
                      = required.type_name
                    AND attribute.attnotnull = (NOT required.is_nullable)
                    AND (
                      (required.default_expression IS NULL
                       AND default_definition.oid IS NULL)
                      OR (
                        required.default_expression IS NOT NULL
                        AND regexp_replace(
                          pg_get_expr(
                            default_definition.adbin, default_definition.adrelid
                          ),
                          E'[[:space:]]+', ' ', 'g'
                        ) = required.default_expression
                      )
                    )
                )
              )
              AND NOT EXISTS (
                SELECT 1
                FROM expected_triggers required
                WHERE NOT EXISTS (
                  SELECT 1
                  FROM pg_trigger trigger
                  JOIN pg_class relation ON relation.oid = trigger.tgrelid
                  JOIN pg_namespace namespace
                    ON namespace.oid = relation.relnamespace
                  JOIN pg_proc procedure ON procedure.oid = trigger.tgfoid
                  JOIN pg_namespace procedure_namespace
                    ON procedure_namespace.oid = procedure.pronamespace
                  WHERE trigger.tgname = required.trigger_name
                    AND relation.relname = 'onnuri_staging_smoke_attempts'
                    AND namespace.nspname = current_schema()
                    AND procedure.proname = required.function_name
                    AND procedure.pronargs = 0
                    AND procedure.prorettype = 'trigger'::regtype
                    AND procedure_namespace.nspname = current_schema()
                    AND trigger.tgenabled = 'O'
                    AND NOT trigger.tgisinternal
                    AND (trigger.tgtype & 3) = 3
                    AND (trigger.tgtype & 60) = 16
                    AND trigger.tgattr::text = ''
                    AND trigger.tgargs = '\\x'::bytea
                    AND trigger.tgqual IS NULL
                )
              )
              AND NOT EXISTS (
                SELECT 1
                FROM pg_trigger trigger
                JOIN pg_class relation ON relation.oid = trigger.tgrelid
                JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
                WHERE relation.relname = 'onnuri_staging_smoke_attempts'
                  AND namespace.nspname = current_schema()
                  AND NOT trigger.tgisinternal
                  AND (trigger.tgtype & 3) = 3
                  AND (trigger.tgtype & 60) = 16
                  AND trigger.tgname NOT IN (
                    'trg_onnuri_smoke_attempt_facade_context',
                    'trg_onnuri_staging_smoke_attempts_authority_immutable',
                    'trg_onnuri_registration_attempt_terminal_guard'
                  )
              )
              AND NOT EXISTS (
                SELECT 1
                FROM expected_constraints required
                WHERE NOT EXISTS (
                  SELECT 1
                  FROM pg_constraint con
                  JOIN pg_class relation ON relation.oid = con.conrelid
                  JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
                  WHERE con.conname = required.constraint_name
                    AND con.contype::text = required.constraint_type
                    AND con.convalidated
                    AND relation.relname = required.table_name
                    AND namespace.nspname = current_schema()
                    AND (
                      required.column_names IS NULL
                      OR ARRAY(
                        SELECT attribute.attname::text
                        FROM unnest(con.conkey) WITH ORDINALITY
                          AS key_column(attnum, ordinal)
                        JOIN pg_attribute attribute
                          ON attribute.attrelid = con.conrelid
                         AND attribute.attnum = key_column.attnum
                        ORDER BY key_column.ordinal
                      ) = required.column_names
                    )
                )
              )
              AND EXISTS (
                SELECT 1
                FROM pg_constraint con
                JOIN pg_class relation ON relation.oid = con.conrelid
                JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
                JOIN pg_class referenced_relation ON referenced_relation.oid = con.confrelid
                JOIN pg_namespace referenced_namespace
                  ON referenced_namespace.oid = referenced_relation.relnamespace
                WHERE relation.relname = 'onnuri_staging_smoke_callback_events'
                  AND namespace.nspname = current_schema()
                  AND con.contype = 'f'
                  AND con.convalidated
                  AND referenced_relation.relname = 'onnuri_staging_smoke_attempts'
                  AND referenced_namespace.nspname = current_schema()
                  AND con.confdeltype = 'r'
                  AND con.confupdtype = 'a'
                  AND ARRAY(
                    SELECT attribute.attname::text
                    FROM unnest(con.conkey) WITH ORDINALITY
                      AS key_column(attnum, ordinal)
                    JOIN pg_attribute attribute
                      ON attribute.attrelid = con.conrelid
                     AND attribute.attnum = key_column.attnum
                    ORDER BY key_column.ordinal
                  ) = ARRAY['attempt_id']
                  AND ARRAY(
                    SELECT attribute.attname::text
                    FROM unnest(con.confkey) WITH ORDINALITY
                      AS key_column(attnum, ordinal)
                    JOIN pg_attribute attribute
                      ON attribute.attrelid = con.confrelid
                     AND attribute.attnum = key_column.attnum
                    ORDER BY key_column.ordinal
                  ) = ARRAY['id']
              )
              AND EXISTS (
                SELECT 1
                FROM pg_constraint con
                JOIN pg_class relation ON relation.oid = con.conrelid
                JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
                WHERE relation.relname = 'onnuri_staging_smoke_callback_events'
                  AND namespace.nspname = current_schema()
                  AND con.conname = 'onnuri_staging_smoke_callback_events_pkey'
                  AND con.contype = 'p'
                  AND con.convalidated
                  AND NOT con.condeferrable
                  AND NOT con.condeferred
                  AND ARRAY(
                    SELECT attribute.attname::text
                    FROM unnest(con.conkey) WITH ORDINALITY
                      AS key_column(attnum, ordinal)
                    JOIN pg_attribute attribute
                      ON attribute.attrelid = con.conrelid
                     AND attribute.attnum = key_column.attnum
                    ORDER BY key_column.ordinal
                  ) = ARRAY['id']
              )
        """)
        fingerprint_probe = text("""
            WITH expected_constraints(label, relation_name) AS (
              VALUES
                ('ck_onnuri_smoke_attempt_bound_context',
                 'onnuri_staging_smoke_attempts'),
                ('uq_onnuri_smoke_callback_nonce',
                 'onnuri_staging_smoke_callback_events'),
                ('ck_onnuri_smoke_callback_event_type',
                 'onnuri_staging_smoke_callback_events'),
                ('ck_onnuri_smoke_callback_duration',
                 'onnuri_staging_smoke_callback_events')
            )
            SELECT label, definition
            FROM (
              SELECT procedure.proname AS label,
                     regexp_replace(
                       pg_get_functiondef(procedure.oid), E'[[:space:]]+', ' ', 'g'
                     ) AS definition
              FROM pg_proc procedure
              JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace
              WHERE namespace.nspname = current_schema()
                AND procedure.pronargs = 0
                AND procedure.proname IN (
                  'onnuri_smoke_authority_row_guard',
                  'onnuri_smoke_facade_context_guard'
                )
              UNION ALL
              SELECT required.label,
                     regexp_replace(
                       pg_get_constraintdef(con.oid), E'[[:space:]]+', ' ', 'g'
                     )
              FROM expected_constraints required
              JOIN pg_class relation ON relation.relname = required.relation_name
              JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
              JOIN pg_constraint con
                ON con.conrelid = relation.oid
               AND con.conname = required.label
              WHERE namespace.nspname = current_schema()
              UNION ALL
              SELECT 'callback_attempt_fk',
                     regexp_replace(
                       pg_get_constraintdef(con.oid), E'[[:space:]]+', ' ', 'g'
                     )
              FROM pg_constraint con
              JOIN pg_class relation ON relation.oid = con.conrelid
              JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
              WHERE relation.relname = 'onnuri_staging_smoke_callback_events'
                AND namespace.nspname = current_schema()
                AND con.contype = 'f'
                AND ARRAY(
                  SELECT attribute.attname::text
                  FROM unnest(con.conkey) WITH ORDINALITY
                    AS key_column(attnum, ordinal)
                  JOIN pg_attribute attribute
                    ON attribute.attrelid = con.conrelid
                   AND attribute.attnum = key_column.attnum
                  ORDER BY key_column.ordinal
                ) = ARRAY['attempt_id']
              UNION ALL
              SELECT 'callback_events_primary_key',
                     regexp_replace(
                       pg_get_constraintdef(con.oid), E'[[:space:]]+', ' ', 'g'
                     )
              FROM pg_constraint con
              JOIN pg_class relation ON relation.oid = con.conrelid
              JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
              WHERE relation.relname = 'onnuri_staging_smoke_callback_events'
                AND namespace.nspname = current_schema()
                AND con.conname = 'onnuri_staging_smoke_callback_events_pkey'
                AND con.contype = 'p'
                AND ARRAY(
                  SELECT attribute.attname::text
                  FROM unnest(con.conkey) WITH ORDINALITY
                    AS key_column(attnum, ordinal)
                  JOIN pg_attribute attribute
                    ON attribute.attrelid = con.conrelid
                   AND attribute.attnum = key_column.attnum
                  ORDER BY key_column.ordinal
                ) = ARRAY['id']
            ) fingerprints
        """)
        try:
            async with self.async_session() as session:
                async with session.begin_nested():
                    if not bool(
                        (await session.execute(contract_probe)).scalar_one()
                    ):
                        return False
                    rows = (await session.execute(fingerprint_probe)).all()
                    labels = [label for label, _ in rows]
                    if (
                        len(rows) != len(_ONNURI_FACADE_CATALOG_FINGERPRINTS)
                        or any(
                            labels.count(label) != 1
                            for label in _ONNURI_FACADE_CATALOG_FINGERPRINTS
                        )
                    ):
                        return False
                    fingerprints = {
                        label: hashlib.sha256(definition.encode("utf-8")).hexdigest()
                        for label, definition in rows
                    }
                    return fingerprints == _ONNURI_FACADE_CATALOG_FINGERPRINTS
        except Exception:
            return False

    async def lookup_onnuri_smoke_bound_attempt(
        self, *, organization_id: int, account_id: str, stock_call_id_digest: str
    ) -> OnnuriSmokeAttemptModel:
        async with self.async_session() as session:
            result = (
                await session.execute(
                    select(
                        OnnuriSmokeAttemptModel,
                        OnnuriSmokeEnvelopeModel.candidate_digest,
                    )
                    .join(
                        OnnuriSmokeEnvelopeModel,
                        OnnuriSmokeEnvelopeModel.id
                        == OnnuriSmokeAttemptModel.envelope_id,
                    )
                    .where(
                        OnnuriSmokeAttemptModel.organization_id == organization_id,
                        OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                        OnnuriSmokeAttemptModel.account_id == account_id,
                        OnnuriSmokeAttemptModel.stock_call_id_digest
                        == stock_call_id_digest,
                    )
                    .execution_options(populate_existing=True)
                )
            ).first()
            if result is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_smoke_bound_attempt_not_found"
                )
            attempt, candidate_digest = result
            setattr(attempt, "candidate_digest", candidate_digest)
            return attempt

    async def accept_onnuri_smoke_callback(
        self, *, organization_id: int, account_id: str, application_id: str,
        run_id: str, attempt_uuid: str, stock_call_id_digest: str,
        event_nonce_digest: str, idempotency_key: str, request_digest: str,
        event_type: str, normalized_status: str, occurred_at: datetime,
        duration_seconds: int | None = None, redacted_cause_category: str | None = None,
    ) -> OnnuriSmokeCallbackEventModel:
        if event_type not in {"status", "cdr"} or normalized_status not in _ONNURI_FACADE_STATUS_RANK:
            raise TelephonyNumberInventoryConflictError("onnuri_smoke_callback_invalid")
        async with self.async_session() as session:
            attempt, envelope = await self._lock_onnuri_smoke_attempt_authority(
                session,
                attempt_uuid=attempt_uuid,
                organization_id=organization_id,
            )
            if envelope is None or not (
                _digest_equal(attempt.account_id, account_id)
                and _digest_equal(attempt.application_id, application_id)
                and _digest_equal(attempt.run_id, run_id)
                and _digest_equal(attempt.stock_call_id_digest, stock_call_id_digest)
            ):
                raise TelephonyNumberInventoryConflictError("onnuri_smoke_callback_not_authorized")
            event = (await session.execute(select(OnnuriSmokeCallbackEventModel).where(
                OnnuriSmokeCallbackEventModel.attempt_id == attempt.id,
                OnnuriSmokeCallbackEventModel.event_nonce_digest == event_nonce_digest,
            ).with_for_update())).scalars().first()
            previous_event = (
                (
                    await session.execute(
                        select(OnnuriSmokeCallbackEventModel)
                        .where(OnnuriSmokeCallbackEventModel.attempt_id == attempt.id)
                        .order_by(
                            OnnuriSmokeCallbackEventModel.accepted_at.desc(),
                            OnnuriSmokeCallbackEventModel.id.desc(),
                        )
                        .limit(1)
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            material = (idempotency_key, request_digest, event_type, normalized_status,
                        occurred_at, duration_seconds, redacted_cause_category)
            if event is not None:
                if (_digest_equal(event.idempotency_key, idempotency_key)
                    and _digest_equal(event.request_digest, request_digest)
                    and (event.event_type, event.normalized_status, event.occurred_at,
                         event.duration_seconds, event.redacted_cause_category) == material[2:]):
                    return event
                raise TelephonyNumberInventoryConflictError("onnuri_smoke_callback_replay")
            current = _onnuri_facade_status(attempt)
            if (
                current in _ONNURI_FACADE_TERMINAL
                or (
                    previous_event is not None
                    and _ONNURI_FACADE_STATUS_RANK[normalized_status]
                    <= _ONNURI_FACADE_STATUS_RANK[previous_event.normalized_status]
                )
                or (
                    normalized_status not in _ONNURI_FACADE_TERMINAL
                    and _ONNURI_FACADE_STATUS_RANK[normalized_status]
                    > _ONNURI_FACADE_STATUS_RANK[current]
                )
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_callback_transition_invalid"
                )
            now = (
                await session.execute(select(func.clock_timestamp()))
            ).scalar_one()
            if (
                normalized_status in _ONNURI_FACADE_TERMINAL
                and (
                    attempt.authority_deadline_at is None
                    or now >= attempt.authority_deadline_at
                )
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_callback_authority_expired"
                )
            event = OnnuriSmokeCallbackEventModel(
                attempt_id=attempt.id, event_nonce_digest=event_nonce_digest,
                idempotency_key=idempotency_key, request_digest=request_digest,
                event_type=event_type, normalized_status=normalized_status,
                occurred_at=occurred_at, accepted_at=now, duration_seconds=duration_seconds,
                redacted_cause_category=redacted_cause_category,
            )
            session.add(event)
            if normalized_status in _ONNURI_FACADE_TERMINAL:
                attempt.state = "terminal"
                attempt.terminal_class = normalized_status
                attempt.terminal_reason = redacted_cause_category or normalized_status
                attempt.terminal_at = now
            await session.commit()
            await session.refresh(event)
            return event

    async def request_onnuri_smoke_containment(
        self, *, organization_id: int, account_id: str, application_id: str,
        run_id: str, attempt_uuid: str, stock_call_id_digest: str, category: str,
    ) -> OnnuriSmokeAttemptModel:
        async with self.async_session() as session:
            attempt, envelope = await self._lock_onnuri_smoke_attempt_authority(
                session,
                attempt_uuid=attempt_uuid,
                organization_id=organization_id,
            )
            if envelope is None or not (
                _digest_equal(attempt.account_id, account_id)
                and _digest_equal(attempt.application_id, application_id)
                and _digest_equal(attempt.run_id, run_id)
                and _digest_equal(attempt.stock_call_id_digest, stock_call_id_digest)
                and isinstance(category, str) and category
            ):
                raise TelephonyNumberInventoryConflictError("onnuri_smoke_containment_not_authorized")
            if attempt.state == "contained":
                if envelope.containment_reason == category:
                    return attempt
                raise TelephonyNumberInventoryConflictError("onnuri_smoke_containment_replay")
            if _onnuri_facade_status(attempt) in _ONNURI_FACADE_TERMINAL:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_containment_terminal"
                )
            now = (await session.execute(select(func.now()))).scalar_one()
            attempt.state = "contained"
            attempt.contained_at = now
            attempt.terminal_class = "contained"
            attempt.terminal_reason = category
            attempt.terminal_at = now
            envelope.state, envelope.contained_at, envelope.containment_reason = "contained", now, category
            await session.commit()
            await session.refresh(attempt)
            return attempt
    async def _validate_onnuri_smoke_inbound_tuple(
        self,
        session,
        *,
        attempt: OnnuriSmokeAttemptModel,
        envelope: OnnuriSmokeEnvelopeModel | None,
        organization_id: int,
        direction: str,
        source_account_id: str | None,
        source_application_id: str | None,
        did_digest: str | None,
        caller_mobile_digest: str | None,
        candidate_digest: str | None,
    ) -> str | None:
        inbound_values = (
            source_account_id,
            source_application_id,
            did_digest,
            caller_mobile_digest,
            candidate_digest,
        )
        if direction != "inbound":
            if any(value is not None for value in inbound_values):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_inbound_tuple_invalid"
                )
            return None
        if any(not isinstance(value, str) or not value for value in inbound_values):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_smoke_inbound_tuple_invalid"
            )
        tuple_digest = _inbound_tuple_digest(
            (
                source_account_id,
                source_application_id,
                did_digest,
                caller_mobile_digest,
                candidate_digest,
            )
        )
        configuration = await session.get(
            TelephonyConfigurationModel,
            attempt.telephony_configuration_id,
            with_for_update=True,
        )
        candidate_id = (
            await session.execute(
                select(TelephonyNumberInventoryModel.onnuri_staging_candidate_id).where(
                    TelephonyNumberInventoryModel.id == attempt.inventory_id
                )
            )
        ).scalar_one_or_none()
        candidate = (
            await session.get(
                OnnuriStagingCandidateModel,
                candidate_id,
                with_for_update=True,
            )
            if candidate_id is not None
            else None
        )
        inventory = await session.get(
            TelephonyNumberInventoryModel,
            attempt.inventory_id,
            with_for_update=True,
        )
        credentials = (
            configuration.credentials
            if configuration is not None and isinstance(configuration.credentials, dict)
            else {}
        )
        authoritative_did_digest = (
            hashlib.sha256(candidate.normalized_did.encode("utf-8")).hexdigest()
            if candidate is not None and isinstance(candidate.normalized_did, str)
            else None
        )
        if (
            attempt.organization_id != organization_id
            or attempt.direction != "inbound"
            or envelope is None
            or envelope.organization_id != organization_id
            or envelope.inventory_id != attempt.inventory_id
            or envelope.telephony_configuration_id != attempt.telephony_configuration_id
            or configuration is None
            or configuration.organization_id != organization_id
            or configuration.provider != "jambonz"
            or not _digest_equal(credentials.get("account_id"), source_account_id)
            or not _digest_equal(
                credentials.get("application_id"), source_application_id
            )
            or inventory is None
            or inventory.id != envelope.inventory_id
            or inventory.organization_id != organization_id
            or inventory.provider != "jambonz"
            or inventory.telephony_configuration_id != configuration.id
            or candidate is None
            or candidate.id != inventory.onnuri_staging_candidate_id
            or candidate.inventory_id != inventory.id
            or candidate.provider != "jambonz"
            or candidate.classification != "onnuri_staging_candidate_v1"
            or candidate.environment != "staging"
            or candidate.state != "active"
            or candidate.retired_at is not None
            or candidate.retired_by_user_id is not None
            or candidate.retired_reason is not None
            or not _digest_equal(authoritative_did_digest, did_digest)
            or not _digest_equal(envelope.destination_hmac_digest, caller_mobile_digest)
            or not _digest_equal(envelope.candidate_digest, candidate_digest)
        ):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_smoke_inbound_tuple_invalid"
            )
        return tuple_digest

    async def bind_onnuri_smoke_stock_call(
        self,
        attempt_uuid: str,
        *,
        organization_id: int,
        idempotency_key: str,
        request_digest: str,
        stock_call_id_digest: str,
        callback_nonce_digest: str,
        source_account_id: str | None = None,
        source_application_id: str | None = None,
        did_digest: str | None = None,
        caller_mobile_digest: str | None = None,
        candidate_digest: str | None = None,
        account_id: str | None = None,
        application_id: str | None = None,
        run_id: str | None = None,
    ) -> OnnuriSmokeAttemptModel:
        """Bind once; this operation deliberately never creates media authority."""
        context = _validated_onnuri_facade_context(
            account_id, application_id, run_id
        )
        async with self.async_session() as session:
            attempt, envelope = await self._lock_onnuri_smoke_attempt_authority(
                session,
                attempt_uuid=attempt_uuid,
                organization_id=organization_id,
            )
            if attempt.idempotency_key != idempotency_key or not _digest_equal(
                attempt.allocation_request_digest, request_digest
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_bind_not_authorized"
                )
            inbound_tuple_digest = await self._validate_onnuri_smoke_inbound_tuple(
                session,
                attempt=attempt,
                envelope=envelope,
                organization_id=organization_id,
                direction=attempt.direction,
                source_account_id=source_account_id,
                source_application_id=source_application_id,
                did_digest=did_digest,
                caller_mobile_digest=caller_mobile_digest,
                candidate_digest=candidate_digest,
            )
            database_now = (await session.execute(select(func.now()))).scalar_one()
            if not await self._onnuri_smoke_envelope_is_current(
                session, envelope, database_now
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_bind_not_authorized"
                )
            if attempt.state == "stock_bound":
                if (
                    _onnuri_facade_context_matches(attempt, context)
                    and _digest_equal(attempt.stock_call_id_digest, stock_call_id_digest)
                    and _digest_equal(
                        attempt.bind_callback_nonce_digest, callback_nonce_digest
                    )
                    and _digest_equal(
                        attempt.inbound_tuple_digest, inbound_tuple_digest
                    )
                ):
                    return attempt
                raise TelephonyNumberInventoryConflictError("onnuri_smoke_bind_replay")
            expected = (
                "dispatch_consumed" if attempt.direction == "outbound" else "allocated"
            )
            if (
                attempt.state != expected
                or not stock_call_id_digest
                or not callback_nonce_digest
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_bind_not_authorized"
                )
            if attempt.direction == "inbound":
                if inbound_tuple_digest is None:
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_smoke_inbound_tuple_invalid"
                    )
                attempt.inbound_tuple_digest = inbound_tuple_digest
                if attempt.account_id is None:
                    attempt.account_id, attempt.application_id, attempt.run_id = context
                elif not _onnuri_facade_context_matches(attempt, context):
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_smoke_bind_context_mismatch"
                    )
            elif attempt.inbound_tuple_digest is not None:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_inbound_tuple_invalid"
                )
            elif not _onnuri_facade_context_matches(attempt, context):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_bind_context_mismatch"
                )
            attempt.stock_call_id_digest = stock_call_id_digest
            attempt.bind_callback_nonce_digest = callback_nonce_digest
            attempt.stock_bound_at = func.now()
            attempt.state = "stock_bound"
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_stock_call_reused"
                ) from exc
            await session.refresh(attempt)
            return attempt

    async def _mint_onnuri_smoke_media(
        self,
        *,
        attempt_uuid: str,
        organization_id: int,
        direction: str,
        authority_kind: str,
        idempotency_key: str,
        callback_nonce_digest: str,
        request_digest: str,
        stock_call_id_digest: str,
        authority_wall_at: datetime,
        deadline_at: datetime,
        builder: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]],
        source_account_id: str | None = None,
        source_application_id: str | None = None,
        did_digest: str | None = None,
        caller_mobile_digest: str | None = None,
        candidate_digest: str | None = None,
        approved_pause_milliseconds: int = 0,
        account_id: str | None = None,
        application_id: str | None = None,
        run_id: str | None = None,
    ) -> tuple[OnnuriSmokeAnswerAuthorizationModel, bytes]:
        context = _validated_onnuri_facade_context(
            account_id, application_id, run_id
        )
        async with self.async_session() as session:
            attempt, envelope = await self._lock_onnuri_smoke_attempt_authority(
                session,
                attempt_uuid=attempt_uuid,
                organization_id=organization_id,
            )
            if attempt.idempotency_key != idempotency_key or not _digest_equal(
                attempt.allocation_request_digest, request_digest
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_answer_authority_invalid"
                )
            if not _onnuri_facade_context_matches(attempt, context):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_answer_authority_context_mismatch"
                )
            inbound_tuple_digest = await self._validate_onnuri_smoke_inbound_tuple(
                session,
                attempt=attempt,
                envelope=envelope,
                organization_id=organization_id,
                direction=direction,
                source_account_id=source_account_id,
                source_application_id=source_application_id,
                did_digest=did_digest,
                caller_mobile_digest=caller_mobile_digest,
                candidate_digest=candidate_digest,
            )
            if (
                direction == "inbound"
                and not _digest_equal(
                    attempt.inbound_tuple_digest, inbound_tuple_digest
                )
            ) or (
                direction != "inbound"
                and (
                    inbound_tuple_digest is not None
                    or attempt.inbound_tuple_digest is not None
                )
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_inbound_tuple_invalid"
                )
            database_now = (await session.execute(select(func.now()))).scalar_one()
            existing = (
                (
                    await session.execute(
                        select(OnnuriSmokeAnswerAuthorizationModel)
                        .where(
                            OnnuriSmokeAnswerAuthorizationModel.attempt_id == attempt.id
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            if existing is not None:
                if (
                    existing.idempotency_key == idempotency_key
                    and _digest_equal(
                        existing.callback_nonce_digest, callback_nonce_digest
                    )
                    and _digest_equal(existing.canonical_request_digest, request_digest)
                    and existing.deadline_at > database_now
                    and existing.recovery_erased_at is None
                    and existing.encrypted_response_recovery is not None
                    and existing.direction == direction
                    and existing.authority_kind == authority_kind
                    and existing.deadline_at == deadline_at
                    and attempt.authority_wall_at == authority_wall_at
                    and existing.observed_carrier_answer_at
                    == (authority_wall_at if direction == "outbound" else None)
                    and existing.approved_pause_milliseconds
                    == approved_pause_milliseconds
                    and _digest_equal(
                        attempt.stock_call_id_digest, stock_call_id_digest
                    )
                    and await self._onnuri_smoke_envelope_is_current(
                        session, envelope, database_now
                    )
                ):
                    recovered = await builder(
                        {
                            "duplicate": True,
                            "encrypted_response_recovery": (
                                existing.encrypted_response_recovery
                            ),
                            "attempt_uuid": attempt.attempt_uuid,
                            "idempotency_key": attempt.idempotency_key,
                            "request_digest": attempt.allocation_request_digest,
                            "candidate_digest": envelope.candidate_digest,
                            "gate_envelope_digest": hashlib.sha256(
                                str(envelope.envelope_uuid).encode("utf-8")
                            ).hexdigest(),
                            "deadline_at": existing.deadline_at,
                        }
                    )
                    response = recovered.get("response")
                    if not isinstance(response, bytes) or not _digest_equal(
                        existing.canonical_response_digest,
                        hashlib.sha256(response).hexdigest(),
                    ):
                        raise TelephonyNumberInventoryConflictError(
                            "onnuri_smoke_answer_recovery_invalid"
                        )
                    return existing, response
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_answer_authority_replay"
                )
            authority_duration_seconds = (
                deadline_at - authority_wall_at
            ).total_seconds()
            budget_seconds = int(authority_duration_seconds)
            if (
                not await self._onnuri_smoke_envelope_is_current(
                    session, envelope, database_now
                )
                or attempt.state != "stock_bound"
                or attempt.direction != direction
                or not _digest_equal(attempt.stock_call_id_digest, stock_call_id_digest)
                or authority_wall_at > database_now
                or database_now >= deadline_at
                or authority_duration_seconds != 60
                or deadline_at > envelope.live_window_expires_at
                or approved_pause_milliseconds < 0
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_answer_authority_invalid"
                )
            issuance_context = {
                "duplicate": False,
                "committed_at": database_now,
                "attempt_uuid": attempt.attempt_uuid,
                "idempotency_key": idempotency_key,
                "request_digest": request_digest,
                "direction": direction,
                "authority_wall_at": authority_wall_at,
                "deadline_at": deadline_at,
                "issued_at": database_now,
                "expires_at": deadline_at,
                "candidate_digest": envelope.candidate_digest,
                "gate_envelope_digest": hashlib.sha256(
                    str(envelope.envelope_uuid).encode("utf-8")
                ).hexdigest(),
                "domain": envelope.media_domain,
                "key_id": envelope.media_key_id,
                "other_key_id": envelope.dispatch_key_id,
                "algorithm_policy_id": envelope.media_algorithm_policy_id,
            }
            attempt.state = "media_issuing"
            await session.commit()
            built = await builder(issuance_context)
            session.expire_all()
            attempt, envelope = await self._lock_onnuri_smoke_attempt_authority(
                session,
                attempt_uuid=attempt_uuid,
                organization_id=organization_id,
            )
            if attempt.idempotency_key != idempotency_key or not _digest_equal(
                attempt.allocation_request_digest, request_digest
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_answer_authority_invalid"
                )
            if not _onnuri_facade_context_matches(attempt, context):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_answer_authority_context_mismatch"
                )
            finalized_tuple_digest = await self._validate_onnuri_smoke_inbound_tuple(
                session,
                attempt=attempt,
                envelope=envelope,
                organization_id=organization_id,
                direction=direction,
                source_account_id=source_account_id,
                source_application_id=source_application_id,
                did_digest=did_digest,
                caller_mobile_digest=caller_mobile_digest,
                candidate_digest=candidate_digest,
            )
            if (
                direction == "inbound"
                and not _digest_equal(
                    attempt.inbound_tuple_digest, finalized_tuple_digest
                )
            ) or (
                direction != "inbound"
                and (
                    finalized_tuple_digest is not None
                    or attempt.inbound_tuple_digest is not None
                )
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_inbound_tuple_invalid"
                )
            finalized_at = (await session.execute(select(func.now()))).scalar_one()
            if (
                attempt.state != "media_issuing"
                or attempt.direction != direction
                or not _digest_equal(attempt.stock_call_id_digest, stock_call_id_digest)
                or not await self._onnuri_smoke_envelope_is_current(
                    session, envelope, finalized_at
                )
                or finalized_at >= deadline_at
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_answer_authority_invalid"
                )
            response = built.get("response")
            encrypted_recovery = built.get("encrypted_response_recovery")
            expires_at = built.get("expires_at")
            if (
                not isinstance(response, bytes)
                or not isinstance(encrypted_recovery, str)
                or not encrypted_recovery
                or built.get("issued_at") != database_now
                or expires_at != deadline_at
                or built.get("domain") != envelope.media_domain
                or built.get("key_id") != envelope.media_key_id
                or built.get("algorithm_policy_id")
                != envelope.media_algorithm_policy_id
                or any(
                    not isinstance(built.get(name), str) or not built.get(name)
                    for name in ("nonce_digest", "token_digest", "receipt_digest")
                )
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_answer_authority_material_invalid"
                )
            response_digest = hashlib.sha256(response).hexdigest()
            authorization = OnnuriSmokeAnswerAuthorizationModel(
                attempt_id=attempt.id,
                direction=direction,
                authority_kind=authority_kind,
                idempotency_key=idempotency_key,
                callback_nonce_digest=callback_nonce_digest,
                canonical_request_digest=request_digest,
                canonical_response_digest=response_digest,
                encrypted_response_recovery=encrypted_recovery,
                committed_at=database_now,
                deadline_at=deadline_at,
                budget_seconds=budget_seconds,
                approved_pause_milliseconds=approved_pause_milliseconds,
                observed_carrier_answer_at=(
                    authority_wall_at if direction == "outbound" else None
                ),
            )
            session.add(authorization)
            session.add(
                OnnuriSmokeCapabilityConsumptionModel(
                    attempt_id=attempt.id,
                    kind="media",
                    domain=envelope.media_domain,
                    key_id=envelope.media_key_id,
                    algorithm_policy_id=envelope.media_algorithm_policy_id,
                    nonce_digest=built["nonce_digest"],
                    token_digest=built["token_digest"],
                    request_digest=request_digest,
                    receipt_digest=built["receipt_digest"],
                    issued_at=database_now,
                    expires_at=deadline_at,
                )
            )
            attempt.authority_kind = authority_kind
            attempt.authority_wall_at = authority_wall_at
            attempt.authority_deadline_at = deadline_at
            attempt.authority_budget_seconds = budget_seconds
            attempt.observed_carrier_answer_at = (
                authority_wall_at if direction == "outbound" else None
            )
            attempt.state = (
                "outbound_answer_recorded_media_issued"
                if direction == "outbound"
                else "inbound_answer_committed_media_issued"
            )
            await session.commit()
            await session.refresh(authorization)
            return authorization, response

    async def record_onnuri_outbound_answer_and_mint_media(self, **kwargs):
        if kwargs.pop("approved_pause_milliseconds", 0) != 0:
            raise TelephonyNumberInventoryConflictError(
                "onnuri_smoke_outbound_pause_prohibited"
            )
        return await self._mint_onnuri_smoke_media(
            direction="outbound",
            authority_kind="outbound_observed_answer",
            approved_pause_milliseconds=0,
            **kwargs,
        )

    async def commit_onnuri_inbound_answer_intent_and_mint_media(self, **kwargs):
        return await self._mint_onnuri_smoke_media(
            direction="inbound",
            authority_kind="inbound_preanswer_commit",
            **kwargs,
        )

    async def consume_onnuri_smoke_media(
        self,
        attempt_uuid: str,
        *,
        organization_id: int,
        nonce_digest: str,
        token_digest: str,
        stock_call_id_digest: str,
        request_digest: str,
        receipt_digest: str,
    ) -> OnnuriSmokeAttemptModel:
        """Atomically consume media and enter RUNNING; a second socket cannot succeed."""
        async with self.async_session() as session:
            attempt, envelope = await self._lock_onnuri_smoke_attempt_authority(
                session,
                attempt_uuid=attempt_uuid,
                organization_id=organization_id,
            )
            capability = (
                (
                    await session.execute(
                        select(OnnuriSmokeCapabilityConsumptionModel)
                        .where(
                            OnnuriSmokeCapabilityConsumptionModel.attempt_id
                            == attempt.id,
                            OnnuriSmokeCapabilityConsumptionModel.kind == "media",
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            database_now = (await session.execute(select(func.now()))).scalar_one()
            authorization = (
                (
                    await session.execute(
                        select(OnnuriSmokeAnswerAuthorizationModel)
                        .where(
                            OnnuriSmokeAnswerAuthorizationModel.attempt_id == attempt.id
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            if (
                not await self._onnuri_smoke_envelope_is_current(
                    session, envelope, database_now
                )
                or capability is None
                or capability.consumed_at is not None
                or capability.domain != envelope.media_domain
                or capability.key_id != envelope.media_key_id
                or capability.expires_at <= database_now
                or authorization is None
                or authorization.deadline_at <= database_now
                or not _digest_equal(capability.nonce_digest, nonce_digest)
                or not _digest_equal(capability.token_digest, token_digest)
                or not _digest_equal(capability.request_digest, request_digest)
                or not _digest_equal(capability.receipt_digest, receipt_digest)
                or not _digest_equal(attempt.stock_call_id_digest, stock_call_id_digest)
                or attempt.state
                not in {
                    "outbound_answer_recorded_media_issued",
                    "inbound_answer_committed_media_issued",
                }
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_media_not_authorized"
                )
            capability.consumed_at = database_now
            attempt.state = "running"
            authorization.encrypted_response_recovery = None
            authorization.recovery_erased_at = database_now
            await session.commit()
            await session.refresh(attempt)
            return attempt

    async def mark_onnuri_smoke_running(
        self, attempt_uuid: str, *, organization_id: int
    ) -> OnnuriSmokeAttemptModel:
        async with self.async_session() as session:
            attempt, envelope = await self._lock_onnuri_smoke_attempt_authority(
                session,
                attempt_uuid=attempt_uuid,
                organization_id=organization_id,
            )
            database_now = (await session.execute(select(func.now()))).scalar_one()
            if (
                attempt.state != "running"
                or attempt.authority_deadline_at is None
                or attempt.authority_deadline_at <= database_now
                or not await self._onnuri_smoke_envelope_is_current(
                    session, envelope, database_now
                )
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_smoke_running_not_authorized"
                )
            return attempt

    async def begin_onnuri_registration_operation(
        self,
        *,
        envelope_uuid: str,
        organization_id: int,
        operation_kind: str,
        request_digest: str,
        candidate_digest: str,
        gate_envelope_digest: str,
        nonce_digest: str,
        execution_seal_uuid: str,
        execution_nonce_digest: str,
        execution_stage_uuid: str,
        execution_stage: str,
        execution_stage_ordinal: int,
        prior_register_gate_id: int | None = None,
        prior_register_operation_uuid: str | None = None,
    ) -> dict[str, Any]:
        digests = (
            request_digest,
            candidate_digest,
            gate_envelope_digest,
            nonce_digest,
            execution_nonce_digest,
        )
        try:
            for value in (envelope_uuid, execution_seal_uuid, execution_stage_uuid):
                if str(UUID(value)) != value:
                    raise ValueError
            if (
                prior_register_operation_uuid is not None
                and str(UUID(prior_register_operation_uuid))
                != prior_register_operation_uuid
            ):
                raise ValueError
        except (TypeError, ValueError, AttributeError):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_registration_identity_invalid"
            ) from None
        linked = (
            prior_register_gate_id is not None
            and prior_register_operation_uuid is not None
        )
        expected_stage = {
            "register": ("register", 1),
            "unregister": ("unregister", 4),
        }.get(operation_kind)
        if (
            isinstance(organization_id, bool)
            or not isinstance(organization_id, int)
            or organization_id <= 0
            or expected_stage != (execution_stage, execution_stage_ordinal)
            or any(not _is_lowercase_sha256(value) for value in digests)
            or ((operation_kind == "unregister") != linked)
            or (
                prior_register_gate_id is not None
                and (
                    isinstance(prior_register_gate_id, bool)
                    or not isinstance(prior_register_gate_id, int)
                    or prior_register_gate_id <= 0
                )
            )
        ):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_registration_gate_invalid"
            )

        execution_payload = {
            "organization_id": organization_id,
            "execution_seal_uuid": execution_seal_uuid,
            "execution_nonce_digest": execution_nonce_digest,
            "candidate_digest": candidate_digest,
            "gate_envelope_digest": gate_envelope_digest,
        }
        async with self.async_session() as session:
            await self._g008_organization_lock(session, organization_id)
            owned_uuid = (
                await session.execute(
                    select(OnnuriSmokeEnvelopeModel.envelope_uuid).where(
                        OnnuriSmokeEnvelopeModel.envelope_uuid == envelope_uuid,
                        OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                    )
                )
            ).scalar_one_or_none()
            if owned_uuid is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_smoke_envelope_not_found"
                )
            await self._acquire_onnuri_smoke_envelope_mutex(
                session, envelope_uuid=owned_uuid
            )
            envelope = (
                (
                    await session.execute(
                        select(OnnuriSmokeEnvelopeModel)
                        .where(
                            OnnuriSmokeEnvelopeModel.envelope_uuid == envelope_uuid,
                            OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            seal, stages = await self._lock_g008_execution(session, execution_payload)
            stage = stages[execution_stage_ordinal - 1]
            expected_gate_digest = hashlib.sha256(
                envelope_uuid.encode("utf-8")
            ).hexdigest()

            if envelope is None:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_registration_gate_not_authorized"
                )
            prior = None
            if operation_kind == "unregister":
                prior = (
                    await session.execute(
                        select(OnnuriRegistrationGateModel)
                        .where(
                            OnnuriRegistrationGateModel.id
                            == prior_register_gate_id,
                            OnnuriRegistrationGateModel.envelope_id == envelope.id,
                            OnnuriRegistrationGateModel.operation_kind == "register",
                            OnnuriRegistrationGateModel.operation_uuid
                            == prior_register_operation_uuid,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()

            binding_digest = _registration_binding_digest(
                organization_id=organization_id,
                envelope_uuid=envelope_uuid,
                operation_kind=operation_kind,
                request_digest=request_digest,
                candidate_digest=candidate_digest,
                gate_envelope_digest=gate_envelope_digest,
                nonce_digest=nonce_digest,
                prior_register_gate_id=prior_register_gate_id,
                prior_register_operation_uuid=prior_register_operation_uuid,
            )
            existing = (
                await session.execute(
                    select(OnnuriRegistrationGateModel)
                    .where(
                        (
                            OnnuriRegistrationGateModel.envelope_id == envelope.id
                            if operation_kind == "register"
                            else OnnuriRegistrationGateModel.unregisters_gate_id
                            == prior_register_gate_id
                        ),
                        OnnuriRegistrationGateModel.operation_kind == operation_kind,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            database_now = (
                await session.execute(select(func.clock_timestamp()))
            ).scalar_one()
            if (
                envelope is None
                or not _onnuri_smoke_has_v3_prerequisites(envelope)
                or (
                    operation_kind != "unregister"
                    and seal.state != "running"
                )
                or (
                    not (
                        seal.live_window_starts_at
                        <= database_now
                        < seal.live_window_expires_at
                    )
                    and operation_kind != "unregister"
                )
                or stage.stage_uuid != execution_stage_uuid
                or stage.stage != execution_stage
                or stage.ordinal != execution_stage_ordinal
                or stage.state != "started"
                or stage.started_at is None
                or stage.started_at > database_now
                or (
                    operation_kind == "register"
                    and not await self._onnuri_smoke_envelope_is_current(
                        session, envelope, database_now
                    )
                )
                or not _digest_equal(envelope.candidate_digest, candidate_digest)
                or not _digest_equal(expected_gate_digest, gate_envelope_digest)
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_registration_gate_not_authorized"
                )
            if operation_kind == "unregister" and (
                prior is None
                or prior.execution_stage_id != stages[0].id
                or prior.transaction_count != 1
                or not prior.unregister_required
                or prior.unregister_satisfied_at is not None
                or prior.state
                not in {"challenged", "completed", "failed", "contained"}
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_unregister_linkage_invalid"
                )
            if existing is not None:
                if (
                    existing.state == "pending"
                    and existing.execution_stage_id == stage.id
                    and _digest_equal(existing.request_digest, binding_digest)
                ):
                    gate = existing
                else:
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_registration_replay_rejected"
                    )
            else:
                gate = OnnuriRegistrationGateModel(
                    envelope_id=envelope.id,
                    execution_stage_id=stage.id,
                    operation_kind=operation_kind,
                    unregisters_gate_id=(
                        prior_register_gate_id
                        if operation_kind == "unregister"
                        else None
                    ),
                    state="pending",
                    request_digest=binding_digest,
                    created_at=database_now,
                )
                session.add(gate)
                await session.flush()

            issued_at = gate.created_at or database_now
            expires_at = (
                issued_at + timedelta(seconds=60)
                if operation_kind == "unregister"
                else min(
                    issued_at + timedelta(seconds=60),
                    envelope.live_window_expires_at,
                    seal.live_window_expires_at,
                )
            )
            if expires_at <= database_now:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_registration_gate_not_authorized"
                )
            await session.commit()
            await session.refresh(gate)
            return {
                "gate": gate,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "candidate_digest": envelope.candidate_digest,
                "gate_envelope_digest": expected_gate_digest,
                "dispatch_domain": envelope.dispatch_domain,
                "dispatch_key_id": envelope.dispatch_key_id,
                "media_key_id": envelope.media_key_id,
                "execution_seal_uuid": seal.execution_seal_uuid,
                "execution_nonce_digest": seal.execution_nonce_digest,
                "execution_stage_uuid": stage.stage_uuid,
                "execution_stage": stage.stage,
                "execution_stage_ordinal": stage.ordinal,
                "prior_register_operation_uuid": (
                    prior.operation_uuid if prior is not None else None
                ),
            }
    async def consume_onnuri_registration_operation(
        self,
        *,
        organization_id: int,
        registration_gate_id: int,
        operation_uuid: str,
        operation_kind: str,
        request_digest: str,
        candidate_digest: str,
        gate_envelope_digest: str,
        nonce_digest: str,
        prior_register_gate_id: int | None = None,
        prior_register_operation_uuid: str | None = None,
    ) -> OnnuriRegistrationGateModel:
        digests = (
            request_digest,
            candidate_digest,
            gate_envelope_digest,
            nonce_digest,
        )
        try:
            if str(UUID(operation_uuid)) != operation_uuid:
                raise ValueError
            if (
                prior_register_operation_uuid is not None
                and str(UUID(prior_register_operation_uuid))
                != prior_register_operation_uuid
            ):
                raise ValueError
        except (TypeError, ValueError, AttributeError):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_registration_identity_invalid"
            ) from None
        linked = (
            prior_register_gate_id is not None
            and prior_register_operation_uuid is not None
        )
        if (
            isinstance(organization_id, bool)
            or not isinstance(organization_id, int)
            or organization_id <= 0
            or isinstance(registration_gate_id, bool)
            or not isinstance(registration_gate_id, int)
            or registration_gate_id <= 0
            or operation_kind not in {"register", "unregister"}
            or any(not _is_lowercase_sha256(value) for value in digests)
            or ((operation_kind == "unregister") != linked)
            or (
                prior_register_gate_id is not None
                and (
                    isinstance(prior_register_gate_id, bool)
                    or not isinstance(prior_register_gate_id, int)
                    or prior_register_gate_id <= 0
                )
            )
        ):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_registration_gate_invalid"
            )

        async with self.async_session() as session:
            await self._g008_organization_lock(session, organization_id)
            owned = (
                await session.execute(
                    select(
                        OnnuriSmokeEnvelopeModel.envelope_uuid,
                        OnnuriRegistrationGateModel.unregisters_gate_id,
                    )
                    .join(
                        OnnuriRegistrationGateModel,
                        OnnuriRegistrationGateModel.envelope_id
                        == OnnuriSmokeEnvelopeModel.id,
                    )
                    .where(
                        OnnuriRegistrationGateModel.id == registration_gate_id,
                        OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                    )
                )
            ).first()
            if owned is None:
                envelope_uuid = None
                linked_prior_id = None
            else:
                envelope_uuid, linked_prior_id = owned
            if envelope_uuid is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_registration_gate_not_found"
                )
            await self._acquire_onnuri_smoke_envelope_mutex(
                session, envelope_uuid=envelope_uuid
            )
            gate_ids = sorted(
                gate_id
                for gate_id in (registration_gate_id, linked_prior_id)
                if gate_id is not None
            )
            locked_gates = (
                (
                    await session.execute(
                        select(OnnuriRegistrationGateModel)
                        .where(OnnuriRegistrationGateModel.id.in_(gate_ids))
                        .order_by(OnnuriRegistrationGateModel.id)
                        .with_for_update()
                    )
                )
                .scalars()
                .all()
            )
            gates_by_id = {locked.id: locked for locked in locked_gates}
            gate = gates_by_id.get(registration_gate_id)
            if gate is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_registration_gate_not_found"
                )
            envelope = (
                (
                    await session.execute(
                        select(OnnuriSmokeEnvelopeModel)
                        .where(
                            OnnuriSmokeEnvelopeModel.id == gate.envelope_id,
                            OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            prior = (
                gates_by_id.get(gate.unregisters_gate_id)
                if gate.unregisters_gate_id is not None
                else None
            )
            database_now = (
                await session.execute(select(func.clock_timestamp()))
            ).scalar_one()
            expected_binding = _registration_binding_digest(
                organization_id=organization_id,
                envelope_uuid=envelope_uuid,
                operation_kind=operation_kind,
                request_digest=request_digest,
                candidate_digest=candidate_digest,
                gate_envelope_digest=gate_envelope_digest,
                nonce_digest=nonce_digest,
                prior_register_gate_id=prior_register_gate_id,
                prior_register_operation_uuid=prior_register_operation_uuid,
            )
            operation_expires_at = (
                (
                    gate.created_at + timedelta(seconds=60)
                    if operation_kind == "unregister"
                    else min(
                        gate.created_at + timedelta(seconds=60),
                        envelope.live_window_expires_at,
                    )
                )
                if gate.created_at is not None and envelope is not None
                else None
            )
            if (
                envelope is None
                or gate.operation_uuid != operation_uuid
                or gate.operation_kind != operation_kind
                or gate.state != "pending"
                or gate.transaction_count != 0
                or gate.retransmission_count != 0
                or operation_expires_at is None
                or operation_expires_at <= database_now
                or not _onnuri_smoke_has_v3_prerequisites(envelope)
                or (
                    operation_kind == "register"
                    and not await self._onnuri_smoke_envelope_is_current(
                        session, envelope, database_now
                    )
                )
                or not _digest_equal(gate.request_digest, expected_binding)
                or not _digest_equal(envelope.candidate_digest, candidate_digest)
                or not _digest_equal(
                    hashlib.sha256(envelope_uuid.encode("utf-8")).hexdigest(),
                    gate_envelope_digest,
                )
                or (
                    operation_kind == "register"
                    and (
                        gate.unregisters_gate_id is not None
                        or prior_register_gate_id is not None
                        or prior_register_operation_uuid is not None
                    )
                )
                or (
                    operation_kind == "unregister"
                    and (
                        gate.unregisters_gate_id != prior_register_gate_id
                        or prior is None
                        or prior.operation_kind != "register"
                        or prior.operation_uuid != prior_register_operation_uuid
                        or prior.transaction_count != 1
                        or not prior.unregister_required
                        or prior.unregister_satisfied_at is not None
                        or prior.state
                        not in {"challenged", "completed", "failed", "contained"}
                    )
                )
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_registration_gate_not_authorized"
                )
            gate.state = "challenged"
            gate.transaction_count = 1
            gate.retransmission_count = 0
            if operation_kind == "register":
                gate.unregister_required = True
            await session.commit()
            await session.refresh(gate)
            return gate

    async def finalize_onnuri_registration_operation(
        self,
        *,
        organization_id: int,
        operation_uuid: str,
        registration_gate_id: int,
        operation_kind: str,
        nonce_digest: str,
        candidate_digest: str,
        gate_envelope_digest: str,
        request_digest: str,
        prior_register_gate_id: int | None,
        prior_register_operation_uuid: str | None,
        outcome: str,
        transaction_count: int,
        retry_count: int,
        response_count: int,
        wire_request_count: int,
        deregistered: bool,
        accepted_expires_seconds: int | None,
        execution_attestation_canonical: bytes,
        execution_attestation_signature: bytes,
        execution_attestation_digest: str,
        execution_attestation_signature_digest: str,
        execution_attestation_key_digest: str,
        execution_attestation_key_id: str,
        execution_attested_at: datetime,
    ) -> tuple[OnnuriRegistrationGateModel, bool]:
        digests = (
            nonce_digest,
            candidate_digest,
            gate_envelope_digest,
            request_digest,
            execution_attestation_digest,
            execution_attestation_signature_digest,
            execution_attestation_key_digest,
        )
        if (
            not isinstance(execution_attestation_canonical, bytes)
            or not execution_attestation_canonical
            or not isinstance(execution_attestation_signature, bytes)
            or len(execution_attestation_signature) != 64
            or not _digest_equal(
                hashlib.sha256(execution_attestation_canonical).hexdigest(),
                execution_attestation_digest,
            )
            or not _digest_equal(
                hashlib.sha256(execution_attestation_signature).hexdigest(),
                execution_attestation_signature_digest,
            )
        ):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_registration_receipt_invalid"
            )
        try:
            if (
                isinstance(registration_gate_id, bool)
                or not isinstance(registration_gate_id, int)
                or registration_gate_id <= 0
                or (
                    prior_register_operation_uuid is not None
                    and str(UUID(prior_register_operation_uuid))
                    != prior_register_operation_uuid
                )
            ):
                raise ValueError
        except (TypeError, ValueError, AttributeError):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_registration_identity_invalid"
            ) from None
        linked = (
            prior_register_gate_id is not None
            and prior_register_operation_uuid is not None
        )
        try:
            if str(UUID(operation_uuid)) != operation_uuid:
                raise ValueError
        except (TypeError, ValueError, AttributeError):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_registration_identity_invalid"
            ) from None
        attested_at_valid = (
            isinstance(execution_attested_at, datetime)
            and execution_attested_at.tzinfo is not None
            and execution_attested_at.utcoffset() is not None
        )
        success_shape_valid = (
            (
                operation_kind == "register"
                and deregistered is False
                and isinstance(accepted_expires_seconds, int)
                and not isinstance(accepted_expires_seconds, bool)
                and accepted_expires_seconds > 0
            )
            or (
                operation_kind == "unregister"
                and deregistered is True
                and accepted_expires_seconds == 0
            )
        )
        nonsuccess_shape_valid = (
            deregistered is False and accepted_expires_seconds is None
        )
        if (
            isinstance(organization_id, bool)
            or not isinstance(organization_id, int)
            or organization_id <= 0
            or operation_kind not in {"register", "unregister"}
            or outcome not in {"succeeded", "failed", "contained"}
            or any(not _is_lowercase_sha256(value) for value in digests)
            or not _is_lowercase_attestation_key_id(
                execution_attestation_key_id
            )
            or not attested_at_valid
            or isinstance(transaction_count, bool)
            or transaction_count != 1
            or isinstance(retry_count, bool)
            or retry_count != 0
            or isinstance(response_count, bool)
            or not 0 <= response_count <= 2
            or isinstance(wire_request_count, bool)
            or not 0 <= wire_request_count <= 2
            or ((operation_kind == "unregister") != linked)
            or (
                prior_register_gate_id is not None
                and (
                    isinstance(prior_register_gate_id, bool)
                    or not isinstance(prior_register_gate_id, int)
                    or prior_register_gate_id <= 0
                )
            )
            or (outcome == "succeeded" and response_count == 0)
            or (outcome == "succeeded" and wire_request_count == 0)
            or (
                outcome == "succeeded"
                and wire_request_count != response_count
            )
            or (outcome == "succeeded" and not success_shape_valid)
            or (outcome != "succeeded" and not nonsuccess_shape_valid)
        ):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_registration_receipt_invalid"
            )
        canonical_attested_at = (
            execution_attested_at.astimezone(UTC)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
        receipt_values = {
            "accepted_expires_seconds": accepted_expires_seconds,
            "candidate_digest": candidate_digest,
            "deregistered": deregistered,
            "execution_attestation_digest": execution_attestation_digest,
            "execution_attestation_signature_digest": (
                execution_attestation_signature_digest
            ),
            "execution_attestation_key_digest": execution_attestation_key_digest,
            "execution_attestation_key_id": execution_attestation_key_id,
            "execution_attested_at": canonical_attested_at,
            "gate_envelope_digest": gate_envelope_digest,
            "nonce_digest": nonce_digest,
            "registration_gate_id": registration_gate_id,
            "operation_kind": operation_kind,
            "operation_uuid": operation_uuid,
            "prior_register_gate_id": prior_register_gate_id,
            "prior_register_operation_uuid": prior_register_operation_uuid,
            "organization_id": organization_id,
            "outcome": outcome,
            "request_digest": request_digest,
            "response_count": response_count,
            "retry_count": retry_count,
            "transaction_count": transaction_count,
            "wire_request_count": wire_request_count,
        }
        receipt_digest = _registration_receipt_digest(receipt_values)
        async with self.async_session() as session:
            await self._g008_organization_lock(session, organization_id)
            owned = (
                await session.execute(
                    select(
                        OnnuriRegistrationGateModel,
                        OnnuriSmokeEnvelopeModel.envelope_uuid,
                    )
                    .join(
                        OnnuriSmokeEnvelopeModel,
                        OnnuriSmokeEnvelopeModel.id
                        == OnnuriRegistrationGateModel.envelope_id,
                    )
                    .where(
                        OnnuriRegistrationGateModel.operation_uuid == operation_uuid,
                        OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                    )
                )
            ).first()
            if owned is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_registration_gate_not_found"
                )
            owned_gate, envelope_uuid = owned
            await self._acquire_onnuri_smoke_envelope_mutex(
                session, envelope_uuid=envelope_uuid
            )
            gate_ids = sorted(
                gate_id
                for gate_id in (owned_gate.id, owned_gate.unregisters_gate_id)
                if gate_id is not None
            )
            locked_gates = (
                (
                    await session.execute(
                        select(OnnuriRegistrationGateModel)
                        .where(OnnuriRegistrationGateModel.id.in_(gate_ids))
                        .order_by(OnnuriRegistrationGateModel.id)
                        .with_for_update()
                    )
                )
                .scalars()
                .all()
            )
            gates_by_id = {locked.id: locked for locked in locked_gates}
            gate = gates_by_id.get(owned_gate.id)
            if gate is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_registration_gate_not_found"
                )
            envelope = (
                (
                    await session.execute(
                        select(OnnuriSmokeEnvelopeModel)
                        .where(
                            OnnuriSmokeEnvelopeModel.id == gate.envelope_id,
                            OnnuriSmokeEnvelopeModel.organization_id
                            == organization_id,
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            if envelope is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_registration_gate_not_found"
                )
            execution = (
                await session.execute(
                    select(G008ExecutionSealModel, G008ExecutionStageModel)
                    .join(
                        G008ExecutionStageModel,
                        G008ExecutionStageModel.execution_seal_id
                        == G008ExecutionSealModel.id,
                    )
                    .where(
                        G008ExecutionStageModel.id == gate.execution_stage_id,
                        G008ExecutionStageModel.organization_id == organization_id,
                        G008ExecutionSealModel.organization_id == organization_id,
                    )
                    .with_for_update()
                )
            ).first()
            if execution is None:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_registration_execution_linkage_invalid"
                )
            seal, stage = execution
            stages = list(
                (
                    await session.execute(
                        select(G008ExecutionStageModel)
                        .where(
                            G008ExecutionStageModel.execution_seal_id == seal.id,
                            G008ExecutionStageModel.organization_id
                            == organization_id,
                        )
                        .order_by(G008ExecutionStageModel.ordinal)
                        .with_for_update()
                    )
                ).scalars()
            )
            if len(stages) != 4:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_registration_execution_linkage_invalid"
                )
            prior = (
                gates_by_id.get(gate.unregisters_gate_id)
                if gate.unregisters_gate_id is not None
                else None
            )
            database_now = (
                await session.execute(select(func.clock_timestamp()))
            ).scalar_one()
            expected_stage = {
                "register": ("register", 1),
                "unregister": ("unregister", 4),
            }.get(operation_kind)
            if (
                gate.id != registration_gate_id
                or gate.operation_kind != operation_kind
                or gate.unregisters_gate_id != prior_register_gate_id
                or expected_stage != (stage.stage, stage.ordinal)
                or stage.execution_seal_id != seal.id
                or not _digest_equal(
                    stage.execution_nonce_digest, seal.execution_nonce_digest
                )
                or not _digest_equal(stage.candidate_digest, candidate_digest)
                or not _digest_equal(stage.candidate_digest, seal.candidate_digest)
                or not _digest_equal(
                    stage.gate_envelope_digest, gate_envelope_digest
                )
                or not _digest_equal(
                    stage.gate_envelope_digest, seal.gate_envelope_digest
                )
                or (
                    operation_kind == "register"
                    and (
                        prior_register_gate_id is not None
                        or prior_register_operation_uuid is not None
                    )
                )
                or (
                    operation_kind == "unregister"
                    and (
                        prior is None
                        or prior.operation_uuid != prior_register_operation_uuid
                        or prior.execution_stage_id is None
                    )
                )
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_registration_receipt_mismatch"
                )

            terminal_state = {
                "succeeded": "completed",
                "failed": "failed",
                "contained": "contained",
            }[outcome]
            stage_terminal_class = (
                "registered"
                if outcome == "succeeded" and operation_kind == "register"
                else "unregistered"
                if outcome == "succeeded"
                else outcome
            )

            def exact_terminal_replay() -> bool:
                seal_effect_matches = (
                    (
                        outcome == "failed"
                        and (
                            (
                                seal.state == "failed"
                                and seal.failed_at == stage.finalized_at
                            )
                            or (
                                operation_kind == "register"
                                and seal.state == "cleanup_required"
                            )
                            or (
                                operation_kind == "unregister"
                                and seal.state == "residue_blocked"
                            )
                        )
                    )
                    or (
                        outcome == "contained"
                        and (
                            (
                                seal.state == "contained"
                                and seal.contained_at == stage.finalized_at
                                and seal.containment_class == stage_terminal_class
                                and _digest_equal(
                                    seal.containment_evidence_digest,
                                    execution_attestation_digest,
                                )
                                and _digest_equal(
                                    seal.containment_evidence_signature_digest,
                                    execution_attestation_signature_digest,
                                )
                                and _digest_equal(
                                    seal.containment_evidence_key_digest,
                                    execution_attestation_key_digest,
                                )
                                and seal.containment_evidence_key_id
                                == execution_attestation_key_id
                            )
                            or (
                                operation_kind == "register"
                                and seal.state == "cleanup_required"
                            )
                            or (
                                operation_kind == "unregister"
                                and seal.state == "residue_blocked"
                            )
                        )
                    )
                    or (
                        outcome == "succeeded"
                        and seal.state
                        in {"running", "completed", "failed", "cleanup_required"}
                    )
                )
                expected_accepted_expires_at = (
                    stage.finalized_at + timedelta(seconds=accepted_expires_seconds)
                    if outcome == "succeeded"
                    and operation_kind == "register"
                    and stage.finalized_at is not None
                    and accepted_expires_seconds is not None
                    else stage.finalized_at
                    if outcome == "succeeded" and operation_kind == "unregister"
                    else None
                )
                prior_effect_matches = (
                    operation_kind != "unregister"
                    or outcome != "succeeded"
                    or (
                        prior is not None
                        and prior.execution_stage_id is not None
                        and prior.unregister_satisfied_at == stage.finalized_at
                    )
                )
                return (
                    gate.state == terminal_state
                    and gate.terminal_at == stage.finalized_at
                    and gate.wire_request_count == wire_request_count
                    and _digest_equal(gate.challenge_digest, receipt_digest)
                    and _digest_equal(
                        gate.execution_attestation_digest,
                        execution_attestation_digest,
                    )
                    and _digest_equal(
                        gate.execution_attestation_signature_digest,
                        execution_attestation_signature_digest,
                    )
                    and _digest_equal(
                        gate.execution_attestation_key_digest,
                        execution_attestation_key_digest,
                    )
                    and _digest_equal(
                        gate.execution_attestation_key_id,
                        execution_attestation_key_id,
                    )
                    and gate.execution_attested_at == execution_attested_at
                    and gate.failure_class == outcome
                    and gate.transaction_count == 1
                    and gate.retransmission_count == 0
                    and gate.accepted_expires_at == expected_accepted_expires_at
                    and stage.state == outcome
                    and stage.terminal_class == stage_terminal_class
                    and _digest_equal(
                        stage.evidence_digest, execution_attestation_digest
                    )
                    and _digest_equal(
                        stage.evidence_signature_digest,
                        execution_attestation_signature_digest,
                    )
                    and _digest_equal(
                        stage.evidence_key_digest,
                        execution_attestation_key_digest,
                    )
                    and stage.evidence_key_id == execution_attestation_key_id
                    and stage.evidence_canonical == execution_attestation_canonical
                    and stage.evidence_signature == execution_attestation_signature
                    and seal_effect_matches
                    and prior_effect_matches
                )

            if gate.state in {"completed", "failed", "contained"}:
                if exact_terminal_replay():
                    return gate, True
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_registration_terminal_replay_rejected"
                )

            prior_operation_uuid = None
            if gate.unregisters_gate_id is not None:
                prior_deadline = (
                    min(
                        prior.created_at + timedelta(seconds=60),
                        envelope.live_window_expires_at,
                    )
                    if prior is not None and prior.created_at is not None
                    else None
                )
                prior_expired_challenge = (
                    prior is not None
                    and prior.state == "challenged"
                    and prior_deadline is not None
                    and prior_deadline <= database_now
                )
                prior_stage = (
                    (
                        await session.execute(
                            select(G008ExecutionStageModel)
                            .where(
                                G008ExecutionStageModel.id
                                == prior.execution_stage_id,
                                G008ExecutionStageModel.organization_id
                                == organization_id,
                                G008ExecutionStageModel.execution_seal_id
                                == seal.id,
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    if prior is not None and prior.execution_stage_id is not None
                    else None
                )
                if (
                    prior is None
                    or prior_stage is None
                    or prior_stage.execution_seal_id != seal.id
                    or prior_stage.organization_id != organization_id
                    or prior_stage.stage != "register"
                    or prior_stage.ordinal != 1
                    or prior.operation_kind != "register"
                    or prior.transaction_count != 1
                    or not prior.unregister_required
                    or prior.unregister_satisfied_at is not None
                    or (
                        prior.state not in {"completed", "failed", "contained"}
                        and not prior_expired_challenge
                    )
                ):
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_unregister_linkage_invalid"
                    )
                prior_operation_uuid = prior.operation_uuid
            expected_binding = _registration_binding_digest(
                organization_id=organization_id,
                envelope_uuid=envelope_uuid,
                operation_kind=operation_kind,
                request_digest=request_digest,
                candidate_digest=candidate_digest,
                gate_envelope_digest=gate_envelope_digest,
                nonce_digest=nonce_digest,
                prior_register_gate_id=gate.unregisters_gate_id,
                prior_register_operation_uuid=prior_operation_uuid,
            )
            operation_deadline = (
                min(
                    stage.stage_deadline_at,
                    seal.live_window_expires_at,
                    envelope.live_window_expires_at,
                )
                if stage.stage_deadline_at is not None
                and operation_kind == "register"
                else stage.stage_deadline_at
            )
            if (
                gate.state != "challenged"
                or gate.transaction_count != 1
                or gate.retransmission_count != 0
                or operation_deadline is None
                or operation_deadline <= database_now
                or (
                    operation_kind != "unregister"
                    and seal.state != "running"
                )
                or not (
                    seal.live_window_starts_at
                    <= database_now
                    < seal.live_window_expires_at
                )
                and operation_kind != "unregister"
                or stage.state != "started"
                or stage.started_at is None
                or stage.started_at > database_now
                or not _onnuri_smoke_has_v3_prerequisites(envelope)
                or (
                    operation_kind == "register"
                    and not await self._onnuri_smoke_envelope_is_current(
                        session, envelope, database_now
                    )
                )
                or not _digest_equal(gate.request_digest, expected_binding)
                or not _digest_equal(envelope.candidate_digest, candidate_digest)
                or not _digest_equal(
                    hashlib.sha256(envelope_uuid.encode("utf-8")).hexdigest(),
                    gate_envelope_digest,
                )
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_registration_gate_not_authorized"
                )
            duplicate_attestation_gate_id = (
                await session.execute(
                    select(OnnuriRegistrationGateModel.id).where(
                        OnnuriRegistrationGateModel.execution_attestation_digest
                        == execution_attestation_digest,
                        OnnuriRegistrationGateModel.id != gate.id,
                    )
                )
            ).scalar_one_or_none()
            if duplicate_attestation_gate_id is not None:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_registration_attestation_replay_rejected"
                )

            gate.state = terminal_state
            gate.transaction_count = 1
            gate.retransmission_count = 0
            gate.wire_request_count = wire_request_count
            gate.challenge_digest = receipt_digest
            gate.failure_class = outcome
            gate.accepted_expires_at = (
                database_now + timedelta(seconds=accepted_expires_seconds)
                if outcome == "succeeded"
                and operation_kind == "register"
                and accepted_expires_seconds is not None
                else database_now
                if outcome == "succeeded" and operation_kind == "unregister"
                else None
            )
            gate.execution_attestation_digest = execution_attestation_digest
            gate.execution_attestation_signature_digest = (
                execution_attestation_signature_digest
            )
            gate.execution_attestation_key_digest = (
                execution_attestation_key_digest
            )
            gate.execution_attestation_key_id = execution_attestation_key_id
            gate.execution_attested_at = execution_attested_at
            gate.terminal_at = database_now

            stage.state = outcome
            stage.terminal_class = stage_terminal_class
            stage.evidence_digest = execution_attestation_digest
            stage.evidence_signature_digest = (
                execution_attestation_signature_digest
            )
            stage.evidence_key_digest = execution_attestation_key_digest
            stage.evidence_key_id = execution_attestation_key_id
            stage.evidence_canonical = execution_attestation_canonical
            stage.evidence_signature = execution_attestation_signature
            stage.finalized_at = database_now
            if outcome == "failed":
                if operation_kind == "register" and gate.unregister_required:
                    seal.state = "cleanup_required"
                elif operation_kind == "unregister":
                    seal.state = "residue_blocked"
                else:
                    seal.state = "failed"
                    seal.failed_at = database_now
            elif outcome == "contained":
                if operation_kind == "register" and gate.unregister_required:
                    seal.state = "cleanup_required"
                elif operation_kind == "unregister":
                    seal.state = "residue_blocked"
                else:
                    seal.state = "contained"
                    seal.containment_class = stage_terminal_class
                    seal.containment_evidence_digest = execution_attestation_digest
                    seal.containment_evidence_signature_digest = (
                        execution_attestation_signature_digest
                    )
                    seal.containment_evidence_key_digest = (
                        execution_attestation_key_digest
                    )
                    seal.containment_evidence_key_id = execution_attestation_key_id
                    seal.contained_at = database_now
            try:
                if operation_kind == "unregister" and outcome == "succeeded":
                    # The prior-register guard verifies the linked unregister row
                    # through a SQL query, so make its exact terminal state visible
                    # inside this transaction before satisfying the obligation.
                    await session.flush([gate, stage, seal])
                    if prior is None:
                        raise TelephonyNumberInventoryConflictError(
                            "onnuri_registration_prior_gate_not_authorized"
                        )
                    await session.refresh(prior)
                    if prior.unregister_satisfied_at != database_now:
                        raise TelephonyNumberInventoryConflictError(
                            "onnuri_registration_prior_gate_not_authorized"
                        )
                    if seal.state == "contained":
                        # Containment is terminal. The completed ordinal-four stage
                        # and satisfied linked register gate are the append-only
                        # cleanup receipt; the seal itself remains contained.
                        pass
                    elif any(row.state in {"failed", "contained"} for row in stages[:3]):
                        seal.state = "failed"
                        seal.failed_at = database_now
                    else:
                        seal.state = "running"
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_registration_attestation_replay_rejected"
                ) from exc
            await session.refresh(gate)
            return gate, False
    async def create_onnuri_registration_gate(
        self,
        *,
        envelope_uuid: str,
        organization_id: int,
        operation_kind: str,
        request_digest: str,
        unregisters_gate_id: int | None = None,
    ) -> OnnuriRegistrationGateModel:
        if (
            operation_kind not in {"register", "unregister"}
            or not isinstance(request_digest, str)
            or len(request_digest) != 64
            or request_digest != request_digest.lower()
            or any(character not in "0123456789abcdef" for character in request_digest)
        ):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_registration_gate_invalid"
            )
        async with self.async_session() as session:
            envelope_uuid_row = (
                await session.execute(
                    select(OnnuriSmokeEnvelopeModel.envelope_uuid).where(
                        OnnuriSmokeEnvelopeModel.envelope_uuid == envelope_uuid,
                        OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                    )
                )
            ).scalar_one_or_none()
            if envelope_uuid_row is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_smoke_envelope_not_found"
                )
            await self._acquire_onnuri_smoke_envelope_mutex(
                session, envelope_uuid=envelope_uuid_row
            )
            envelope = (
                (
                    await session.execute(
                        select(OnnuriSmokeEnvelopeModel)
                        .where(
                            OnnuriSmokeEnvelopeModel.envelope_uuid == envelope_uuid,
                            OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            database_now = (await session.execute(select(func.now()))).scalar_one()
            if envelope.evaluator_version == ONNURI_SMOKE_AUTHORITY_V3:
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_registration_legacy_path_disabled"
                )
            if not await self._onnuri_smoke_envelope_is_current(
                session, envelope, database_now
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_registration_gate_not_authorized"
                )
            if operation_kind == "register":
                existing_register = (
                    await session.execute(
                        select(OnnuriRegistrationGateModel)
                        .where(
                            OnnuriRegistrationGateModel.envelope_id == envelope.id,
                            OnnuriRegistrationGateModel.operation_kind == "register",
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if existing_register is not None:
                    if (
                        existing_register.state not in {"completed", "failed", "contained"}
                        and hmac.compare_digest(
                            existing_register.request_digest, request_digest
                        )
                    ):
                        return existing_register
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_registration_register_replay_rejected"
                    )
            else:
                prior = (
                    await session.execute(
                        select(OnnuriRegistrationGateModel)
                        .join(
                            OnnuriSmokeEnvelopeModel,
                            OnnuriRegistrationGateModel.envelope_id
                            == OnnuriSmokeEnvelopeModel.id,
                        )
                        .where(
                            OnnuriRegistrationGateModel.id == unregisters_gate_id,
                            OnnuriRegistrationGateModel.envelope_id == envelope.id,
                            OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    prior is None
                    or prior.envelope_id != envelope.id
                    or prior.operation_kind != "register"
                ):
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_unregister_linkage_invalid"
                    )
                existing_unregister = (
                    await session.execute(
                        select(OnnuriRegistrationGateModel.id)
                        .where(
                            OnnuriRegistrationGateModel.unregisters_gate_id == prior.id,
                            OnnuriRegistrationGateModel.operation_kind == "unregister",
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if existing_unregister is not None:
                    raise TelephonyNumberInventoryConflictError(
                        "onnuri_unregister_replay_rejected"
                    )
            gate = OnnuriRegistrationGateModel(
                envelope_id=envelope.id,
                operation_kind=operation_kind,
                unregisters_gate_id=unregisters_gate_id,
                state="pending",
                request_digest=request_digest,
            )
            session.add(gate)
            await session.commit()
            await session.refresh(gate)
            return gate

    async def update_onnuri_registration_gate(
        self,
        gate_id: int,
        *,
        organization_id: int,
        state: str,
        transaction_count: int,
        retransmission_count: int,
        challenge_digest: str | None = None,
        requested_expires_seconds: int | None = None,
        accepted_expires_at: datetime | None = None,
        failure_class: str | None = None,
    ) -> OnnuriRegistrationGateModel:
        if (
            state not in {"pending", "challenged"}
            or not 0 <= transaction_count <= MAX_ONNURI_REGISTRATION_APPLICATION_RETRIES
            or not 0
            <= retransmission_count
            <= MAX_ONNURI_REGISTRATION_PROTOCOL_RETRANSMISSIONS
        ):
            raise TelephonyNumberInventoryConflictError(
                "onnuri_registration_transaction_invalid"
            )
        async with self.async_session() as session:
            envelope_uuid = (
                await session.execute(
                    select(OnnuriSmokeEnvelopeModel.envelope_uuid)
                    .join(
                        OnnuriRegistrationGateModel,
                        OnnuriRegistrationGateModel.envelope_id
                        == OnnuriSmokeEnvelopeModel.id,
                    )
                    .where(
                        OnnuriRegistrationGateModel.id == gate_id,
                        OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                    )
                )
            ).scalar_one_or_none()
            if envelope_uuid is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_registration_gate_not_found"
                )
            await self._acquire_onnuri_smoke_envelope_mutex(
                session, envelope_uuid=envelope_uuid
            )
            gate = await session.get(
                OnnuriRegistrationGateModel, gate_id, with_for_update=True
            )
            if gate is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "onnuri_registration_gate_not_found"
                )
            envelope = (
                (
                    await session.execute(
                        select(OnnuriSmokeEnvelopeModel)
                        .where(
                            OnnuriSmokeEnvelopeModel.id == gate.envelope_id,
                            OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .first()
            )
            database_now = (await session.execute(select(func.now()))).scalar_one()
            if (
                envelope is not None
                and envelope.evaluator_version == ONNURI_SMOKE_AUTHORITY_V3
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_registration_legacy_path_disabled"
                )
            if (
                envelope is None
                or envelope.organization_id != organization_id
                or not await self._onnuri_smoke_envelope_is_current(
                    session, envelope, database_now
                )
                or gate.state in {"completed", "failed", "contained"}
            ):
                raise TelephonyNumberInventoryConflictError(
                    "onnuri_registration_gate_not_authorized"
                )
            gate.state = state
            gate.transaction_count = transaction_count
            gate.retransmission_count = retransmission_count
            gate.challenge_digest = challenge_digest
            gate.requested_expires_seconds = requested_expires_seconds
            gate.accepted_expires_at = accepted_expires_at
            gate.failure_class = failure_class
            if state in {"completed", "failed", "contained"}:
                gate.terminal_at = database_now
            await session.commit()
            await session.refresh(gate)
            return gate

    async def set_onnuri_smoke_terminal(
        self,
        attempt_uuid: str,
        *,
        organization_id: int,
        terminal_class: str,
        terminal_reason: str,
        contain: bool = False,
    ) -> OnnuriSmokeAttemptModel:
        async with self.async_session() as session:
            attempt, envelope = await self._lock_onnuri_smoke_attempt_authority(
                session,
                attempt_uuid=attempt_uuid,
                organization_id=organization_id,
            )
            if attempt.state in {"terminal", "contained"}:
                return attempt
            database_now = (await session.execute(select(func.now()))).scalar_one()
            attempt.state = "contained" if contain else "terminal"
            attempt.terminal_class = terminal_class
            attempt.terminal_reason = terminal_reason
            attempt.terminal_at = database_now
            attempt.contained_at = database_now if contain else None
            if contain:
                if envelope is None:
                    raise TelephonyNumberInventoryNotFoundError(
                        "onnuri_smoke_envelope_not_found"
                    )
                envelope.state = "contained"
                envelope.contained_at = database_now
                envelope.containment_reason = terminal_reason
            await session.commit()
            await session.refresh(attempt)
            return attempt

    async def get_onnuri_smoke_redacted_status(
        self, envelope_uuid: str, *, organization_id: int
    ) -> dict[str, Any] | None:
        async with self.async_session() as session:
            envelope = (
                (
                    await session.execute(
                        select(OnnuriSmokeEnvelopeModel).where(
                            OnnuriSmokeEnvelopeModel.envelope_uuid == envelope_uuid,
                            OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                        )
                    )
                )
                .scalars()
                .first()
            )
            if envelope is None:
                return None
            database_now = (await session.execute(select(func.now()))).scalar_one()
            attempts = (
                (
                    await session.execute(
                        select(OnnuriSmokeAttemptModel)
                        .where(OnnuriSmokeAttemptModel.envelope_id == envelope.id)
                        .order_by(OnnuriSmokeAttemptModel.ordinal)
                    )
                )
                .scalars()
                .all()
            )
            return {
                "envelope_uuid": envelope.envelope_uuid,
                "state": envelope.state,
                "current": (
                    envelope.state == "armed"
                    and envelope.revoked_at is None
                    and envelope.contained_at is None
                    and envelope.live_window_starts_at
                    <= database_now
                    < envelope.live_window_expires_at
                ),
                "remaining_attempts": max(0, 3 - len(attempts)),
                "max_duration_seconds": 60,
                "attempts": [
                    {
                        "attempt_uuid": row.attempt_uuid,
                        "ordinal": row.ordinal,
                        "direction": row.direction,
                        "state": row.state,
                        "terminal_class": row.terminal_class,
                    }
                    for row in attempts
                ],
            }

    @staticmethod
    def _validate_g008_payload(
        payload: dict[str, Any],
        *,
        required: set[str],
        allowed: set[str],
    ) -> None:
        if not isinstance(payload, dict) or set(payload) - allowed:
            raise TelephonyNumberInventoryConflictError("g008_payload_invalid")
        if required - set(payload):
            raise TelephonyNumberInventoryConflictError("g008_payload_incomplete")

    @staticmethod
    def _validate_g008_digest(value: Any) -> str:
        if not _is_lowercase_sha256(value):
            raise TelephonyNumberInventoryConflictError("g008_digest_invalid")
        return value

    @staticmethod
    def _validate_g008_uuid(value: Any) -> str:
        try:
            parsed = UUID(str(value))
        except (TypeError, ValueError, AttributeError) as exc:
            raise TelephonyNumberInventoryConflictError("g008_uuid_invalid") from exc
        canonical = str(parsed)
        if value != canonical:
            raise TelephonyNumberInventoryConflictError("g008_uuid_invalid")
        return canonical

    @staticmethod
    def _validate_g008_time(value: Any) -> datetime:
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise TelephonyNumberInventoryConflictError("g008_timestamp_invalid")
        return value

    @staticmethod
    def _g008_common_keys() -> set[str]:
        return {
            "organization_id",
            "execution_seal_uuid",
            "execution_nonce_digest",
            "candidate_digest",
            "gate_envelope_digest",
        }

    @staticmethod
    def _g008_expected_stages(execution_mode: str) -> list[tuple[int, str]]:
        if execution_mode == "legacy_registration":
            return [
                (1, "register"),
                (2, "outbound_call"),
                (3, "inbound_call"),
                (4, "unregister"),
            ]
        if execution_mode == "ip_to_ip_no_register":
            return [
                (1, "peer_attach"),
                (2, "outbound_call"),
                (3, "inbound_call"),
                (4, "peer_detach"),
            ]
        raise TelephonyNumberInventoryConflictError("g008_execution_mode_invalid")

    @classmethod
    def _validate_g008_common(cls, payload: dict[str, Any]) -> None:
        if not isinstance(payload.get("organization_id"), int) or isinstance(
            payload.get("organization_id"), bool
        ):
            raise TelephonyNumberInventoryConflictError("g008_organization_invalid")
        cls._validate_g008_uuid(payload.get("execution_seal_uuid"))
        for key in (
            "execution_nonce_digest",
            "candidate_digest",
            "gate_envelope_digest",
        ):
            cls._validate_g008_digest(payload.get(key))

    @staticmethod
    async def _g008_organization_lock(session, organization_id: int) -> None:
        await session.execute(
            select(
                func.pg_advisory_xact_lock(
                    func.hashtext("g008-execution-organization"), organization_id
                )
            )
        )

    async def _lock_g008_execution(
        self, session, payload: dict[str, Any]
    ) -> tuple[G008ExecutionSealModel, list[G008ExecutionStageModel]]:
        self._validate_g008_common(payload)
        organization_id = payload["organization_id"]
        await self._g008_organization_lock(session, organization_id)
        seal = (
            (
                await session.execute(
                    select(G008ExecutionSealModel)
                    .where(
                        G008ExecutionSealModel.execution_seal_uuid
                        == payload["execution_seal_uuid"],
                        G008ExecutionSealModel.organization_id == organization_id,
                        G008ExecutionSealModel.execution_nonce_digest
                        == payload["execution_nonce_digest"],
                        G008ExecutionSealModel.candidate_digest
                        == payload["candidate_digest"],
                        G008ExecutionSealModel.gate_envelope_digest
                        == payload["gate_envelope_digest"],
                    )
                    .with_for_update()
                )
            )
            .scalars()
            .one_or_none()
        )
        if seal is None:
            raise TelephonyNumberInventoryConflictError("g008_execution_binding_mismatch")
        stages = (
            (
                await session.execute(
                    select(G008ExecutionStageModel)
                    .where(G008ExecutionStageModel.execution_seal_id == seal.id)
                    .order_by(G008ExecutionStageModel.ordinal)
                    .with_for_update()
                )
            )
            .scalars()
            .all()
        )
        expected_stages = self._g008_expected_stages(seal.execution_mode)
        if [(row.ordinal, row.stage) for row in stages] != expected_stages:
            raise TelephonyNumberInventoryConflictError("g008_execution_stage_set_invalid")
        return seal, stages

    @staticmethod
    def _g008_seal_data(
        seal: G008ExecutionSealModel,
        stages: list[G008ExecutionStageModel],
    ) -> dict[str, Any]:
        return {
            "organization_id": seal.organization_id,
            "execution_seal_uuid": seal.execution_seal_uuid,
            "schema_version": seal.schema_version,
            "execution_nonce_digest": seal.execution_nonce_digest,
            "candidate_digest": seal.candidate_digest,
            "gate_envelope_digest": seal.gate_envelope_digest,
            "execution_mode": seal.execution_mode,
            "owned_target_digest": seal.owned_target_digest,
            "source_external_ipv4": seal.source_external_ipv4,
            "peer_signaling_ipv4_cidr": seal.peer_signaling_ipv4_cidr,
            "peer_signaling_udp_port": seal.peer_signaling_udp_port,
            "destination_hmac_digest": seal.destination_hmac_digest,
            "reserved_inbound_did_digest": seal.reserved_inbound_did_digest,
            "reserved_inbound_caller_digest": seal.reserved_inbound_caller_digest,
            "policy_digest": seal.policy_digest,
            "retry_count": seal.retry_count,
            "concurrency_count": seal.concurrency_count,
            "call_deadline_seconds": seal.call_deadline_seconds,
            "state": seal.state,
            "live_window_starts_at": seal.live_window_starts_at,
            "live_window_expires_at": seal.live_window_expires_at,
            "sealed_at": seal.sealed_at,
            "started_at": seal.started_at,
            "stage_deadline_at": next((row.stage_deadline_at for row in stages if row.state == "started"), None),
            "containment_class": seal.containment_class,
            "containment_evidence_digest": seal.containment_evidence_digest,
            "containment_evidence_signature_digest": (
                seal.containment_evidence_signature_digest
            ),
            "containment_evidence_key_digest": seal.containment_evidence_key_digest,
            "containment_evidence_key_id": seal.containment_evidence_key_id,
            "contained_at": seal.contained_at,
            "final_evidence_digest": seal.final_evidence_digest,
            "final_evidence_signature_digest": seal.final_evidence_signature_digest,
            "final_evidence_key_digest": seal.final_evidence_key_digest,
            "final_evidence_key_id": seal.final_evidence_key_id,
            "completed_at": seal.completed_at,
            "failed_at": seal.failed_at,
            "stages": [
                {
                    "stage_uuid": row.stage_uuid,
                    "stage": row.stage,
                    "ordinal": row.ordinal,
                    "state": row.state,
                    "started_at": row.started_at,
                    "stage_deadline_at": row.stage_deadline_at,
                    "terminal_class": row.terminal_class,
                    "evidence_digest": row.evidence_digest,
                    "evidence_signature_digest": row.evidence_signature_digest,
                    "evidence_key_digest": row.evidence_key_digest,
                    "evidence_key_id": row.evidence_key_id,
                    "finalized_at": row.finalized_at,
                }
                for row in stages
            ],
        }

    async def _g008_flush_and_project(
        self,
        session,
        seal: G008ExecutionSealModel,
        stages: list[G008ExecutionStageModel],
    ) -> dict[str, Any]:
        await session.flush()
        await session.refresh(seal)
        for stage in stages:
            await session.refresh(stage)
        return self._g008_seal_data(seal, stages)

    @classmethod
    def _validate_g008_authority_evidence(
        cls, evidence: dict[str, Any]
    ) -> dict[str, Any]:
        required = {
            "evidence_digest",
            "evidence_signature_digest",
            "evidence_key_digest",
            "evidence_key_id",
            "canonical_evidence",
            "evidence_signature",
        }
        cls._validate_g008_payload(evidence, required=required, allowed=required)
        for key in (
            "evidence_digest",
            "evidence_signature_digest",
            "evidence_key_digest",
        ):
            cls._validate_g008_digest(evidence[key])
        if not _is_lowercase_attestation_key_id(evidence["evidence_key_id"]):
            raise TelephonyNumberInventoryConflictError("g008_evidence_key_id_invalid")
        canonical_evidence = evidence["canonical_evidence"]
        signature = evidence["evidence_signature"]
        if (
            not isinstance(canonical_evidence, bytes)
            or not canonical_evidence
            or not isinstance(signature, bytes)
            or len(signature) != 64
            or not _digest_equal(
                hashlib.sha256(canonical_evidence).hexdigest(),
                evidence["evidence_digest"],
            )
            or not _digest_equal(
                hashlib.sha256(signature).hexdigest(),
                evidence["evidence_signature_digest"],
            )
        ):
            raise TelephonyNumberInventoryConflictError("g008_evidence_artifact_invalid")
        return evidence

    async def _g008_evidence_ingredients(
        self,
        session,
        seal: G008ExecutionSealModel,
        stages: list[G008ExecutionStageModel],
        *,
        evidence_kind: str,
        evidence_at: datetime,
        containment_class: str | None = None,
        active_stage_ordinal: int | None = None,
        require_completed_linkage: bool = True,
    ) -> dict[str, Any]:
        gates = (
            (
                await session.execute(
                    select(OnnuriRegistrationGateModel)
                    .where(
                        OnnuriRegistrationGateModel.execution_stage_id.in_(
                            tuple(row.id for row in stages)
                        )
                    )
                    .order_by(OnnuriRegistrationGateModel.execution_stage_id)
                    .with_for_update()
                )
            )
            .scalars()
            .all()
        )
        gates_by_stage_id = {gate.execution_stage_id: gate for gate in gates}
        if seal.execution_mode == "ip_to_ip_no_register":
            if gates:
                raise TelephonyNumberInventoryConflictError(
                    "g008_registration_linkage_invalid"
                )
            registration_linkage: list[dict[str, Any]] = []
        else:
            register_gate = gates_by_stage_id.get(stages[0].id)
            unregister_gate = gates_by_stage_id.get(stages[3].id)
            unexpected_gate = any(
                gate.execution_stage_id not in {stages[0].id, stages[3].id}
                for gate in gates
            )
            if require_completed_linkage:
                linkage_invalid = (
                    unexpected_gate
                    or len(gates) != 2
                    or register_gate is None
                    or unregister_gate is None
                    or register_gate.operation_kind != "register"
                    or unregister_gate.operation_kind != "unregister"
                    or unregister_gate.unregisters_gate_id != register_gate.id
                    or register_gate.state != "completed"
                    or unregister_gate.state != "completed"
                )
            else:
                linkage_invalid = (
                    unexpected_gate
                    or (
                        register_gate is not None
                        and register_gate.operation_kind != "register"
                    )
                ) or (
                    unregister_gate is not None
                    and (
                        unregister_gate.operation_kind != "unregister"
                        or register_gate is None
                        or unregister_gate.unregisters_gate_id != register_gate.id
                    )
                )
            if linkage_invalid:
                raise TelephonyNumberInventoryConflictError(
                    "g008_registration_linkage_invalid"
                )
            registration_linkage = [
                {
                    "ordinal": stage.ordinal,
                    "registration_gate_id": gate.id,
                    "operation_uuid": gate.operation_uuid,
                    "operation_kind": gate.operation_kind,
                    "unregisters_gate_id": gate.unregisters_gate_id,
                    "state": gate.state,
                    "request_digest": gate.request_digest,
                    "terminal_at": gate.terminal_at,
                    "execution_attestation_digest": gate.execution_attestation_digest,
                    "execution_attestation_signature_digest": (
                        gate.execution_attestation_signature_digest
                    ),
                    "execution_attestation_key_digest": (
                        gate.execution_attestation_key_digest
                    ),
                    "execution_attestation_key_id": gate.execution_attestation_key_id,
                    "execution_attested_at": gate.execution_attested_at,
                }
                for stage in stages
                for gate in (gates_by_stage_id.get(stage.id),)
                if gate is not None
            ]
        return {
            "evidence_kind": evidence_kind,
            "evidence_at": evidence_at,
            "containment_class": containment_class,
            "active_stage_ordinal": active_stage_ordinal,
            "seal": self._g008_seal_data(seal, stages),
            "registration_linkage": registration_linkage,
        }

    async def create_execution_seal(
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        payload = dict(payload)
        payload.setdefault("execution_mode", "legacy_registration")
        payload.setdefault("owned_target_digest", None)
        payload.setdefault("source_external_ipv4", None)
        payload.setdefault("peer_signaling_ipv4_cidr", None)
        payload.setdefault("peer_signaling_udp_port", None)
        common = self._g008_common_keys()
        extras = {
            "schema_version",
            "destination_hmac_digest",
            "reserved_inbound_did_digest",
            "reserved_inbound_caller_digest",
            "policy_digest",
            "stages",
            "live_window_starts_at",
            "live_window_expires_at",
            "retry_count",
            "concurrency_count",
            "call_deadline_seconds",
            "sealed_at",
            "execution_mode",
            "owned_target_digest",
            "source_external_ipv4",
            "peer_signaling_ipv4_cidr",
            "peer_signaling_udp_port",
        }
        self._validate_g008_payload(
            payload, required=common | extras, allowed=common | extras
        )
        self._validate_g008_common(payload)
        if (
            payload["schema_version"] != "recova-g008-execution-seal-v1"
            or payload["stages"]
            != [name for _, name in self._g008_expected_stages(payload["execution_mode"])]
            or payload["retry_count"] != 0
            or payload["concurrency_count"] != 1
            or payload["call_deadline_seconds"] != 60
        ):
            raise TelephonyNumberInventoryConflictError("g008_execution_policy_invalid")
        network_values = (
            payload["source_external_ipv4"],
            payload["peer_signaling_ipv4_cidr"],
            payload["peer_signaling_udp_port"],
            payload["owned_target_digest"],
        )
        if payload["execution_mode"] == "legacy_registration":
            if any(value is not None for value in network_values):
                raise TelephonyNumberInventoryConflictError("g008_execution_mode_binding_invalid")
        else:
            import ipaddress

            try:
                source = ipaddress.ip_address(payload["source_external_ipv4"])
                peer = ipaddress.ip_network(payload["peer_signaling_ipv4_cidr"], strict=True)
            except ValueError:
                raise TelephonyNumberInventoryConflictError(
                    "g008_execution_mode_binding_invalid"
                ) from None
            if (
                source.version != 4
                or peer.version != 4
                or peer.prefixlen != 32
                or payload["source_external_ipv4"] != str(source)
                or payload["peer_signaling_ipv4_cidr"] != str(peer)
                or payload["peer_signaling_udp_port"] != 5060
                or not _is_lowercase_sha256(payload["owned_target_digest"])
            ):
                raise TelephonyNumberInventoryConflictError("g008_execution_mode_binding_invalid")
        for key in (
            "destination_hmac_digest",
            "reserved_inbound_did_digest",
            "reserved_inbound_caller_digest",
            "policy_digest",
        ):
            self._validate_g008_digest(payload[key])
        starts_at = self._validate_g008_time(payload["live_window_starts_at"])
        expires_at = self._validate_g008_time(payload["live_window_expires_at"])
        sealed_at = self._validate_g008_time(payload["sealed_at"])
        if starts_at >= expires_at or sealed_at >= expires_at:
            raise TelephonyNumberInventoryConflictError("g008_execution_window_invalid")
        async with self.async_session() as session:
            try:
                await self._g008_organization_lock(session, payload["organization_id"])
                await self._ensure_organization_exists(
                    session, payload["organization_id"]
                )
                existing = (
                    await session.execute(
                        select(G008ExecutionSealModel)
                        .where(
                            or_(
                                G008ExecutionSealModel.execution_seal_uuid
                                == payload["execution_seal_uuid"],
                                G008ExecutionSealModel.execution_nonce_digest
                                == payload["execution_nonce_digest"],
                            )
                        )
                        .limit(1)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    existing_stages = list(
                        (
                            await session.execute(
                                select(G008ExecutionStageModel)
                                .where(
                                    G008ExecutionStageModel.execution_seal_id
                                    == existing.id
                                )
                                .order_by(G008ExecutionStageModel.ordinal)
                                .with_for_update()
                            )
                        ).scalars()
                    )
                    exact_binding = (
                        existing.execution_seal_uuid
                        == payload["execution_seal_uuid"]
                        and existing.organization_id == payload["organization_id"]
                        and _digest_equal(
                            existing.execution_nonce_digest,
                            payload["execution_nonce_digest"],
                        )
                        and _digest_equal(
                            existing.candidate_digest, payload["candidate_digest"]
                        )
                        and _digest_equal(
                            existing.gate_envelope_digest,
                            payload["gate_envelope_digest"],
                        )
                        and existing.execution_mode == payload["execution_mode"]
                        and existing.owned_target_digest == payload["owned_target_digest"]
                        and existing.source_external_ipv4 == payload["source_external_ipv4"]
                        and existing.peer_signaling_ipv4_cidr == payload["peer_signaling_ipv4_cidr"]
                        and existing.peer_signaling_udp_port == payload["peer_signaling_udp_port"]
                        and _digest_equal(
                            existing.destination_hmac_digest,
                            payload["destination_hmac_digest"],
                        )
                        and _digest_equal(
                            existing.reserved_inbound_did_digest,
                            payload["reserved_inbound_did_digest"],
                        )
                        and _digest_equal(
                            existing.reserved_inbound_caller_digest,
                            payload["reserved_inbound_caller_digest"],
                        )
                        and _digest_equal(
                            existing.policy_digest, payload["policy_digest"]
                        )
                        and existing.schema_version == payload["schema_version"]
                        and existing.live_window_starts_at == starts_at
                        and existing.live_window_expires_at == expires_at
                        and existing.retry_count == 0
                        and existing.concurrency_count == 1
                        and existing.call_deadline_seconds == 60
                        and [
                            (row.ordinal, row.stage) for row in existing_stages
                        ]
                        == self._g008_expected_stages(payload["execution_mode"])
                    )
                    if exact_binding:
                        return self._g008_seal_data(existing, existing_stages)
                    raise TelephonyNumberInventoryConflictError(
                        "g008_execution_seal_conflict"
                    )
                seal = G008ExecutionSealModel(
                    execution_seal_uuid=payload["execution_seal_uuid"],
                    schema_version=payload["schema_version"],
                    organization_id=payload["organization_id"],
                    execution_nonce_digest=payload["execution_nonce_digest"],
                    candidate_digest=payload["candidate_digest"],
                    gate_envelope_digest=payload["gate_envelope_digest"],
                    destination_hmac_digest=payload["destination_hmac_digest"],
                    execution_mode=payload["execution_mode"],
                    owned_target_digest=payload["owned_target_digest"],
                    source_external_ipv4=payload["source_external_ipv4"],
                    peer_signaling_ipv4_cidr=payload["peer_signaling_ipv4_cidr"],
                    peer_signaling_udp_port=payload["peer_signaling_udp_port"],
                    reserved_inbound_did_digest=payload[
                        "reserved_inbound_did_digest"
                    ],
                    reserved_inbound_caller_digest=payload[
                        "reserved_inbound_caller_digest"
                    ],
                    policy_digest=payload["policy_digest"],
                    retry_count=0,
                    concurrency_count=1,
                    call_deadline_seconds=60,
                    state="sealed",
                    live_window_starts_at=starts_at,
                    live_window_expires_at=expires_at,
                    sealed_at=sealed_at,
                )
                session.add(seal)
                await session.flush()
                stages = []
                for ordinal, stage_name in enumerate(payload["stages"], 1):
                    stage = G008ExecutionStageModel(
                        execution_seal_id=seal.id,
                        organization_id=seal.organization_id,
                        execution_nonce_digest=seal.execution_nonce_digest,
                        candidate_digest=seal.candidate_digest,
                        gate_envelope_digest=seal.gate_envelope_digest,
                        stage=stage_name,
                        ordinal=ordinal,
                        state="pending",
                    )
                    session.add(stage)
                    stages.append(stage)
                projection = await self._g008_flush_and_project(
                    session, seal, stages
                )
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise TelephonyNumberInventoryConflictError(
                    "g008_execution_seal_conflict"
                ) from exc
            return projection

    async def consume_execution_nonce(
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        keys = self._g008_common_keys() | {"trusted_keyset_digest"}
        self._validate_g008_payload(payload, required=keys, allowed=keys)
        self._validate_g008_digest(payload["trusted_keyset_digest"])
        async with self.async_session() as session:
            try:
                seal, stages = await self._lock_g008_execution(session, payload)
                database_now = (
                    await session.execute(select(func.clock_timestamp()))
                ).scalar_one()
                if (
                    seal.state != "sealed"
                    or not (
                        seal.live_window_starts_at
                        <= database_now
                        < seal.live_window_expires_at
                    )
                    or any(stage.state != "pending" for stage in stages)
                ):
                    raise TelephonyNumberInventoryConflictError(
                        "g008_execution_nonce_not_consumable"
                    )
                consumption = G008ExecutionNonceConsumptionModel(
                    organization_id=payload["organization_id"],
                    execution_seal_uuid=payload["execution_seal_uuid"],
                    execution_nonce_digest=payload["execution_nonce_digest"],
                    candidate_digest=payload["candidate_digest"],
                    gate_envelope_digest=payload["gate_envelope_digest"],
                    trusted_keyset_digest=payload["trusted_keyset_digest"],
                    consumed_at=database_now,
                )
                session.add(consumption)
                await session.flush()
                await session.refresh(consumption)
                await session.commit()
                return {
                    "organization_id": consumption.organization_id,
                    "execution_seal_uuid": consumption.execution_seal_uuid,
                    "execution_nonce_digest": consumption.execution_nonce_digest,
                    "candidate_digest": consumption.candidate_digest,
                    "gate_envelope_digest": consumption.gate_envelope_digest,
                    "trusted_keyset_digest": consumption.trusted_keyset_digest,
                    "consumed_at": consumption.consumed_at,
                }
            except IntegrityError as exc:
                await session.rollback()
                raise TelephonyNumberInventoryConflictError(
                    "g008_execution_nonce_not_consumable"
                ) from exc
    async def start_execution_stage(
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        keys = self._g008_common_keys() | {"stage", "ordinal", "started_at"}
        self._validate_g008_payload(payload, required=keys, allowed=keys)
        self._validate_g008_time(payload["started_at"])
        async with self.async_session() as session:
            seal, stages = await self._lock_g008_execution(session, payload)
            if (
                not isinstance(payload["ordinal"], int)
                or not 1 <= payload["ordinal"] <= 4
            ):
                raise TelephonyNumberInventoryConflictError("g008_stage_invalid")
            stage = stages[payload["ordinal"] - 1]
            if stage.stage != payload["stage"]:
                raise TelephonyNumberInventoryConflictError("g008_stage_invalid")
            database_now = (
                await session.execute(select(func.clock_timestamp()))
            ).scalar_one()
            if stage.state == "started":
                projection = self._g008_seal_data(seal, stages)
                projection["stages"][stage.ordinal - 1]["recovered"] = True
                return projection
            nonce_consumption = (
                await session.execute(
                    select(G008ExecutionNonceConsumptionModel).where(
                        G008ExecutionNonceConsumptionModel.organization_id
                        == payload["organization_id"],
                        G008ExecutionNonceConsumptionModel.execution_seal_uuid
                        == payload["execution_seal_uuid"],
                        G008ExecutionNonceConsumptionModel.execution_nonce_digest
                        == payload["execution_nonce_digest"],
                        G008ExecutionNonceConsumptionModel.candidate_digest
                        == payload["candidate_digest"],
                        G008ExecutionNonceConsumptionModel.gate_envelope_digest
                        == payload["gate_envelope_digest"],
                    )
                )
            ).scalar_one_or_none()
            if nonce_consumption is None or (
                payload["ordinal"] == 1
                and nonce_consumption.consumed_at + timedelta(seconds=60)
                <= database_now
            ):
                raise TelephonyNumberInventoryConflictError(
                    "g008_execution_nonce_not_consumed"
                )
            started_at = database_now
            cleanup_gate = None
            if payload["ordinal"] == 4:
                cleanup_gate = (
                    await session.execute(
                        select(OnnuriRegistrationGateModel.id)
                        .join(
                            G008ExecutionStageModel,
                            G008ExecutionStageModel.id
                            == OnnuriRegistrationGateModel.execution_stage_id,
                        )
                        .where(
                            G008ExecutionStageModel.execution_seal_id == seal.id,
                            G008ExecutionStageModel.organization_id
                            == payload["organization_id"],
                            G008ExecutionStageModel.ordinal == 1,
                            OnnuriRegistrationGateModel.operation_kind == "register",
                            OnnuriRegistrationGateModel.transaction_count == 1,
                            OnnuriRegistrationGateModel.unregister_required.is_(True),
                            OnnuriRegistrationGateModel.unregister_satisfied_at.is_(None),
                        )
                    )
                ).scalar_one_or_none()
            cleanup_start = cleanup_gate is not None and seal.state in {
                "running",
                "cleanup_required",
                "residue_blocked",
                "contained",
            }
            if not cleanup_start and not (
                seal.live_window_starts_at <= database_now < seal.live_window_expires_at
            ):
                raise TelephonyNumberInventoryConflictError(
                    "g008_execution_not_in_live_window"
                )
            if stage.state != "pending":
                raise TelephonyNumberInventoryConflictError(
                    "g008_stage_not_startable"
                )
            if not cleanup_start and any(
                row.state != "succeeded" for row in stages[: stage.ordinal - 1]
            ):
                raise TelephonyNumberInventoryConflictError("g008_stage_wrong_order")
            stage.stage_deadline_at = database_now + timedelta(
                seconds=seal.call_deadline_seconds
            )
            stage.state = "started"
            stage.started_at = started_at
            if seal.state == "sealed":
                seal.state = "running"
                seal.started_at = started_at
            elif cleanup_start and seal.state != "contained":
                seal.state = "cleanup_required"
            projection = await self._g008_flush_and_project(session, seal, stages)
            await session.commit()
            return projection

    async def get_execution_stage_status(
        self,
        *,
        organization_id: int,
        execution_seal_uuid: str,
        execution_nonce_digest: str,
        candidate_digest: str,
        gate_envelope_digest: str,
        stage: str,
        ordinal: int,
    ) -> dict[str, Any] | None:
        payload = {
            "organization_id": organization_id,
            "execution_seal_uuid": execution_seal_uuid,
            "execution_nonce_digest": execution_nonce_digest,
            "candidate_digest": candidate_digest,
            "gate_envelope_digest": gate_envelope_digest,
        }
        self._validate_g008_common(payload)
        expected_stage = {
            1: "register",
            2: "outbound_call",
            3: "inbound_call",
            4: "unregister",
        }.get(ordinal)
        if (
            organization_id <= 0
            or expected_stage is None
            or stage != expected_stage
        ):
            raise TelephonyNumberInventoryConflictError("g008_stage_invalid")

        async with self.async_session() as session:
            result = (
                await session.execute(
                    select(G008ExecutionSealModel, G008ExecutionStageModel)
                    .join(
                        G008ExecutionStageModel,
                        G008ExecutionStageModel.execution_seal_id
                        == G008ExecutionSealModel.id,
                    )
                    .where(
                        G008ExecutionSealModel.organization_id == organization_id,
                        G008ExecutionSealModel.execution_seal_uuid
                        == execution_seal_uuid,
                        G008ExecutionSealModel.execution_nonce_digest
                        == execution_nonce_digest,
                        G008ExecutionSealModel.candidate_digest == candidate_digest,
                        G008ExecutionSealModel.gate_envelope_digest
                        == gate_envelope_digest,
                        G008ExecutionStageModel.organization_id == organization_id,
                        G008ExecutionStageModel.execution_nonce_digest
                        == execution_nonce_digest,
                        G008ExecutionStageModel.candidate_digest == candidate_digest,
                        G008ExecutionStageModel.gate_envelope_digest
                        == gate_envelope_digest,
                        G008ExecutionStageModel.stage == stage,
                        G008ExecutionStageModel.ordinal == ordinal,
                    )
                )
            ).first()
            if result is None:
                return None
            seal, stage_row = result
            database_now = (
                await session.execute(select(func.clock_timestamp()))
            ).scalar_one()
            if (
                stage_row.stage_deadline_at is None
                or database_now >= stage_row.stage_deadline_at
            ):
                raise TelephonyNumberInventoryConflictError("g008_execution_stage_expired")
            gate = (
                (
                    await session.execute(
                        select(OnnuriRegistrationGateModel)
                        .join(
                            OnnuriSmokeEnvelopeModel,
                            OnnuriSmokeEnvelopeModel.id
                            == OnnuriRegistrationGateModel.envelope_id,
                        )
                        .where(
                            OnnuriRegistrationGateModel.execution_stage_id
                            == stage_row.id,
                            OnnuriSmokeEnvelopeModel.organization_id
                            == organization_id,
                        )
                    )
                )
                .scalars()
                .one_or_none()
            )
            return {
                "organization_id": seal.organization_id,
                "execution_seal_uuid": seal.execution_seal_uuid,
                "execution_nonce_digest": seal.execution_nonce_digest,
                "candidate_digest": seal.candidate_digest,
                "gate_envelope_digest": seal.gate_envelope_digest,
                "seal_state": seal.state,
                "stage_uuid": stage_row.stage_uuid,
                "stage": stage_row.stage,
                "ordinal": stage_row.ordinal,
                "state": stage_row.state,
                "recovered": stage_row.state in {"succeeded", "failed", "contained"},
                "started_at": stage_row.started_at,
                "stage_deadline_at": stage_row.stage_deadline_at,
                "terminal_class": stage_row.terminal_class,
                "evidence_digest": stage_row.evidence_digest,
                "evidence_signature_digest": stage_row.evidence_signature_digest,
                "evidence_key_digest": stage_row.evidence_key_digest,
                "evidence_key_id": stage_row.evidence_key_id,
                "finalized_at": stage_row.finalized_at,
                "registration_gate_id": gate.id if gate is not None else None,
                "registration_operation_uuid": (
                    gate.operation_uuid if gate is not None else None
                ),
                "registration_operation_kind": (
                    gate.operation_kind if gate is not None else None
                ),
                "registration_gate_state": gate.state if gate is not None else None,
                "registration_gate_request_digest": (
                    gate.request_digest if gate is not None else None
                ),
                "registration_gate_terminal_at": (
                    gate.terminal_at if gate is not None else None
                ),
                "registration_gate_execution_attestation_digest": (
                    gate.execution_attestation_digest if gate is not None else None
                ),
                "registration_gate_execution_attestation_signature_digest": (
                    gate.execution_attestation_signature_digest
                    if gate is not None
                    else None
                ),
                "registration_gate_execution_attestation_key_digest": (
                    gate.execution_attestation_key_digest
                    if gate is not None
                    else None
                ),
                "registration_gate_execution_attestation_key_id": (
                    gate.execution_attestation_key_id if gate is not None else None
                ),
                "registration_gate_execution_attested_at": (
                    gate.execution_attested_at if gate is not None else None
                ),
                "prior_register_gate_id": (
                    gate.unregisters_gate_id if gate is not None else None
                ),
            }

    async def bind_g008_outbound_observation(
        self, payload: dict[str, Any]
    ) -> dict[str, Any] | None:
        keys = {"organization_id", "attempt_uuid"}
        self._validate_g008_payload(payload, required=keys, allowed=keys)
        organization_id = payload["organization_id"]
        if (
            isinstance(organization_id, bool)
            or not isinstance(organization_id, int)
            or organization_id <= 0
        ):
            raise TelephonyNumberInventoryConflictError("g008_organization_invalid")
        attempt_uuid = self._validate_g008_uuid(payload["attempt_uuid"])
        async with self.async_session() as session:
            await self._g008_organization_lock(session, organization_id)
            owned = (
                await session.execute(
                    select(OnnuriSmokeAttemptModel, OnnuriSmokeEnvelopeModel)
                    .join(
                        OnnuriSmokeEnvelopeModel,
                        OnnuriSmokeEnvelopeModel.id
                        == OnnuriSmokeAttemptModel.envelope_id,
                    )
                    .where(
                        OnnuriSmokeAttemptModel.organization_id == organization_id,
                        OnnuriSmokeEnvelopeModel.organization_id == organization_id,
                        OnnuriSmokeAttemptModel.attempt_uuid == attempt_uuid,
                    )
                    .with_for_update()
                )
            ).first()
            if owned is None:
                raise TelephonyNumberInventoryNotFoundError(
                    "g008_outbound_dispatch_not_found"
                )
            attempt, envelope = owned
            existing = (
                await session.execute(
                    select(G008OutboundBindingModel)
                    .where(
                        G008OutboundBindingModel.organization_id == organization_id,
                        G008OutboundBindingModel.smoke_attempt_id == attempt.id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if existing is not None:
                return {
                    "stock_call_id_digest": existing.stock_call_id_digest,
                    "terminal_class": existing.terminal_class,
                    "terminal_at": existing.terminal_at,
                    "bound_at": existing.bound_at,
                }
            gate_envelope_digest = hashlib.sha256(
                envelope.envelope_uuid.encode("utf-8")
            ).hexdigest()
            matches = (
                await session.execute(
                    select(G008ExecutionSealModel, G008ExecutionStageModel)
                    .join(
                        G008ExecutionStageModel,
                        G008ExecutionStageModel.execution_seal_id
                        == G008ExecutionSealModel.id,
                    )
                    .where(
                        G008ExecutionSealModel.organization_id == organization_id,
                        G008ExecutionSealModel.state == "running",
                        G008ExecutionSealModel.candidate_digest
                        == envelope.candidate_digest,
                        G008ExecutionSealModel.gate_envelope_digest
                        == gate_envelope_digest,
                        G008ExecutionSealModel.destination_hmac_digest
                        == envelope.destination_hmac_digest,
                        G008ExecutionStageModel.organization_id == organization_id,
                        G008ExecutionStageModel.stage == "outbound_call",
                        G008ExecutionStageModel.ordinal == 2,
                        G008ExecutionStageModel.state == "started",
                        G008ExecutionStageModel.started_at.is_not(None),
                    )
                    .order_by(G008ExecutionSealModel.id)
                    .limit(2)
                    .with_for_update()
                )
            ).all()
            callback_events = (
                (
                    await session.execute(
                        select(OnnuriSmokeCallbackEventModel)
                        .where(
                            OnnuriSmokeCallbackEventModel.attempt_id == attempt.id,
                            OnnuriSmokeCallbackEventModel.normalized_status
                            == "completed",
                            OnnuriSmokeCallbackEventModel.accepted_at
                            == attempt.terminal_at,
                        )
                        .order_by(OnnuriSmokeCallbackEventModel.id)
                        .limit(2)
                        .with_for_update()
                    )
                )
                .scalars()
                .all()
            )
            if not matches:
                return None
            if (
                len(matches) != 1
                or attempt.direction != "outbound"
                or attempt.state != "terminal"
                or attempt.terminal_class != "call_completed"
                or attempt.dispatch_receipt_digest is None
                or attempt.account_id is None
                or attempt.application_id is None
                or attempt.stock_call_id_digest is None
                or attempt.authority_deadline_at is None
                or attempt.terminal_at is None
                or attempt.allocated_at is None
                or attempt.allocated_at < matches[0][1].started_at
                or attempt.terminal_at > attempt.authority_deadline_at
                or len(callback_events) != 1
                or callback_events[0].accepted_at != attempt.terminal_at
                or not _is_lowercase_sha256(attempt.dispatch_receipt_digest)
                or not _is_lowercase_sha256(attempt.stock_call_id_digest)
                or envelope.max_outbound_attempts != 1
                or envelope.max_inbound_attempts != 1
                or envelope.max_concurrency != 1
                or envelope.retries != 0
                or envelope.max_duration_seconds != 60
            ):
                raise TelephonyNumberInventoryConflictError(
                    "g008_outbound_terminal_observation_missing"
                )
            _, stage = matches[0]
            observed_clock = (
                await session.execute(select(func.clock_timestamp()))
            ).scalar_one()
            if observed_clock >= attempt.authority_deadline_at:
                raise TelephonyNumberInventoryConflictError(
                    "g008_outbound_terminal_observation_expired"
                )
            bound_at = max(observed_clock, attempt.terminal_at)
            binding = G008OutboundBindingModel(
                organization_id=organization_id,
                execution_stage_id=stage.id,
                smoke_attempt_id=attempt.id,
                account_uuid=attempt.account_id,
                application_uuid=attempt.application_id,
                stock_call_id_digest=attempt.stock_call_id_digest,
                authority_deadline_at=attempt.authority_deadline_at,
                terminal_class=attempt.terminal_class,
                terminal_at=attempt.terminal_at,
                bound_at=bound_at,
            )
            session.add(binding)
            await session.flush()
            await session.refresh(binding)
            projection = {
                "stock_call_id_digest": binding.stock_call_id_digest,
                "terminal_class": binding.terminal_class,
                "terminal_at": binding.terminal_at,
                "bound_at": binding.bound_at,
            }
            await session.commit()
            return projection
    async def finalize_execution_stage(
        self,
        payload: dict[str, Any],
        *,
        evidence_builder: Callable[
            [dict[str, Any]], Awaitable[dict[str, Any]]
        ],
    ) -> dict[str, Any]:
        keys = self._g008_common_keys() | {
            "stage",
            "ordinal",
            "stage_state",
            "terminal_class",
        }
        self._validate_g008_payload(payload, required=keys, allowed=keys)
        if payload["stage_state"] not in {"succeeded", "failed"}:
            raise TelephonyNumberInventoryConflictError("g008_stage_state_invalid")
        if not isinstance(payload["terminal_class"], str) or not payload[
            "terminal_class"
        ].strip():
            raise TelephonyNumberInventoryConflictError(
                "g008_terminal_class_invalid"
            )
        if (
            not isinstance(payload["ordinal"], int)
            or payload["ordinal"] not in {2, 3}
        ):
            raise TelephonyNumberInventoryConflictError(
                "g008_registration_stage_requires_attestation"
            )
        async with self.async_session() as session:
            seal, stages = await self._lock_g008_execution(session, payload)
            finalized_at = (
                await session.execute(select(func.clock_timestamp()))
            ).scalar_one()
            stage = stages[payload["ordinal"] - 1]
            if (
                stage.stage_deadline_at is None
                or finalized_at >= stage.stage_deadline_at
            ):
                raise TelephonyNumberInventoryConflictError("g008_execution_stage_expired")
            terminal_class = payload["terminal_class"].strip()
            if stage.state in {"succeeded", "failed", "contained"}:
                if (
                    stage.state == payload["stage_state"]
                    and stage.terminal_class == terminal_class
                ):
                    projection = self._g008_seal_data(seal, stages)
                    projection["stages"][stage.ordinal - 1]["recovered"] = True
                    return projection
                raise TelephonyNumberInventoryConflictError(
                    "g008_stage_terminal_replay_rejected"
                )
            if (
                stage.stage != payload["stage"]
                or stage.state != "started"
                or stage.started_at is None
                or finalized_at < stage.started_at
            ):
                raise TelephonyNumberInventoryConflictError(
                    "g008_stage_not_finalizable"
                )
            if stage.ordinal == 2 and payload["stage_state"] == "succeeded":
                outbound_binding_id = (
                    await session.execute(
                        select(G008OutboundBindingModel.id).where(
                            G008OutboundBindingModel.organization_id
                            == seal.organization_id,
                            G008OutboundBindingModel.execution_stage_id == stage.id,
                            G008OutboundBindingModel.terminal_class == terminal_class,
                        )
                    )
                ).scalar_one_or_none()
                if outbound_binding_id is None:
                    raise TelephonyNumberInventoryConflictError(
                        "g008_outbound_stage_unobserved"
                    )
            if stage.ordinal == 3 and payload["stage_state"] == "succeeded":
                inbound_binding_id = (
                    await session.execute(
                        select(G008InboundBindingModel.id).where(
                            G008InboundBindingModel.organization_id
                            == seal.organization_id,
                            G008InboundBindingModel.execution_stage_id == stage.id,
                            G008InboundBindingModel.state == "bound",
                        )
                    )
                ).scalar_one_or_none()
                if inbound_binding_id is None:
                    raise TelephonyNumberInventoryConflictError(
                        "g008_inbound_stage_unbound"
                    )
            evidence = self._validate_g008_authority_evidence(
                await evidence_builder(
                    {
                        "evidence_kind": "stage",
                        "evidence_at": finalized_at,
                        "seal": self._g008_seal_data(seal, stages),
                        "stage_ordinal": stage.ordinal,
                        "stage_state": payload["stage_state"],
                        "terminal_class": terminal_class,
                        "registration_linkage": [],
                    }
                )
            )
            stage.state = payload["stage_state"]
            stage.terminal_class = terminal_class
            stage.evidence_digest = evidence["evidence_digest"]
            stage.evidence_signature_digest = evidence[
                "evidence_signature_digest"
            ]
            stage.evidence_key_digest = evidence["evidence_key_digest"]
            stage.evidence_key_id = evidence["evidence_key_id"]
            stage.evidence_canonical = evidence["canonical_evidence"]
            stage.evidence_signature = evidence["evidence_signature"]
            stage.finalized_at = finalized_at
            if stage.state == "failed":
                register_gate = (
                    await session.execute(
                        select(OnnuriRegistrationGateModel.id).where(
                            OnnuriRegistrationGateModel.execution_stage_id
                            == stages[0].id,
                            OnnuriRegistrationGateModel.transaction_count == 1,
                            OnnuriRegistrationGateModel.unregister_required.is_(True),
                            OnnuriRegistrationGateModel.unregister_satisfied_at.is_(None),
                        )
                    )
                ).scalar_one_or_none()
                if register_gate is not None:
                    seal.state = "cleanup_required"
                else:
                    seal.state = "failed"
                    seal.failed_at = finalized_at
            projection = await self._g008_flush_and_project(session, seal, stages)
            await session.commit()
            return projection

    async def finalize_execution_evidence(
        self,
        payload: dict[str, Any],
        *,
        evidence_builder: Callable[
            [dict[str, Any]], Awaitable[dict[str, Any]]
        ],
    ) -> dict[str, Any]:
        keys = self._g008_common_keys()
        self._validate_g008_payload(payload, required=keys, allowed=keys)
        async with self.async_session() as session:
            seal, stages = await self._lock_g008_execution(session, payload)
            if seal.state == "completed":
                return self._g008_seal_data(seal, stages)
            completed_at = (
                await session.execute(select(func.clock_timestamp()))
            ).scalar_one()
            if seal.state not in {"contained", "running"} or any(
                row.state != "succeeded" for row in stages
            ):
                raise TelephonyNumberInventoryConflictError(
                    "g008_execution_not_completable"
                )

            if completed_at < stages[-1].finalized_at:
                raise TelephonyNumberInventoryConflictError("g008_timestamp_invalid")
            ingredients = await self._g008_evidence_ingredients(
                session,
                seal,
                stages,
                evidence_kind="completion",
                evidence_at=completed_at,
            )
            evidence = self._validate_g008_authority_evidence(
                await evidence_builder(ingredients)
            )
            seal.state = "completed"
            seal.final_evidence_digest = evidence["evidence_digest"]
            seal.final_evidence_signature_digest = evidence[
                "evidence_signature_digest"
            ]
            seal.final_evidence_key_digest = evidence["evidence_key_digest"]
            seal.final_evidence_key_id = evidence["evidence_key_id"]
            seal.final_evidence_canonical = evidence["canonical_evidence"]
            seal.final_evidence_signature = evidence["evidence_signature"]
            seal.completed_at = completed_at
            projection = await self._g008_flush_and_project(session, seal, stages)
            await session.commit()
            return projection

    async def contain_execution(
        self,
        payload: dict[str, Any],
        *,
        evidence_builder: Callable[
            [dict[str, Any]], Awaitable[dict[str, Any]]
        ],
    ) -> dict[str, Any]:
        keys = self._g008_common_keys() | {"containment_class"}
        self._validate_g008_payload(payload, required=keys, allowed=keys)
        if not isinstance(payload["containment_class"], str) or not payload[
            "containment_class"
        ].strip():
            raise TelephonyNumberInventoryConflictError(
                "g008_containment_class_invalid"
            )
        containment_class = payload["containment_class"].strip()
        async with self.async_session() as session:
            seal, stages = await self._lock_g008_execution(session, payload)
            if seal.state == "contained":
                if seal.containment_class == containment_class:
                    return self._g008_seal_data(seal, stages)
                raise TelephonyNumberInventoryConflictError(
                    "g008_containment_terminal_replay_rejected"
                )
            if seal.state in {"cleanup_required", "residue_blocked"}:
                contained_stages = [
                    row
                    for row in stages
                    if row.state == "contained"
                    and row.terminal_class == containment_class
                ]
                if len(contained_stages) == 1:
                    return self._g008_seal_data(seal, stages)
                raise TelephonyNumberInventoryConflictError(
                    "g008_containment_terminal_replay_rejected"
                )
            contained_at = (
                await session.execute(select(func.clock_timestamp()))
            ).scalar_one()
            successful_cleanup = (
                seal.state == "running"
                and containment_class == "verified_terminal"
                and all(row.state == "succeeded" for row in stages)
            )
            if seal.state not in {"sealed", "running"}:
                raise TelephonyNumberInventoryConflictError(
                    "g008_execution_not_containable"
                )
            if successful_cleanup:
                active = stages[-1]
            else:
                active_stages = [row for row in stages if row.state == "started"]
                if len(active_stages) != 1:
                    raise TelephonyNumberInventoryConflictError(
                        "g008_active_stage_invalid"
                    )
                active = active_stages[0]

            if not successful_cleanup:
                stage_ingredients = await self._g008_evidence_ingredients(
                    session,
                    seal,
                    stages,
                    evidence_kind="stage_containment",
                    evidence_at=contained_at,
                    containment_class=containment_class,
                    active_stage_ordinal=active.ordinal,
                    require_completed_linkage=False,
                )
                stage_registration_linkage = [
                    linkage
                    for linkage in stage_ingredients["registration_linkage"]
                    if linkage["ordinal"] == active.ordinal
                ]
                active_evidence = self._validate_g008_authority_evidence(
                    await evidence_builder(
                        {
                            "evidence_kind": "stage_containment",
                            "evidence_at": contained_at,
                            "seal": self._g008_seal_data(seal, stages),
                            "stage_ordinal": active.ordinal,
                            "stage_state": "contained",
                            "terminal_class": containment_class,
                            "registration_linkage": stage_registration_linkage,
                        }
                    )
                )
                active.state = "contained"
                active.terminal_class = containment_class
                active.evidence_digest = active_evidence["evidence_digest"]
                active.evidence_signature_digest = active_evidence[
                    "evidence_signature_digest"
                ]
                active.evidence_key_digest = active_evidence["evidence_key_digest"]
                active.evidence_key_id = active_evidence["evidence_key_id"]
                active.evidence_canonical = active_evidence["canonical_evidence"]
                active.evidence_signature = active_evidence["evidence_signature"]
                active.finalized_at = contained_at
            register_gate = (
                await session.execute(
                    select(OnnuriRegistrationGateModel.id).where(
                        OnnuriRegistrationGateModel.execution_stage_id == stages[0].id,
                        OnnuriRegistrationGateModel.transaction_count == 1,
                        OnnuriRegistrationGateModel.unregister_required.is_(True),
                        OnnuriRegistrationGateModel.unregister_satisfied_at.is_(None),
                    )
                )
            ).scalar_one_or_none()
            if register_gate is not None:
                seal.state = "cleanup_required"
                projection = await self._g008_flush_and_project(
                    session, seal, stages
                )
                await session.commit()
                return projection
            if successful_cleanup:
                cleanup_gates = (
                    await session.execute(
                        select(OnnuriRegistrationGateModel)
                        .where(
                            OnnuriRegistrationGateModel.execution_stage_id.in_(
                                (stages[0].id, stages[3].id)
                            )
                        )
                        .with_for_update()
                    )
                ).scalars().all()
                if (
                    len(cleanup_gates) != 2
                    or {gate.operation_kind for gate in cleanup_gates}
                    != {"register", "unregister"}
                    or any(gate.state != "completed" for gate in cleanup_gates)
                    or any(
                        gate.operation_kind == "register"
                        and gate.unregister_satisfied_at is None
                        for gate in cleanup_gates
                    )
                ):
                    raise TelephonyNumberInventoryConflictError(
                        "g008_cleanup_not_verified"
                    )

            ingredients = await self._g008_evidence_ingredients(
                session,
                seal,
                stages,
                evidence_kind="containment",
                evidence_at=contained_at,
                containment_class=containment_class,
                active_stage_ordinal=active.ordinal,
                require_completed_linkage=successful_cleanup,
            )
            aggregate_evidence = self._validate_g008_authority_evidence(
                await evidence_builder(ingredients)
            )
            seal.state = "contained"
            seal.containment_class = containment_class
            seal.containment_evidence_digest = aggregate_evidence[
                "evidence_digest"
            ]
            seal.containment_evidence_signature_digest = aggregate_evidence[
                "evidence_signature_digest"
            ]
            seal.containment_evidence_key_digest = aggregate_evidence[
                "evidence_key_digest"
            ]
            seal.containment_evidence_key_id = aggregate_evidence["evidence_key_id"]
            seal.containment_evidence_canonical = aggregate_evidence[
                "canonical_evidence"
            ]
            seal.containment_evidence_signature = aggregate_evidence[
                "evidence_signature"
            ]
            seal.contained_at = contained_at
            projection = await self._g008_flush_and_project(session, seal, stages)
            await session.commit()
            return projection

    @staticmethod
    def _g008_inbound_binding_data(
        binding: G008InboundBindingModel,
    ) -> dict[str, Any]:
        claims = dict(binding.canonical_claims)
        return {
            "state": binding.state,
            "organization_id": binding.organization_id,
            "account_uuid": binding.account_uuid,
            "application_uuid": binding.application_uuid,
            "stock_call_uuid": binding.stock_call_uuid,
            "stock_call_id_digest": binding.stock_call_id_digest,
            "did_digest": binding.did_digest,
            "caller_digest": binding.caller_digest,
            "direction": binding.direction,
            "run_uuid": binding.run_uuid,
            "attempt_uuid": binding.attempt_uuid,
            "idempotency_uuid": binding.idempotency_uuid,
            "bind_receipt_uuid": binding.bind_receipt_uuid,
            "request_digest": binding.request_digest,
            "authority_deadline_at": binding.authority_deadline_at,
            "issued_at": binding.issued_at,
            "bound_at": binding.bound_at,
            "receipt_schema": binding.receipt_schema,
            "receipt_domain": binding.receipt_domain,
            "receipt_algorithm": binding.receipt_algorithm,
            "receipt_key_id": binding.receipt_key_id,
            "receipt_spki_digest": binding.receipt_spki_digest,
            "receipt_signature_digest": binding.receipt_signature_digest,
            "receipt_unsigned_digest": binding.receipt_unsigned_digest,
            "recovery_ciphertext": binding.recovery_ciphertext,
            "recovery_ciphertext_digest": binding.recovery_ciphertext_digest,
            "canonical_claims": claims,
            "candidate_digest": claims["candidate_digest"],
            "execution_stage_uuid": claims["execution_stage_uuid"],
        }

    @classmethod
    def _validate_g008_bind_receipt(
        cls,
        receipt: dict[str, Any],
        *,
        canonical_claims: dict[str, Any],
    ) -> dict[str, Any]:
        keys = {
            "receipt_schema",
            "receipt_domain",
            "receipt_algorithm",
            "receipt_key_id",
            "receipt_spki_digest",
            "receipt_signature_digest",
            "receipt_unsigned_digest",
            "canonical_claims",
            "recovery_ciphertext",
            "recovery_ciphertext_digest",
        }
        cls._validate_g008_payload(receipt, required=keys, allowed=keys)
        if (
            receipt["receipt_schema"] != "recova-g008-inbound-bind-receipt-v1"
            or receipt["receipt_domain"]
            != "recova.onnuri.smoke.g008.inbound-bind.v1"
            or receipt["receipt_algorithm"] != "ES256"
            or receipt["canonical_claims"] != canonical_claims
            or not _is_lowercase_attestation_key_id(receipt["receipt_key_id"])
        ):
            raise TelephonyNumberInventoryConflictError(
                "g008_inbound_bind_receipt_invalid"
            )
        for key in (
            "receipt_spki_digest",
            "receipt_signature_digest",
            "receipt_unsigned_digest",
            "recovery_ciphertext_digest",
        ):
            cls._validate_g008_digest(receipt[key])
        if (
            not isinstance(receipt["recovery_ciphertext"], str)
            or not receipt["recovery_ciphertext"]
            or not _digest_equal(
                hashlib.sha256(
                    receipt["recovery_ciphertext"].encode("utf-8")
                ).hexdigest(),
                receipt["recovery_ciphertext_digest"],
            )
        ):
            raise TelephonyNumberInventoryConflictError(
                "g008_inbound_bind_receipt_invalid"
            )
        return receipt

    async def _resume_g008_inbound_binding(
        self,
        *,
        organization_id: int,
        binding_id: int,
        canonical_claims: dict[str, Any],
        receipt_builder: Callable[
            [dict[str, Any]], Awaitable[dict[str, Any]]
        ],
    ) -> dict[str, Any]:
        receipt = self._validate_g008_bind_receipt(
            await receipt_builder({"canonical_claims": dict(canonical_claims)}),
            canonical_claims=canonical_claims,
        )
        async with self.async_session() as session:
            await self._g008_organization_lock(session, organization_id)
            binding = (
                (
                    await session.execute(
                        select(G008InboundBindingModel)
                        .where(
                            G008InboundBindingModel.id == binding_id,
                            G008InboundBindingModel.organization_id
                            == organization_id,
                        )
                        .with_for_update()
                        .execution_options(populate_existing=True)
                    )
                )
                .scalars()
                .one_or_none()
            )
            if binding is None or binding.canonical_claims != canonical_claims:
                raise TelephonyNumberInventoryConflictError(
                    "g008_inbound_binding_conflict"
                )
            if binding.state == "bound":
                return self._g008_inbound_binding_data(binding)
            if binding.state != "issuing":
                raise TelephonyNumberInventoryConflictError(
                    "g008_inbound_binding_conflict"
                )
            stage = (
                (
                    await session.execute(
                        select(G008ExecutionStageModel)
                        .where(
                            G008ExecutionStageModel.id
                            == binding.execution_stage_id,
                            G008ExecutionStageModel.organization_id
                            == organization_id,
                            G008ExecutionStageModel.stage == "inbound_call",
                            G008ExecutionStageModel.ordinal == 3,
                            G008ExecutionStageModel.state == "started",
                        )
                        .with_for_update()
                        .execution_options(populate_existing=True)
                    )
                )
                .scalars()
                .one_or_none()
            )
            if stage is None or stage.stock_call_id_digest is not None:
                raise TelephonyNumberInventoryConflictError(
                    "g008_inbound_binding_conflict"
                )
            bound_at = (
                await session.execute(select(func.clock_timestamp()))
            ).scalar_one()
            if bound_at >= binding.authority_deadline_at:
                raise TelephonyNumberInventoryConflictError(
                    "g008_inbound_binding_expired"
                )
            binding.receipt_key_id = receipt["receipt_key_id"]
            binding.receipt_spki_digest = receipt["receipt_spki_digest"]
            binding.receipt_signature_digest = receipt[
                "receipt_signature_digest"
            ]
            binding.receipt_unsigned_digest = receipt["receipt_unsigned_digest"]
            binding.recovery_ciphertext = receipt["recovery_ciphertext"]
            binding.recovery_ciphertext_digest = receipt[
                "recovery_ciphertext_digest"
            ]
            binding.state = "bound"
            binding.bound_at = bound_at
            stage.account_uuid = binding.account_uuid
            stage.application_uuid = binding.application_uuid
            stage.run_uuid = binding.run_uuid
            stage.attempt_uuid = binding.attempt_uuid
            stage.stock_call_id_digest = binding.stock_call_id_digest
            stage.idempotency_digest = hashlib.sha256(
                binding.idempotency_uuid.encode("utf-8")
            ).hexdigest()
            stage.request_digest = binding.request_digest
            stage.did_digest = binding.did_digest
            stage.caller_digest = binding.caller_digest
            stage.authority_deadline_at = binding.authority_deadline_at
            stage.bound_at = bound_at
            stage.bind_receipt_digest = receipt["receipt_unsigned_digest"]
            stage.bind_receipt_signature_digest = receipt[
                "receipt_signature_digest"
            ]
            binding_data = self._g008_inbound_binding_data(binding)
            await session.commit()
            return binding_data

    async def claim_reserved_inbound_and_bind(
        self,
        payload: dict[str, Any],
        *,
        receipt_builder: Callable[
            [dict[str, Any]], Awaitable[dict[str, Any]]
        ],
    ) -> dict[str, Any]:
        keys = {
            "organization_id",
            "account_uuid",
            "application_uuid",
            "stock_call_uuid",
            "did_digest",
            "caller_digest",
        }
        self._validate_g008_payload(payload, required=keys, allowed=keys)
        organization_id = payload["organization_id"]
        if (
            isinstance(organization_id, bool)
            or not isinstance(organization_id, int)
            or organization_id <= 0
        ):
            raise TelephonyNumberInventoryConflictError("g008_organization_invalid")
        account_uuid = self._validate_g008_uuid(payload["account_uuid"])
        application_uuid = self._validate_g008_uuid(payload["application_uuid"])
        stock_call_uuid = self._validate_g008_uuid(payload["stock_call_uuid"])
        did_digest = self._validate_g008_digest(payload["did_digest"])
        caller_digest = self._validate_g008_digest(payload["caller_digest"])
        stock_call_id_digest = hashlib.sha256(
            stock_call_uuid.encode("utf-8")
        ).hexdigest()
        request_claims = {
            "account_uuid": account_uuid,
            "application_uuid": application_uuid,
            "caller_digest": caller_digest,
            "did_digest": did_digest,
            "organization_id": organization_id,
            "stock_call_uuid": stock_call_uuid,
        }
        request_digest = hashlib.sha256(
            json.dumps(
                request_claims, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

        async with self.async_session() as session:
            await self._g008_organization_lock(session, organization_id)
            existing = (
                (
                    await session.execute(
                        select(G008InboundBindingModel)
                        .where(
                            G008InboundBindingModel.organization_id
                            == organization_id,
                            G008InboundBindingModel.account_uuid == account_uuid,
                            G008InboundBindingModel.stock_call_id_digest
                            == stock_call_id_digest,
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .one_or_none()
            )
            if existing is not None:
                if (
                    existing.application_uuid != application_uuid
                    or existing.stock_call_uuid != stock_call_uuid
                    or not _digest_equal(existing.did_digest, did_digest)
                    or not _digest_equal(existing.caller_digest, caller_digest)
                    or not _digest_equal(existing.request_digest, request_digest)
                ):
                    raise TelephonyNumberInventoryConflictError(
                        "g008_inbound_binding_conflict"
                    )
                if existing.state == "bound":
                    return self._g008_inbound_binding_data(existing)
                database_now = (
                    await session.execute(select(func.clock_timestamp()))
                ).scalar_one()
                if database_now >= existing.authority_deadline_at:
                    raise TelephonyNumberInventoryConflictError(
                        "g008_inbound_binding_expired"
                    )
                existing.issuance_attempt_count += 1
                existing.lease_expires_at = min(
                    database_now + timedelta(seconds=15),
                    existing.authority_deadline_at,
                )
                binding_id = existing.id
                canonical_claims = dict(existing.canonical_claims)
                await session.commit()
                return await self._resume_g008_inbound_binding(
                    organization_id=organization_id,
                    binding_id=binding_id,
                    canonical_claims=canonical_claims,
                    receipt_builder=receipt_builder,
                )

            database_now = (
                await session.execute(select(func.clock_timestamp()))
            ).scalar_one()
            matches = (
                (
                    await session.execute(
                        select(G008ExecutionSealModel, G008ExecutionStageModel)
                        .join(
                            G008ExecutionStageModel,
                            G008ExecutionStageModel.execution_seal_id
                            == G008ExecutionSealModel.id,
                        )
                        .where(
                            G008ExecutionSealModel.organization_id
                            == organization_id,
                            G008ExecutionSealModel.reserved_inbound_did_digest
                            == did_digest,
                            G008ExecutionSealModel.reserved_inbound_caller_digest
                            == caller_digest,
                            G008ExecutionSealModel.state == "running",
                            G008ExecutionSealModel.live_window_starts_at
                            <= database_now,
                            G008ExecutionSealModel.live_window_expires_at
                            >= database_now + timedelta(seconds=60),
                            G008ExecutionStageModel.organization_id
                            == organization_id,
                            G008ExecutionStageModel.stage == "inbound_call",
                            G008ExecutionStageModel.ordinal == 3,
                            G008ExecutionStageModel.state == "started",
                            G008ExecutionStageModel.started_at.is_not(None),
                            G008ExecutionStageModel.started_at <= database_now,
                        )
                        .order_by(G008ExecutionSealModel.id)
                        .limit(2)
                        .with_for_update()
                    )
                )
                .all()
            )
            if len(matches) != 1:
                raise TelephonyNumberInventoryConflictError(
                    "g008_inbound_reservation_not_claimable"
                )
            seal, stage = matches[0]
            run_uuid = str(uuid4())
            attempt_uuid = str(uuid4())
            idempotency_uuid = str(uuid4())
            bind_receipt_uuid = str(uuid4())
            authority_deadline_at = database_now + timedelta(seconds=60)
            canonical_claims = {
                **request_claims,
                "algorithm": "ES256",
                "attempt_uuid": attempt_uuid,
                "authority_deadline_at": authority_deadline_at.isoformat(),
                "bind_receipt_uuid": bind_receipt_uuid,
                "candidate_digest": seal.candidate_digest,
                "direction": "inbound",
                "domain": "recova.onnuri.smoke.g008.inbound-bind.v1",
                "execution_seal_uuid": seal.execution_seal_uuid,
                "execution_stage_uuid": stage.stage_uuid,
                "gate_envelope_digest": seal.gate_envelope_digest,
                "idempotency_uuid": idempotency_uuid,
                "issued_at": database_now.isoformat(),
                "request_digest": request_digest,
                "run_uuid": run_uuid,
                "schema": "recova-g008-inbound-bind-receipt-v1",
                "stock_call_id_digest": stock_call_id_digest,
            }
            binding = G008InboundBindingModel(
                organization_id=organization_id,
                execution_stage_id=stage.id,
                account_uuid=account_uuid,
                application_uuid=application_uuid,
                stock_call_uuid=stock_call_uuid,
                stock_call_id_digest=stock_call_id_digest,
                did_digest=did_digest,
                caller_digest=caller_digest,
                direction="inbound",
                run_uuid=run_uuid,
                attempt_uuid=attempt_uuid,
                idempotency_uuid=idempotency_uuid,
                bind_receipt_uuid=bind_receipt_uuid,
                request_digest=request_digest,
                canonical_claims=canonical_claims,
                state="issuing",
                lease_expires_at=database_now + timedelta(seconds=15),
                issuance_attempt_count=1,
                authority_deadline_at=authority_deadline_at,
                issued_at=database_now,
            )
            session.add(binding)
            try:
                await session.flush()
                binding_id = binding.id
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise TelephonyNumberInventoryConflictError(
                    "g008_inbound_binding_conflict"
                ) from exc

        receipt = self._validate_g008_bind_receipt(
            await receipt_builder({"canonical_claims": dict(canonical_claims)}),
            canonical_claims=canonical_claims,
        )

        async with self.async_session() as session:
            await self._g008_organization_lock(session, organization_id)
            binding = (
                (
                    await session.execute(
                        select(G008InboundBindingModel)
                        .where(
                            G008InboundBindingModel.id == binding_id,
                            G008InboundBindingModel.organization_id
                            == organization_id,
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .one_or_none()
            )
            if binding is None or binding.canonical_claims != canonical_claims:
                raise TelephonyNumberInventoryConflictError(
                    "g008_inbound_binding_conflict"
                )
            if binding.state == "bound":
                return self._g008_inbound_binding_data(binding)
            if binding.state != "issuing":
                raise TelephonyNumberInventoryConflictError(
                    "g008_inbound_binding_conflict"
                )
            bound_at = (
                await session.execute(select(func.clock_timestamp()))
            ).scalar_one()
            if bound_at >= binding.authority_deadline_at:
                raise TelephonyNumberInventoryConflictError(
                    "g008_inbound_binding_expired"
                )
            binding.receipt_key_id = receipt["receipt_key_id"]
            binding.receipt_spki_digest = receipt["receipt_spki_digest"]
            binding.receipt_signature_digest = receipt[
                "receipt_signature_digest"
            ]
            binding.receipt_unsigned_digest = receipt["receipt_unsigned_digest"]
            binding.recovery_ciphertext = receipt["recovery_ciphertext"]
            binding.recovery_ciphertext_digest = receipt[
                "recovery_ciphertext_digest"
            ]
            binding.state = "bound"
            binding.bound_at = bound_at
            await session.flush([binding])
            stage = (
                (
                    await session.execute(
                        select(G008ExecutionStageModel)
                        .where(
                            G008ExecutionStageModel.id == binding.execution_stage_id,
                            G008ExecutionStageModel.organization_id == organization_id,
                            G008ExecutionStageModel.stage == "inbound_call",
                            G008ExecutionStageModel.ordinal == 3,
                            G008ExecutionStageModel.state == "started",
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .one_or_none()
            )
            if stage is None or stage.stock_call_id_digest is not None:
                raise TelephonyNumberInventoryConflictError(
                    "g008_inbound_binding_conflict"
                )
            stage.account_uuid = binding.account_uuid
            stage.application_uuid = binding.application_uuid
            stage.run_uuid = binding.run_uuid
            stage.attempt_uuid = binding.attempt_uuid
            stage.stock_call_id_digest = binding.stock_call_id_digest
            stage.idempotency_digest = hashlib.sha256(
                binding.idempotency_uuid.encode("utf-8")
            ).hexdigest()
            stage.request_digest = binding.request_digest
            stage.did_digest = binding.did_digest
            stage.caller_digest = binding.caller_digest
            stage.authority_deadline_at = binding.authority_deadline_at
            stage.bound_at = bound_at
            stage.bind_receipt_digest = receipt["receipt_unsigned_digest"]
            stage.bind_receipt_signature_digest = receipt[
                "receipt_signature_digest"
            ]
            binding_data = self._g008_inbound_binding_data(binding)
            await session.commit()
            return binding_data

    async def lookup_g008_bound_status(
        self,
        *,
        organization_id: int,
        account_uuid: str,
        stock_call_id_digest: str,
    ) -> dict[str, Any] | None:
        if (
            isinstance(organization_id, bool)
            or not isinstance(organization_id, int)
            or organization_id <= 0
        ):
            raise TelephonyNumberInventoryConflictError(
                "g008_inbound_status_context_invalid"
            )
        account_uuid = self._validate_g008_uuid(account_uuid)
        self._validate_g008_digest(stock_call_id_digest)
        async with self.async_session() as session:
            result = (
                await session.execute(
                    select(
                        G008InboundBindingModel,
                        G008ExecutionStageModel,
                        G008ExecutionSealModel,
                    )
                    .join(
                        G008ExecutionStageModel,
                        G008ExecutionStageModel.id
                        == G008InboundBindingModel.execution_stage_id,
                    )
                    .join(
                        G008ExecutionSealModel,
                        G008ExecutionSealModel.id
                        == G008ExecutionStageModel.execution_seal_id,
                    )
                    .where(
                        G008InboundBindingModel.organization_id == organization_id,
                        G008InboundBindingModel.account_uuid == account_uuid,
                        G008InboundBindingModel.stock_call_id_digest
                        == stock_call_id_digest,
                        G008ExecutionStageModel.organization_id == organization_id,
                        G008ExecutionSealModel.organization_id == organization_id,
                    )
                )
            ).one_or_none()
            if result is None:
                return None
            binding, stage, seal = result
            data = self._g008_inbound_binding_data(binding)
            terminal = (
                stage.state in {"succeeded", "failed", "contained"}
                or seal.state in {"contained", "completed", "failed"}
            )
            data.update(
                {
                    "seal_state": seal.state,
                    "stage_state": stage.state,
                    "terminal_class": stage.terminal_class,
                    "finalized_at": stage.finalized_at,
                    "terminal": terminal,
                    "terminal_state": (
                        stage.state
                        if stage.state in {"succeeded", "failed", "contained"}
                        else seal.state
                        if seal.state in {"contained", "completed", "failed"}
                        else None
                    ),
                }
            )
            return data

    async def _resolve_assignment_config(
        self,
        session,
        *,
        provider: str,
        organization_id: int,
        telephony_configuration_id: int | None,
    ) -> TelephonyConfigurationModel:
        if telephony_configuration_id is not None:
            config = await session.get(
                TelephonyConfigurationModel, telephony_configuration_id
            )
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
            phone = await session.get(
                TelephonyPhoneNumberModel, row.telephony_phone_number_id
            )
            if phone and phone.organization_id != organization_id:
                raise TelephonyNumberInventoryConflictError(
                    "telephony_number_inventory_phone_number_mismatch"
                )

        if phone is None:
            existing = (
                (
                    await session.execute(
                        select(TelephonyPhoneNumberModel).where(
                            TelephonyPhoneNumberModel.organization_id
                            == organization_id,
                            TelephonyPhoneNumberModel.address_normalized
                            == row.address_normalized,
                        )
                    )
                )
                .scalars()
                .first()
            )
            if existing:
                metadata = existing.extra_metadata or {}
                existing_inventory_id = _coerce_inventory_id(
                    metadata.get(INVENTORY_ID_METADATA_KEY)
                )
                if (
                    INVENTORY_ID_METADATA_KEY in metadata
                    and existing_inventory_id is None
                ) or existing_inventory_id not in (None, row.id):
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
                    extra_metadata=_with_assigned_inventory_metadata(
                        {},
                        inventory_id=row.id,
                    ),
                )
                session.add(phone)
                await session.flush()

        phone.telephony_configuration_id = config.id
        phone.label = label if label is not None else phone.label
        if inbound_workflow_id is not None:
            phone.inbound_workflow_id = inbound_workflow_id
        phone.is_active = True
        phone.extra_metadata = _with_assigned_inventory_metadata(
            _strip_live_validation_metadata(phone.extra_metadata),
            inventory_id=row.id,
        )
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
    async def _ensure_organization_exists(
        session, organization_id: int
    ) -> OrganizationModel:
        organization = await session.get(OrganizationModel, organization_id)
        if not organization:
            raise TelephonyNumberInventoryNotFoundError("organization_not_found")
        return organization

    @staticmethod
    async def _require_superuser(session, actor_user_id: int) -> UserModel:
        actor = await session.get(UserModel, actor_user_id)
        if actor is None or not actor.is_superuser:
            raise TelephonyNumberInventoryConflictError(
                "onnuri_staging_superuser_required"
            )
        return actor

    @staticmethod
    async def _require_organization_member(
        session, actor_user_id: int, organization_id: int
    ) -> UserModel:
        result = await session.execute(
            select(UserModel)
            .join(UserModel.organizations)
            .where(
                UserModel.id == actor_user_id,
                OrganizationModel.id == organization_id,
            )
        )
        actor = result.scalars().first()
        if actor is None:
            raise TelephonyNumberInventoryConflictError(
                "onnuri_staging_organization_membership_required"
            )
        return actor

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


def _coerce_inventory_id(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.isdecimal():
        parsed = int(value)
        return parsed if parsed > 0 else None
    return None


def _with_assigned_inventory_metadata(
    extra_metadata: dict[str, Any] | None,
    *,
    inventory_id: int,
    telephony_phone_number_id: int | None = None,
) -> dict[str, Any]:
    metadata = dict(extra_metadata or {})
    metadata[RECOVA_INVENTORY_STATE_KEY] = INVENTORY_STATUS_ASSIGNED
    metadata[MANAGED_BY_METADATA_KEY] = MANAGED_INVENTORY_CREDENTIAL
    metadata[INVENTORY_ID_METADATA_KEY] = inventory_id
    if telephony_phone_number_id is not None:
        metadata[TELEPHONY_PHONE_NUMBER_ID_METADATA_KEY] = telephony_phone_number_id
    return metadata


def _with_live_validation_metadata(
    extra_metadata: dict[str, Any] | None,
    *,
    row: TelephonyNumberInventoryModel,
    live_validation_source: str,
    live_validation_evidence_id: str,
    contract_version: str,
    call_attempt_id: str | None,
) -> dict[str, Any]:
    metadata = dict(extra_metadata or {})
    metadata[CONTRACT_VERSION_METADATA_KEY] = contract_version
    metadata[IS_CONTRACT_FIXTURE_METADATA_KEY] = False
    metadata[LIVE_TRUNK_VALIDATED_METADATA_KEY] = True
    metadata[LIVE_VALIDATION_SOURCE_METADATA_KEY] = live_validation_source
    metadata[LIVE_VALIDATION_EVIDENCE_ID_METADATA_KEY] = live_validation_evidence_id
    metadata[LIVE_VALIDATION_TRUSTED_WRITER_METADATA_KEY] = (
        LIVE_VALIDATION_TRUSTED_WRITER
    )
    metadata[PROVIDER_METADATA_KEY] = row.provider
    metadata[PROVIDER_CONFIG_ID_METADATA_KEY] = str(row.telephony_configuration_id)
    metadata[TELEPHONY_CONFIGURATION_ID_METADATA_KEY] = row.telephony_configuration_id
    metadata[PHONE_NUMBER_ID_METADATA_KEY] = row.telephony_phone_number_id
    metadata[TELEPHONY_PHONE_NUMBER_ID_METADATA_KEY] = row.telephony_phone_number_id
    metadata[INVENTORY_ID_METADATA_KEY] = row.id
    if call_attempt_id:
        metadata[CALL_ATTEMPT_ID_METADATA_KEY] = call_attempt_id
    return metadata


def _strip_assigned_inventory_metadata(
    extra_metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    metadata = dict(extra_metadata or {})
    metadata.pop(RECOVA_INVENTORY_STATE_KEY, None)
    metadata.pop(INVENTORY_ID_METADATA_KEY, None)
    metadata.pop(TELEPHONY_PHONE_NUMBER_ID_METADATA_KEY, None)
    if metadata.get(MANAGED_BY_METADATA_KEY) == MANAGED_INVENTORY_CREDENTIAL:
        metadata.pop(MANAGED_BY_METADATA_KEY, None)
    return metadata


def _strip_live_validation_metadata(
    extra_metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    metadata = dict(extra_metadata or {})
    for key in (
        CONTRACT_VERSION_METADATA_KEY,
        IS_CONTRACT_FIXTURE_METADATA_KEY,
        LIVE_TRUNK_VALIDATED_METADATA_KEY,
        LIVE_VALIDATION_SOURCE_METADATA_KEY,
        LIVE_VALIDATION_EVIDENCE_ID_METADATA_KEY,
        LIVE_VALIDATION_TRUSTED_WRITER_METADATA_KEY,
        PROVIDER_CONFIG_ID_METADATA_KEY,
        TELEPHONY_CONFIGURATION_ID_METADATA_KEY,
        PHONE_NUMBER_ID_METADATA_KEY,
        CALL_ATTEMPT_ID_METADATA_KEY,
    ):
        metadata.pop(key, None)
    return metadata


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.isoformat()
