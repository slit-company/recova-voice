"""Atomic telephony-wide admission control for live call attempts."""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any

import redis.asyncio as aioredis
from loguru import logger

from api.constants import DEFAULT_ORG_CONCURRENCY_LIMIT, REDIS_URL
from api.services.telephony.cdr import (
    TelephonyEventRecord,
    TelephonyEventType,
    TelephonyFailureCategory,
    build_call_attempt_id,
    record_telephony_event,
)
from api.services.telephony.ops_alerts import (
    TelephonyOpsAlert,
    TelephonyOpsAlertSeverity,
    TelephonyOpsAlertSink,
    TelephonyOpsAlertType,
    telephony_ops_alert_sink,
)


@dataclass(frozen=True)
class TelephonyAdmissionRequest:
    provider: str
    organization_id: int
    direction: str
    workflow_run_id: int | None = None
    call_attempt_id: str | None = None
    event_id: str | None = None
    provider_call_id: str | None = None
    telephony_configuration_id: int | None = None
    telephony_phone_number_id: int | None = None
    inventory_id: int | None = None
    workflow_id: int | None = None
    campaign_id: int | None = None
    queued_run_id: int | None = None
    trunk: str | None = None
    profile: str | None = None
    contract_version: str | None = None
    is_contract_fixture: bool = False
    live_validation_source: str | None = None
    live_validation_evidence_id: str | None = None


@dataclass(frozen=True)
class TelephonyAdmissionResult:
    allowed: bool
    call_attempt_id: str
    slot_id: str | None = None
    denied_dimension: str | None = None
    reason: str | None = None
    existing: bool = False


class TelephonyAdmissionController:
    """Redis-backed admission counter with idempotent acquire/release."""

    def __init__(
        self,
        *,
        redis_client: Any | None = None,
        alert_sink: TelephonyOpsAlertSink | None = None,
        default_ttl_seconds: int | None = None,
        stale_slot_seconds: int | None = None,
    ):
        self._redis_client = redis_client
        self._alert_sink = alert_sink or telephony_ops_alert_sink
        self.default_ttl_seconds = default_ttl_seconds or int(
            os.getenv("TELEPHONY_ADMISSION_SLOT_TTL_SECONDS", "3600")
        )
        self.stale_slot_seconds = stale_slot_seconds or int(
            os.getenv("TELEPHONY_ADMISSION_STALE_SECONDS", "1800")
        )
        self.global_limit = int(os.getenv("TELEPHONY_ADMISSION_GLOBAL_LIMIT", "100"))
        self.provider_limit = int(os.getenv("TELEPHONY_ADMISSION_PROVIDER_LIMIT", "60"))
        self.org_limit = int(
            os.getenv("TELEPHONY_ADMISSION_ORG_LIMIT", str(DEFAULT_ORG_CONCURRENCY_LIMIT))
        )
        self.direction_limit = int(os.getenv("TELEPHONY_ADMISSION_DIRECTION_LIMIT", "60"))
        self.trunk_limit = int(os.getenv("TELEPHONY_ADMISSION_TRUNK_LIMIT", "30"))

    async def _get_redis(self):
        if self._redis_client is None:
            self._redis_client = await aioredis.from_url(REDIS_URL, decode_responses=True)
        return self._redis_client

    async def acquire(self, request: TelephonyAdmissionRequest) -> TelephonyAdmissionResult:
        call_attempt_id = build_call_attempt_id(
            direction=request.direction,
            provider=request.provider,
            workflow_run_id=request.workflow_run_id,
            call_attempt_id=request.call_attempt_id,
            provider_call_id=request.provider_call_id,
            event_id=request.event_id,
        )
        dimensions = self._dimensions(request)
        slot_id = f"tas_{uuid.uuid4().hex}"
        now = time.time()
        stale_cutoff = now - self.stale_slot_seconds
        slot_key = self._slot_key(call_attempt_id)
        workflow_key = self._workflow_key(request.workflow_run_id)
        slot_payload = {
            "slot_id": slot_id,
            "call_attempt_id": call_attempt_id,
            "provider": request.provider,
            "organization_id": str(request.organization_id),
            "direction": request.direction,
            "workflow_run_id": "" if request.workflow_run_id is None else str(request.workflow_run_id),
            "telephony_configuration_id": ""
            if request.telephony_configuration_id is None
            else str(request.telephony_configuration_id),
            "telephony_phone_number_id": ""
            if request.telephony_phone_number_id is None
            else str(request.telephony_phone_number_id),
            "inventory_id": ""
            if request.inventory_id is None
            else str(request.inventory_id),
            "workflow_id": "" if request.workflow_id is None else str(request.workflow_id),
            "campaign_id": "" if request.campaign_id is None else str(request.campaign_id),
            "queued_run_id": "" if request.queued_run_id is None else str(request.queued_run_id),
            "contract_version": request.contract_version or "",
            "is_contract_fixture": "1" if request.is_contract_fixture else "0",
            "live_validation_source": request.live_validation_source or "",
            "live_validation_evidence_id": request.live_validation_evidence_id or "",
            "dimensions": json.dumps([key for key, _ in dimensions]),
            "acquired_at": str(now),
        }

        lua_script = """
        local slot_key = KEYS[1]
        local workflow_key = KEYS[2]
        local now = tonumber(ARGV[1])
        local stale_cutoff = tonumber(ARGV[2])
        local ttl = tonumber(ARGV[3])
        local slot_id = ARGV[4]
        local dimension_count = tonumber(ARGV[5])
        local payload_start = 6 + (dimension_count * 2)

        if redis.call('EXISTS', slot_key) == 1 then
          local existing_slot_id = redis.call('HGET', slot_key, 'slot_id')
          redis.call('EXPIRE', slot_key, ttl)
          if workflow_key ~= '' then redis.call('EXPIRE', workflow_key, ttl) end
          return {1, existing_slot_id, 'existing'}
        end

        for i = 0, dimension_count - 1 do
          local key = ARGV[6 + (i * 2)]
          redis.call('ZREMRANGEBYSCORE', key, 0, stale_cutoff)
        end

        for i = 0, dimension_count - 1 do
          local key = ARGV[6 + (i * 2)]
          local limit = tonumber(ARGV[7 + (i * 2)])
          if redis.call('ZCARD', key) >= limit then
            return {0, '', key}
          end
        end

        for i = 0, dimension_count - 1 do
          local key = ARGV[6 + (i * 2)]
          redis.call('ZADD', key, now, slot_id)
          redis.call('EXPIRE', key, ttl)
        end

        for i = payload_start, #ARGV, 2 do
          redis.call('HSET', slot_key, ARGV[i], ARGV[i + 1])
        end
        redis.call('EXPIRE', slot_key, ttl)
        if workflow_key ~= '' then
          redis.call('SETEX', workflow_key, ttl, slot_key)
        end
        return {1, slot_id, 'acquired'}
        """

        redis_client = await self._get_redis()
        dimension_args: list[Any] = []
        for key, limit in dimensions:
            dimension_args.extend([key, limit])
        payload_args: list[Any] = []
        for key, value in slot_payload.items():
            payload_args.extend([key, value])

        try:
            result = await redis_client.eval(
                lua_script,
                2,
                slot_key,
                workflow_key or "",
                now,
                stale_cutoff,
                self.default_ttl_seconds,
                slot_id,
                len(dimensions),
                *dimension_args,
                *payload_args,
            )
        except Exception as exc:
            logger.error(f"Telephony admission acquire failed closed: {exc}")
            await self._emit_capacity_alert(
                request,
                denied_dimension="redis_unavailable",
                summary="Telephony admission Redis unavailable; call denied fail-closed",
            )
            return TelephonyAdmissionResult(
                allowed=False,
                call_attempt_id=call_attempt_id,
                denied_dimension="redis_unavailable",
                reason="admission_unavailable",
            )

        allowed = bool(int(result[0]))
        if allowed:
            acquired_slot_id = result[1]
            existing = result[2] == "existing"
            if not existing:
                await record_telephony_event(
                    TelephonyEventRecord(
                        provider=request.provider,
                        direction=request.direction,
                        event_type=TelephonyEventType.ADMISSION_ACQUIRED,
                        status="acquired",
                        organization_id=request.organization_id,
                        telephony_configuration_id=request.telephony_configuration_id,
                        telephony_phone_number_id=request.telephony_phone_number_id,
                        inventory_id=request.inventory_id,
                        workflow_id=request.workflow_id,
                        workflow_run_id=request.workflow_run_id,
                        campaign_id=request.campaign_id,
                        queued_run_id=request.queued_run_id,
                        call_attempt_id=call_attempt_id,
                        event_id=f"admission-acquired:{call_attempt_id}",
                        admission_slot_id=acquired_slot_id,
                        contract_version=request.contract_version,
                        is_contract_fixture=request.is_contract_fixture,
                        live_validation_source=request.live_validation_source,
                        live_validation_evidence_id=request.live_validation_evidence_id,
                    )
                )
            return TelephonyAdmissionResult(
                allowed=True,
                call_attempt_id=call_attempt_id,
                slot_id=acquired_slot_id,
                existing=existing,
            )

        denied_dimension = result[2]
        await record_telephony_event(
            TelephonyEventRecord(
                provider=request.provider,
                direction=request.direction,
                event_type=TelephonyEventType.ADMISSION_DENIED,
                status="denied",
                organization_id=request.organization_id,
                telephony_configuration_id=request.telephony_configuration_id,
                telephony_phone_number_id=request.telephony_phone_number_id,
                inventory_id=request.inventory_id,
                workflow_id=request.workflow_id,
                workflow_run_id=request.workflow_run_id,
                campaign_id=request.campaign_id,
                queued_run_id=request.queued_run_id,
                call_attempt_id=call_attempt_id,
                event_id=f"admission-denied:{call_attempt_id}:{denied_dimension}",
                failure_category=TelephonyFailureCategory.ADMISSION_CAPACITY,
                contract_version=request.contract_version,
                is_contract_fixture=request.is_contract_fixture,
                live_validation_source=request.live_validation_source,
                live_validation_evidence_id=request.live_validation_evidence_id,
            )
        )
        await self._emit_capacity_alert(request, denied_dimension=denied_dimension)
        return TelephonyAdmissionResult(
            allowed=False,
            call_attempt_id=call_attempt_id,
            denied_dimension=denied_dimension,
            reason="capacity_denied",
        )

    async def release(
        self,
        *,
        call_attempt_id: str | None = None,
        workflow_run_id: int | None = None,
        slot_id: str | None = None,
        reason: str,
    ) -> bool:
        redis_client = await self._get_redis()
        slot_key = self._slot_key(call_attempt_id) if call_attempt_id else None
        if workflow_run_id is not None:
            workflow_slot_key = await redis_client.get(self._workflow_key(workflow_run_id))
            if workflow_slot_key:
                slot_key = workflow_slot_key
        if slot_id and not slot_key:
            slot_key = f"telephony_admission:slot_by_id:{slot_id}"
        if not slot_key:
            return False

        lua_script = """
        local slot_key = KEYS[1]
        if redis.call('EXISTS', slot_key) == 0 then
          return {0, '', '', '', '', '', '', '', '', ''}
        end
        local slot_id = redis.call('HGET', slot_key, 'slot_id') or ''
        local dimensions_json = redis.call('HGET', slot_key, 'dimensions') or '[]'
        local call_attempt_id = redis.call('HGET', slot_key, 'call_attempt_id') or ''
        local provider = redis.call('HGET', slot_key, 'provider') or ''
        local organization_id = redis.call('HGET', slot_key, 'organization_id') or ''
        local direction = redis.call('HGET', slot_key, 'direction') or ''
        local workflow_run_id = redis.call('HGET', slot_key, 'workflow_run_id') or ''
        local workflow_key = ''
        if workflow_run_id ~= '' then workflow_key = 'telephony_admission:workflow_run:' .. workflow_run_id end
        local dimensions = cjson.decode(dimensions_json)
        for _, key in ipairs(dimensions) do
          redis.call('ZREM', key, slot_id)
        end
        redis.call('DEL', slot_key)
        if workflow_key ~= '' then redis.call('DEL', workflow_key) end
        return {1, slot_id, call_attempt_id, provider, organization_id, direction, workflow_run_id,
                redis.call('HGET', slot_key, 'telephony_configuration_id') or '',
                redis.call('HGET', slot_key, 'telephony_phone_number_id') or '',
                redis.call('HGET', slot_key, 'contract_version') or ''}
        """
        # The final HGETs above run after DEL in Redis and return empty strings;
        # the fields needed for event identity are captured before deletion.
        try:
            result = await redis_client.eval(lua_script, 1, slot_key)
        except Exception as exc:
            logger.error(f"Telephony admission release failed: {exc}")
            return False

        released = bool(int(result[0]))
        if not released:
            return False

        released_attempt_id = result[2] or call_attempt_id
        provider = result[3] or "unknown"
        organization_id = _parse_optional_int(result[4])
        direction = result[5] or "unknown"
        released_workflow_run_id = _parse_optional_int(result[6]) or workflow_run_id
        await record_telephony_event(
            TelephonyEventRecord(
                provider=provider,
                direction=direction,
                event_type=TelephonyEventType.ADMISSION_RELEASED,
                status="released",
                organization_id=organization_id,
                workflow_run_id=released_workflow_run_id,
                call_attempt_id=released_attempt_id,
                event_id=f"admission-release:{released_attempt_id}:{reason}",
                release_reason=reason,
                admission_slot_id=result[1],
            )
        )
        return True

    async def emit_slot_leak(
        self,
        *,
        provider: str,
        organization_id: int | None,
        direction: str,
        call_attempt_id: str,
        slot_id: str,
    ) -> None:
        await record_telephony_event(
            TelephonyEventRecord(
                provider=provider,
                direction=direction,
                event_type=TelephonyEventType.SLOT_LEAK,
                status="failed",
                organization_id=organization_id,
                call_attempt_id=call_attempt_id,
                event_id=f"slot-leak:{call_attempt_id}:{slot_id}",
                failure_category=TelephonyFailureCategory.SLOT_LEAK,
                admission_slot_id=slot_id,
            )
        )
        await self._alert_sink.emit(
            TelephonyOpsAlert(
                alert_type=TelephonyOpsAlertType.SLOT_LEAK,
                severity=TelephonyOpsAlertSeverity.CRITICAL,
                summary="Telephony admission slot leak detected",
                organization_id=organization_id,
                provider=provider,
                details={"call_attempt_id": call_attempt_id, "slot_id": slot_id},
                dedupe_components=(direction,),
            )
        )

    def _dimensions(self, request: TelephonyAdmissionRequest) -> list[tuple[str, int]]:
        dimensions = [
            ("telephony_admission:dim:global", self.global_limit),
            (f"telephony_admission:dim:provider:{request.provider}", self.provider_limit),
            (
                f"telephony_admission:dim:org:{request.organization_id}",
                self.org_limit,
            ),
            (
                f"telephony_admission:dim:provider:{request.provider}:direction:{request.direction}",
                self.direction_limit,
            ),
        ]
        trunk = request.trunk or request.profile
        if trunk:
            dimensions.append(
                (f"telephony_admission:dim:provider:{request.provider}:trunk:{trunk}", self.trunk_limit)
            )
        return dimensions

    async def _emit_capacity_alert(
        self,
        request: TelephonyAdmissionRequest,
        *,
        denied_dimension: str,
        summary: str | None = None,
    ) -> None:
        await self._alert_sink.emit(
            TelephonyOpsAlert(
                alert_type=TelephonyOpsAlertType.ADMISSION_CAPACITY,
                severity=TelephonyOpsAlertSeverity.WARNING,
                summary=summary or "Telephony admission capacity denied a call attempt",
                organization_id=request.organization_id,
                provider=request.provider,
                details={
                    "direction": request.direction,
                    "denied_dimension": denied_dimension,
                    "workflow_run_id": request.workflow_run_id,
                    "campaign_id": request.campaign_id,
                    "queued_run_id": request.queued_run_id,
                    "contract_version": request.contract_version,
                    "live_validation_source": request.live_validation_source,
                    "live_validation_evidence_id": request.live_validation_evidence_id,
                    "inventory_id": request.inventory_id,
                },
                is_contract_fixture=request.is_contract_fixture,
                dedupe_components=(request.direction, denied_dimension),
            )
        )

    @staticmethod
    def _slot_key(call_attempt_id: str) -> str:
        return f"telephony_admission:slot:{call_attempt_id}"

    @staticmethod
    def _workflow_key(workflow_run_id: int | None) -> str:
        return "" if workflow_run_id is None else f"telephony_admission:workflow_run:{workflow_run_id}"


def _parse_optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


telephony_admission_controller = TelephonyAdmissionController()
