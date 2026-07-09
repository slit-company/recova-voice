"""Typed telephony operations alerts with dedupe and escalation."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from loguru import logger

from api.db import db_client


class TelephonyOpsAlertType(StrEnum):
    TRUNK_NODE_HEALTH = "trunk_node_health"
    ROUTE_SYNC_FAILURE = "route_sync_failure"
    OUTBOUND_FAILURE_SPIKE = "outbound_failure_spike"
    ADMISSION_CAPACITY = "admission_capacity"
    MEDIA_STREAM_FAILURE = "media_stream_failure"
    SIGNATURE_FAILURE_SPIKE = "signature_failure_spike"
    MISSING_LATE_CDR = "missing_late_cdr"
    MISSING_RECORDING_UPLOAD = "missing_recording_upload"
    SLOT_LEAK = "slot_leak"
    NUMBER_QUARANTINE_ROUTING_SUSPICION = "number_quarantine_routing_suspicion"
    CONTRACT_SIMULATOR_REGRESSION = "contract_simulator_regression"
    PROVIDER_STATUS_FAILURE = "provider_status_failure"


class TelephonyOpsAlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True)
class TelephonyOpsAlert:
    alert_type: TelephonyOpsAlertType
    severity: TelephonyOpsAlertSeverity
    summary: str
    organization_id: int | None = None
    provider: str | None = None
    source: str = "runtime"
    details: dict[str, Any] = field(default_factory=dict)
    is_contract_fixture: bool = False
    dedupe_components: tuple[str, ...] = ()


_SENSITIVE_KEY_FRAGMENTS = (
    "account",
    "auth",
    "credential",
    "phone",
    "number",
    "destination",
    "caller",
    "called",
    "secret",
    "signature",
    "token",
    "call_id",
)


class TelephonyOpsAlertSink:
    """Sink facade selected by environment while preserving typed alert input."""

    def __init__(self, sink_name: str | None = None):
        self.sink_name = (sink_name or os.getenv("TELEPHONY_OPS_ALERT_SINK", "db")).lower()
        self.dedupe_window_seconds = int(
            os.getenv("TELEPHONY_OPS_ALERT_DEDUPE_WINDOW_SECONDS", "300")
        )
        self.escalation_threshold = int(
            os.getenv("TELEPHONY_OPS_ALERT_ESCALATION_THRESHOLD", "3")
        )
        self.page_contract_simulator = (
            os.getenv("TELEPHONY_CONTRACT_SIMULATOR_ALERTS_PAGE_LIVE", "false").lower()
            == "true"
        )

    async def emit(self, alert: TelephonyOpsAlert):
        details_redacted = redact_alert_details(alert.details)
        should_page_live_ops = self._should_page_live_ops(alert)
        dedupe_key = self._dedupe_key(alert)

        if self.sink_name == "disabled":
            logger.debug(f"Telephony ops alert disabled: {alert.alert_type}:{dedupe_key}")
            return None

        if self.sink_name == "log":
            logger.warning(
                "Telephony ops alert {} severity={} page_live={} dedupe={} details={}",
                alert.alert_type,
                alert.severity,
                should_page_live_ops,
                dedupe_key,
                details_redacted,
            )
            return None

        return await db_client.upsert_telephony_ops_alert(
            alert_type=alert.alert_type.value,
            severity=alert.severity.value,
            dedupe_key=dedupe_key,
            summary=alert.summary,
            details_redacted=details_redacted,
            organization_id=alert.organization_id,
            provider=alert.provider,
            source=alert.source,
            is_contract_fixture=alert.is_contract_fixture,
            should_page_live_ops=should_page_live_ops,
            escalation_threshold=self.escalation_threshold,
        )

    def _dedupe_key(self, alert: TelephonyOpsAlert) -> str:
        bucket = int(datetime.now(UTC).timestamp() // self.dedupe_window_seconds)
        components = [
            alert.alert_type.value,
            alert.severity.value,
            str(alert.organization_id or "global"),
            alert.provider or "unknown",
            alert.source,
            *alert.dedupe_components,
            str(bucket),
        ]
        return ":".join(_clean_component(component) for component in components)

    def _should_page_live_ops(self, alert: TelephonyOpsAlert) -> bool:
        if alert.is_contract_fixture or alert.source == "contract_simulator":
            return self.page_contract_simulator
        return alert.severity == TelephonyOpsAlertSeverity.CRITICAL


def _clean_component(component: str) -> str:
    return component.replace(":", "_")[:80]


def redact_alert_details(value: Any, *, key: object | None = None):
    if key is not None:
        key_text = str(key).lower()
        if any(fragment in key_text for fragment in _SENSITIVE_KEY_FRAGMENTS):
            return "[redacted]"
    if isinstance(value, dict):
        return {
            item_key: redact_alert_details(item_value, key=item_key)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [redact_alert_details(item) for item in value]
    return value


telephony_ops_alert_sink = TelephonyOpsAlertSink()
