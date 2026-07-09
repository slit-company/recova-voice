"""Recova-defined Jambonz V1 contract schemas, fixtures, and simulator helpers.

These artifacts are supplier-independent. They validate Recova's adapter and
runtime behavior before live SIP/070 trunk details are available. Payloads
created by this module are always contract fixtures and must not be counted as
live trunk readiness evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field

JAMBONZ_CONTRACT_VERSION = "jambonz_contract_v1"
JAMBONZ_PROVIDER = "jambonz"
JAMBONZ_SIGNATURE_HEADER = "x-recova-jambonz-signature"
JAMBONZ_TIMESTAMP_HEADER = "x-recova-jambonz-timestamp"
JAMBONZ_NONCE_HEADER = "x-recova-jambonz-nonce"
JAMBONZ_CONTRACT_MODE_HEADER = "x-recova-contract-mode"
JAMBONZ_CONTRACT_MODE_FIXTURE = "contract_fixture"
JAMBONZ_REPLAY_TOLERANCE_SECONDS = 300


class _ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class JambonzInboundWebhook(_ContractModel):
    provider: Literal["jambonz"] = JAMBONZ_PROVIDER
    contract_version: Literal["jambonz_contract_v1"] = JAMBONZ_CONTRACT_VERSION
    event_type: Literal["inbound"] = "inbound"
    account_id: str
    application_id: str | None = None
    call_id: str
    from_number: str
    to_number: str
    direction: Literal["inbound"] = "inbound"
    call_status: str = "ringing"
    from_country: str | None = "KR"
    to_country: str | None = "KR"
    is_contract_fixture: bool = True


class JambonzMediaStartFrame(_ContractModel):
    provider: Literal["jambonz"] = JAMBONZ_PROVIDER
    contract_version: Literal["jambonz_contract_v1"] = JAMBONZ_CONTRACT_VERSION
    event: Literal["start"] = "start"
    account_id: str
    application_id: str | None = None
    call_id: str
    stream_id: str
    codec: Literal["PCMU", "PCMA", "L16"] = "PCMU"
    sample_rate: int = 8000
    direction: Literal["inbound", "outbound"]
    is_contract_fixture: bool = True


class JambonzOutboundCallRequest(_ContractModel):
    provider: Literal["jambonz"] = JAMBONZ_PROVIDER
    contract_version: Literal["jambonz_contract_v1"] = JAMBONZ_CONTRACT_VERSION
    account_id: str
    application_id: str
    from_number: str
    to_number: str
    answer_url: str
    status_callback_url: str
    workflow_run_id: int | None = None
    workflow_id: int | None = None
    user_id: int | None = None
    timeout_seconds: int = 30
    outbound_profile_id: str | None = None
    is_contract_fixture: bool = False


class JambonzOutboundCallResponse(_ContractModel):
    provider: Literal["jambonz"] = JAMBONZ_PROVIDER
    contract_version: Literal["jambonz_contract_v1"] = JAMBONZ_CONTRACT_VERSION
    account_id: str
    call_id: str
    status: Literal["queued", "initiated", "ringing", "answered"] = "initiated"
    is_contract_fixture: bool = True


class JambonzStatusCallback(_ContractModel):
    provider: Literal["jambonz"] = JAMBONZ_PROVIDER
    contract_version: Literal["jambonz_contract_v1"] = JAMBONZ_CONTRACT_VERSION
    event_type: Literal["status"] = "status"
    account_id: str
    application_id: str | None = None
    call_id: str
    status: Literal[
        "initiated",
        "ringing",
        "answered",
        "completed",
        "busy",
        "no-answer",
        "failed",
        "canceled",
        "media-error",
    ]
    from_number: str
    to_number: str
    direction: Literal["inbound", "outbound"]
    duration_seconds: int | None = None
    failure_cause: str | None = None
    idempotency_key: str
    is_contract_fixture: bool = True


class JambonzCdrEvent(_ContractModel):
    provider: Literal["jambonz"] = JAMBONZ_PROVIDER
    contract_version: Literal["jambonz_contract_v1"] = JAMBONZ_CONTRACT_VERSION
    event_type: Literal["cdr"] = "cdr"
    account_id: str
    application_id: str | None = None
    call_id: str
    direction: Literal["inbound", "outbound"]
    from_number: str
    to_number: str
    started_at: str
    answered_at: str | None = None
    ended_at: str
    duration_seconds: int
    hangup_cause: str | None = None
    idempotency_key: str
    is_contract_fixture: bool = True


def canonical_json(payload: Mapping[str, Any] | BaseModel) -> str:
    if isinstance(payload, BaseModel):
        payload = payload.model_dump(exclude_none=True)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _header_lookup(headers: Mapping[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return ""


def build_signature(secret: str, raw_body: str, *, timestamp: int, nonce: str) -> str:
    signed = f"{timestamp}.{nonce}.{raw_body}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()


@dataclass
class JambonzReplayGuard:
    """Small process-local replay guard used by the contract adapter.

    Live multi-worker replay durability belongs in the shared admission/CDR lane;
    this guard still makes unsigned/replayed contract callbacks fail closed in
    unit and single-process runtime tests.
    """

    tolerance_seconds: int = JAMBONZ_REPLAY_TOLERANCE_SECONDS
    _seen: dict[str, int] = field(default_factory=dict)

    def check_and_store(
        self, nonce: str, timestamp: int, *, now: int | None = None, scope: str = ""
    ) -> bool:
        now = int(time.time()) if now is None else now
        cutoff = now - self.tolerance_seconds
        self._seen = {key: ts for key, ts in self._seen.items() if ts >= cutoff}
        replay_key = f"{scope}:{nonce}" if scope else nonce
        if replay_key in self._seen:
            return False
        self._seen[replay_key] = timestamp
        return True


def signed_headers(
    secret: str,
    payload: Mapping[str, Any] | BaseModel,
    *,
    timestamp: int | None = None,
    nonce: str | None = None,
    contract_mode: str = JAMBONZ_CONTRACT_MODE_FIXTURE,
) -> dict[str, str]:
    timestamp = int(time.time()) if timestamp is None else timestamp
    nonce = nonce or str(uuid.uuid4())
    raw_body = canonical_json(payload)
    return {
        JAMBONZ_SIGNATURE_HEADER: build_signature(
            secret, raw_body, timestamp=timestamp, nonce=nonce
        ),
        JAMBONZ_TIMESTAMP_HEADER: str(timestamp),
        JAMBONZ_NONCE_HEADER: nonce,
        JAMBONZ_CONTRACT_MODE_HEADER: contract_mode,
        "content-type": "application/json",
    }


def verify_signed_payload(
    secret: str,
    raw_body: str,
    headers: Mapping[str, str],
    *,
    replay_guard: JambonzReplayGuard | None = None,
    now: int | None = None,
    tolerance_seconds: int = JAMBONZ_REPLAY_TOLERANCE_SECONDS,
    replay_scope: str = "",
) -> bool:
    if not secret:
        return False

    signature = _header_lookup(headers, JAMBONZ_SIGNATURE_HEADER)
    timestamp_raw = _header_lookup(headers, JAMBONZ_TIMESTAMP_HEADER)
    nonce = _header_lookup(headers, JAMBONZ_NONCE_HEADER)
    if not (signature and timestamp_raw and nonce):
        return False

    try:
        timestamp = int(timestamp_raw)
    except (TypeError, ValueError):
        return False

    now = int(time.time()) if now is None else now
    if abs(now - timestamp) > tolerance_seconds:
        return False

    expected = build_signature(secret, raw_body, timestamp=timestamp, nonce=nonce)
    if not hmac.compare_digest(expected, signature):
        return False

    if replay_guard is not None and not replay_guard.check_and_store(
        nonce, timestamp, now=now, scope=replay_scope
    ):
        return False

    return True


def capacity_denied_response(message: str = "현재 통화량이 많아 연결할 수 없습니다.") -> list[dict[str, Any]]:
    return [
        {"verb": "say", "text": message, "synthesizer": {"language": "ko-KR"}},
        {"verb": "hangup"},
    ]


def system_unavailable_response(message: str = "죄송합니다. 지금은 통화를 연결할 수 없습니다.") -> list[dict[str, Any]]:
    return [
        {"verb": "say", "text": message, "synthesizer": {"language": "ko-KR"}},
        {"verb": "hangup"},
    ]


KR_NUMBER_VARIANTS = {
    "domestic_070": "07012345678",
    "domestic_mobile": "01012345678",
    "e164_070": "+827012345678",
}


class JambonzContractSimulator:
    """Deterministic local helper for contract-mode Jambonz events."""

    def __init__(
        self,
        *,
        account_id: str = "acct_contract_kr_070",
        application_id: str = "app_contract_recova",
        webhook_secret: str = "contract-secret",
        base_timestamp: int = 1_700_000_000,
    ):
        self.account_id = account_id
        self.application_id = application_id
        self.webhook_secret = webhook_secret
        self.base_timestamp = base_timestamp
        self._counter = 0

    def _next_nonce(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter:04d}"

    def sign(self, payload: BaseModel | Mapping[str, Any], *, nonce_prefix: str) -> tuple[dict[str, Any], dict[str, str], str]:
        body = canonical_json(payload)
        nonce = self._next_nonce(nonce_prefix)
        headers = signed_headers(
            self.webhook_secret,
            payload,
            timestamp=self.base_timestamp + self._counter,
            nonce=nonce,
        )
        if isinstance(payload, BaseModel):
            return payload.model_dump(exclude_none=True), headers, body
        return dict(payload), headers, body

    def inbound(self, *, from_number: str = "01012345678", to_number: str = "07012345678") -> tuple[dict[str, Any], dict[str, str], str]:
        payload = JambonzInboundWebhook(
            account_id=self.account_id,
            application_id=self.application_id,
            call_id="jb-in-contract-0001",
            from_number=from_number,
            to_number=to_number,
        )
        return self.sign(payload, nonce_prefix="inbound")
    def inbound_live_validation_injection(self) -> tuple[dict[str, Any], dict[str, str], str]:
        payload, _, _ = self.inbound()
        payload.update(
            {
                "live_trunk_validated": True,
                "live_validation_source": "simulator",
                "live_validation_evidence_id": "simulated-live-evidence",
            }
        )
        return self.sign(payload, nonce_prefix="live-injection")


    def media_start(self, *, direction: Literal["inbound", "outbound"] = "inbound") -> dict[str, Any]:
        return JambonzMediaStartFrame(
            account_id=self.account_id,
            application_id=self.application_id,
            call_id="jb-in-contract-0001",
            stream_id="jb-stream-contract-0001",
            direction=direction,
        ).model_dump(exclude_none=True)

    def outbound_response(self) -> dict[str, Any]:
        return JambonzOutboundCallResponse(
            account_id=self.account_id,
            call_id="jb-out-contract-0001",
            status="initiated",
        ).model_dump(exclude_none=True)

    def status(self, status: str = "completed") -> tuple[dict[str, Any], dict[str, str], str]:
        payload = JambonzStatusCallback(
            account_id=self.account_id,
            application_id=self.application_id,
            call_id="jb-out-contract-0001",
            status=status,
            from_number="+827012345678",
            to_number="+821012345678",
            direction="outbound",
            duration_seconds=42 if status == "completed" else None,
            failure_cause=None if status == "completed" else status,
            idempotency_key=f"status:jb-out-contract-0001:{status}",
        )
        return self.sign(payload, nonce_prefix="status")
    def status_live_validation_injection(self) -> tuple[dict[str, Any], dict[str, str], str]:
        payload, _, _ = self.status(status="completed")
        payload.update(
            {
                "live_trunk_validated": True,
                "live_validation_source": "simulator",
                "live_validation_evidence_id": "simulated-status-evidence",
            }
        )
        return self.sign(payload, nonce_prefix="status-live-injection")


    def cdr(self) -> tuple[dict[str, Any], dict[str, str], str]:
        payload = JambonzCdrEvent(
            account_id=self.account_id,
            application_id=self.application_id,
            call_id="jb-out-contract-0001",
            direction="outbound",
            from_number="+827012345678",
            to_number="+821012345678",
            started_at="2026-07-09T03:00:00Z",
            answered_at="2026-07-09T03:00:03Z",
            ended_at="2026-07-09T03:00:45Z",
            duration_seconds=42,
            hangup_cause="normal",
            idempotency_key="cdr:jb-out-contract-0001:completed",
        )
        return self.sign(payload, nonce_prefix="cdr")

    def unsigned(self) -> tuple[dict[str, Any], dict[str, str], str]:
        payload, _, body = self.inbound()
        return payload, {"content-type": "application/json"}, body

    def malformed_signature(self) -> tuple[dict[str, Any], dict[str, str], str]:
        payload, headers, body = self.inbound()
        headers[JAMBONZ_SIGNATURE_HEADER] = "bad-signature"
        return payload, headers, body


CONTRACT_FIXTURES = {
    "kr_number_variants": KR_NUMBER_VARIANTS,
    "capacity_denied_response": capacity_denied_response(),
    "system_unavailable_response": system_unavailable_response(),
    "live_validation_injection": {
        "live_trunk_validated": True,
        "live_validation_source": "simulator",
        "live_validation_evidence_id": "simulated-live-evidence",
    },
}


__all__ = [
    "CONTRACT_FIXTURES",
    "JAMBONZ_CONTRACT_MODE_FIXTURE",
    "JAMBONZ_CONTRACT_MODE_HEADER",
    "JAMBONZ_CONTRACT_VERSION",
    "JAMBONZ_NONCE_HEADER",
    "JAMBONZ_PROVIDER",
    "JAMBONZ_REPLAY_TOLERANCE_SECONDS",
    "JAMBONZ_SIGNATURE_HEADER",
    "JAMBONZ_TIMESTAMP_HEADER",
    "JambonzCdrEvent",
    "JambonzContractSimulator",
    "JambonzInboundWebhook",
    "JambonzMediaStartFrame",
    "JambonzOutboundCallRequest",
    "JambonzOutboundCallResponse",
    "JambonzReplayGuard",
    "JambonzStatusCallback",
    "KR_NUMBER_VARIANTS",
    "build_signature",
    "canonical_json",
    "capacity_denied_response",
    "signed_headers",
    "system_unavailable_response",
    "verify_signed_payload",
]
