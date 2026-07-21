"""Jambonz implementation of the TelephonyProvider interface.

This adapter targets Recova's `jambonz_contract_v1` first. It is hidden from
self-serve configuration and is intended for operator-owned Korean 070 runtime
paths.
"""

from __future__ import annotations

from datetime import datetime, timezone
import base64
import binascii
import hashlib
import hmac
import json
import random
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import aiohttp
from fastapi import HTTPException
from loguru import logger
from pydantic import ValidationError

from api.services.onnuri_smoke_capabilities import (
    CapabilityBinding,
    ECDSA_P256_SHA256_POLICY_ID,
    SmokeCapabilityIssuer,
    opaque_signing_bytes,
    parse_dispatch_capability,
    parse_media_capability,
    sha256_hex,
)
from api.services.telephony.onnuri_preflight_policy import (
    DISPATCH_CAPABILITY_DOMAIN,
    MEDIA_CAPABILITY_DOMAIN,
)
from api.services.telephony.base import (
    CallInitiationResult,
    NormalizedInboundData,
    ProviderSyncResult,
    TelephonyProvider,
)
from api.services.telephony.providers.jambonz.contract import (
    JAMBONZ_CONTRACT_VERSION,
    JambonzOutboundCallRequest,
    JambonzReplayGuard,
    capacity_denied_response,
    canonical_json,
    system_unavailable_response,
    verify_signed_payload,
)
from api.services.telephony.providers.jambonz.facade.models import (
    OuterCallCreateRequest,
    OuterCallCreateResponse,
)
from api.services.telephony.status_processor import redact_telephony_payload_for_logs
from api.utils.common import get_backend_endpoints
from api.utils.telephony_address import normalize_telephony_address

if TYPE_CHECKING:
    from fastapi import WebSocket


_STATUS_MAP = {
    "initiated": "initiated",
    "trying": "initiated",
    "ringing": "ringing",
    "answered": "answered",
    "in-progress": "answered",
    "completed": "completed",
    "complete": "completed",
    "busy": "busy",
    "no-answer": "no-answer",
    "no_answer": "no-answer",
    "failed": "failed",
    "failure": "failed",
    "canceled": "canceled",
    "cancelled": "canceled",
    "media-error": "error",
    "media_error": "error",
}


def _is_canonical_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


class JambonzProvider(TelephonyProvider):
    """Recova first-party Jambonz provider."""

    PROVIDER_NAME = "jambonz"
    WEBHOOK_ENDPOINT = "jambonz/answer"

    _replay_guard = JambonzReplayGuard()

    def __init__(self, config: Dict[str, Any]):
        self.base_url = (config.get("base_url") or "").rstrip("/")
        self.account_id = config.get("account_id") or ""
        self.application_id = config.get("application_id") or ""
        self.api_key = config.get("api_key") or ""
        self.webhook_secret = config.get("webhook_secret") or ""
        self.outbound_profile_id = config.get("outbound_profile_id")
        self.from_numbers = config.get("from_numbers", [])
        self._smoke_capability_issuer: SmokeCapabilityIssuer | None = config.get(
            "smoke_capability_issuer"
        )
        self._media_capability_verifier: SmokeCapabilityIssuer | None = config.get(
            "media_capability_verifier"
        )
        if isinstance(self.from_numbers, str):
            self.from_numbers = [self.from_numbers]

    def _assigned_caller_ids(self) -> set[str]:
        normalized: set[str] = set()
        for number in self.from_numbers:
            if not number:
                continue
            normalized.add(
                normalize_telephony_address(str(number), country_hint="KR").canonical
            )
        return normalized

    def _require_assigned_recova_070_caller(self, from_number: str | None) -> str:
        if from_number is None:
            if not self.from_numbers:
                raise HTTPException(
                    status_code=400,
                    detail="jambonz_assigned_recova_070_caller_required",
                )
            from_number = random.choice(self.from_numbers)

        normalized = normalize_telephony_address(
            from_number, country_hint="KR"
        ).canonical
        if normalized not in self._assigned_caller_ids() or not normalized.startswith(
            "+8270"
        ):
            raise HTTPException(
                status_code=400,
                detail="jambonz_assigned_recova_070_caller_required",
            )
        return normalized


    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def initiate_call(
        self,
        to_number: str,
        webhook_url: str,
        workflow_run_id: Optional[int] = None,
        from_number: Optional[str] = None,
        **kwargs: Any,
    ) -> CallInitiationResult:
        """Initiate an outbound call via the contract call-create endpoint."""
        if not self.validate_config():
            raise ValueError("Jambonz provider not properly configured")

        from_number = self._require_assigned_recova_070_caller(from_number)
        to_number = normalize_telephony_address(to_number, country_hint="KR").canonical
        logger.info("Selected Recova 070 caller ID [redacted] for Jambonz outbound call")

        backend_endpoint, _ = await get_backend_endpoints()
        status_callback_url = (
            f"{backend_endpoint}/api/v1/telephony/jambonz/status/{workflow_run_id}"
        )
        authority_values = {
            "organization_id": kwargs.get("organization_id"),
            "attempt_id": kwargs.get("attempt_id")
            or kwargs.get("smoke_attempt_uuid")
            or kwargs.get("application_attempt_id"),
            "idempotency_key": kwargs.get("idempotency_key"),
            "authority_deadline": kwargs.get("authority_deadline")
            or kwargs.get("authority_deadline_utc"),
            "dispatch_capability": kwargs.get("dispatch_capability"),
        }
        classified = bool(kwargs.get("classified_smoke")) or any(
            value is not None for value in authority_values.values()
        )
        run_id = (
            kwargs.get("envelope_id")
            or kwargs.get("smoke_envelope_uuid")
            or kwargs.get("run_id")
        )
        if run_id is None and workflow_run_id is not None:
            run_id = str(workflow_run_id)
        legacy_fixture = bool(kwargs.get("is_contract_fixture"))
        if not classified and not legacy_fixture:
            raise HTTPException(
                status_code=403, detail="jambonz_live_dispatch_authority_required"
            )

        if classified:
            missing = [key for key, value in authority_values.items() if not value]
            if not run_id:
                missing.append("run_id")
            if kwargs.get("direction", "outbound") != "outbound":
                raise HTTPException(status_code=400, detail="jambonz_direction_mismatch")
            if missing:
                raise HTTPException(
                    status_code=400,
                    detail=f"jambonz_authority_metadata_required:{','.join(missing)}",
                )
            capability = authority_values["dispatch_capability"]
            if isinstance(capability, str):
                capability_bytes = capability.encode("utf-8")
            elif isinstance(capability, bytes):
                capability_bytes = capability
            else:
                raise HTTPException(
                    status_code=400, detail="jambonz_invalid_dispatch_capability"
                )
            try:
                signed_capability = parse_dispatch_capability(capability_bytes)
            except Exception as exc:
                raise HTTPException(
                    status_code=400, detail="jambonz_invalid_dispatch_capability"
                ) from exc
            deadline_value = authority_values["authority_deadline"]
            try:
                if not isinstance(deadline_value, datetime):
                    deadline_value = datetime.fromisoformat(
                        str(deadline_value).replace("Z", "+00:00")
                    )
                if (
                    deadline_value.tzinfo is None
                    or deadline_value.utcoffset() is None
                ):
                    raise ValueError("naive deadline")
                deadline_value = deadline_value.astimezone(timezone.utc)
            except (TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=400, detail="jambonz_invalid_authority_deadline"
                ) from exc
            authority_values["authority_deadline"] = deadline_value.isoformat()
            dispatch_domain = (
                kwargs.get("dispatch_domain")
                or kwargs.get("dispatch_verification_domain")
            )
            dispatch_key_id = kwargs.get("dispatch_key_id")
            dispatch_algorithm_policy_id = kwargs.get(
                "dispatch_algorithm_policy_id"
            )
            capability_claims = signed_capability.claims
            candidate_digest = capability_claims.get("candidate_digest")
            gate_envelope_digest = capability_claims.get("gate_envelope_digest")
            if (
                dispatch_domain != DISPATCH_CAPABILITY_DOMAIN
                or signed_capability.verification_domain
                != DISPATCH_CAPABILITY_DOMAIN
                or not dispatch_key_id
                or signed_capability.key_id != dispatch_key_id
                or dispatch_algorithm_policy_id
                != ECDSA_P256_SHA256_POLICY_ID
                or signed_capability.expires_at != deadline_value
                or capability_claims.get("organization_id")
                != authority_values["organization_id"]
                or capability_claims.get("account_id") != self.account_id
                or capability_claims.get("application_id") != self.application_id
                or str(capability_claims.get("run_id")) != str(run_id)
                or str(capability_claims.get("attempt_id"))
                != str(authority_values["attempt_id"])
                or capability_claims.get("direction") != "outbound"
                or capability_claims.get("idempotency_key")
                != authority_values["idempotency_key"]
                or capability_claims.get("authority_deadline")
                != deadline_value.isoformat()
                or not _is_canonical_sha256(candidate_digest)
                or not _is_canonical_sha256(gate_envelope_digest)
            ):
                raise HTTPException(
                    status_code=400, detail="jambonz_dispatch_capability_binding_mismatch"
                )
            max_call_seconds = int(
                kwargs.get("max_call_seconds")
                or kwargs.get("max_duration_seconds")
                or 60
            )
            if max_call_seconds != 60:
                raise HTTPException(
                    status_code=400, detail="jambonz_max_call_seconds_must_be_60"
                )
            facade_request = OuterCallCreateRequest(
                organization_id=authority_values["organization_id"],
                application_id=self.application_id,
                run_id=str(run_id),
                attempt_id=str(authority_values["attempt_id"]),
                direction="outbound",
                authority_deadline=deadline_value,
                idempotency_key=authority_values["idempotency_key"],
                candidate_digest=candidate_digest,
                gate_envelope_digest=gate_envelope_digest,
                dispatch_capability=signed_capability,
                from_address=from_number,
                to_address=to_number,
                answer_hook_url=(
                    f"{self.base_url}/v1/jambonz-contract/hooks/outbound/"
                    "record-answer-and-mint-media"
                ),
                status_hook_url=(
                    f"{self.base_url}/v1/jambonz-contract/hooks/status"
                ),
                ring_timeout_seconds=min(
                    30, max(1, int(kwargs.get("timeout_seconds") or 30))
                ),
                time_limit_seconds=60,
            )
            payload = facade_request.model_dump(mode="json")
            payload["dispatch_capability"] = json.loads(capability_bytes)
            payload["from_address"] = from_number
            payload["to_address"] = to_number
        else:
            payload = JambonzOutboundCallRequest(
                account_id=self.account_id,
                application_id=self.application_id,
                from_number=from_number,
                to_number=to_number,
                answer_url=webhook_url,
                status_callback_url=status_callback_url,
                workflow_run_id=workflow_run_id,
                workflow_id=kwargs.get("workflow_id"),
                user_id=kwargs.get("user_id"),
                timeout_seconds=int(kwargs.get("timeout_seconds") or 30),
                outbound_profile_id=self.outbound_profile_id,
                is_contract_fixture=True,
            ).model_dump(exclude_none=True)

        log_source = (
            {key: value for key, value in payload.items() if key != "dispatch_capability"}
            if classified
            else payload
        )
        log_payload = redact_telephony_payload_for_logs(log_source)
        logger.info(f"Jambonz call-create payload: {json.dumps(log_payload)}")

        endpoint = (
            f"{self.base_url}/v1/jambonz-contract/accounts/"
            f"{self.account_id}/calls"
        )
        async with aiohttp.ClientSession() as session:
            async with session.post(
                endpoint, json=payload, headers=self._headers()
            ) as response:
                response_text = await response.text()
                if response.status not in (200, 201, 202):
                    logger.error(
                        f"Jambonz call-create failed: HTTP {response.status}"
                    )
                    raise HTTPException(
                        status_code=response.status,
                        detail="Jambonz call-create rejected",
                    )
                try:
                    response_data = json.loads(response_text) if response_text else {}
                except json.JSONDecodeError as exc:
                    raise HTTPException(
                        status_code=502, detail="Invalid Jambonz call-create response"
                    ) from exc

        if classified:
            try:
                facade_response = OuterCallCreateResponse.model_validate(response_data)
            except ValidationError as exc:
                raise HTTPException(
                    status_code=502, detail="Invalid authoritative Jambonz response"
                ) from exc
            context = facade_response.context
            if (
                context.organization_id != authority_values["organization_id"]
                or context.account_id != self.account_id
                or context.application_id != self.application_id
                or context.run_id != str(run_id)
                or context.attempt_id != str(authority_values["attempt_id"])
                or context.direction.value != "outbound"
                or facade_response.idempotency_key
                != authority_values["idempotency_key"]
                or not facade_response.dispatch_receipt_id
                or not facade_response.bind_receipt_id
                or context.stock_call_id != facade_response.stock_call_id
                or context.authority_deadline != deadline_value
                or context.candidate_digest != candidate_digest
                or context.gate_envelope_digest != gate_envelope_digest
            ):
                raise HTTPException(
                    status_code=502, detail="Jambonz dispatch receipt binding mismatch"
                )
            call_id = facade_response.stock_call_id
        else:
            if not response_data.get("is_contract_fixture", False):
                raise HTTPException(
                    status_code=502,
                    detail="Unclassified Jambonz response cannot establish live authority",
                )
            call_id = (
                response_data.get("call_id")
                or response_data.get("sid")
                or response_data.get("callSid")
                or response_data.get("call_sid")
                or ""
            )
            if not call_id:
                raise HTTPException(
                    status_code=502, detail="Jambonz response missing call_id"
                )

        provider_metadata = {
            "call_id": call_id,
            "jambonz_account_id": self.account_id,
            "jambonz_contract_version": JAMBONZ_CONTRACT_VERSION,
            "contract_version": (
                "recova-jambonz-facade-v1"
                if classified
                else JAMBONZ_CONTRACT_VERSION
            ),
            "is_contract_fixture": bool(
                response_data.get("is_contract_fixture", False)
            ),
            "direction": "outbound",
        }
        if classified:
            provider_metadata.update(
                {
                    "run_id": str(run_id),
                    "envelope_id": str(run_id),
                    "attempt_id": str(authority_values["attempt_id"]),
                    "idempotency_key": facade_response.idempotency_key,
                    "request_digest": facade_response.request_digest,
                    "dispatch_receipt_id": facade_response.dispatch_receipt_id,
                    "bind_receipt_id": facade_response.bind_receipt_id,
                }
            )
        return CallInitiationResult(
            call_id=call_id,
            status=response_data.get("status", "initiated"),
            caller_number=from_number,
            provider_metadata=provider_metadata,
            raw_response=response_data,
        )

    async def get_call_status(self, call_id: str) -> Dict[str, Any]:
        """Get status through the Recova-owned Jambonz contract endpoint.

        Native public Jambonz REST status semantics are intentionally excluded
        from V1 readiness. Readiness-sensitive status/CDR evidence must come
        through signed contract callbacks or the contract adapter endpoint.
        """
        if not self.validate_config():
            raise ValueError("Jambonz provider not properly configured")
        endpoint = (
            f"{self.base_url}/v1/jambonz-contract/accounts/"
            f"{self.account_id}/calls/{call_id}"
        )
        async with aiohttp.ClientSession() as session:
            async with session.get(endpoint, headers=self._headers()) as response:
                if response.status != 200:
                    body = await response.text()
                    raise Exception(f"Failed to get Jambonz contract call status: {body}")
                data = await response.json()
        data["contract_version"] = data.get("contract_version") or JAMBONZ_CONTRACT_VERSION
        return data

    async def get_available_phone_numbers(self) -> List[str]:
        return self.from_numbers

    def validate_config(self) -> bool:
        return bool(
            self.base_url
            and self.account_id
            and self.application_id
            and self.api_key
            and self.webhook_secret
            and self.from_numbers
        )

    async def verify_webhook_signature(
        self, url: str, params: Dict[str, Any], signature: str
    ) -> bool:
        raw_body = params.get("_raw_body") or canonical_json(params)
        headers = {
            "x-recova-jambonz-signature": signature,
            "x-recova-jambonz-timestamp": str(params.get("timestamp") or ""),
            "x-recova-jambonz-nonce": str(params.get("nonce") or ""),
        }
        return verify_signed_payload(
            self.webhook_secret,
            raw_body,
            headers,
            replay_guard=self._replay_guard,
        )

    async def get_webhook_response(
        self,
        workflow_id: int,
        user_id: int,
        workflow_run_id: int,
        **authority: Any,
    ) -> list[dict[str, Any]]:
        _, wss_backend_endpoint = await get_backend_endpoints()
        websocket_url = (
            f"{wss_backend_endpoint}/api/v1/telephony/ws/"
            f"{workflow_id}/{user_id}/{workflow_run_id}"
        )
        return self._connect_verbs(
            websocket_url, workflow_run_id, **authority
        )

    async def get_call_cost(self, call_id: str) -> Dict[str, Any]:
        return {
            "cost_usd": 0.0,
            "duration": 0,
            "status": "unknown",
            "error": "Jambonz contract does not expose live cost data",
        }

    def parse_status_callback(self, data: Dict[str, Any]) -> Dict[str, Any]:
        envelope = data.get("data") if isinstance(data.get("data"), dict) else data
        context = envelope.get("context")
        if not isinstance(context, dict):
            context = envelope
        status_raw = (
            envelope.get("status")
            or envelope.get("call_status")
            or envelope.get("event")
            or envelope.get("event_type")
            or ""
        )
        if status_raw == "cdr":
            status_raw = "completed"
        status = _STATUS_MAP.get(str(status_raw).lower(), str(status_raw).lower())
        duration = envelope.get("duration_seconds") or envelope.get("duration")
        if duration is not None:
            duration = str(duration)
        return {
            "call_id": (
                envelope.get("stock_call_id")
                or envelope.get("call_id")
                or envelope.get("callSid")
                or ""
            ),
            "status": status,
            "from_number": envelope.get("from_number") or envelope.get("from"),
            "to_number": envelope.get("to_number") or envelope.get("to"),
            "direction": envelope.get("direction") or context.get("direction"),
            "duration": duration,
            "extra": data,
        }

    async def handle_websocket(
        self,
        websocket: "WebSocket",
        workflow_id: int,
        user_id: int,
        workflow_run_id: int,
    ) -> None:
        """Handle a Jambonz contract media WebSocket connection."""
        from api.services.pipecat.run_pipeline import run_pipeline_telephony

        start_raw = await websocket.receive_text()
        try:
            start = json.loads(start_raw)
        except json.JSONDecodeError:
            await websocket.close(code=4400, reason="Invalid Jambonz start frame")
            return

        event = start.get("event") or start.get("type")
        native_metadata = not event and (
            start.get("callSid") or start.get("accountSid") or start.get("sampleRate")
        )
        if event not in {"start", "media_start"} and not native_metadata:
            await websocket.close(code=4400, reason="Expected Jambonz start frame")
            return

        metadata = start.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        fixture = bool(
            start.get("is_contract_fixture")
            or metadata.get("is_contract_fixture")
        )
        account_id = (
            start.get("account_id")
            or start.get("accountSid")
            or metadata.get("account_id")
        )
        application_id = (
            start.get("application_id")
            or start.get("applicationSid")
            or metadata.get("application_id")
        )
        if account_id and account_id != self.account_id:
            await websocket.close(code=4403, reason="Jambonz account mismatch")
            return
        if application_id and application_id != self.application_id:
            await websocket.close(code=4403, reason="Jambonz application mismatch")
            return

        stream_id = (
            start.get("stream_id")
            or start.get("streamSid")
            or start.get("callSid")
            or ""
        )
        call_id = start.get("call_id") or start.get("callSid") or ""
        if not (stream_id and call_id):
            await websocket.close(code=4400, reason="Missing Jambonz stream identifiers")
            return

        strict_authority = not fixture
        authority_deadline = (
            start.get("authority_deadline")
            or metadata.get("authority_deadline")
        )
        remaining_seconds: int | None = None
        if strict_authority:
            required_authority = {
                "organization_id": metadata.get("organization_id"),
                "account_id": account_id,
                "application_id": application_id,
                "envelope_id": metadata.get("envelope_id"),
                "run_id": start.get("run_id") or metadata.get("run_id"),
                "workflow_run_id": metadata.get("workflow_run_id"),
                "attempt_id": start.get("attempt_id") or metadata.get("attempt_id"),
                "direction": start.get("direction") or metadata.get("direction"),
                "idempotency_key": (
                    start.get("idempotency_key")
                    or metadata.get("idempotency_key")
                ),
                "callback_event_nonce": metadata.get("callback_event_nonce")
                or metadata.get("event_nonce"),
                "request_digest": metadata.get("request_digest")
                or metadata.get("canonical_request_digest"),
                "stock_call_id_digest": metadata.get("stock_call_id_digest"),
                "authority_receipt_id": (
                    start.get("authority_receipt_id")
                    or metadata.get("authority_receipt_id")
                ),
                "authority_deadline": authority_deadline,
                "media_verification_domain": (
                    start.get("media_verification_domain")
                    or metadata.get("media_verification_domain")
                ),
                "media_key_id": (
                    start.get("media_key_id") or metadata.get("media_key_id")
                ),
                "candidate_digest": metadata.get("candidate_digest"),
                "gate_envelope_digest": metadata.get("gate_envelope_digest"),
                "observed_event_wall_time": metadata.get(
                    "observed_event_wall_time"
                )
                or metadata.get("observed_wall_time"),
            }
            if (
                any(not value for value in required_authority.values())
                or str(required_authority["workflow_run_id"]) != str(workflow_run_id)
                or required_authority["envelope_id"]
                != required_authority["run_id"]
                or required_authority["media_verification_domain"]
                != MEDIA_CAPABILITY_DOMAIN
                or required_authority["stock_call_id_digest"]
                != hashlib.sha256(call_id.encode("utf-8")).hexdigest()
            ):
                await websocket.close(code=4403, reason="Jambonz media authority required")
                return
            try:
                deadline = datetime.fromisoformat(
                    str(authority_deadline).replace("Z", "+00:00")
                )
                if deadline.tzinfo is None or deadline.utcoffset() is None:
                    raise ValueError("naive deadline")
                deadline = deadline.astimezone(timezone.utc)
            except (TypeError, ValueError):
                await websocket.close(code=4403, reason="Invalid media deadline")
                return
            remaining_seconds = max(
                0,
                min(
                    60,
                    int((deadline - datetime.now(timezone.utc)).total_seconds()),
                ),
            )
            if remaining_seconds <= 0:
                await websocket.close(code=4408, reason="Media authority expired")
                return
            sample_rate = int(
                start.get("sample_rate") or start.get("sampleRate") or 8000
            )
            codec = start.get("codec") or metadata.get("codec") or "L16"
            if sample_rate != 8000 or codec != "L16":
                await websocket.close(
                    code=4400, reason="Jambonz media must be 8 kHz L16"
                )
                return
            authorization = websocket.headers.get("authorization", "")
            try:
                scheme, encoded = authorization.split(" ", 1)
                if scheme.lower() != "basic":
                    raise ValueError("wrong scheme")
                decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
                username, opaque_media_capability = decoded.split(":", 1)
                if username != "recova-media" or not opaque_media_capability:
                    raise ValueError("invalid credentials")
            except (ValueError, UnicodeDecodeError, binascii.Error):
                await websocket.close(code=4403, reason="Jambonz media authority required")
                return

            verifier = self._media_capability_verifier
            if verifier is None:
                await websocket.close(code=4403, reason="Jambonz media authority unavailable")
                return
            try:
                observed_wall_time = datetime.fromisoformat(
                    str(required_authority["observed_event_wall_time"]).replace(
                        "Z", "+00:00"
                    )
                )
                if (
                    observed_wall_time.tzinfo is None
                    or observed_wall_time.utcoffset() is None
                ):
                    raise ValueError("naive observed wall time")
                observed_wall_time = observed_wall_time.astimezone(timezone.utc)
                binding = CapabilityBinding(
                    organization_id=int(required_authority["organization_id"]),
                    account_id=str(required_authority["account_id"]),
                    application_id=str(required_authority["application_id"]),
                    run_id=str(required_authority["run_id"]),
                    attempt_id=str(required_authority["attempt_id"]),
                    direction=required_authority["direction"],
                    idempotency_key=str(required_authority["idempotency_key"]),
                    request_digest=str(required_authority["request_digest"]),
                    stock_call_id=call_id,
                    callback_event_nonce=str(
                        required_authority["callback_event_nonce"]
                    ),
                    candidate_digest=str(required_authority["candidate_digest"]),
                    gate_envelope_digest=str(
                        required_authority["gate_envelope_digest"]
                    ),
                    observed_event_wall_time=observed_wall_time,
                )
                opaque_media = opaque_media_capability.encode("utf-8")
                parsed = parse_media_capability(opaque_media)
                capability_expires = datetime.fromisoformat(
                    parsed["expires_at"].replace("Z", "+00:00")
                ).astimezone(timezone.utc)
                if (
                    parsed["claims"]
                    != binding.claims(authority_deadline=capability_expires)
                    or parsed["verification_domain"] != MEDIA_CAPABILITY_DOMAIN
                    or parsed["key_id"] != required_authority["media_key_id"]
                    or capability_expires != deadline
                    or required_authority["authority_receipt_id"]
                    != f"{binding.attempt_id}:media-authority"
                ):
                    raise ValueError("capability binding mismatch")
                verified = await verifier.verify(
                    "media",
                    opaque_media,
                    opaque_signing_bytes(opaque_media, kind="media"),
                    parsed["signature"],
                    binding,
                )
                if (
                    not hmac.compare_digest(
                        verified.token_digest, sha256_hex(opaque_media)
                    )
                    or not hmac.compare_digest(
                        verified.nonce_digest, sha256_hex(parsed["nonce"])
                    )
                    or not hmac.compare_digest(
                        verified.receipt_digest, sha256_hex(parsed["signature"])
                    )
                ):
                    raise ValueError("capability digest mismatch")
                from api.services.onnuri_staging_preflight import consume_smoke_media

                await consume_smoke_media(
                    binding.attempt_id,
                    organization_id=binding.organization_id,
                    nonce_digest=verified.nonce_digest,
                    token_digest=verified.token_digest,
                    stock_call_id_digest=required_authority[
                        "stock_call_id_digest"
                    ],
                    request_digest=binding.request_digest,
                    receipt_digest=verified.receipt_digest,
                )
            except Exception:
                await websocket.close(code=4403, reason="Jambonz media authority rejected")
                return

        if not strict_authority:
            sample_rate = int(
                start.get("sample_rate") or start.get("sampleRate") or 8000
            )

        await run_pipeline_telephony(
            websocket,
            provider_name=self.PROVIDER_NAME,
            workflow_id=workflow_id,
            workflow_run_id=workflow_run_id,
            user_id=user_id,
            call_id=call_id,
            transport_kwargs={
                "stream_id": stream_id,
                "call_id": call_id,
                "jambonz_sample_rate": sample_rate,
                "strict_authority": strict_authority,
                "authority_deadline": authority_deadline,
                "remaining_seconds": remaining_seconds,
            },
        )

    @classmethod
    def can_handle_webhook(
        cls, webhook_data: Dict[str, Any], headers: Dict[str, str]
    ) -> bool:
        if any(key.lower() == "x-recova-jambonz-signature" for key in headers):
            return True
        return (
            webhook_data.get("provider") == cls.PROVIDER_NAME
            or webhook_data.get("contract_version") == JAMBONZ_CONTRACT_VERSION
        )

    @staticmethod
    def parse_inbound_webhook(webhook_data: Dict[str, Any]) -> NormalizedInboundData:
        envelope = (
            webhook_data.get("data")
            if isinstance(webhook_data.get("data"), dict)
            else webhook_data
        )
        from_raw = envelope.get("from_number") or envelope.get("from") or ""
        to_raw = envelope.get("to_number") or envelope.get("to") or ""
        from_country = envelope.get("from_country") or envelope.get("fromCountry") or "KR"
        to_country = envelope.get("to_country") or envelope.get("toCountry") or "KR"
        return NormalizedInboundData(
            provider=JambonzProvider.PROVIDER_NAME,
            call_id=envelope.get("call_id") or envelope.get("callSid") or "",
            from_number=(
                normalize_telephony_address(from_raw, country_hint=from_country).canonical
                if from_raw
                else ""
            ),
            to_number=(
                normalize_telephony_address(to_raw, country_hint=to_country).canonical
                if to_raw
                else ""
            ),
            direction=envelope.get("direction", "inbound"),
            call_status=envelope.get("call_status") or envelope.get("status", "ringing"),
            account_id=envelope.get("account_id") or envelope.get("accountSid"),
            from_country=from_country,
            to_country=to_country,
            raw_data=webhook_data,
        )

    @staticmethod
    def validate_account_id(config_data: dict, webhook_account_id: str) -> bool:
        return bool(webhook_account_id) and config_data.get("account_id") == webhook_account_id

    async def verify_inbound_signature(
        self,
        url: str,
        webhook_data: Dict[str, Any],
        headers: Dict[str, str],
        body: str = "",
    ) -> bool:
        raw_body = body or canonical_json(webhook_data)
        envelope = (
            webhook_data.get("data")
            if isinstance(webhook_data.get("data"), dict)
            else webhook_data
        )
        context = envelope.get("context")
        if not isinstance(context, dict):
            context = envelope
        account_id = context.get("account_id") or envelope.get("accountSid")
        application_id = (
            context.get("application_id") or envelope.get("applicationSid")
        )
        if account_id and account_id != self.account_id:
            return False
        if application_id and application_id != self.application_id:
            return False
        event_nonce = envelope.get("event_nonce")
        if event_nonce:
            signed_nonce = next(
                (
                    value
                    for key, value in headers.items()
                    if key.lower() == "x-recova-jambonz-nonce"
                ),
                "",
            )
            if signed_nonce != event_nonce:
                return False
        return verify_signed_payload(
            self.webhook_secret,
            raw_body,
            headers,
            replay_guard=self._replay_guard,
            replay_scope=f"{self.account_id}:{self.application_id}",
        )

    async def start_inbound_stream(
        self,
        *,
        websocket_url: str,
        workflow_run_id: int,
        normalized_data: NormalizedInboundData,
        backend_endpoint: str,
    ):
        from fastapi.responses import JSONResponse

        return JSONResponse(
            content=self._connect_verbs(websocket_url, workflow_run_id),
            media_type="application/json",
        )

    async def configure_inbound(
        self, address: str, webhook_url: Optional[str]
    ) -> ProviderSyncResult:
        """Operator assignment owns Jambonz route sync; self-serve sync is a no-op."""
        return ProviderSyncResult(ok=True)

    @staticmethod
    def generate_error_response(error_type: str, message: str):
        from fastapi.responses import JSONResponse

        return JSONResponse(
            content=system_unavailable_response(message),
            media_type="application/json",
        )

    @staticmethod
    def generate_validation_error_response(error_type):
        from fastapi.responses import JSONResponse

        if str(error_type).endswith("CAPACITY_EXCEEDED"):
            content = capacity_denied_response()
        else:
            content = system_unavailable_response()
        return JSONResponse(content=content, media_type="application/json")

    async def transfer_call(
        self,
        destination: str,
        transfer_id: str,
        conference_name: str,
        timeout: int = 30,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        raise NotImplementedError("Jambonz transfer support is not in the V1 core")

    def supports_transfers(self) -> bool:
        return False

    def _connect_verbs(
        self,
        websocket_url: str,
        workflow_run_id: int,
        **authority: Any,
    ) -> list[dict[str, Any]]:
        media_capability = authority.get("media_capability")
        if isinstance(media_capability, bytes):
            try:
                media_capability = media_capability.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise HTTPException(
                    status_code=400, detail="jambonz_invalid_media_capability"
                ) from exc
        authority_fields = {
            "organization_id": authority.get("organization_id"),
            "envelope_id": authority.get("envelope_id")
            or authority.get("smoke_envelope_uuid")
            or authority.get("run_id")
            or str(workflow_run_id),
            "run_id": authority.get("smoke_envelope_uuid")
            or authority.get("run_id")
            or str(workflow_run_id),
            "attempt_id": authority.get("attempt_id")
            or authority.get("smoke_attempt_uuid")
            or authority.get("application_attempt_id"),
            "idempotency_key": authority.get("idempotency_key"),
            "authority_deadline": authority.get("authority_deadline")
            or authority.get("authority_deadline_utc"),
            "media_domain": authority.get("media_domain")
            or authority.get("media_verification_domain"),
            "media_key_id": authority.get("media_key_id"),
            "account_id": authority.get("account_id") or self.account_id,
            "application_id": authority.get("application_id")
            or self.application_id,
            "call_id": authority.get("call_id"),
            "direction": authority.get("direction"),
            "authority_receipt_id": authority.get("authority_receipt_id"),
            "callback_event_nonce": authority.get("callback_event_nonce")
            or authority.get("event_nonce"),
            "request_digest": authority.get("request_digest")
            or authority.get("canonical_request_digest"),
            "stock_call_id_digest": authority.get("stock_call_id_digest"),
            "candidate_digest": authority.get("candidate_digest"),
            "gate_envelope_digest": authority.get("gate_envelope_digest"),
            "observed_event_wall_time": authority.get("observed_event_wall_time")
            or authority.get("observed_wall_time"),
        }
        strict_authority = media_capability is not None or any(
            value is not None for value in authority.values()
        )
        metadata = {
            "provider": self.PROVIDER_NAME,
            "workflow_run_id": workflow_run_id,
            "contract_version": JAMBONZ_CONTRACT_VERSION,
        }
        listen: dict[str, Any] = {
            "verb": "listen",
            "url": websocket_url,
            "mixType": "mono",
            "sampleRate": 8000,
            "bidirectionalAudio": {
                "enabled": True,
                "streaming": True,
                "sampleRate": 8000,
                "encoding": "L16",
            },
            "metadata": metadata,
        }
        if strict_authority:
            missing = [
                key for key, value in authority_fields.items() if not value
            ]
            if not media_capability:
                missing.append("media_capability")
            if missing:
                raise HTTPException(
                    status_code=400,
                    detail=f"jambonz_media_authority_required:{','.join(missing)}",
                )
            if (
                authority_fields["media_domain"] != MEDIA_CAPABILITY_DOMAIN
                or authority_fields["account_id"] != self.account_id
                or authority_fields["application_id"] != self.application_id
                or authority_fields["direction"] not in {"inbound", "outbound"}
                or authority_fields["envelope_id"] != authority_fields["run_id"]
                or authority_fields["stock_call_id_digest"]
                != hashlib.sha256(
                    str(authority_fields["call_id"]).encode("utf-8")
                ).hexdigest()
            ):
                raise HTTPException(
                    status_code=400, detail="jambonz_media_authority_binding_mismatch"
                )
            try:
                deadline = datetime.fromisoformat(
                    str(authority_fields["authority_deadline"]).replace("Z", "+00:00")
                )
                if deadline.tzinfo is None or deadline.utcoffset() is None:
                    raise ValueError("naive deadline")
                deadline = deadline.astimezone(timezone.utc)
            except (TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=400, detail="jambonz_invalid_media_deadline"
                ) from exc
            signed_remaining = int(
                (deadline - datetime.now(timezone.utc)).total_seconds()
            )
            remaining_value = authority.get("remaining_seconds")
            supplied_remaining = (
                signed_remaining
                if remaining_value is None
                else int(remaining_value)
            )
            remaining_seconds = max(0, min(60, signed_remaining, supplied_remaining))
            if remaining_seconds <= 0:
                raise HTTPException(
                    status_code=400, detail="jambonz_media_authority_expired"
                )
            listen["wsAuth"] = {
                "username": "recova-media",
                "password": media_capability,
            }
            metadata.update(
                {
                    **authority_fields,
                    "envelope_id": authority_fields["envelope_id"],
                    "remaining_seconds": remaining_seconds,
                    "codec": "L16",
                }
            )
        else:
            metadata["is_contract_fixture"] = True
        return [{"verb": "answer"}, listen]


__all__ = ["JambonzProvider"]
