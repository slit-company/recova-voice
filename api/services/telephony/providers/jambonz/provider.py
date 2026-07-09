"""Jambonz implementation of the TelephonyProvider interface.

This adapter targets Recova's `jambonz_contract_v1` first. It is hidden from
self-serve configuration and is intended for operator-owned Korean 070 runtime
paths.
"""

from __future__ import annotations

import json
import random
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import aiohttp
from fastapi import HTTPException
from loguru import logger

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
        ).model_dump(exclude_none=True)

        log_payload = redact_telephony_payload_for_logs(payload)
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
                        f"Jambonz call-create failed: HTTP {response.status} {response_text}"
                    )
                    raise HTTPException(status_code=response.status, detail=response_text)
                try:
                    response_data = json.loads(response_text) if response_text else {}
                except json.JSONDecodeError as exc:
                    raise HTTPException(
                        status_code=502, detail="Invalid Jambonz call-create response"
                    ) from exc

        call_id = (
            response_data.get("call_id")
            or response_data.get("sid")
            or response_data.get("callSid")
            or response_data.get("call_sid")
            or ""
        )
        if not call_id:
            raise HTTPException(status_code=502, detail="Jambonz response missing call_id")

        return CallInitiationResult(
            call_id=call_id,
            status=response_data.get("status", "initiated"),
            caller_number=from_number,
            provider_metadata={
                "call_id": call_id,
                "jambonz_account_id": self.account_id,
                "jambonz_contract_version": JAMBONZ_CONTRACT_VERSION,
                "is_contract_fixture": bool(response_data.get("is_contract_fixture", False)),
            },
            raw_response=response_data,
        )

    async def get_call_status(self, call_id: str) -> Dict[str, Any]:
        if not self.validate_config():
            raise ValueError("Jambonz provider not properly configured")
        endpoint = f"{self.base_url}/v1/Accounts/{self.account_id}/Calls/{call_id}"
        async with aiohttp.ClientSession() as session:
            async with session.get(endpoint, headers=self._headers()) as response:
                if response.status != 200:
                    body = await response.text()
                    raise Exception(f"Failed to get Jambonz call status: {body}")
                return await response.json()

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
        self, workflow_id: int, user_id: int, workflow_run_id: int
    ) -> list[dict[str, Any]]:
        _, wss_backend_endpoint = await get_backend_endpoints()
        websocket_url = (
            f"{wss_backend_endpoint}/api/v1/telephony/ws/"
            f"{workflow_id}/{user_id}/{workflow_run_id}"
        )
        return self._connect_verbs(websocket_url, workflow_run_id)

    async def get_call_cost(self, call_id: str) -> Dict[str, Any]:
        return {
            "cost_usd": 0.0,
            "duration": 0,
            "status": "unknown",
            "error": "Jambonz contract does not expose live cost data",
        }

    def parse_status_callback(self, data: Dict[str, Any]) -> Dict[str, Any]:
        envelope = data.get("data") if isinstance(data.get("data"), dict) else data
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
            "call_id": envelope.get("call_id") or envelope.get("callSid") or "",
            "status": status,
            "from_number": envelope.get("from_number") or envelope.get("from"),
            "to_number": envelope.get("to_number") or envelope.get("to"),
            "direction": envelope.get("direction"),
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

        account_id = start.get("account_id") or start.get("accountSid")
        application_id = start.get("application_id") or start.get("applicationSid")
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

        sample_rate = int(start.get("sample_rate") or start.get("sampleRate") or 8000)

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
        account_id = envelope.get("account_id") or envelope.get("accountSid")
        application_id = envelope.get("application_id") or envelope.get("applicationSid")
        if account_id and account_id != self.account_id:
            return False
        if application_id and application_id != self.application_id:
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
        self, websocket_url: str, workflow_run_id: int
    ) -> list[dict[str, Any]]:
        return [
            {"verb": "answer"},
            {
                "verb": "listen",
                "url": websocket_url,
                "mixType": "mono",
                "sampleRate": 8000,
                "bidirectionalAudio": {
                    "enabled": True,
                    "streaming": True,
                    "sampleRate": 8000,
                },
                "metadata": {
                    "provider": self.PROVIDER_NAME,
                    "workflow_run_id": workflow_run_id,
                    "contract_version": JAMBONZ_CONTRACT_VERSION,
                },
            },
        ]


__all__ = ["JambonzProvider"]
