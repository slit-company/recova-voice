"""ClawOps implementation of the TelephonyProvider interface."""

import base64
import hashlib
import hmac
import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from urllib.parse import quote
from xml.sax.saxutils import escape, quoteattr

import aiohttp
from fastapi import HTTPException
from loguru import logger

from api.services.telephony.base import (
    CallInitiationResult,
    NormalizedInboundData,
    ProviderSyncResult,
    TelephonyProvider,
)
from api.services.telephony.status_processor import redact_telephony_payload_for_logs
from api.utils.common import get_backend_endpoints
from api.utils.telephony_address import normalize_telephony_address

if TYPE_CHECKING:
    from fastapi import WebSocket


class ClawOpsProvider(TelephonyProvider):
    """ClawOps CPaaS provider using VoiceML + Stream for real-time media."""

    PROVIDER_NAME = "clawops"
    WEBHOOK_ENDPOINT = "clawops-voiceml"
    BASE_URL = "https://api.claw-ops.com"

    def __init__(self, config: Dict[str, Any]):
        self.account_id = config.get("account_id")
        self.api_key = config.get("api_key")
        self.signing_key = config.get("signing_key")
        self.from_numbers = config.get("from_numbers", [])
        if isinstance(self.from_numbers, str):
            self.from_numbers = [self.from_numbers]
        self.base_url = config.get("base_url") or self.BASE_URL

    async def initiate_call(
        self,
        to_number: str,
        webhook_url: str,
        workflow_run_id: Optional[int] = None,
        from_number: Optional[str] = None,
        **kwargs: Any,
    ) -> CallInitiationResult:
        """Initiate an outbound call via ClawOps Calls API."""
        if not self.validate_config():
            raise ValueError("ClawOps provider not properly configured")

        selected_from = from_number or self.from_numbers[0]
        if selected_from not in self.from_numbers:
            raise HTTPException(
                status_code=400,
                detail="clawops_from_number_not_configured",
            )
        endpoint = f"{self.base_url}/v1/accounts/{self.account_id}/calls"
        payload: Dict[str, Any] = {
            "To": self._to_clawops_number(to_number),
            "From": self._to_clawops_number(selected_from),
            "Url": webhook_url,
            "StatusCallbackEvent": "initiated ringing answered completed",
        }

        timeout = kwargs.get("Timeout") or kwargs.get("timeout")
        if timeout is not None:
            payload["Timeout"] = int(timeout)

        if workflow_run_id:
            backend_endpoint, _ = await get_backend_endpoints()
            payload["StatusCallback"] = (
                f"{backend_endpoint}/api/v1/telephony/clawops/status-callback/"
                f"{workflow_run_id}"
            )

        async with aiohttp.ClientSession() as session:
            async with session.post(
                endpoint,
                json=payload,
                headers=self._api_headers(),
            ) as response:
                response_data = await self._safe_json_response(response)
                if response.status != 201:
                    logger.error(
                        "ClawOps call initiation failed: "
                        f"status={response.status} body="
                        f"{redact_telephony_payload_for_logs(response_data)}"
                    )
                    raise HTTPException(
                        status_code=response.status,
                        detail="clawops_start_call_failed",
                    )

        call_id = response_data.get("callId") or response_data.get("CallId")
        if not call_id:
            logger.error(
                "ClawOps call initiation response missing callId: "
                f"{redact_telephony_payload_for_logs(response_data)}"
            )
            raise HTTPException(
                status_code=502,
                detail="clawops_response_missing_call_id",
            )

        return CallInitiationResult(
            call_id=call_id,
            status=response_data.get("status", "queued"),
            caller_number=selected_from,
            provider_metadata={"call_id": call_id},
            raw_response=redact_telephony_payload_for_logs(response_data),
        )

    async def get_call_status(self, call_id: str) -> Dict[str, Any]:
        if not self.validate_config():
            raise ValueError("ClawOps provider not properly configured")

        endpoint = f"{self.base_url}/v1/accounts/{self.account_id}/calls/{call_id}"
        async with aiohttp.ClientSession() as session:
            async with session.get(endpoint, headers=self._api_headers()) as response:
                data = await self._safe_json_response(response)
                if response.status != 200:
                    logger.error(
                        f"Failed to get ClawOps call status: HTTP {response.status}"
                    )
                    raise Exception("Failed to get ClawOps call status")
                return redact_telephony_payload_for_logs(data)

    async def get_available_phone_numbers(self) -> List[str]:
        return self.from_numbers

    def validate_config(self) -> bool:
        return bool(
            self.account_id and self.api_key and self.signing_key and self.from_numbers
        )

    async def verify_webhook_signature(
        self, url: str, params: Dict[str, Any], signature: str
    ) -> bool:
        if not self.signing_key:
            logger.warning("ClawOps signing_key is not configured")
            return False
        if not signature:
            logger.warning("Missing ClawOps X-Signature header")
            return False

        signed_data = url + "".join(
            f"{key}{self._stringify_param_value(params[key])}" for key in sorted(params)
        )
        expected = base64.b64encode(
            hmac.new(
                self.signing_key.encode("utf-8"),
                signed_data.encode("utf-8"),
                hashlib.sha256,
            ).digest()
        ).decode("ascii")
        return hmac.compare_digest(expected, signature)

    async def get_webhook_response(
        self, workflow_id: int, user_id: int, workflow_run_id: int
    ) -> str:
        """Generate VoiceML that connects the call to Recova's media WebSocket."""
        _, wss_backend_endpoint = await get_backend_endpoints()
        stream_url = (
            f"{wss_backend_endpoint}/api/v1/telephony/ws/"
            f"{workflow_id}/{user_id}/{workflow_run_id}"
        )
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Connect>
        <Stream url={quoteattr(stream_url)} track="inbound">
            <Parameter name="provider" value="clawops"/>
            <Parameter name="workflowRunId" value={quoteattr(str(workflow_run_id))}/>
        </Stream>
    </Connect>
    <Pause length="40"/>
</Response>"""

    async def get_call_cost(self, call_id: str) -> Dict[str, Any]:
        try:
            call_data = await self.get_call_status(call_id)
            return {
                "cost_usd": 0.0,
                "duration": call_data.get("duration") or 0,
                "status": call_data.get("status", "unknown"),
                "raw_response": call_data,
            }
        except Exception as exc:
            logger.error(f"Exception fetching ClawOps call cost/status: {exc}")
            return {
                "cost_usd": 0.0,
                "duration": 0,
                "status": "error",
                "error": str(exc),
            }

    def parse_status_callback(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "call_id": data.get("CallId") or data.get("callId") or "",
            "status": data.get("CallStatus")
            or data.get("status")
            or data.get("Status")
            or "",
            "from_number": self._normalize_optional_phone(
                data.get("From") or data.get("from")
            ),
            "to_number": self._normalize_optional_phone(
                data.get("To") or data.get("to")
            ),
            "direction": data.get("Direction") or data.get("direction"),
            "duration": data.get("CallDuration")
            or data.get("Duration")
            or data.get("duration"),
            "extra": data,
        }

    async def handle_websocket(
        self,
        websocket: "WebSocket",
        workflow_id: int,
        user_id: int,
        workflow_run_id: int,
    ) -> None:
        """Handle ClawOps Stream WebSocket handshake and start the pipeline."""
        from api.services.pipecat.run_pipeline import run_pipeline_telephony

        first_msg = json.loads(await websocket.receive_text())
        if first_msg.get("event") == "connected":
            start_msg = json.loads(await websocket.receive_text())
        else:
            start_msg = first_msg

        if start_msg.get("event") != "start":
            logger.error(f"Expected ClawOps start event, got: {start_msg.get('event')}")
            await websocket.close(code=4400, reason="Expected start event")
            return

        start_data = start_msg.get("start", {})
        stream_id = start_data.get("streamId")
        call_id = start_data.get("callId")
        account_id = start_data.get("accountId")
        media_format = start_data.get("mediaFormat") or {}

        if not stream_id or not call_id:
            await websocket.close(code=4400, reason="Missing streamId or callId")
            return

        if account_id and account_id != self.account_id:
            logger.warning(
                f"ClawOps Stream account mismatch for run {workflow_run_id}: "
                "received [redacted]"
            )
            await websocket.close(code=4403, reason="Account mismatch")
            return

        if media_format and (
            media_format.get("encoding") != "audio/x-mulaw"
            or int(media_format.get("sampleRate", 0)) != 8000
        ):
            logger.warning(
                f"Unexpected ClawOps media format for run {workflow_run_id}: "
                f"{media_format}"
            )

        await run_pipeline_telephony(
            websocket,
            provider_name=self.PROVIDER_NAME,
            workflow_id=workflow_id,
            workflow_run_id=workflow_run_id,
            user_id=user_id,
            call_id=call_id,
            transport_kwargs={"stream_id": stream_id, "call_id": call_id},
        )

    @classmethod
    def can_handle_webhook(
        cls, webhook_data: Dict[str, Any], headers: Dict[str, str]
    ) -> bool:
        if "CallId" in webhook_data and "AccountId" in webhook_data:
            return True
        if "callId" in webhook_data and "accountId" in webhook_data:
            return True
        user_agent = headers.get("user-agent", "").lower()
        return "clawops" in user_agent or "claw-ops" in user_agent

    @staticmethod
    def parse_inbound_webhook(webhook_data: Dict[str, Any]) -> NormalizedInboundData:
        from_raw = webhook_data.get("From") or webhook_data.get("from") or ""
        to_raw = webhook_data.get("To") or webhook_data.get("to") or ""
        return NormalizedInboundData(
            provider=ClawOpsProvider.PROVIDER_NAME,
            call_id=webhook_data.get("CallId") or webhook_data.get("callId") or "",
            from_number=ClawOpsProvider._normalize_optional_phone(from_raw),
            to_number=ClawOpsProvider._normalize_optional_phone(to_raw),
            direction=webhook_data.get("Direction")
            or webhook_data.get("direction")
            or "inbound",
            call_status=webhook_data.get("CallStatus")
            or webhook_data.get("status")
            or "ringing",
            account_id=webhook_data.get("AccountId") or webhook_data.get("accountId"),
            from_country=webhook_data.get("FromCountry") or "KR",
            to_country=webhook_data.get("ToCountry") or "KR",
            raw_data=webhook_data,
        )

    @staticmethod
    def validate_account_id(config_data: dict, webhook_account_id: str) -> bool:
        return bool(
            webhook_account_id and config_data.get("account_id") == webhook_account_id
        )

    async def verify_inbound_signature(
        self,
        url: str,
        webhook_data: Dict[str, Any],
        headers: Dict[str, str],
        body: str = "",
    ) -> bool:
        normalized_headers = {key.lower(): value for key, value in headers.items()}
        signature = normalized_headers.get("x-signature", "")
        return await self.verify_webhook_signature(url, webhook_data, signature)

    async def configure_inbound(
        self, address: str, webhook_url: Optional[str]
    ) -> ProviderSyncResult:
        if not self.validate_config():
            return ProviderSyncResult(
                ok=False, message="ClawOps provider not properly configured"
            )

        number = self._to_clawops_number(address)
        endpoint = (
            f"{self.base_url}/v1/accounts/{self.account_id}/numbers/{quote(number)}"
        )
        body: Dict[str, Any] = {
            "routingType": "webhook",
            "webhookUrl": webhook_url,
            "webhookMethod": "POST",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.put(
                    endpoint, json=body, headers=self._api_headers()
                ) as response:
                    response_data = await self._safe_json_response(response)
                    if response.status != 200:
                        logger.error(
                            "ClawOps number webhook update failed: "
                            f"HTTP {response.status} "
                            f"{redact_telephony_payload_for_logs(response_data)}"
                        )
                        return ProviderSyncResult(
                            ok=False,
                            message=f"ClawOps API {response.status}: {response_data}",
                        )
        except Exception as exc:
            logger.error(f"Exception updating ClawOps number webhook: {exc}")
            return ProviderSyncResult(ok=False, message=f"ClawOps update failed: {exc}")

        return ProviderSyncResult(ok=True)

    async def start_inbound_stream(
        self,
        *,
        websocket_url: str,
        workflow_run_id: int,
        normalized_data: NormalizedInboundData,
        backend_endpoint: str,
    ):
        from fastapi import Response

        voiceml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Connect>
        <Stream url={quoteattr(websocket_url)} track="inbound">
            <Parameter name="provider" value="clawops"/>
            <Parameter name="workflowRunId" value={quoteattr(str(workflow_run_id))}/>
        </Stream>
    </Connect>
    <Pause length="40"/>
</Response>"""
        return Response(content=voiceml, media_type="application/xml")

    @staticmethod
    def generate_error_response(error_type: str, message: str) -> tuple:
        from fastapi import Response

        voiceml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say language="ko">{escape(message)}</Say>
    <Hangup/>
</Response>"""
        return Response(content=voiceml, media_type="application/xml")

    @staticmethod
    def generate_validation_error_response(error_type) -> tuple:
        from api.errors.telephony_errors import TELEPHONY_ERROR_MESSAGES, TelephonyError

        message = TELEPHONY_ERROR_MESSAGES.get(
            error_type, TELEPHONY_ERROR_MESSAGES[TelephonyError.GENERAL_AUTH_FAILED]
        )
        return ClawOpsProvider.generate_error_response(str(error_type), message)

    async def transfer_call(
        self,
        destination: str,
        transfer_id: str,
        conference_name: str,
        timeout: int = 30,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        raise NotImplementedError("ClawOps provider does not support Recova transfers")

    def supports_transfers(self) -> bool:
        return False

    def _api_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    @staticmethod
    async def _safe_json_response(response) -> Dict[str, Any]:
        try:
            return await response.json()
        except Exception:
            text = await response.text()
            return {"raw": text}

    @staticmethod
    def _stringify_param_value(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            return "".join(str(item) for item in value)
        return str(value)

    @staticmethod
    def _normalize_optional_phone(value: Any) -> str:
        if not value:
            return ""
        try:
            return normalize_telephony_address(str(value), country_hint="KR").canonical
        except Exception:
            return str(value)

    @staticmethod
    def _to_clawops_number(value: str) -> str:
        normalized = normalize_telephony_address(value, country_hint="KR")
        canonical = normalized.canonical
        if canonical.startswith("+82"):
            return "0" + canonical[3:]
        return canonical.lstrip("+")
