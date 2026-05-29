"""Amazon Connect outbound-control provider."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import aioboto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import HTTPException, Response
from loguru import logger

from api.enums import WorkflowRunMode
from api.services.telephony.base import (
    CallInitiationResult,
    NormalizedInboundData,
    TelephonyProvider,
)

if TYPE_CHECKING:
    from fastapi import WebSocket

_TERMINAL_STATUSES = {"completed", "failed", "busy", "no-answer", "canceled"}


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, dict):
        return {k: _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_jsonable(v) for v in value]
    return value


class AWSConnectProvider(TelephonyProvider):
    """Outbound-only Amazon Connect provider.

    This provider starts a published Amazon Connect contact flow with
    StartOutboundVoiceContact. It is intentionally not a full Recova media
    transport; the contact flow owns the audio experience until a dedicated
    Amazon Connect media bridge is designed.
    """

    PROVIDER_NAME = WorkflowRunMode.AWS_CONNECT.value
    WEBHOOK_ENDPOINT = None
    SUPPORTS_MEDIA_TRANSPORT = False
    SUPPORTS_PREVIEW_SMOKE = True

    def __init__(self, config: Dict[str, Any]):
        self.region = config.get("region")
        self.instance_id = config.get("instance_id")
        self.contact_flow_id = config.get("contact_flow_id")
        self.queue_id = config.get("queue_id")
        # Server-controlled local/dev profile only. Do not read this from a
        # stored org config; tenant-controlled config must not select arbitrary
        # AWS profiles present on the server.
        self.aws_profile = os.getenv("AWS_CONNECT_AWS_PROFILE") or os.getenv(
            "AWS_PROFILE"
        )
        ring_timeout_seconds = config.get("ring_timeout_seconds")
        self.ring_timeout_seconds = (
            int(ring_timeout_seconds) if ring_timeout_seconds is not None else None
        )
        configured_from_numbers = config.get("from_numbers") or []
        if isinstance(configured_from_numbers, str):
            configured_from_numbers = [configured_from_numbers]
        self.from_numbers = [
            str(number).strip()
            for number in configured_from_numbers
            if str(number).strip()
        ]

    def _session(self) -> aioboto3.Session:
        if self.aws_profile:
            return aioboto3.Session(profile_name=self.aws_profile)
        return aioboto3.Session()

    async def initiate_call(
        self,
        to_number: str,
        webhook_url: str,
        workflow_run_id: Optional[int] = None,
        from_number: Optional[str] = None,
        **kwargs: Any,
    ) -> CallInitiationResult:
        """Start an outbound voice contact through Amazon Connect."""
        if not self.validate_config():
            raise ValueError("Amazon Connect provider not properly configured")

        source_phone_number = self._select_source_phone_number(from_number)
        request: Dict[str, Any] = {
            "InstanceId": self.instance_id,
            "ContactFlowId": self.contact_flow_id,
            "DestinationPhoneNumber": to_number,
            "Name": f"Recova preview {workflow_run_id or 'call'}",
            "Description": "Recova phone-preview outbound smoke/contact-flow call",
            "Attributes": {
                "recova_workflow_run_id": str(workflow_run_id or ""),
                "recova_workflow_id": str(kwargs.get("workflow_id") or ""),
                "recova_user_id": str(kwargs.get("user_id") or ""),
                "recova_preview": "true",
            },
        }
        # Prefer explicit SourcePhoneNumber so Recova's selected representative
        # number wins even when the queue has a different outbound caller ID.
        if source_phone_number:
            request["SourcePhoneNumber"] = source_phone_number
        elif self.queue_id:
            request["QueueId"] = self.queue_id
        else:
            raise ValueError(
                "Amazon Connect requires a source phone number or queue_id"
            )
        # A custom ring timer is opt-in because Amazon Connect can reject this
        # parameter unless the contact uses CAMPAIGN traffic. The default
        # Recova preview config leaves it unset and lets Connect choose.
        if self.ring_timeout_seconds is not None:
            request["RingTimeoutInSeconds"] = self.ring_timeout_seconds

        logger.info(
            "[AWSConnect] Starting outbound contact "
            f"instance={self.instance_id} flow={self.contact_flow_id} "
            f"workflow_run_id={workflow_run_id} source_configured={bool(source_phone_number)}"
        )

        try:
            session = self._session()
            async with session.client("connect", region_name=self.region) as client:
                response = await client.start_outbound_voice_contact(**request)
        except (ClientError, BotoCoreError) as exc:
            logger.error(
                "[AWSConnect] StartOutboundVoiceContact failed: "
                f"{exc.__class__.__name__}"
            )
            raise HTTPException(
                status_code=502, detail="aws_connect_start_outbound_failed"
            ) from exc

        contact_id = response.get("ContactId", "")
        return CallInitiationResult(
            call_id=contact_id,
            status="initiated",
            caller_number=source_phone_number,
            provider_metadata={
                "call_id": contact_id,
                "contact_id": contact_id,
                "contact_flow_id": self.contact_flow_id,
                "instance_id": self.instance_id,
            },
            raw_response={"ContactId": contact_id},
        )

    def _select_source_phone_number(self, from_number: Optional[str]) -> Optional[str]:
        if from_number:
            return from_number
        if not self.from_numbers:
            return None
        return self.from_numbers[0]

    async def get_call_status(self, call_id: str) -> Dict[str, Any]:
        if not self.validate_config():
            raise ValueError("Amazon Connect provider not properly configured")
        if not call_id:
            raise ValueError("call_id is required")

        try:
            session = self._session()
            async with session.client("connect", region_name=self.region) as client:
                response = await client.describe_contact(
                    InstanceId=self.instance_id,
                    ContactId=call_id,
                )
        except (ClientError, BotoCoreError) as exc:
            logger.error(
                f"[AWSConnect] DescribeContact failed: {exc.__class__.__name__}"
            )
            raise HTTPException(
                status_code=502, detail="aws_connect_describe_contact_failed"
            ) from exc

        contact = response.get("Contact", {})
        disconnect_reason = contact.get("DisconnectReason")
        status = "completed" if contact.get("DisconnectTimestamp") else "in_progress"
        if disconnect_reason in {
            "OUTBOUND_DESTINATION_ENDPOINT_ERROR",
            "TELECOM_PROBLEM",
        }:
            status = "failed"

        return {
            "call_id": contact.get("Id") or call_id,
            "status": status,
            "disconnect_reason": disconnect_reason,
            "initiation_method": contact.get("InitiationMethod"),
            "initiation_timestamp": _to_jsonable(contact.get("InitiationTimestamp")),
            "connected_to_system_timestamp": _to_jsonable(
                contact.get("ConnectedToSystemTimestamp")
            ),
            "disconnect_timestamp": _to_jsonable(contact.get("DisconnectTimestamp")),
        }

    async def get_available_phone_numbers(self) -> List[str]:
        return self.from_numbers

    def validate_config(self) -> bool:
        if not (self.region and self.instance_id and self.contact_flow_id):
            return False
        if self.ring_timeout_seconds is not None and (
            self.ring_timeout_seconds < 15 or self.ring_timeout_seconds > 60
        ):
            return False
        return bool(self.queue_id or self.from_numbers)

    async def verify_webhook_signature(
        self, url: str, params: Dict[str, Any], signature: str
    ) -> bool:
        return False

    async def get_webhook_response(
        self, workflow_id: int, user_id: int, workflow_run_id: int
    ) -> str:
        logger.warning(
            "get_webhook_response called for aws_connect; Amazon Connect "
            "contact flows do not request provider markup from Recova."
        )
        return ""

    async def get_call_cost(self, call_id: str) -> Dict[str, Any]:
        status = await self.get_call_status(call_id)
        return {
            "cost_usd": None,
            "duration": None,
            "status": status.get("status", "unknown"),
            "error": "Amazon Connect provider does not expose per-call cost here",
        }

    def parse_status_callback(self, data: Dict[str, Any]) -> Dict[str, Any]:
        detail = data.get("detail", data)
        contact_id = detail.get("contactId") or detail.get("ContactId") or ""
        event_type = str(detail.get("eventType") or detail.get("EventType") or "")
        status = "completed" if event_type.upper() == "DISCONNECTED" else "in_progress"
        return {
            "call_id": contact_id,
            "status": status,
            "from_number": None,
            "to_number": None,
            "duration": None,
            "extra": {"event_type": event_type},
        }

    async def handle_websocket(
        self,
        websocket: "WebSocket",
        workflow_id: int,
        user_id: int,
        workflow_run_id: int,
    ) -> None:
        await websocket.close(code=1003, reason="aws_connect_media_not_supported")

    @classmethod
    def can_handle_webhook(
        cls, webhook_data: Dict[str, Any], headers: Dict[str, str]
    ) -> bool:
        return False

    @staticmethod
    def parse_inbound_webhook(webhook_data: Dict[str, Any]) -> NormalizedInboundData:
        return NormalizedInboundData(
            provider=AWSConnectProvider.PROVIDER_NAME,
            call_id="",
            from_number="",
            to_number="",
            direction="inbound",
            call_status="unsupported",
            account_id=None,
            raw_data={},
        )

    @staticmethod
    def validate_account_id(config_data: dict, webhook_account_id: str) -> bool:
        return False

    async def verify_inbound_signature(
        self,
        url: str,
        webhook_data: Dict[str, Any],
        headers: Dict[str, str],
        body: str = "",
    ) -> bool:
        return False

    async def start_inbound_stream(
        self,
        *,
        websocket_url: str,
        workflow_run_id: int,
        normalized_data: NormalizedInboundData,
        backend_endpoint: str,
    ):
        return Response(status_code=204)

    @staticmethod
    def generate_error_response(error_type: str, message: str) -> tuple:
        return (
            Response(
                content=json.dumps({"error": error_type, "message": message}),
                media_type="application/json",
            ),
            "application/json",
        )

    async def transfer_call(
        self,
        destination: str,
        transfer_id: str,
        conference_name: str,
        timeout: int = 30,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        raise NotImplementedError("Amazon Connect provider does not support transfers")

    def supports_transfers(self) -> bool:
        return False

    @property
    def terminal_statuses(self) -> set[str]:
        return _TERMINAL_STATUSES
