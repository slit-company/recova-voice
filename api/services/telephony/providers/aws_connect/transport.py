"""Amazon Connect transport placeholder.

Amazon Connect StartOutboundVoiceContact executes a Connect contact flow; it does
not open the provider WebSocket transport used by Twilio/ARI/Telnyx for Recova's
Pipecat runtime. The provider is intentionally outbound-control only for the
current Recova smoke/preview path.
"""

from __future__ import annotations

from typing import Any

from fastapi import WebSocket

from api.services.pipecat.audio_config import AudioConfig


async def create_transport(
    websocket: WebSocket,
    workflow_run_id: int,
    audio_config: AudioConfig,
    organization_id: int,
    **kwargs: Any,
):
    raise NotImplementedError(
        "Amazon Connect does not expose a Recova WebSocket media transport. "
        "Use SIP/ARI for full low-latency Recova AI calls, or an Amazon Connect "
        "contact flow/Lambda harness for smoke tests."
    )
