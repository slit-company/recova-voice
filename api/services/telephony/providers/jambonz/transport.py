"""Jambonz transport factory."""

from datetime import datetime, timezone
from fastapi import WebSocket
from pipecat.transports.websocket.fastapi import (
    FastAPIWebsocketParams,
    FastAPIWebsocketTransport,
)

from api.services.pipecat.audio_config import AudioConfig
from api.services.pipecat.audio_mixer import build_audio_out_mixer
from api.services.pipecat.transport_params import realtime_param_overrides
from api.services.telephony.factory import load_credentials_for_transport

from .serializers import JambonzFrameSerializer


async def create_transport(
    websocket: WebSocket,
    workflow_run_id: int,
    audio_config: AudioConfig,
    organization_id: int,
    *,
    ambient_noise_config: dict | None = None,
    telephony_configuration_id: int | None = None,
    is_realtime: bool = False,
    stream_id: str,
    call_id: str,
    jambonz_sample_rate: int | None = None,
    strict_authority: bool = False,
    authority_deadline: str | None = None,
    remaining_seconds: int | None = None,
):
    """Create a transport for Jambonz contract media streams."""
    await load_credentials_for_transport(
        organization_id, telephony_configuration_id, expected_provider="jambonz"
    )
    if strict_authority:
        if (
            jambonz_sample_rate != 8000
            or audio_config.transport_in_sample_rate != 8000
            or audio_config.transport_out_sample_rate != 8000
            or not authority_deadline
            or remaining_seconds is None
        ):
            raise ValueError("invalid Jambonz media authority transport parameters")
        try:
            deadline = datetime.fromisoformat(
                authority_deadline.replace("Z", "+00:00")
            )
            if deadline.tzinfo is None or deadline.utcoffset() is None:
                raise ValueError("naive deadline")
            deadline = deadline.astimezone(timezone.utc)
        except ValueError as exc:
            raise ValueError("invalid Jambonz media authority deadline") from exc
        wall_remaining = int(
            (deadline - datetime.now(timezone.utc)).total_seconds()
        )
        remaining_seconds = max(0, min(60, remaining_seconds, wall_remaining))
        if remaining_seconds <= 0:
            raise ValueError("Jambonz media authority expired")

    serializer = JambonzFrameSerializer(
        stream_id=stream_id,
        call_id=call_id,
        params=JambonzFrameSerializer.InputParams(
            jambonz_sample_rate=(
                jambonz_sample_rate or audio_config.transport_in_sample_rate
            ),
            sample_rate=audio_config.pipeline_sample_rate,
            strict_authority=strict_authority,
            remaining_seconds=remaining_seconds,
        ),
    )

    mixer = await build_audio_out_mixer(
        audio_config.transport_out_sample_rate, ambient_noise_config
    )

    return FastAPIWebsocketTransport(
        websocket=websocket,
        params=FastAPIWebsocketParams(
            audio_in_enabled=True,
            audio_out_enabled=True,
            audio_in_sample_rate=audio_config.transport_in_sample_rate,
            audio_out_sample_rate=audio_config.transport_out_sample_rate,
            audio_out_mixer=mixer,
            serializer=serializer,
            **realtime_param_overrides(is_realtime),
        ),
    )
