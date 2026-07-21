"""Jambonz contract WebSocket frame serializer."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

from pipecat.audio.dtmf.types import KeypadEntry
from pipecat.audio.utils import create_stream_resampler, ulaw_to_pcm
from pipecat.frames.frames import (
    AudioRawFrame,
    CancelFrame,
    EndFrame,
    Frame,
    InputAudioRawFrame,
    InputDTMFFrame,
    InterruptionFrame,
    OutputTransportMessageFrame,
    OutputTransportMessageUrgentFrame,
    StartFrame,
)
from pipecat.serializers.base_serializer import FrameSerializer


class JambonzFrameSerializer(FrameSerializer):
    """Serializer for Recova's Jambonz contract media WebSocket frames."""

    class InputParams(FrameSerializer.InputParams):
        jambonz_sample_rate: int = 8000
        sample_rate: int | None = None
        strict_authority: bool = False
        remaining_seconds: int | None = None

    def __init__(
        self,
        *,
        stream_id: str,
        call_id: str,
        params: InputParams | None = None,
    ):
        params = params or JambonzFrameSerializer.InputParams()
        super().__init__(params)
        self._params: JambonzFrameSerializer.InputParams = params
        self._stream_id = stream_id
        self._call_id = call_id
        self._jambonz_sample_rate = self._params.jambonz_sample_rate
        self._sample_rate = 0
        self._input_resampler = create_stream_resampler()
        self._output_resampler = create_stream_resampler()
        self._strict_authority = self._params.strict_authority
        self._deadline = (
            time.monotonic() + max(0, self._params.remaining_seconds)
            if self._params.remaining_seconds is not None
            else None
        )
        self._disconnect_emitted = False

    async def setup(self, frame: StartFrame):
        self._sample_rate = self._params.sample_rate or frame.audio_in_sample_rate
    def _expired(self) -> bool:
        return self._deadline is not None and time.monotonic() >= self._deadline

    def _disconnect(self) -> str | None:
        if self._disconnect_emitted:
            return None
        self._disconnect_emitted = True
        return json.dumps(
            {
                "type": "disconnect",
                "stream_id": self._stream_id,
                "call_id": self._call_id,
                "reason": "authority_deadline",
            }
        )


    async def serialize(self, frame: Frame) -> str | bytes | None:
        if self._expired():
            return self._disconnect()

        if isinstance(frame, (EndFrame, CancelFrame)):
            return self._disconnect()

        if isinstance(frame, InterruptionFrame):
            return json.dumps(
                {
                    "type": "command",
                    "command": "killAudio",
                    "stream_id": self._stream_id,
                    "call_id": self._call_id,
                }
            )

        if isinstance(frame, AudioRawFrame):
            if self._strict_authority and getattr(frame, "num_channels", 1) != 1:
                return None
            serialized_data = await self._output_resampler.resample(
                frame.audio,
                frame.sample_rate,
                self._jambonz_sample_rate,
            )
            if not serialized_data:
                return None
            return serialized_data

        if isinstance(
            frame, (OutputTransportMessageFrame, OutputTransportMessageUrgentFrame)
        ):
            if self.should_ignore_frame(frame):
                return None
            return json.dumps(frame.message)

        return None

    async def deserialize(self, data: str | bytes) -> Frame | None:
        if self._expired():
            return None
        if isinstance(data, bytes):
            deserialized_data = await self._input_resampler.resample(
                data,
                self._jambonz_sample_rate,
                self._sample_rate,
            )
            if not deserialized_data:
                return None
            return InputAudioRawFrame(
                audio=deserialized_data,
                num_channels=1,
                sample_rate=self._sample_rate,
            )

        message: dict[str, Any] = json.loads(data)
        event = message.get("event")

        if event == "media":
            if self._strict_authority:
                return None
            payload_base64 = message.get("media", {}).get("payload")
            if not payload_base64:
                return None
            payload = base64.b64decode(payload_base64)
            deserialized_data = await ulaw_to_pcm(
                payload,
                self._jambonz_sample_rate,
                self._sample_rate,
                self._input_resampler,
            )
            if not deserialized_data:
                return None
            return InputAudioRawFrame(
                audio=deserialized_data,
                num_channels=1,
                sample_rate=self._sample_rate,
            )

        if event == "dtmf":
            dtmf = message.get("dtmf")
            digit = dtmf.get("digit") if isinstance(dtmf, dict) else dtmf
            digit = digit or message.get("digit")
            try:
                return InputDTMFFrame(KeypadEntry(digit))
            except ValueError:
                return None

        return None


__all__ = ["JambonzFrameSerializer"]
