"""Jambonz contract WebSocket frame serializer."""

from __future__ import annotations

import base64
import json
from typing import Any

from pipecat.audio.dtmf.types import KeypadEntry
from pipecat.audio.utils import create_stream_resampler, pcm_to_ulaw, ulaw_to_pcm
from pipecat.frames.frames import (
    AudioRawFrame,
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

    async def setup(self, frame: StartFrame):
        self._sample_rate = self._params.sample_rate or frame.audio_in_sample_rate

    async def serialize(self, frame: Frame) -> str | bytes | None:
        if isinstance(frame, InterruptionFrame):
            return json.dumps(
                {"event": "clear", "stream_id": self._stream_id, "call_id": self._call_id}
            )

        if isinstance(frame, AudioRawFrame):
            serialized_data = await pcm_to_ulaw(
                frame.audio,
                frame.sample_rate,
                self._jambonz_sample_rate,
                self._output_resampler,
            )
            if not serialized_data:
                return None
            return json.dumps(
                {
                    "event": "media",
                    "stream_id": self._stream_id,
                    "call_id": self._call_id,
                    "media": {
                        "payload": base64.b64encode(serialized_data).decode("utf-8")
                    },
                }
            )

        if isinstance(
            frame, (OutputTransportMessageFrame, OutputTransportMessageUrgentFrame)
        ):
            if self.should_ignore_frame(frame):
                return None
            return json.dumps(frame.message)

        return None

    async def deserialize(self, data: str | bytes) -> Frame | None:
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        message: dict[str, Any] = json.loads(data)
        event = message.get("event")

        if event == "media":
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
            digit = message.get("dtmf", {}).get("digit") or message.get("digit")
            try:
                return InputDTMFFrame(KeypadEntry(digit))
            except ValueError:
                return None

        return None


__all__ = ["JambonzFrameSerializer"]
