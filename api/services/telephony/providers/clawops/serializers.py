"""ClawOps Stream WebSocket frame serializer."""

import base64
import json

import aiohttp
from loguru import logger

from pipecat.audio.dtmf.types import KeypadEntry
from pipecat.audio.utils import create_stream_resampler, pcm_to_ulaw, ulaw_to_pcm
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


class ClawOpsFrameSerializer(FrameSerializer):
    """Serializer for ClawOps VoiceML Stream WebSocket protocol."""

    class InputParams(FrameSerializer.InputParams):
        clawops_sample_rate: int = 8000
        sample_rate: int | None = None
        auto_hang_up: bool = True

    def __init__(
        self,
        *,
        stream_id: str,
        call_id: str,
        account_id: str | None = None,
        api_key: str | None = None,
        base_url: str = "https://api.claw-ops.com",
        params: InputParams | None = None,
    ):
        params = params or ClawOpsFrameSerializer.InputParams()
        super().__init__(params)
        self._params: ClawOpsFrameSerializer.InputParams = params

        if self._params.auto_hang_up:
            missing = []
            if not call_id:
                missing.append("call_id")
            if not account_id:
                missing.append("account_id")
            if not api_key:
                missing.append("api_key")
            if missing:
                raise ValueError(
                    "auto_hang_up is enabled but missing required parameters: "
                    + ", ".join(missing)
                )

        self._stream_id = stream_id
        self._call_id = call_id
        self._account_id = account_id
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._clawops_sample_rate = self._params.clawops_sample_rate
        self._sample_rate = 0
        self._input_resampler = create_stream_resampler()
        self._output_resampler = create_stream_resampler()
        self._hangup_attempted = False

    async def setup(self, frame: StartFrame):
        self._sample_rate = self._params.sample_rate or frame.audio_in_sample_rate

    async def serialize(self, frame: Frame) -> str | bytes | None:
        if isinstance(frame, (EndFrame, CancelFrame)):
            if self._params.auto_hang_up and not self._hangup_attempted:
                self._hangup_attempted = True
                await self._hang_up_call()
            return None

        if isinstance(frame, InterruptionFrame):
            return json.dumps({"event": "clear"})

        if isinstance(frame, AudioRawFrame):
            serialized_data = await pcm_to_ulaw(
                frame.audio,
                frame.sample_rate,
                self._clawops_sample_rate,
                self._output_resampler,
            )
            if not serialized_data:
                return None

            return json.dumps(
                {
                    "event": "media",
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
        message = json.loads(data)
        event = message.get("event")

        if event == "media":
            payload_base64 = message.get("media", {}).get("payload")
            if not payload_base64:
                return None
            payload = base64.b64decode(payload_base64)
            deserialized_data = await ulaw_to_pcm(
                payload,
                self._clawops_sample_rate,
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
            digit = message.get("dtmf", {}).get("digit")
            try:
                return InputDTMFFrame(KeypadEntry(digit))
            except ValueError:
                return None

        return None

    async def _hang_up_call(self) -> None:
        if not self._account_id or not self._api_key or not self._call_id:
            return

        endpoint = (
            f"{self._base_url}/v1/accounts/{self._account_id}/calls/{self._call_id}"
        )
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    endpoint, json={"Status": "completed"}, headers=headers
                ) as response:
                    if response.status not in (200, 204, 404):
                        logger.warning(
                            "ClawOps call termination returned HTTP "
                            f"{response.status} for call {self._call_id}"
                        )
        except Exception as exc:
            logger.warning(
                f"ClawOps call termination failed for call {self._call_id}: {exc}"
            )


__all__ = ["ClawOpsFrameSerializer"]
