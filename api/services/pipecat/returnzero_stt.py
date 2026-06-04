import asyncio
import hashlib
import json
import time
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from urllib.parse import urlencode

import aiohttp
from loguru import logger

from pipecat.frames.frames import (
    CancelFrame,
    EndFrame,
    Frame,
    InterimTranscriptionFrame,
    StartFrame,
    TranscriptionFrame,
)
from pipecat.services.settings import NOT_GIVEN, STTSettings, _NotGiven, assert_given
from pipecat.services.stt_service import WebsocketSTTService
from pipecat.transcriptions.language import Language
from pipecat.utils.time import time_now_iso8601
from pipecat.utils.tracing.service_decorators import traced_stt

from api.services.pipecat.latency_events import milliseconds_from_seconds

try:
    from websockets.asyncio.client import connect as websocket_connect
    from websockets.protocol import State
except ModuleNotFoundError as exc:
    logger.error("websockets is required for ReturnZero STT")
    raise Exception(f"Missing module: {exc}") from exc


DEFAULT_RETURNZERO_API_BASE_URL = "https://openapi.vito.ai"
DEFAULT_RETURNZERO_STREAM_PATH = "/v1/transcribe:streaming"
RETURNZERO_AUTH_PATH = "/v1/authenticate"
RETURNZERO_EOS_MESSAGE = "EOS"
RETURNZERO_TOKEN_REFRESH_MARGIN_SECONDS = 300

_RETURNZERO_TOKEN_CACHE: dict[tuple[str, str, str], "ReturnZeroToken"] = {}
_RETURNZERO_TOKEN_CACHE_LOCK = asyncio.Lock()


@dataclass
class ReturnZeroToken:
    access_token: str
    expire_at: float


@dataclass
class ReturnZeroSTTSettings(STTSettings):
    domain: str | None | _NotGiven = field(default_factory=lambda: NOT_GIVEN)
    use_itn: bool | None | _NotGiven = field(default_factory=lambda: NOT_GIVEN)
    use_disfluency_filter: bool | None | _NotGiven = field(
        default_factory=lambda: NOT_GIVEN
    )
    use_profanity_filter: bool | None | _NotGiven = field(
        default_factory=lambda: NOT_GIVEN
    )
    use_punctuation: bool | None | _NotGiven = field(default_factory=lambda: NOT_GIVEN)


class ReturnZeroSTTService(WebsocketSTTService):
    Settings = ReturnZeroSTTSettings
    _settings: Settings

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        api_base_url: str = DEFAULT_RETURNZERO_API_BASE_URL,
        sample_rate: int | None = None,
        keyterms: list[str] | None = None,
        encoding: str = "LINEAR16",
        settings: Settings | None = None,
        ttfs_p99_latency: float | None = None,
        latency_timings: dict[str, float] | None = None,
        **kwargs,
    ):
        default_settings = self.Settings(
            model="sommers_ko",
            language="ko",
            domain="CALL",
            use_itn=True,
            use_disfluency_filter=False,
            use_profanity_filter=False,
            use_punctuation=True,
        )
        if settings is not None:
            default_settings.apply_update(settings)

        super().__init__(
            sample_rate=sample_rate,
            keepalive_timeout=1,
            keepalive_interval=5,
            ttfs_p99_latency=ttfs_p99_latency,
            settings=default_settings,
            **kwargs,
        )

        self._client_id = client_id
        self._client_secret = client_secret
        self._api_base_url = api_base_url.rstrip("/")
        self._encoding = encoding
        self._keyterms = keyterms or []
        self._token: ReturnZeroToken | None = None
        self._latency_timings = latency_timings
        self._receive_task = None

    def can_generate_metrics(self) -> bool:
        return True

    async def start(self, frame: StartFrame):
        await super().start(frame)
        await self._connect()

    async def stop(self, frame: EndFrame):
        await super().stop(frame)
        await self._send_stop_recording()
        await self._disconnect()

    async def cancel(self, frame: CancelFrame):
        await super().cancel(frame)
        await self._disconnect()

    async def run_stt(self, audio: bytes) -> AsyncGenerator[Frame | None, None]:
        await self.start_processing_metrics()
        if self._websocket and self._websocket.state is State.OPEN:
            await self.send_with_retry(audio, self._report_error)
        yield None

    async def _connect(self):
        await self._connect_websocket()
        await super()._connect()
        if self._websocket and not self._receive_task:
            self._receive_task = self.create_task(
                self._receive_task_handler(self._report_error)
            )

    async def _disconnect(self):
        await super()._disconnect()
        if self._receive_task:
            await self.cancel_task(self._receive_task)
            self._receive_task = None
        await self._disconnect_websocket()

    async def _connect_websocket(self):
        try:
            if self._websocket and self._websocket.state is State.OPEN:
                return

            access_token = await self._fetch_token()
            websocket_started_at = time.perf_counter()
            try:
                self._websocket = await websocket_connect(
                    self.build_streaming_url(),
                    additional_headers={"Authorization": f"Bearer {access_token}"},
                )
            finally:
                self._record_latency_elapsed(
                    "returnzero_ws_connect_ms", websocket_started_at
                )
            if not self._websocket:
                await self.push_error(error_msg="Unable to connect to ReturnZero STT")
                raise RuntimeError("Unable to connect to ReturnZero STT")
            await self._call_event_handler("on_connected")
        except Exception as exc:
            await self.push_error(
                error_msg=f"Unable to connect to ReturnZero STT: {exc}",
                exception=exc,
            )
            raise

    async def _disconnect_websocket(self):
        try:
            if self._websocket and self._websocket.state is State.OPEN:
                await self._websocket.close()
        except Exception as exc:
            await self.push_error(
                error_msg=f"Error closing ReturnZero websocket: {exc}",
                exception=exc,
            )
        finally:
            self._websocket = None
            await self._call_event_handler("on_disconnected")

    def build_streaming_url(self) -> str:
        settings = self._settings
        query: dict[str, str] = {
            "sample_rate": str(self.sample_rate or self._init_sample_rate or 16000),
            "encoding": self._encoding,
            "model_name": assert_given(settings.model) or "sommers_ko",
            "domain": assert_given(settings.domain) or "CALL",
            "use_itn": self._bool_param(assert_given(settings.use_itn)),
            "use_disfluency_filter": self._bool_param(
                assert_given(settings.use_disfluency_filter)
            ),
            "use_profanity_filter": self._bool_param(
                assert_given(settings.use_profanity_filter)
            ),
            "use_punctuation": self._bool_param(assert_given(settings.use_punctuation)),
        }
        language = assert_given(settings.language)
        if language:
            query["language"] = str(language)
        if self._keyterms:
            query["keywords"] = ",".join(self._keyterms)
        return f"{self._streaming_base_url()}{DEFAULT_RETURNZERO_STREAM_PATH}?{urlencode(query)}"

    @staticmethod
    def _bool_param(value: bool | None) -> str:
        return "true" if value else "false"

    def _streaming_base_url(self) -> str:
        if self._api_base_url.startswith("https://"):
            return self._api_base_url.replace("https://", "wss://", 1)
        if self._api_base_url.startswith("http://"):
            return self._api_base_url.replace("http://", "ws://", 1)
        return f"wss://{self._api_base_url}"

    async def _fetch_token(self) -> str:
        if self._token and self._token.expire_at > (
            time.time() + RETURNZERO_TOKEN_REFRESH_MARGIN_SECONDS
        ):
            self._record_latency_value("returnzero_auth_ms", 0.0)
            return self._token.access_token

        cache_key = self._token_cache_key()
        async with _RETURNZERO_TOKEN_CACHE_LOCK:
            cached_token = _RETURNZERO_TOKEN_CACHE.get(cache_key)
            if cached_token and cached_token.expire_at > (
                time.time() + RETURNZERO_TOKEN_REFRESH_MARGIN_SECONDS
            ):
                self._token = cached_token
                self._record_latency_value("returnzero_auth_ms", 0.0)
                return cached_token.access_token

            token = await self._fetch_token_from_returnzero()
            _RETURNZERO_TOKEN_CACHE[cache_key] = token
            self._token = token
            return token.access_token

    async def _fetch_token_from_returnzero(self) -> ReturnZeroToken:
        auth_url = f"{self._api_base_url}{RETURNZERO_AUTH_PATH}"
        auth_started_at = time.perf_counter()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    auth_url,
                    data={
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                    },
                ) as response:
                    if not response.ok:
                        raise RuntimeError(
                            "ReturnZero authentication failed with HTTP "
                            f"{response.status}"
                        )
                    payload_object = await response.json()
        finally:
            self._record_latency_elapsed("returnzero_auth_ms", auth_started_at)

        if not isinstance(payload_object, dict):
            raise RuntimeError("ReturnZero authentication returned an invalid payload")
        access_token_object = payload_object.get("access_token")
        expire_at_object = payload_object.get("expire_at")
        if not isinstance(access_token_object, str) or not isinstance(
            expire_at_object, (int, float)
        ):
            raise RuntimeError("ReturnZero authentication response is missing token data")

        return ReturnZeroToken(
            access_token=access_token_object,
            expire_at=float(expire_at_object),
        )

    def _token_cache_key(self) -> tuple[str, str, str]:
        return (
            self._api_base_url,
            self._credential_digest(self._client_id),
            self._credential_digest(self._client_secret),
        )

    @staticmethod
    def _credential_digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _record_latency_elapsed(self, key: str, started_at: float) -> None:
        self._record_latency_value(
            key, milliseconds_from_seconds(time.perf_counter() - started_at) or 0.0
        )

    def _record_latency_value(self, key: str, value: float) -> None:
        if self._latency_timings is None:
            return
        self._latency_timings[key] = value

    async def _send_stop_recording(self):
        if self._websocket and self._websocket.state is State.OPEN:
            await self._websocket.send(RETURNZERO_EOS_MESSAGE)

    def _get_websocket(self):
        if self._websocket:
            return self._websocket
        raise RuntimeError("ReturnZero websocket is not connected")

    async def _receive_messages(self):
        async for message in self._get_websocket():
            content = self._parse_message(message)
            if content is None:
                continue
            transcript = self._extract_transcript(content)
            if not transcript:
                continue
            is_final = bool(content.get("final"))
            if is_final:
                await self.push_frame(
                    TranscriptionFrame(
                        transcript,
                        self._user_id,
                        time_now_iso8601(),
                        self._language_for_frame(),
                        result=content,
                        finalized=True,
                    )
                )
                await self._handle_transcription(transcript, is_final=True)
                await self.stop_processing_metrics()
            else:
                await self.push_frame(
                    InterimTranscriptionFrame(
                        transcript,
                        self._user_id,
                        time_now_iso8601(),
                        self._language_for_frame(),
                        result=content,
                    )
                )

    def _parse_message(self, message: str | bytes) -> dict[str, object] | None:
        if isinstance(message, bytes):
            message = message.decode("utf-8")
        try:
            content_object = json.loads(message)
        except json.JSONDecodeError:
            logger.warning(f"{self}: ReturnZero returned non-JSON message")
            return None
        if not isinstance(content_object, dict):
            logger.warning(f"{self}: ReturnZero returned non-object JSON message")
            return None
        return content_object

    @staticmethod
    def _extract_transcript(content: dict[str, object]) -> str | None:
        alternatives_object = content.get("alternatives")
        if not isinstance(alternatives_object, list) or not alternatives_object:
            return None
        first_object = alternatives_object[0]
        if not isinstance(first_object, dict):
            return None
        text_object = first_object.get("text")
        if not isinstance(text_object, str):
            return None
        return text_object

    def _language_for_frame(self) -> Language | None:
        language = assert_given(self._settings.language)
        if isinstance(language, Language):
            return language
        if isinstance(language, str):
            try:
                return Language(language)
            except ValueError:
                return None
        return None

    @traced_stt
    async def _handle_transcription(self, transcript: str, is_final: bool):
        pass
