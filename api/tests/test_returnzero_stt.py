import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from websockets.protocol import State

from api.schemas.user_configuration import UserConfiguration
from api.routes.user import UserConfigurationRequestResponseSchema
from api.services.configuration.check_validity import UserConfigurationValidator
from api.services.configuration.masking import mask_key, mask_user_config
from api.services.configuration.merge import merge_user_configurations
from api.services.configuration.registry import (
    REGISTRY,
    ReturnZeroSTTConfiguration,
    ServiceProviders,
    ServiceType,
)
from api.services.pipecat.returnzero_stt import (
    ReturnZeroSTTService,
    ReturnZeroSTTSettings,
)
from api.services.pipecat.service_factory import create_stt_service
from pipecat.frames.frames import InterimTranscriptionFrame, TranscriptionFrame


class _FakeReturnZeroResponse:
    def __init__(self, payload: dict[str, object], status: int = 200):
        self._payload = payload
        self.status = status
        self.ok = status < 400

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def json(self):
        return self._payload


class _FakeReturnZeroSession:
    def __init__(self, factory: "_FakeReturnZeroSessionFactory"):
        self._factory = factory

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, url: str, data: dict[str, str]):
        self._factory.calls.append({"url": url, "data": data})
        return _FakeReturnZeroResponse(self._factory.payload)


class _FakeReturnZeroSessionFactory:
    def __init__(self, payload: dict[str, object]):
        self.payload = payload
        self.calls: list[dict[str, object]] = []

    def __call__(self):
        return _FakeReturnZeroSession(self)


class _FakeOpenWebSocket:
    state = State.OPEN


def _returnzero_user_config():
    return SimpleNamespace(
        stt=SimpleNamespace(
            provider=ServiceProviders.RETURNZERO.value,
            api_key=None,
            model="sommers_ko",
            language="ko",
            client_id="client-id",
            client_secret="client-secret",
            domain="CALL",
            use_itn=True,
            use_disfluency_filter=False,
            use_profanity_filter=False,
            use_punctuation=True,
        )
    )


def test_returnzero_stt_schema_is_registered_for_ui():
    provider = ServiceProviders.RETURNZERO.value

    assert REGISTRY[ServiceType.STT][provider] is ReturnZeroSTTConfiguration

    schema = ReturnZeroSTTConfiguration.model_json_schema()
    properties = schema["properties"]

    assert schema["title"] == "ReturnZero"
    assert properties["model"]["examples"] == ["sommers_ko", "sommers_ja", "whisper"]
    assert properties["language"]["default"] == "ko"
    assert properties["client_secret"]["secret"] is True
    assert properties["api_key"]["hidden"] is True


def test_returnzero_client_secret_is_masked_and_preserved_on_round_trip():
    config = UserConfiguration(
        stt=ReturnZeroSTTConfiguration(
            provider=ServiceProviders.RETURNZERO.value,
            model="sommers_ko",
            language="ko",
            client_id="client-id",
            client_secret="client-secret-value",
        )
    )

    masked = mask_user_config(config)
    assert masked["stt"]["client_secret"] == mask_key("client-secret-value")

    merged = merge_user_configurations(
        config,
        {
            "stt": {
                "provider": ServiceProviders.RETURNZERO.value,
                "model": "sommers_ko",
                "language": "ko",
                "client_id": "client-id",
                "client_secret": masked["stt"]["client_secret"],
            }
        },
    )

    assert isinstance(merged.stt, ReturnZeroSTTConfiguration)
    assert merged.stt.client_secret == "client-secret-value"


def test_returnzero_validator_checks_client_credentials_without_api_key():
    validator = UserConfigurationValidator()
    service = ReturnZeroSTTConfiguration(
        provider=ServiceProviders.RETURNZERO.value,
        model="sommers_ko",
        language="ko",
        client_id="client-id",
        client_secret="client-secret",
    )

    assert validator._validate_service(service, "stt") == []

    missing_secret = ReturnZeroSTTConfiguration.model_construct(
        provider=ServiceProviders.RETURNZERO.value,
        api_key=None,
        model="sommers_ko",
        language="ko",
        client_id="client-id",
        client_secret="",
    )

    errors = validator._validate_service(missing_secret, "stt")
    assert errors == [
        {
            "model": "stt",
            "message": "client_id and client_secret are required for ReturnZero STT",
        }
    ]


def test_user_configuration_request_schema_allows_returnzero_boolean_flags():
    payload = UserConfigurationRequestResponseSchema.model_validate(
        {
            "stt": {
                "provider": ServiceProviders.RETURNZERO.value,
                "model": "sommers_ko",
                "client_id": "client-id",
                "client_secret": "client-secret",
                "use_itn": True,
                "use_disfluency_filter": False,
            }
        }
    )

    assert payload.stt
    assert payload.stt["use_itn"] is True
    assert payload.stt["use_disfluency_filter"] is False


def test_create_returnzero_stt_service_uses_client_credentials_and_audio_settings():
    user_config = _returnzero_user_config()
    audio_config = SimpleNamespace(transport_in_sample_rate=8000)

    with patch("api.services.pipecat.service_factory.ReturnZeroSTTService") as mock_service:
        create_stt_service(user_config, audio_config, keyterms=["리턴제로:3.5"])

    assert mock_service.call_count == 1
    kwargs = mock_service.call_args.kwargs
    assert kwargs["client_id"] == "client-id"
    assert kwargs["client_secret"] == "client-secret"
    assert kwargs["sample_rate"] == 8000
    assert kwargs["keyterms"] == ["리턴제로:3.5"]
    assert kwargs["settings"].model == "sommers_ko"
    assert kwargs["settings"].language == "ko"
    assert kwargs["settings"].domain == "CALL"
    assert kwargs["ttfs_p99_latency"] is None


@pytest.mark.asyncio
async def test_returnzero_service_reuses_instance_token_until_near_expiry_baseline():
    session_factory = _FakeReturnZeroSessionFactory(
        {"access_token": "instance-token", "expire_at": time.time() + 600}
    )
    service = ReturnZeroSTTService(
        client_id="baseline-client-id",
        client_secret="baseline-client-secret",
    )

    with patch(
        "api.services.pipecat.returnzero_stt.aiohttp.ClientSession",
        session_factory,
    ):
        first = await service._fetch_token()
        second = await service._fetch_token()

    assert first == "instance-token"
    assert second == "instance-token"
    assert len(session_factory.calls) == 1


@pytest.mark.asyncio
async def test_returnzero_token_cache_reuses_valid_token():
    session_factory = _FakeReturnZeroSessionFactory(
        {"access_token": "shared-token", "expire_at": time.time() + 600}
    )
    websocket_calls: list[dict[str, object]] = []

    async def fake_websocket_connect(url: str, additional_headers: dict[str, str]):
        websocket_calls.append({"url": url, "headers": additional_headers})
        return _FakeOpenWebSocket()

    first_service = ReturnZeroSTTService(
        client_id="cache-client-id",
        client_secret="cache-client-secret",
        api_base_url="https://returnzero-cache.test",
    )
    second_service = ReturnZeroSTTService(
        client_id="cache-client-id",
        client_secret="cache-client-secret",
        api_base_url="https://returnzero-cache.test",
    )

    with (
        patch(
            "api.services.pipecat.returnzero_stt.aiohttp.ClientSession",
            session_factory,
        ),
        patch(
            "api.services.pipecat.returnzero_stt.websocket_connect",
            side_effect=fake_websocket_connect,
        ),
    ):
        await first_service._connect_websocket()
        await second_service._connect_websocket()

    assert len(session_factory.calls) == 1
    assert len(websocket_calls) == 2
    assert websocket_calls[0]["headers"] == {"Authorization": "Bearer shared-token"}
    assert websocket_calls[1]["headers"] == {"Authorization": "Bearer shared-token"}


@pytest.mark.asyncio
async def test_returnzero_token_cache_refreshes_near_expiry_token():
    session_factory = _FakeReturnZeroSessionFactory(
        {"access_token": "near-expiry-token", "expire_at": time.time() + 299}
    )

    async def fake_websocket_connect(url: str, additional_headers: dict[str, str]):
        return _FakeOpenWebSocket()

    first_service = ReturnZeroSTTService(
        client_id="near-expiry-client-id",
        client_secret="near-expiry-client-secret",
        api_base_url="https://returnzero-near-expiry.test",
    )
    second_service = ReturnZeroSTTService(
        client_id="near-expiry-client-id",
        client_secret="near-expiry-client-secret",
        api_base_url="https://returnzero-near-expiry.test",
    )

    with (
        patch(
            "api.services.pipecat.returnzero_stt.aiohttp.ClientSession",
            session_factory,
        ),
        patch(
            "api.services.pipecat.returnzero_stt.websocket_connect",
            side_effect=fake_websocket_connect,
        ),
    ):
        await first_service._connect_websocket()
        await second_service._connect_websocket()

    assert len(session_factory.calls) == 2


def test_returnzero_service_passes_configured_ttfs_p99_latency(monkeypatch):
    user_config = _returnzero_user_config()
    audio_config = SimpleNamespace(transport_in_sample_rate=8000)

    with patch("api.services.pipecat.service_factory.ReturnZeroSTTService") as mock_service:
        create_stt_service(
            user_config,
            audio_config,
            returnzero_ttfs_p99_latency_seconds=0.42,
        )

    assert mock_service.call_args.kwargs["ttfs_p99_latency"] == 0.42

    monkeypatch.setenv("RETURNZERO_TTFS_P99_SECONDS", "0.77")
    with patch("api.services.pipecat.service_factory.ReturnZeroSTTService") as mock_service:
        create_stt_service(user_config, audio_config)

    assert mock_service.call_args.kwargs["ttfs_p99_latency"] == 0.77


def test_create_stt_service_does_not_forward_ttfs_without_configuration(monkeypatch):
    user_config = _returnzero_user_config()
    audio_config = SimpleNamespace(transport_in_sample_rate=8000)

    monkeypatch.delenv("RETURNZERO_TTFS_P99_SECONDS", raising=False)
    with patch("api.services.pipecat.service_factory.ReturnZeroSTTService") as mock_service:
        create_stt_service(user_config, audio_config)

    assert mock_service.call_args.kwargs["ttfs_p99_latency"] is None


def test_returnzero_service_ignores_invalid_ttfs_env(monkeypatch):
    user_config = _returnzero_user_config()
    audio_config = SimpleNamespace(transport_in_sample_rate=8000)

    monkeypatch.setenv("RETURNZERO_TTFS_P99_SECONDS", "not-a-float")
    with patch("api.services.pipecat.service_factory.ReturnZeroSTTService") as mock_service:
        create_stt_service(user_config, audio_config)

    assert mock_service.call_args.kwargs["ttfs_p99_latency"] is None


@pytest.mark.asyncio
async def test_returnzero_connect_records_auth_and_websocket_timings():
    session_factory = _FakeReturnZeroSessionFactory(
        {"access_token": "timing-token", "expire_at": time.time() + 600}
    )
    latency_timings: dict[str, float] = {}

    async def fake_websocket_connect(url: str, additional_headers: dict[str, str]):
        return _FakeOpenWebSocket()

    service = ReturnZeroSTTService(
        client_id="timing-client-id",
        client_secret="timing-client-secret",
        api_base_url="https://returnzero-timing.test",
        latency_timings=latency_timings,
    )

    with (
        patch(
            "api.services.pipecat.returnzero_stt.aiohttp.ClientSession",
            session_factory,
        ),
        patch(
            "api.services.pipecat.returnzero_stt.websocket_connect",
            side_effect=fake_websocket_connect,
        ),
    ):
        await service._connect_websocket()

    assert latency_timings["returnzero_auth_ms"] >= 0
    assert latency_timings["returnzero_ws_connect_ms"] >= 0
    assert "timing-client-secret" not in json.dumps(latency_timings)


def test_returnzero_streaming_url_uses_rtzr_websocket_parameters():
    service = ReturnZeroSTTService(
        client_id="client-id",
        client_secret="client-secret",
        sample_rate=8000,
        keyterms=["예약", "리턴제로:3.5"],
        settings=ReturnZeroSTTSettings(
            model="sommers_ko",
            language="ko",
            domain="CALL",
            use_itn=True,
            use_disfluency_filter=False,
            use_profanity_filter=False,
            use_punctuation=True,
        ),
    )

    url = service.build_streaming_url()
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    assert parsed.scheme == "wss"
    assert parsed.netloc == "openapi.vito.ai"
    assert parsed.path == "/v1/transcribe:streaming"
    assert params["sample_rate"] == ["8000"]
    assert params["encoding"] == ["LINEAR16"]
    assert params["model_name"] == ["sommers_ko"]
    assert params["language"] == ["ko"]
    assert params["domain"] == ["CALL"]
    assert params["use_itn"] == ["true"]
    assert params["use_disfluency_filter"] == ["false"]
    assert params["use_profanity_filter"] == ["false"]
    assert params["use_punctuation"] == ["true"]
    assert params["keywords"] == ["예약,리턴제로:3.5"]


@pytest.mark.asyncio
async def test_returnzero_receive_messages_pushes_interim_and_final_frames():
    class FakeWebSocket:
        def __init__(self, messages: list[str]):
            self._messages = iter(messages)

        def __aiter__(self):
            return self

        async def __anext__(self):
            try:
                return next(self._messages)
            except StopIteration as exc:
                raise StopAsyncIteration from exc

    service = ReturnZeroSTTService(
        client_id="client-id",
        client_secret="client-secret",
        settings=ReturnZeroSTTSettings(model="sommers_ko", language="ko"),
    )
    service._websocket = FakeWebSocket(
        [
            json.dumps({"final": False, "alternatives": [{"text": "안녕"}]}),
            json.dumps({"final": True, "alternatives": [{"text": "안녕하세요"}]}),
        ]
    )
    service._user_id = "user-1"
    pushed_frames: list[InterimTranscriptionFrame | TranscriptionFrame] = []
    service.push_frame = AsyncMock(side_effect=lambda frame, direction=None: pushed_frames.append(frame))
    service.stop_processing_metrics = AsyncMock()

    await service._receive_messages()

    assert isinstance(pushed_frames[0], InterimTranscriptionFrame)
    assert pushed_frames[0].text == "안녕"
    assert isinstance(pushed_frames[1], TranscriptionFrame)
    assert pushed_frames[1].text == "안녕하세요"
    assert pushed_frames[1].finalized is True
    assert pushed_frames[1].user_id == "user-1"
