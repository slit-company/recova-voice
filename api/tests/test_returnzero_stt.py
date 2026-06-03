import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

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
    user_config = SimpleNamespace(
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
