from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from api.services.configuration.registry import ServiceProviders
from api.services.pipecat.service_factory import (
    OPENAI_TTS_AGGREGATION_SILENCE_SECONDS,
    create_tts_service,
)


def _audio_config() -> SimpleNamespace:
    return SimpleNamespace(
        transport_out_sample_rate=24000,
        transport_in_sample_rate=16000,
    )


def test_speed_demo_overrides_elevenlabs_aggregation_silence():
    # Given
    user_config = SimpleNamespace(
        tts=SimpleNamespace(
            provider=ServiceProviders.ELEVENLABS.value,
            api_key="el-test",
            base_url="https://api.elevenlabs.io",
            model="eleven_flash_v2_5",
            voice="Rachel - voice-id",
            speed=1.0,
        )
    )
    # When
    with patch(
        "api.services.pipecat.service_factory.ElevenLabsTTSService"
    ) as mock_service:
        create_tts_service(
            user_config,
            _audio_config(),
            aggregation_silence_seconds=0.35,
        )
    # Then
    assert mock_service.call_count == 1
    assert mock_service.call_args.kwargs["silence_time_s"] == 0.35


def test_openai_keeps_035_default_when_no_override():
    # Given
    user_config = SimpleNamespace(
        tts=SimpleNamespace(
            provider=ServiceProviders.OPENAI.value,
            api_key="sk-test-tts",
            model="gpt-4o-mini-tts",
            voice="shimmer",
            speed=None,
        )
    )
    # When
    with patch("api.services.pipecat.service_factory.OpenAITTSService") as mock_service:
        create_tts_service(user_config, _audio_config())
    # Then
    assert mock_service.call_count == 1
    assert (
        mock_service.call_args.kwargs["silence_time_s"]
        == OPENAI_TTS_AGGREGATION_SILENCE_SECONDS
    )


def test_unsupported_tts_provider_ignores_override_explicitly():
    # Given
    user_config = SimpleNamespace(
        tts=SimpleNamespace(
            provider=ServiceProviders.CAMB.value,
            api_key="camb-test",
            model="mars-flash",
            voice="147320",
            language="en-us",
        )
    )
    mock_instance = MagicMock()
    mock_instance._settings = MagicMock()
    # When
    with patch("pipecat.services.camb.tts.CambTTSService") as mock_service:
        mock_service.return_value = mock_instance
        create_tts_service(
            user_config,
            _audio_config(),
            aggregation_silence_seconds=0.35,
        )
    # Then
    assert mock_service.call_count == 1
    assert "silence_time_s" not in mock_service.call_args.kwargs
