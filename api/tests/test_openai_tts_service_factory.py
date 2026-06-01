from types import SimpleNamespace
from unittest.mock import patch

from api.services.configuration.registry import ServiceProviders
from api.services.pipecat.service_factory import (
    OPENAI_TTS_AGGREGATION_SILENCE_SECONDS,
    OPENAI_TTS_NATIVE_SAMPLE_RATE,
    create_tts_service,
)


def test_create_openai_tts_service_uses_native_sample_rate():
    user_config = SimpleNamespace(
        tts=SimpleNamespace(
            provider=ServiceProviders.OPENAI.value,
            api_key="sk-test-tts",
            model="gpt-4o-mini-tts",
            voice="shimmer",
            speed=1.2,
        )
    )
    audio_config = SimpleNamespace(
        transport_out_sample_rate=8000,
        transport_in_sample_rate=8000,
    )

    with patch("api.services.pipecat.service_factory.OpenAITTSService") as mock_service:
        create_tts_service(user_config, audio_config)

    assert mock_service.call_count == 1
    kwargs = mock_service.call_args.kwargs
    assert kwargs["sample_rate"] == OPENAI_TTS_NATIVE_SAMPLE_RATE
    assert kwargs["silence_time_s"] == OPENAI_TTS_AGGREGATION_SILENCE_SECONDS
    assert kwargs["settings"].model == "gpt-4o-mini-tts"
    assert kwargs["settings"].voice == "shimmer"
    assert kwargs["settings"].speed == 1.2
