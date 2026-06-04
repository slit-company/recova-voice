from pipecat.turns.user_stop import SpeechTimeoutUserTurnStopStrategy
from loguru import logger

from api.services.configuration.registry import ServiceProviders
from api.services.pipecat.run_pipeline import (
    _create_standard_user_turn_config,
    _log_resolved_latency_profile,
)


def test_standard_speed_demo_uses_350ms_user_speech_timeout():
    # Given
    user_speech_timeout_seconds = 0.35

    # When
    strategies = _create_standard_user_turn_config(
        stt_provider=ServiceProviders.RETURNZERO.value,
        stt_model="sommers_ko",
        turn_stop_strategy="transcription",
        smart_turn_stop_secs=2.0,
        user_speech_timeout_seconds=user_speech_timeout_seconds,
    )

    # Then
    assert isinstance(strategies.stop[0], SpeechTimeoutUserTurnStopStrategy)
    assert strategies.stop[0]._user_speech_timeout == 0.35


def test_balanced_profile_keeps_600ms_user_speech_timeout():
    # Given
    user_speech_timeout_seconds = 0.6

    # When
    strategies = _create_standard_user_turn_config(
        stt_provider=ServiceProviders.RETURNZERO.value,
        stt_model="sommers_ko",
        turn_stop_strategy="transcription",
        smart_turn_stop_secs=2.0,
        user_speech_timeout_seconds=user_speech_timeout_seconds,
    )

    # Then
    assert isinstance(strategies.stop[0], SpeechTimeoutUserTurnStopStrategy)
    assert strategies.stop[0]._user_speech_timeout == 0.6


def test_run_pipeline_logs_resolved_latency_profile_for_observability():
    # Given
    messages: list[str] = []
    sink_id = logger.add(messages.append, format="{message}")

    # When
    try:
        _log_resolved_latency_profile(
            workflow_run_id=42,
            latency_profile="speed_demo",
            is_phone_preview_run=True,
            runtime_latency_profile="speed_demo",
        )
    finally:
        logger.remove(sink_id)

    # Then
    assert any("workflow_run_id=42" in message for message in messages)
    assert any("latency_profile=speed_demo" in message for message in messages)
    assert any("runtime_latency_profile=speed_demo" in message for message in messages)
