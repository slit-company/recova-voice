import importlib

import pytest
from pipecat.utils.enums import RealtimeFeedbackType

from api.services.pipecat.in_memory_buffers import InMemoryLogsBuffer


@pytest.mark.asyncio
async def test_in_memory_logs_buffer_stamps_current_node_baseline():
    buffer = InMemoryLogsBuffer(workflow_run_id=101)
    buffer.set_current_node("start", "Start")

    await buffer.append(
        {
            "type": RealtimeFeedbackType.LATENCY_MEASURED.value,
            "payload": {"latency_seconds": 0.42},
        }
    )

    [event] = buffer.get_events()
    assert event["node_id"] == "start"
    assert event["node_name"] == "Start"
    assert event["turn"] == 0
    assert event["payload"] == {"latency_seconds": 0.42}


def _latency_events_module():
    try:
        return importlib.import_module("api.services.pipecat.latency_events")
    except ModuleNotFoundError as exc:
        pytest.fail(f"latency_events module missing: {exc}")


def test_latency_breakdown_event_redacts_sensitive_fields():
    module = _latency_events_module()

    event = module.build_voice_latency_breakdown_event(
        workflow_run_id=123,
        latency_profile="speed_demo",
        user_stop_to_bot_started_ms=420.5,
        first_response_ms=250.0,
        first_response_ms_fallback=None,
        extra_payload={
            "client_secret": "super-secret",
            "Authorization": "Bearer token",
            "phone_number": "+821012345678",
            "nested": {"api_key": "key", "safe": "kept"},
        },
    )

    assert event["type"] == RealtimeFeedbackType.LATENCY_MEASURED.value
    assert event["payload"]["kind"] == "voice_latency_breakdown"
    assert event["payload"]["workflow_run_id"] == 123
    assert event["payload"]["latency_profile"] == "speed_demo"
    assert event["payload"]["user_stop_to_bot_started_ms"] == 420.5
    assert event["payload"]["first_response_ms"] == 250.0
    assert event["payload"]["client_secret"] == "[redacted]"
    assert event["payload"]["Authorization"] == "[redacted]"
    assert event["payload"]["phone_number"] == "[redacted]"
    assert event["payload"]["nested"]["api_key"] == "[redacted]"
    assert event["payload"]["nested"]["safe"] == "kept"
