from __future__ import annotations

from typing import Any

from pipecat.utils.enums import RealtimeFeedbackType

_SENSITIVE_EXACT_KEYS = {
    "authorization",
    "client_secret",
    "secret",
    "token",
    "api_key",
    "credential",
}
_SENSITIVE_KEY_FRAGMENTS = (
    "phone",
    "number",
    "caller",
    "called",
    "account",
    "sid",
    "secret",
    "token",
    "api_key",
    "credential",
)


def milliseconds_from_seconds(seconds: float | None) -> float | None:
    if seconds is None:
        return None
    return round(seconds * 1000, 3)


def _is_sensitive_key(key: object) -> bool:
    key_text = str(key).lower()
    return key_text in _SENSITIVE_EXACT_KEYS or any(
        fragment in key_text for fragment in _SENSITIVE_KEY_FRAGMENTS
    )


def _redact_sensitive(value: Any, *, key: object | None = None) -> Any:
    if key is not None and _is_sensitive_key(key):
        return "[redacted]"
    if isinstance(value, dict):
        return {
            item_key: _redact_sensitive(item_value, key=item_key)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_sensitive(item) for item in value]
    return value


def serialize_latency_breakdown(breakdown: Any) -> dict[str, Any] | None:
    if breakdown is None:
        return None
    if hasattr(breakdown, "model_dump"):
        return _redact_sensitive(breakdown.model_dump())
    if isinstance(breakdown, dict):
        return _redact_sensitive(breakdown)
    return _redact_sensitive({"value": str(breakdown)})


def build_voice_latency_breakdown_event(
    *,
    workflow_run_id: int,
    latency_profile: str | None,
    pipeline_started_at: str | None = None,
    client_connected_at: str | None = None,
    initial_response_triggered_at: str | None = None,
    pre_call_fetch_wait_ms: float | None = None,
    returnzero_auth_ms: float | None = None,
    returnzero_ws_connect_ms: float | None = None,
    stt_first_interim_ms: float | None = None,
    stt_final_ms: float | None = None,
    vad_stop_to_final_ms: float | None = None,
    user_turn_stopped_at: str | None = None,
    llm_ttfb_ms: float | None = None,
    tts_ttfb_ms: float | None = None,
    bot_started_speaking_at: str | None = None,
    first_response_ms: float | None = None,
    first_response_ms_fallback: str | None = None,
    user_stop_to_bot_started_ms: float | None = None,
    pipecat_latency_breakdown: dict[str, Any] | None = None,
    extra_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "kind": "voice_latency_breakdown",
        "workflow_run_id": workflow_run_id,
        "latency_profile": latency_profile or "balanced",
        "pipeline_started_at": pipeline_started_at,
        "client_connected_at": client_connected_at,
        "initial_response_triggered_at": initial_response_triggered_at,
        "pre_call_fetch_wait_ms": pre_call_fetch_wait_ms,
        "returnzero_auth_ms": returnzero_auth_ms,
        "returnzero_ws_connect_ms": returnzero_ws_connect_ms,
        "stt_first_interim_ms": stt_first_interim_ms,
        "stt_final_ms": stt_final_ms,
        "vad_stop_to_final_ms": vad_stop_to_final_ms,
        "user_turn_stopped_at": user_turn_stopped_at,
        "llm_ttfb_ms": llm_ttfb_ms,
        "tts_ttfb_ms": tts_ttfb_ms,
        "bot_started_speaking_at": bot_started_speaking_at,
        "first_response_ms": first_response_ms,
        "first_response_ms_fallback": first_response_ms_fallback,
        "user_stop_to_bot_started_ms": user_stop_to_bot_started_ms,
    }
    if pipecat_latency_breakdown is not None:
        payload["pipecat_latency_breakdown"] = pipecat_latency_breakdown
    if extra_payload:
        payload.update(extra_payload)

    return {
        "type": RealtimeFeedbackType.LATENCY_MEASURED.value,
        "payload": _redact_sensitive(payload),
    }


def build_speed_demo_startup_warning_event(
    *,
    workflow_run_id: int,
    warning_code: str,
    node_id: str,
    node_name: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "kind": "voice_latency_warning",
        "workflow_run_id": workflow_run_id,
        "latency_profile": "speed_demo",
        "warning_code": warning_code,
        "node_id": node_id,
        "node_name": node_name,
    }
    return {
        "type": RealtimeFeedbackType.LATENCY_MEASURED.value,
        "payload": _redact_sensitive(payload),
    }
