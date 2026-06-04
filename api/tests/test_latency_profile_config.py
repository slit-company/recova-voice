import pytest
from pydantic import ValidationError

from api.services.pipecat.latency_config import (
    RuntimeLatencyContext,
    SPEED_DEMO_DEFAULT_GREETING,
    WorkflowLatencyConfiguration,
    apply_speed_demo_node_overrides,
    resolve_voice_latency_config,
)
from api.services.pipecat.latency_events import build_speed_demo_startup_warning_event
from api.services.workflow.dto import (
    AgentNodeData,
    EdgeDataDTO,
    Position,
    ReactFlowDTO,
    RFEdgeDTO,
    RFNodeDTO,
    StartCallNodeData,
)
from api.services.workflow.workflow_graph import WorkflowGraph


def _speed_demo_workflow_graph_without_greeting() -> WorkflowGraph:
    return WorkflowGraph(
        ReactFlowDTO(
            nodes=[
                RFNodeDTO(
                    id="start",
                    type="startCall",
                    position=Position(x=0, y=0),
                    data=StartCallNodeData(
                        name="Start",
                        prompt="Start the conversation.",
                        is_start=True,
                        allow_interrupt=False,
                        delayed_start=True,
                        add_global_prompt=False,
                    ),
                ),
                RFNodeDTO(
                    id="agent",
                    type="agentNode",
                    position=Position(x=200, y=0),
                    data=AgentNodeData(
                        name="Agent",
                        prompt="Continue the conversation.",
                        allow_interrupt=False,
                        add_global_prompt=False,
                    ),
                ),
            ],
            edges=[
                RFEdgeDTO(
                    id="start-agent",
                    source="start",
                    target="agent",
                    data=EdgeDataDTO(
                        label="Continue",
                        condition="Continue the demo conversation.",
                    ),
                ),
            ],
        )
    )


def test_speed_demo_profile_resolves_expected_defaults():
    # Given
    workflow_config = WorkflowLatencyConfiguration.model_validate(
        {"latency_profile": "speed_demo"}
    )

    # When
    resolved = resolve_voice_latency_config(
        workflow_configurations=workflow_config,
        runtime_context=RuntimeLatencyContext.model_validate({}),
    )

    # Then
    assert resolved.latency_profile == "speed_demo"
    assert resolved.user_speech_timeout_seconds == 0.35
    assert resolved.tts_aggregation_silence_seconds == 0.35
    assert resolved.pre_call_fetch_timeout_seconds == 0.5
    assert resolved.pre_call_fetch_required is False
    assert resolved.returnzero_ttfs_p99_latency_seconds is None
    assert resolved.speed_profile_respect_delayed_start is False


def test_runtime_initial_context_profile_overrides_workflow_config_for_preview():
    # Given
    workflow_config = WorkflowLatencyConfiguration.model_validate(
        {"latency_profile": "balanced"}
    )
    runtime_context = RuntimeLatencyContext.model_validate(
        {"runtime_latency_profile": "speed_demo"}
    )

    # When
    resolved = resolve_voice_latency_config(
        workflow_configurations=workflow_config,
        runtime_context=runtime_context,
        allow_runtime_profile_override=True,
    )

    # Then
    assert resolved.latency_profile == "speed_demo"
    assert resolved.user_speech_timeout_seconds == 0.35
    assert workflow_config.latency_profile == "balanced"


def test_custom_profile_validates_bounds():
    # Given / When / Then
    with pytest.raises(ValidationError):
        WorkflowLatencyConfiguration.model_validate(
            {
                "latency_profile": "custom",
                "user_speech_timeout_seconds": 0.24,
            }
        )

    with pytest.raises(ValidationError):
        WorkflowLatencyConfiguration.model_validate(
            {
                "latency_profile": "custom",
                "tts_aggregation_silence_seconds": 1.51,
            }
        )

    with pytest.raises(ValidationError):
        WorkflowLatencyConfiguration.model_validate(
            {
                "latency_profile": "custom",
                "pre_call_fetch_timeout_seconds": 0.09,
            }
        )

    valid_config = WorkflowLatencyConfiguration.model_validate(
        {
            "latency_profile": "custom",
            "user_speech_timeout_seconds": 0.42,
            "tts_aggregation_silence_seconds": 0.44,
            "pre_call_fetch_timeout_seconds": 0.8,
            "pre_call_fetch_required": False,
            "returnzero_ttfs_p99_latency_seconds": 0.6,
            "speed_profile_respect_delayed_start": True,
        }
    )

    resolved = resolve_voice_latency_config(
        workflow_configurations=valid_config,
        runtime_context=RuntimeLatencyContext.model_validate({}),
    )

    assert resolved.latency_profile == "custom"
    assert resolved.user_speech_timeout_seconds == 0.42
    assert resolved.tts_aggregation_silence_seconds == 0.44
    assert resolved.pre_call_fetch_timeout_seconds == 0.8
    assert resolved.pre_call_fetch_required is False
    assert resolved.returnzero_ttfs_p99_latency_seconds == 0.6
    assert resolved.speed_profile_respect_delayed_start is True


def test_speed_demo_warns_when_start_node_has_no_greeting():
    # Given
    workflow_graph = _speed_demo_workflow_graph_without_greeting()
    start_node = workflow_graph.nodes["start"]
    saved_start_data = start_node.data

    # When
    warnings = apply_speed_demo_node_overrides(workflow_graph)

    # Then
    assert len(warnings) == 1
    assert warnings[0].code == "speed_demo_missing_greeting"
    assert warnings[0].node_id == "start"
    warning_event = build_speed_demo_startup_warning_event(
        workflow_run_id=42,
        warning_code=warnings[0].code,
        node_id=warnings[0].node_id,
        node_name=warnings[0].node_name,
    )
    assert warning_event["payload"]["kind"] == "voice_latency_warning"
    assert warning_event["payload"]["warning_code"] == "speed_demo_missing_greeting"
    assert start_node.greeting_type == "text"
    assert start_node.greeting == SPEED_DEMO_DEFAULT_GREETING
    assert start_node.allow_interrupt is True
    assert start_node.delayed_start is False
    assert saved_start_data.greeting is None
    assert saved_start_data.allow_interrupt is False
    assert saved_start_data.delayed_start is True


def test_speed_demo_runtime_overrides_agent_interrupt_without_persisting_data():
    # Given
    workflow_graph = _speed_demo_workflow_graph_without_greeting()
    agent_node = workflow_graph.nodes["agent"]
    saved_agent_data = agent_node.data

    # When
    apply_speed_demo_node_overrides(workflow_graph)

    # Then
    assert agent_node.allow_interrupt is True
    assert agent_node.delayed_start is False
    assert saved_agent_data.allow_interrupt is False
