from dataclasses import dataclass
from typing import Final, Literal, assert_never

from pydantic import BaseModel, ConfigDict, Field

from api.services.workflow.workflow_graph import WorkflowGraph

LatencyProfile = Literal["balanced", "speed_demo", "custom"]
SpeedDemoWarningCode = Literal["speed_demo_missing_greeting"]

BALANCED_USER_SPEECH_TIMEOUT_SECONDS: Final = 0.6
BALANCED_PRE_CALL_FETCH_TIMEOUT_SECONDS: Final = 10.0
SPEED_DEMO_USER_SPEECH_TIMEOUT_SECONDS: Final = 0.35
SPEED_DEMO_TTS_AGGREGATION_SILENCE_SECONDS: Final = 0.35
SPEED_DEMO_PRE_CALL_FETCH_TIMEOUT_SECONDS: Final = 0.5
SPEED_DEMO_DEFAULT_GREETING: Final = (
    "안녕하세요, Recova 데모 상담원입니다. 무엇을 도와드릴까요?"
)


class WorkflowLatencyConfiguration(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    latency_profile: LatencyProfile | None = None
    user_speech_timeout_seconds: float | None = Field(
        default=None, ge=0.25, le=1.5
    )
    tts_aggregation_silence_seconds: float | None = Field(
        default=None, ge=0.2, le=1.5
    )
    pre_call_fetch_timeout_seconds: float | None = Field(
        default=None, ge=0.1, le=10.0
    )
    pre_call_fetch_required: bool | None = None
    returnzero_ttfs_p99_latency_seconds: float | None = Field(
        default=None, ge=0.2, le=3.0
    )
    speed_profile_respect_delayed_start: bool | None = None


class RuntimeLatencyContext(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    runtime_latency_profile: str | None = None


@dataclass(frozen=True, slots=True)
class ResolvedVoiceLatencyConfig:
    latency_profile: LatencyProfile
    user_speech_timeout_seconds: float
    tts_aggregation_silence_seconds: float | None
    pre_call_fetch_timeout_seconds: float
    pre_call_fetch_required: bool
    returnzero_ttfs_p99_latency_seconds: float | None
    speed_profile_respect_delayed_start: bool


@dataclass(frozen=True, slots=True)
class SpeedDemoNodeOverrideWarning:
    code: SpeedDemoWarningCode
    node_id: str
    node_name: str


def apply_speed_demo_node_overrides(
    workflow_graph: WorkflowGraph,
) -> tuple[SpeedDemoNodeOverrideWarning, ...]:
    warnings: list[SpeedDemoNodeOverrideWarning] = []

    for node in workflow_graph.nodes.values():
        match node.node_type:
            case "startCall":
                node.allow_interrupt = True
                node.delayed_start = False
                if not node.greeting and not node.greeting_recording_id:
                    node.greeting_type = "text"
                    node.greeting = SPEED_DEMO_DEFAULT_GREETING
                    warnings.append(
                        SpeedDemoNodeOverrideWarning(
                            code="speed_demo_missing_greeting",
                            node_id=node.id,
                            node_name=node.name,
                        )
                    )
            case "agentNode":
                node.allow_interrupt = True
                node.delayed_start = False
            case _:
                continue

    return tuple(warnings)


def resolve_voice_latency_config(
    *,
    workflow_configurations: WorkflowLatencyConfiguration | None,
    runtime_context: RuntimeLatencyContext | None,
    allow_runtime_profile_override: bool = False,
) -> ResolvedVoiceLatencyConfig:
    profile = _resolve_profile(
        workflow_configurations=workflow_configurations,
        runtime_context=runtime_context,
        allow_runtime_profile_override=allow_runtime_profile_override,
    )
    config = workflow_configurations or WorkflowLatencyConfiguration()

    match profile:
        case "balanced":
            return ResolvedVoiceLatencyConfig(
                latency_profile="balanced",
                user_speech_timeout_seconds=BALANCED_USER_SPEECH_TIMEOUT_SECONDS,
                tts_aggregation_silence_seconds=None,
                pre_call_fetch_timeout_seconds=BALANCED_PRE_CALL_FETCH_TIMEOUT_SECONDS,
                pre_call_fetch_required=True,
                returnzero_ttfs_p99_latency_seconds=(
                    config.returnzero_ttfs_p99_latency_seconds
                ),
                speed_profile_respect_delayed_start=False,
            )
        case "speed_demo":
            return ResolvedVoiceLatencyConfig(
                latency_profile="speed_demo",
                user_speech_timeout_seconds=SPEED_DEMO_USER_SPEECH_TIMEOUT_SECONDS,
                tts_aggregation_silence_seconds=(
                    SPEED_DEMO_TTS_AGGREGATION_SILENCE_SECONDS
                ),
                pre_call_fetch_timeout_seconds=(
                    SPEED_DEMO_PRE_CALL_FETCH_TIMEOUT_SECONDS
                ),
                pre_call_fetch_required=False,
                returnzero_ttfs_p99_latency_seconds=(
                    config.returnzero_ttfs_p99_latency_seconds
                ),
                speed_profile_respect_delayed_start=(
                    config.speed_profile_respect_delayed_start or False
                ),
            )
        case "custom":
            return ResolvedVoiceLatencyConfig(
                latency_profile="custom",
                user_speech_timeout_seconds=(
                    config.user_speech_timeout_seconds
                    or BALANCED_USER_SPEECH_TIMEOUT_SECONDS
                ),
                tts_aggregation_silence_seconds=(
                    config.tts_aggregation_silence_seconds
                ),
                pre_call_fetch_timeout_seconds=(
                    config.pre_call_fetch_timeout_seconds
                    or BALANCED_PRE_CALL_FETCH_TIMEOUT_SECONDS
                ),
                pre_call_fetch_required=(
                    config.pre_call_fetch_required
                    if config.pre_call_fetch_required is not None
                    else True
                ),
                returnzero_ttfs_p99_latency_seconds=(
                    config.returnzero_ttfs_p99_latency_seconds
                ),
                speed_profile_respect_delayed_start=(
                    config.speed_profile_respect_delayed_start or False
                ),
            )
        case unreachable:
            assert_never(unreachable)


def _resolve_profile(
    *,
    workflow_configurations: WorkflowLatencyConfiguration | None,
    runtime_context: RuntimeLatencyContext | None,
    allow_runtime_profile_override: bool,
) -> LatencyProfile:
    runtime_profile = _runtime_latency_profile(runtime_context)
    if allow_runtime_profile_override and runtime_profile is not None:
        return runtime_profile
    if workflow_configurations and workflow_configurations.latency_profile:
        return workflow_configurations.latency_profile
    return "balanced"


def _runtime_latency_profile(
    runtime_context: RuntimeLatencyContext | None,
) -> LatencyProfile | None:
    if runtime_context is None:
        return None

    match runtime_context.runtime_latency_profile:
        case "balanced":
            return "balanced"
        case "speed_demo":
            return "speed_demo"
        case "custom":
            return "custom"
        case None:
            return None
        case _:
            return None
