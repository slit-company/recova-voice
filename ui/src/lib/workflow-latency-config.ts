import type { WorkflowConfigurations } from "@/types/workflow-configurations";

const LATENCY_TUNING_KEYS = [
    "user_speech_timeout_seconds",
    "tts_aggregation_silence_seconds",
    "pre_call_fetch_timeout_seconds",
    "pre_call_fetch_required",
    "returnzero_ttfs_p99_latency_seconds",
    "speed_profile_respect_delayed_start",
] as const satisfies readonly (keyof WorkflowConfigurations)[];

export function stripLatencyTuningFields(
    configurations: WorkflowConfigurations | null | undefined,
): Partial<WorkflowConfigurations> {
    const preservedConfigurations: Partial<WorkflowConfigurations> = {
        ...(configurations ?? {}),
    };

    for (const key of LATENCY_TUNING_KEYS) {
        delete preservedConfigurations[key];
    }

    return preservedConfigurations;
}
