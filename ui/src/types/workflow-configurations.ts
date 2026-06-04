export interface AmbientNoiseConfiguration {
    enabled: boolean;
    volume: number;
    storage_key?: string;
    storage_backend?: string;
    original_filename?: string;
}

export type TurnStopStrategy = 'transcription' | 'turn_analyzer';
export const LATENCY_PROFILES = ['balanced', 'speed_demo', 'custom'] as const;
export type LatencyProfile = typeof LATENCY_PROFILES[number];

export const DEFAULT_LATENCY_CONFIGURATION = {
    latency_profile: 'balanced',
    user_speech_timeout_seconds: 0.6,
    tts_aggregation_silence_seconds: 0.35,
    pre_call_fetch_timeout_seconds: 10,
    pre_call_fetch_required: true,
    returnzero_ttfs_p99_latency_seconds: 1,
    speed_profile_respect_delayed_start: false,
} as const satisfies {
    readonly latency_profile: LatencyProfile;
    readonly user_speech_timeout_seconds: number;
    readonly tts_aggregation_silence_seconds: number;
    readonly pre_call_fetch_timeout_seconds: number;
    readonly pre_call_fetch_required: boolean;
    readonly returnzero_ttfs_p99_latency_seconds: number;
    readonly speed_profile_respect_delayed_start: boolean;
};

export interface VoicemailDetectionConfiguration {
    enabled: boolean;
    use_workflow_llm: boolean;
    provider?: string;
    model?: string;
    api_key?: string;
    system_prompt?: string;
    long_speech_timeout: number;  // seconds cutoff for long speech detection
}

export const DEFAULT_VOICEMAIL_DETECTION_CONFIGURATION: VoicemailDetectionConfiguration = {
    enabled: false,
    use_workflow_llm: true,
    long_speech_timeout: 8.0,
};

export interface ModelOverrides {
    llm?: {
        provider?: string;
        model?: string;
        api_key?: string;
        [key: string]: unknown;
    };
    tts?: {
        provider?: string;
        model?: string;
        voice?: string;
        api_key?: string;
        [key: string]: unknown;
    };
    stt?: {
        provider?: string;
        model?: string;
        api_key?: string;
        [key: string]: unknown;
    };
    realtime?: {
        provider?: string;
        model?: string;
        voice?: string;
        api_key?: string;
        [key: string]: unknown;
    };
    is_realtime?: boolean;
}

export interface WorkflowConfigurations {
    ambient_noise_configuration: AmbientNoiseConfiguration;
    max_call_duration: number;  // Maximum call duration in seconds
    max_user_idle_timeout: number;  // Maximum user idle time in seconds
    smart_turn_stop_secs: number;  // Timeout in seconds for incomplete turn detection
    turn_stop_strategy: TurnStopStrategy;  // Strategy for detecting end of user turn
    dictionary?: string;  // Comma-separated words for voice agent to listen for
    latency_profile?: LatencyProfile;
    user_speech_timeout_seconds?: number;
    tts_aggregation_silence_seconds?: number;
    pre_call_fetch_timeout_seconds?: number;
    pre_call_fetch_required?: boolean;
    returnzero_ttfs_p99_latency_seconds?: number;
    speed_profile_respect_delayed_start?: boolean;
    voicemail_detection?: VoicemailDetectionConfiguration;
    context_compaction_enabled?: boolean;  // Summarize context on node transitions to remove stale tool calls
    model_overrides?: ModelOverrides;  // Per-workflow model configuration overrides
    [key: string]: unknown;  // Allow additional properties for future configurations
}

export const DEFAULT_WORKFLOW_CONFIGURATIONS: WorkflowConfigurations = {
    ambient_noise_configuration: {
        enabled: false,
        volume: 0.3
    },
    max_call_duration: 600,  // 10 minutes
    max_user_idle_timeout: 10,  // 10 seconds
    smart_turn_stop_secs: 2,  // 2 seconds
    turn_stop_strategy: 'transcription',  // Default to transcription-based detection
    dictionary: '',
    latency_profile: DEFAULT_LATENCY_CONFIGURATION.latency_profile,
    pre_call_fetch_required: DEFAULT_LATENCY_CONFIGURATION.pre_call_fetch_required,
    speed_profile_respect_delayed_start: DEFAULT_LATENCY_CONFIGURATION.speed_profile_respect_delayed_start
};
