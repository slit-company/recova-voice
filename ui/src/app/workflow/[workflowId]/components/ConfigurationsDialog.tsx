import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { stripLatencyTuningFields } from "@/lib/workflow-latency-config";
import {
    AmbientNoiseConfiguration,
    DEFAULT_LATENCY_CONFIGURATION,
    LatencyProfile,
    TurnStopStrategy,
    WorkflowConfigurations,
} from "@/types/workflow-configurations";

import { LatencyProfileControls } from "./LatencyProfileControls";

interface ConfigurationsDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    workflowConfigurations: WorkflowConfigurations | null;
    workflowName: string;
    onSave: (configurations: WorkflowConfigurations, workflowName: string) => Promise<void>;
}

const DEFAULT_AMBIENT_NOISE_CONFIG: AmbientNoiseConfiguration = {
    enabled: false,
    volume: 0.3,
};

export const ConfigurationsDialog = ({
    open,
    onOpenChange,
    workflowConfigurations,
    workflowName,
    onSave
}: ConfigurationsDialogProps) => {
    const [name, setName] = useState<string>(workflowName);
    const [ambientNoiseConfig, setAmbientNoiseConfig] = useState<AmbientNoiseConfiguration>(
        workflowConfigurations?.ambient_noise_configuration || DEFAULT_AMBIENT_NOISE_CONFIG
    );
    const [maxCallDuration, setMaxCallDuration] = useState<number>(
        workflowConfigurations?.max_call_duration || 600  // Default 10 minutes
    );
    const [maxUserIdleTimeout, setMaxUserIdleTimeout] = useState<number>(
        workflowConfigurations?.max_user_idle_timeout || 10  // Default 10 seconds
    );
    const [smartTurnStopSecs, setSmartTurnStopSecs] = useState<number>(
        workflowConfigurations?.smart_turn_stop_secs || 2  // Default 2 seconds
    );
    const [turnStopStrategy, setTurnStopStrategy] = useState<TurnStopStrategy>(
        workflowConfigurations?.turn_stop_strategy || 'transcription'
    );
    const [latencyProfile, setLatencyProfile] = useState<LatencyProfile>(
        workflowConfigurations?.latency_profile || DEFAULT_LATENCY_CONFIGURATION.latency_profile
    );
    const [userSpeechTimeoutSeconds, setUserSpeechTimeoutSeconds] = useState<number>(
        workflowConfigurations?.user_speech_timeout_seconds || DEFAULT_LATENCY_CONFIGURATION.user_speech_timeout_seconds
    );
    const [ttsAggregationSilenceSeconds, setTtsAggregationSilenceSeconds] = useState<number>(
        workflowConfigurations?.tts_aggregation_silence_seconds || DEFAULT_LATENCY_CONFIGURATION.tts_aggregation_silence_seconds
    );
    const [preCallFetchTimeoutSeconds, setPreCallFetchTimeoutSeconds] = useState<number>(
        workflowConfigurations?.pre_call_fetch_timeout_seconds || DEFAULT_LATENCY_CONFIGURATION.pre_call_fetch_timeout_seconds
    );
    const [preCallFetchRequired, setPreCallFetchRequired] = useState<boolean>(
        workflowConfigurations?.pre_call_fetch_required ?? DEFAULT_LATENCY_CONFIGURATION.pre_call_fetch_required
    );
    const [returnzeroTtfsP99LatencySeconds, setReturnzeroTtfsP99LatencySeconds] = useState<number>(
        workflowConfigurations?.returnzero_ttfs_p99_latency_seconds || DEFAULT_LATENCY_CONFIGURATION.returnzero_ttfs_p99_latency_seconds
    );
    const [speedProfileRespectDelayedStart, setSpeedProfileRespectDelayedStart] = useState<boolean>(
        workflowConfigurations?.speed_profile_respect_delayed_start ?? DEFAULT_LATENCY_CONFIGURATION.speed_profile_respect_delayed_start
    );
    const [contextCompactionEnabled, setContextCompactionEnabled] = useState<boolean>(
        workflowConfigurations?.context_compaction_enabled ?? false
    );
    const [isSaving, setIsSaving] = useState(false);

    const handleSave = async () => {
        setIsSaving(true);
        try {
            await onSave({
                ...stripLatencyTuningFields(workflowConfigurations),
                ambient_noise_configuration: ambientNoiseConfig,
                max_call_duration: maxCallDuration,
                max_user_idle_timeout: maxUserIdleTimeout,
                smart_turn_stop_secs: smartTurnStopSecs,
                turn_stop_strategy: turnStopStrategy,
                latency_profile: latencyProfile,
                ...(latencyProfile === "custom" ? {
                    user_speech_timeout_seconds: userSpeechTimeoutSeconds,
                    tts_aggregation_silence_seconds: ttsAggregationSilenceSeconds,
                    pre_call_fetch_timeout_seconds: preCallFetchTimeoutSeconds,
                    pre_call_fetch_required: preCallFetchRequired,
                    returnzero_ttfs_p99_latency_seconds: returnzeroTtfsP99LatencySeconds,
                } : {}),
                ...(latencyProfile === "speed_demo" ? {
                    speed_profile_respect_delayed_start: speedProfileRespectDelayedStart,
                } : {}),
                context_compaction_enabled: contextCompactionEnabled,
            }, name);
            onOpenChange(false);
        } catch (error) {
            console.error("Failed to save configurations:", error);
        } finally {
            setIsSaving(false);
        }
    };

    // Sync state with props when dialog opens
    useEffect(() => {
        if (open) {
            setName(workflowName);
            setAmbientNoiseConfig(workflowConfigurations?.ambient_noise_configuration || DEFAULT_AMBIENT_NOISE_CONFIG);
            setMaxCallDuration(workflowConfigurations?.max_call_duration || 600);
            setMaxUserIdleTimeout(workflowConfigurations?.max_user_idle_timeout || 10);
            setSmartTurnStopSecs(workflowConfigurations?.smart_turn_stop_secs || 2);
            setTurnStopStrategy(workflowConfigurations?.turn_stop_strategy || 'transcription');
            setLatencyProfile(workflowConfigurations?.latency_profile || DEFAULT_LATENCY_CONFIGURATION.latency_profile);
            setUserSpeechTimeoutSeconds(workflowConfigurations?.user_speech_timeout_seconds || DEFAULT_LATENCY_CONFIGURATION.user_speech_timeout_seconds);
            setTtsAggregationSilenceSeconds(workflowConfigurations?.tts_aggregation_silence_seconds || DEFAULT_LATENCY_CONFIGURATION.tts_aggregation_silence_seconds);
            setPreCallFetchTimeoutSeconds(workflowConfigurations?.pre_call_fetch_timeout_seconds || DEFAULT_LATENCY_CONFIGURATION.pre_call_fetch_timeout_seconds);
            setPreCallFetchRequired(workflowConfigurations?.pre_call_fetch_required ?? DEFAULT_LATENCY_CONFIGURATION.pre_call_fetch_required);
            setReturnzeroTtfsP99LatencySeconds(workflowConfigurations?.returnzero_ttfs_p99_latency_seconds || DEFAULT_LATENCY_CONFIGURATION.returnzero_ttfs_p99_latency_seconds);
            setSpeedProfileRespectDelayedStart(workflowConfigurations?.speed_profile_respect_delayed_start ?? DEFAULT_LATENCY_CONFIGURATION.speed_profile_respect_delayed_start);
            setContextCompactionEnabled(workflowConfigurations?.context_compaction_enabled ?? false);
        }
    }, [open, workflowName, workflowConfigurations]);

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="max-w-lg">
                <DialogHeader>
                    <DialogTitle>Configurations</DialogTitle>
                </DialogHeader>

                <div className="space-y-6">
                    {/* Workflow Name Section */}
                    <div className="space-y-4">
                        <div>
                            <h3 className="text-sm font-semibold mb-1">Agent Name</h3>
                            <p className="text-xs text-muted-foreground">
                                The name of your agent
                            </p>
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="workflow_name" className="text-xs">
                                Name
                            </Label>
                            <Input
                                id="workflow_name"
                                type="text"
                                value={name}
                                onChange={(e) => setName(e.target.value)}
                                placeholder="Enter Agent name"
                            />
                        </div>
                    </div>

                    {/* Ambient Noise Section */}
                    <div className="space-y-4">
                        <div>
                            <h3 className="text-sm font-semibold mb-1">Ambient Noise</h3>
                            <p className="text-xs text-muted-foreground">
                                Add background office ambient noise to make the conversation sound more natural.
                            </p>
                        </div>

                        <div className="space-y-4">
                            <div className="flex items-center justify-between">
                                <Label htmlFor="ambient-noise-enabled" className="text-sm">
                                    Use Ambient Noise
                                </Label>
                                <Switch
                                    id="ambient-noise-enabled"
                                    checked={ambientNoiseConfig.enabled}
                                    onCheckedChange={(checked) =>
                                        setAmbientNoiseConfig(prev => ({ ...prev, enabled: checked }))
                                    }
                                />
                            </div>

                            {ambientNoiseConfig.enabled && (
                                <div className="space-y-2">
                                    <Label htmlFor="ambient-volume" className="text-xs">
                                        Volume
                                    </Label>
                                    <Input
                                        id="ambient-volume"
                                        type="number"
                                        step="0.1"
                                        min="0"
                                        max="1"
                                        value={ambientNoiseConfig.volume}
                                        onChange={(e) => {
                                            const value = parseFloat(e.target.value);
                                            if (!isNaN(value)) {
                                                setAmbientNoiseConfig(prev => ({ ...prev, volume: value }));
                                            }
                                        }}
                                    />
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Turn Detection Section */}
                    <div className="space-y-4">
                        <div>
                            <h3 className="text-sm font-semibold mb-1">Turn Detection</h3>
                            <p className="text-xs text-muted-foreground">
                                Configure how the agent detects when the user has finished speaking.
                            </p>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="turn_stop_strategy" className="text-xs">
                                Detection Strategy
                            </Label>
                            <Select
                                value={turnStopStrategy}
                                onValueChange={(value: TurnStopStrategy) => setTurnStopStrategy(value)}
                            >
                                <SelectTrigger id="turn_stop_strategy">
                                    <SelectValue placeholder="Select strategy" />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="transcription">
                                        Transcription-based
                                    </SelectItem>
                                    <SelectItem value="turn_analyzer">
                                        Smart Turn Analyzer
                                    </SelectItem>
                                </SelectContent>
                            </Select>
                            <p className="text-xs text-muted-foreground">
                                {turnStopStrategy === 'transcription'
                                    ? "Best for short responses (1-2 word statements). Ends turn when transcription indicates completion."
                                    : "Best for longer responses with natural pauses. Uses ML model to detect end of turn."}
                            </p>
                        </div>

                        {turnStopStrategy === 'turn_analyzer' && (
                            <div className="space-y-2">
                                <Label htmlFor="smart_turn_stop_secs" className="text-xs">
                                    Incomplete Turn Timeout (seconds)
                                </Label>
                                <Input
                                    id="smart_turn_stop_secs"
                                    type="number"
                                    step="0.5"
                                    min="0.5"
                                    max="10"
                                    value={smartTurnStopSecs}
                                    onChange={(e) => {
                                        const value = parseFloat(e.target.value);
                                        if (!isNaN(value) && value >= 0.5) {
                                            setSmartTurnStopSecs(value);
                                        }
                                    }}
                                />
                                <p className="text-xs text-muted-foreground">
                                    Max silence duration before ending an incomplete turn. Default: 2 seconds
                                </p>
                            </div>
                        )}
                    </div>

                    <LatencyProfileControls
                        latencyProfile={latencyProfile}
                        userSpeechTimeoutSeconds={userSpeechTimeoutSeconds}
                        ttsAggregationSilenceSeconds={ttsAggregationSilenceSeconds}
                        preCallFetchTimeoutSeconds={preCallFetchTimeoutSeconds}
                        preCallFetchRequired={preCallFetchRequired}
                        returnzeroTtfsP99LatencySeconds={returnzeroTtfsP99LatencySeconds}
                        speedProfileRespectDelayedStart={speedProfileRespectDelayedStart}
                        onLatencyProfileChange={setLatencyProfile}
                        onUserSpeechTimeoutSecondsChange={setUserSpeechTimeoutSeconds}
                        onTtsAggregationSilenceSecondsChange={setTtsAggregationSilenceSeconds}
                        onPreCallFetchTimeoutSecondsChange={setPreCallFetchTimeoutSeconds}
                        onPreCallFetchRequiredChange={setPreCallFetchRequired}
                        onReturnzeroTtfsP99LatencySecondsChange={setReturnzeroTtfsP99LatencySeconds}
                        onSpeedProfileRespectDelayedStartChange={setSpeedProfileRespectDelayedStart}
                    />

                    {/* Context Management Section */}
                    <div className="space-y-4">
                        <div>
                            <h3 className="text-sm font-semibold mb-1">Context Compaction</h3>
                            <p className="text-xs text-muted-foreground">
                                Automatically summarize conversation context when transitioning between nodes. Removes stale tool calls and keeps the context clean for the new node.
                            </p>
                        </div>

                        <div className="flex items-center justify-between">
                            <Label htmlFor="context-compaction-enabled" className="text-sm">
                                Enable Context Compaction
                            </Label>
                            <Switch
                                id="context-compaction-enabled"
                                checked={contextCompactionEnabled}
                                onCheckedChange={setContextCompactionEnabled}
                            />
                        </div>
                    </div>

                    {/* Call Management Section */}
                    <div className="space-y-4">
                        <div>
                            <h3 className="text-sm font-semibold mb-1">Call Management</h3>
                            <p className="text-xs text-muted-foreground">
                                Configure call duration limits and idle timeout settings.
                            </p>
                        </div>

                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label htmlFor="max_call_duration" className="text-xs">
                                    Max Call Duration (seconds)
                                </Label>
                                <Input
                                    id="max_call_duration"
                                    type="number"
                                    step="1"
                                    min="1"
                                    value={maxCallDuration}
                                    onChange={(e) => {
                                        const value = parseInt(e.target.value);
                                        if (!isNaN(value) && value > 0) {
                                            setMaxCallDuration(value);
                                        }
                                    }}
                                />
                                <p className="text-xs text-muted-foreground">Default: 600 (10 minutes)</p>
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="max_user_idle_timeout" className="text-xs">
                                    Max User Idle Timeout (seconds)
                                </Label>
                                <Input
                                    id="max_user_idle_timeout"
                                    type="number"
                                    step="1"
                                    min="1"
                                    value={maxUserIdleTimeout}
                                    onChange={(e) => {
                                        const value = parseInt(e.target.value);
                                        if (!isNaN(value) && value > 0) {
                                            setMaxUserIdleTimeout(value);
                                        }
                                    }}
                                />
                                <p className="text-xs text-muted-foreground">Default: 10 seconds</p>
                            </div>
                        </div>
                    </div>
                </div>

                <DialogFooter>
                    <Button variant="outline" onClick={() => onOpenChange(false)}>
                        Cancel
                    </Button>
                    <Button onClick={handleSave} disabled={isSaving}>
                        {isSaving ? "Saving..." : "Save"}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
};
