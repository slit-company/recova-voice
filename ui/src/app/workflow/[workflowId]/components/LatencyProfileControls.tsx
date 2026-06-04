import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import type { LatencyProfile } from "@/types/workflow-configurations";

interface LatencyProfileControlsProps {
    readonly latencyProfile: LatencyProfile;
    readonly userSpeechTimeoutSeconds: number;
    readonly ttsAggregationSilenceSeconds: number;
    readonly preCallFetchTimeoutSeconds: number;
    readonly preCallFetchRequired: boolean;
    readonly returnzeroTtfsP99LatencySeconds: number;
    readonly speedProfileRespectDelayedStart: boolean;
    readonly onLatencyProfileChange: (value: LatencyProfile) => void;
    readonly onUserSpeechTimeoutSecondsChange: (value: number) => void;
    readonly onTtsAggregationSilenceSecondsChange: (value: number) => void;
    readonly onPreCallFetchTimeoutSecondsChange: (value: number) => void;
    readonly onPreCallFetchRequiredChange: (value: boolean) => void;
    readonly onReturnzeroTtfsP99LatencySecondsChange: (value: number) => void;
    readonly onSpeedProfileRespectDelayedStartChange: (value: boolean) => void;
}

function isLatencyProfile(value: string): value is LatencyProfile {
    switch (value) {
        case "balanced":
        case "speed_demo":
        case "custom":
            return true;
        default:
            return false;
    }
}

function parseBoundedNumber(
    value: string,
    min: number,
    max: number,
    onChange: (value: number) => void,
) {
    const parsed = Number.parseFloat(value);
    if (!Number.isNaN(parsed) && parsed >= min && parsed <= max) {
        onChange(parsed);
    }
}

export function LatencyProfileControls({
    latencyProfile,
    userSpeechTimeoutSeconds,
    ttsAggregationSilenceSeconds,
    preCallFetchTimeoutSeconds,
    preCallFetchRequired,
    returnzeroTtfsP99LatencySeconds,
    speedProfileRespectDelayedStart,
    onLatencyProfileChange,
    onUserSpeechTimeoutSecondsChange,
    onTtsAggregationSilenceSecondsChange,
    onPreCallFetchTimeoutSecondsChange,
    onPreCallFetchRequiredChange,
    onReturnzeroTtfsP99LatencySecondsChange,
    onSpeedProfileRespectDelayedStartChange,
}: LatencyProfileControlsProps) {
    return (
        <div className="space-y-4">
            <div>
                <h3 className="text-sm font-semibold mb-1">Latency Profile</h3>
                <p className="text-xs text-muted-foreground">
                    Select the call latency behavior for this agent.
                </p>
            </div>

            <div className="space-y-2">
                <Label htmlFor="latency_profile" className="text-xs">
                    Profile
                </Label>
                <Select
                    value={latencyProfile}
                    onValueChange={(value) => {
                        if (isLatencyProfile(value)) {
                            onLatencyProfileChange(value);
                        }
                    }}
                >
                    <SelectTrigger id="latency_profile">
                        <SelectValue placeholder="Select profile" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="balanced">Balanced</SelectItem>
                        <SelectItem value="speed_demo">Speed demo</SelectItem>
                        <SelectItem value="custom">Custom</SelectItem>
                    </SelectContent>
                </Select>
            </div>

            {latencyProfile === "speed_demo" && (
                <div className="flex items-center justify-between">
                    <Label htmlFor="speed-respect-delayed-start" className="text-sm">
                        Respect delayed start
                    </Label>
                    <Switch
                        id="speed-respect-delayed-start"
                        checked={speedProfileRespectDelayedStart}
                        onCheckedChange={onSpeedProfileRespectDelayedStartChange}
                    />
                </div>
            )}

            {latencyProfile === "custom" && (
                <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                        <Label htmlFor="user_speech_timeout_seconds" className="text-xs">
                            User speech timeout
                        </Label>
                        <Input
                            id="user_speech_timeout_seconds"
                            type="number"
                            step="0.05"
                            min="0.25"
                            max="1.5"
                            value={userSpeechTimeoutSeconds}
                            onChange={(event) =>
                                parseBoundedNumber(
                                    event.target.value,
                                    0.25,
                                    1.5,
                                    onUserSpeechTimeoutSecondsChange,
                                )
                            }
                        />
                    </div>

                    <div className="space-y-2">
                        <Label htmlFor="tts_aggregation_silence_seconds" className="text-xs">
                            TTS silence
                        </Label>
                        <Input
                            id="tts_aggregation_silence_seconds"
                            type="number"
                            step="0.05"
                            min="0.2"
                            max="1.5"
                            value={ttsAggregationSilenceSeconds}
                            onChange={(event) =>
                                parseBoundedNumber(
                                    event.target.value,
                                    0.2,
                                    1.5,
                                    onTtsAggregationSilenceSecondsChange,
                                )
                            }
                        />
                    </div>

                    <div className="space-y-2">
                        <Label htmlFor="pre_call_fetch_timeout_seconds" className="text-xs">
                            Pre-call fetch timeout
                        </Label>
                        <Input
                            id="pre_call_fetch_timeout_seconds"
                            type="number"
                            step="0.1"
                            min="0.1"
                            max="10"
                            value={preCallFetchTimeoutSeconds}
                            onChange={(event) =>
                                parseBoundedNumber(
                                    event.target.value,
                                    0.1,
                                    10,
                                    onPreCallFetchTimeoutSecondsChange,
                                )
                            }
                        />
                    </div>

                    <div className="space-y-2">
                        <Label htmlFor="returnzero_ttfs_p99_latency_seconds" className="text-xs">
                            ReturnZero TTFS P99
                        </Label>
                        <Input
                            id="returnzero_ttfs_p99_latency_seconds"
                            type="number"
                            step="0.05"
                            min="0.2"
                            max="3"
                            value={returnzeroTtfsP99LatencySeconds}
                            onChange={(event) =>
                                parseBoundedNumber(
                                    event.target.value,
                                    0.2,
                                    3,
                                    onReturnzeroTtfsP99LatencySecondsChange,
                                )
                            }
                        />
                    </div>

                    <div className="col-span-2 flex items-center justify-between">
                        <Label htmlFor="pre-call-fetch-required" className="text-sm">
                            Require pre-call fetch
                        </Label>
                        <Switch
                            id="pre-call-fetch-required"
                            checked={preCallFetchRequired}
                            onCheckedChange={onPreCallFetchRequiredChange}
                        />
                    </div>
                </div>
            )}
        </div>
    );
}
