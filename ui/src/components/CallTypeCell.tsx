"use client";

import { ArrowDownLeft, ArrowUpRight, Globe, MessageSquare, Phone } from "lucide-react";

import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useLocale } from "@/context/LocaleContext";

const WEB_CALL_MODES = new Set(["webrtc", "smallwebrtc"]);
const TEXT_CHAT_MODES = new Set(["textchat"]);

const getCallChannel = (mode?: string | null): "phone" | "web" | "chat" => {
    if (mode && TEXT_CHAT_MODES.has(mode)) return "chat";
    if (mode && WEB_CALL_MODES.has(mode)) return "web";
    return "phone";
};

export function CallTypeCell({
    mode,
    callType,
}: {
    mode?: string | null;
    callType?: string | null;
}) {
    const { t } = useLocale();

    if (!mode && !callType) {
        return <span className="text-sm text-muted-foreground">-</span>;
    }

    const channel = getCallChannel(mode);
    const ChannelIcon = channel === "chat" ? MessageSquare : channel === "web" ? Globe : Phone;
    const channelLabel = channel === "chat" ? t('callType.chat') : channel === "web" ? t('callType.web') : t('callType.phone');

    const isInbound = callType === "inbound";
    const DirectionIcon = isInbound ? ArrowDownLeft : ArrowUpRight;
    const directionLabel = isInbound ? t('callType.inbound') : t('callType.outbound');

    return (
        <Tooltip>
            <TooltipTrigger asChild>
                <span className="inline-flex items-center gap-1">
                    <ChannelIcon className="h-4 w-4 text-muted-foreground" />
                    <DirectionIcon
                        className={`h-3.5 w-3.5 ${isInbound ? "text-emerald-600" : "text-blue-600"}`}
                    />
                </span>
            </TooltipTrigger>
            <TooltipContent sideOffset={4}>
                {directionLabel} · {channelLabel}
            </TooltipContent>
        </Tooltip>
    );
}
