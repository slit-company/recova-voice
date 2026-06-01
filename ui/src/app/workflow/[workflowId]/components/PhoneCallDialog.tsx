"use client";

import "react-international-phone/style.css";

import { CheckCircle2, Loader2, PhoneCall, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { PhoneInput } from "react-international-phone";

import { client } from "@/client/client.gen";
import {
    callPhonePreviewApiV1PhonePreviewCallPost,
    getPhonePreviewStatusByStatusPathApiV1PhonePreviewStatusSessionIdGet,
    startPhonePreviewApiV1PhonePreviewStartPost,
    verifyPhonePreviewApiV1PhonePreviewVerifyPost,
} from "@/client/sdk.gen";
import type { PhonePreviewResponse } from "@/client/types.gen";
import { Button } from "@/components/ui/button";
import {
    Dialog,
    DialogClose,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useLocale } from "@/context/LocaleContext";

type PreviewStep = "entry" | "otp" | "calling" | "complete";
type PreviewMode = "outbound" | "inbound";
type BusyState = "saving" | "starting" | "verifying" | "calling" | "waiting" | null;
type ExtendedPhonePreviewResponse = PhonePreviewResponse & {
    inbound_phone_number?: string | null;
};

interface PhoneCallDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    workflowId: number;
    user: { id: string; email?: string };
    hasUnsavedChanges?: boolean;
    saveLatestDraft?: () => Promise<void>;
}

const getDetailMessage = (error: unknown): string => {
    if (typeof error === "string") return error;
    if (!error || typeof error !== "object") return "Request failed";

    const detail = (error as { detail?: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
        return detail
            .map((item) => {
                if (item && typeof item === "object" && "msg" in item) {
                    return String((item as { msg: unknown }).msg);
                }
                return String(item);
            })
            .join(", ");
    }
    if (detail) return JSON.stringify(detail);
    return JSON.stringify(error);
};

const sessionIdFrom = (data: PhonePreviewResponse) => {
    const id = data.session_id;
    return id === undefined || id === null ? "" : String(id);
};
const otpRequiredFrom = (data: PhonePreviewResponse) =>
    data.otp_required ?? data.status === "pending_verification";
const maskedPhoneFrom = (data: PhonePreviewResponse) => data.masked_phone ?? "";
const expiresAtFrom = (data: PhonePreviewResponse) => data.expires_at ?? "";
const workflowRunIdFrom = (data: PhonePreviewResponse) => data.workflow_run_id ?? null;
const failureReasonFrom = (data: PhonePreviewResponse) => data.failure_reason ?? null;
const inboundPhoneNumberFrom = (data: ExtendedPhonePreviewResponse) => data.inbound_phone_number ?? "";

export const PhoneCallDialog = ({
    open,
    onOpenChange,
    workflowId,
    user,
    hasUnsavedChanges = false,
    saveLatestDraft,
}: PhoneCallDialogProps) => {
    const { t } = useLocale();

    const [displayName, setDisplayName] = useState("");
    const [phoneNumber, setPhoneNumber] = useState("");
    const [previewMode, setPreviewMode] = useState<PreviewMode>("outbound");
    const [otpCode, setOtpCode] = useState("");
    const [sessionId, setSessionId] = useState("");
    const [maskedPhone, setMaskedPhone] = useState("");
    const [inboundPhoneNumber, setInboundPhoneNumber] = useState("");
    const [expiresAt, setExpiresAt] = useState("");
    const [workflowRunId, setWorkflowRunId] = useState<number | string | null>(null);
    const [status, setStatus] = useState<string>("idle");
    const [step, setStep] = useState<PreviewStep>("entry");
    const [busy, setBusy] = useState<BusyState>(null);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<string | null>(null);

    const normalizedDisplayName = useMemo(() => displayName.trim(), [displayName]);

    useEffect(() => {
        if (!open) return;

        setDisplayName(user.email?.split("@")[0] ?? "");
        setPhoneNumber("");
        setPreviewMode("outbound");
        setOtpCode("");
        setSessionId("");
        setMaskedPhone("");
        setInboundPhoneNumber("");
        setExpiresAt("");
        setWorkflowRunId(null);
        setStatus("idle");
        setStep("entry");
        setBusy(null);
        setError(null);
        setSuccess(null);
    }, [open, user.email]);

    const formatError = useCallback((raw: unknown) => {
        const message = getDetailMessage(raw);
        const lower = message.toLowerCase();
        if (lower.includes("telephony_not_configured")) return t("phoneCall.errorTelephonyNotConfigured");
        if (lower.includes("draft_not_ready")) return t("phoneCall.errorDraftNotReady");
        if (lower.includes("rate") || lower.includes("cooldown")) return t("phoneCall.errorRateLimited");
        if (lower.includes("awaiting_inbound")) return t("phoneCall.errorInboundAlreadyWaiting");
        if (lower.includes("otp") || lower.includes("verification")) return t("phoneCall.errorVerification");
        return message;
    }, [t]);

    const applyPreviewStatus = useCallback((data: ExtendedPhonePreviewResponse) => {
        const nextSessionId = sessionIdFrom(data);
        const nextMaskedPhone = maskedPhoneFrom(data);
        const nextExpiresAt = expiresAtFrom(data);
        const nextWorkflowRunId = workflowRunIdFrom(data);
        const failureReason = failureReasonFrom(data);
        const nextInboundPhoneNumber = inboundPhoneNumberFrom(data);

        if (nextSessionId) setSessionId(nextSessionId);
        if (nextMaskedPhone) setMaskedPhone(nextMaskedPhone);
        if (nextExpiresAt) setExpiresAt(nextExpiresAt);
        if (nextInboundPhoneNumber) setInboundPhoneNumber(nextInboundPhoneNumber);
        setStatus((current) => data.status ?? current);
        setWorkflowRunId(nextWorkflowRunId);
        if (failureReason) {
            setError(formatError(failureReason));
            setSuccess(null);
        }
        if (data.status === "failed" || data.status === "completed") {
            setStep("complete");
        }
    }, [formatError]);

    const unwrapPreviewResponse = useCallback((response: { data?: ExtendedPhonePreviewResponse; error?: unknown }) => {
        if (response.error) {
            throw new Error(formatError(response.error));
        }
        if (!response.data) {
            throw new Error("Missing preview response");
        }
        return response.data;
    }, [formatError]);

    const startPreview = useCallback(async (body: {
        workflow_id: number;
        display_name: string | null;
        phone_number: string;
    }) => {
        const response = await startPhonePreviewApiV1PhonePreviewStartPost({
            body,
        });
        return unwrapPreviewResponse(response);
    }, [unwrapPreviewResponse]);

    const verifyPreview = useCallback(async (body: {
        session_id: number;
        otp_code: string;
    }) => {
        const response = await verifyPhonePreviewApiV1PhonePreviewVerifyPost({
            body,
        });
        return unwrapPreviewResponse(response);
    }, [unwrapPreviewResponse]);

    const callPreview = useCallback(async (body: { session_id: number }) => {
        const response = await callPhonePreviewApiV1PhonePreviewCallPost({
            body,
        });
        return unwrapPreviewResponse(response);
    }, [unwrapPreviewResponse]);

    const waitInboundPreview = useCallback(async (body: { session_id: number }) => {
        const response = await client.post({
            url: "/api/v1/phone-preview/wait-inbound",
            body,
            headers: { "Content-Type": "application/json" },
        }) as { data?: ExtendedPhonePreviewResponse; error?: unknown };
        return unwrapPreviewResponse(response);
    }, [unwrapPreviewResponse]);

    const getPreviewStatus = useCallback(async (targetSessionId: string) => {
        const numericSessionId = Number(targetSessionId);
        const response = await getPhonePreviewStatusByStatusPathApiV1PhonePreviewStatusSessionIdGet({
            path: { session_id: numericSessionId },
        });
        return unwrapPreviewResponse(response);
    }, [unwrapPreviewResponse]);

    const saveDraftIfNeeded = async () => {
        if (!hasUnsavedChanges || !saveLatestDraft) return;
        setBusy("saving");
        await saveLatestDraft();
    };

    useEffect(() => {
        if (!open || !sessionId || step !== "calling") return;
        if (status === "completed" || status === "failed") return;

        let cancelled = false;
        const interval = window.setInterval(() => {
            void getPreviewStatus(sessionId)
                .then((data) => {
                    if (!cancelled) applyPreviewStatus(data);
                })
                .catch((err) => {
                    if (!cancelled) {
                        setError(err instanceof Error ? err.message : formatError(err));
                    }
                });
        }, 3000);

        return () => {
            cancelled = true;
            window.clearInterval(interval);
        };
    }, [applyPreviewStatus, formatError, getPreviewStatus, open, sessionId, status, step]);

    const beginCall = async (targetSessionId = sessionId) => {
        if (!targetSessionId) return;

        setBusy("calling");
        setStep("calling");
        setStatus("calling");
        setError(null);
        setSuccess(null);

        const data = await callPreview({ session_id: Number(targetSessionId) });
        const nextStatus = data.status ?? "calling";
        const nextWorkflowRunId = workflowRunIdFrom(data);
        const failureReason = failureReasonFrom(data);

        setStatus(nextStatus);
        setWorkflowRunId(nextWorkflowRunId);
        setStep(nextStatus === "failed" ? "complete" : "calling");
        if (failureReason) {
            setError(formatError(failureReason));
            setSuccess(null);
        } else {
            setSuccess(t("phoneCall.callStarted"));
        }
    };

    const beginInboundWait = async (targetSessionId = sessionId) => {
        if (!targetSessionId) return;

        setBusy("waiting");
        setStep("calling");
        setStatus("awaiting_inbound");
        setError(null);
        setSuccess(null);

        const data = await waitInboundPreview({ session_id: Number(targetSessionId) });
        const nextStatus = data.status ?? "awaiting_inbound";
        const nextInboundPhoneNumber = inboundPhoneNumberFrom(data);
        const failureReason = failureReasonFrom(data);

        setStatus(nextStatus);
        if (nextInboundPhoneNumber) setInboundPhoneNumber(nextInboundPhoneNumber);
        setStep(nextStatus === "failed" ? "complete" : "calling");
        if (failureReason) {
            setError(formatError(failureReason));
            setSuccess(null);
        } else {
            setSuccess(t("phoneCall.inboundWaiting"));
        }
    };

    const continueAfterVerification = async (targetSessionId = sessionId) => {
        if (previewMode === "inbound") {
            await beginInboundWait(targetSessionId);
            return;
        }
        await beginCall(targetSessionId);
    };

    const handleStartPreview = async () => {
        const trimmedPhone = phoneNumber.trim();
        if (!trimmedPhone) {
            setError(t("phoneCall.phoneRequired"));
            return;
        }

        setError(null);
        setSuccess(null);
        setBusy("starting");

        try {
            await saveDraftIfNeeded();

            setBusy("starting");
            const data = await startPreview({
                workflow_id: workflowId,
                display_name: normalizedDisplayName || null,
                phone_number: trimmedPhone,
            });
            const nextSessionId = sessionIdFrom(data);
            const nextMaskedPhone = maskedPhoneFrom(data);
            const nextExpiresAt = expiresAtFrom(data);

            setSessionId(nextSessionId);
            setMaskedPhone(nextMaskedPhone);
            setExpiresAt(nextExpiresAt);
            setStatus(data.status ?? (otpRequiredFrom(data) ? "pending_verification" : "verified"));

            if (otpRequiredFrom(data)) {
                setStep("otp");
                setSuccess(t("phoneCall.otpSent"));
                return;
            }

            await continueAfterVerification(nextSessionId);
        } catch (err) {
            setError(err instanceof Error ? err.message : formatError(err));
            setStep("entry");
        } finally {
            setBusy(null);
        }
    };

    const handleVerifyAndCall = async () => {
        if (!sessionId) {
            setError(t("phoneCall.missingSession"));
            return;
        }
        if (otpCode.length !== 6) {
            setError(t("phoneCall.otpRequired"));
            return;
        }

        setError(null);
        setSuccess(null);
        setBusy("verifying");

        try {
            const verified = await verifyPreview({
                session_id: Number(sessionId),
                otp_code: otpCode,
            });
            const nextSessionId = sessionIdFrom(verified) || sessionId;
            setSessionId(nextSessionId);
            setStatus(verified.status ?? "verified");
            await continueAfterVerification(nextSessionId);
        } catch (err) {
            setError(err instanceof Error ? err.message : formatError(err));
        } finally {
            setBusy(null);
        }
    };

    const resetToEntry = () => {
        setOtpCode("");
        setSessionId("");
        setMaskedPhone("");
        setInboundPhoneNumber("");
        setExpiresAt("");
        setWorkflowRunId(null);
        setStatus("idle");
        setStep("entry");
        setError(null);
        setSuccess(null);
        setBusy(null);
    };

    const handlePhoneInputChange = (formattedValue: string) => {
        setPhoneNumber(formattedValue);
        setError(null);
        setSuccess(null);
    };

    const statusLabel = (() => {
        if (busy === "saving") return t("phoneCall.statusSavingDraft");
        if (busy === "starting") return t("phoneCall.statusPreparing");
        if (busy === "verifying") return t("phoneCall.statusVerifying");
        if (busy === "calling") return t("phoneCall.statusCalling");
        if (busy === "waiting") return t("phoneCall.statusWaitingInbound");
        if (step === "otp") return t("phoneCall.statusOtp");
        if (status === "awaiting_inbound") return t("phoneCall.statusWaitingInbound");
        if (status === "failed") return t("phoneCall.statusFailed");
        if (status === "completed" || status === "complete") return t("phoneCall.statusCompleted");
        if (status === "calling" || step === "calling") return t("phoneCall.statusCalling");
        return t("phoneCall.statusReady");
    })();

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-[520px]">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <PhoneCall className="h-5 w-5 text-teal-600" />
                        {t("phoneCall.title")}
                    </DialogTitle>
                    <DialogDescription>{t("phoneCall.description")}</DialogDescription>
                </DialogHeader>

                <div className="space-y-4">
                    <div className="rounded-lg border bg-muted/40 px-3 py-2 text-sm">
                        <div className="flex items-start gap-2">
                            <ShieldCheck className="mt-0.5 h-4 w-4 text-teal-600" />
                            <div>
                                <p className="font-medium">{t("phoneCall.systemCallerTitle")}</p>
                                <p className="text-muted-foreground">{t("phoneCall.systemCallerDescription")}</p>
                            </div>
                        </div>
                    </div>

                    <div className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
                        <span className="text-muted-foreground">{t("phoneCall.status")}</span>
                        <span className="font-medium">{statusLabel}</span>
                    </div>

                    {step === "entry" && (
                        <>
                            <Tabs
                                value={previewMode}
                                onValueChange={(value) => setPreviewMode(value as PreviewMode)}
                                className="w-full"
                            >
                                <TabsList className="grid w-full grid-cols-2">
                                    <TabsTrigger value="outbound" disabled={busy !== null}>
                                        {t("phoneCall.modeOutbound")}
                                    </TabsTrigger>
                                    <TabsTrigger value="inbound" disabled={busy !== null}>
                                        {t("phoneCall.modeInbound")}
                                    </TabsTrigger>
                                </TabsList>
                            </Tabs>

                            <div className="space-y-1.5">
                                <Label htmlFor="preview-display-name">{t("phoneCall.nameLabel")}</Label>
                                <Input
                                    id="preview-display-name"
                                    value={displayName}
                                    onChange={(event) => setDisplayName(event.target.value)}
                                    placeholder={t("phoneCall.namePlaceholder")}
                                    disabled={busy !== null}
                                />
                            </div>

                            <div className="space-y-1.5">
                                <Label htmlFor="preview-phone-number">{t("phoneCall.phoneLabel")}</Label>
                                <PhoneInput
                                    inputProps={{ id: "preview-phone-number", name: "preview-phone-number" }}
                                    defaultCountry="kr"
                                    value={phoneNumber}
                                    onChange={handlePhoneInputChange}
                                    disabled={busy !== null}
                                />
                                <p className="text-xs text-muted-foreground">{t("phoneCall.phoneHelp")}</p>
                            </div>

                            {hasUnsavedChanges && (
                                <div className="rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-xs text-yellow-700">
                                    {t("phoneCall.unsavedDraftWillSave")}
                                </div>
                            )}
                        </>
                    )}

                    {step === "otp" && (
                        <div className="space-y-3">
                            <div className="rounded-md border border-teal-500/30 bg-teal-500/10 px-3 py-2 text-sm">
                                <p className="font-medium">{t("phoneCall.otpTitle")}</p>
                                <p className="text-muted-foreground">
                                    {t("phoneCall.otpDescription")} {maskedPhone || phoneNumber}
                                </p>
                                {expiresAt && (
                                    <p className="mt-1 text-xs text-muted-foreground">
                                        {t("phoneCall.otpExpires")} {new Date(expiresAt).toLocaleTimeString()}
                                    </p>
                                )}
                            </div>
                            <div className="space-y-1.5">
                                <Label htmlFor="preview-otp">{t("phoneCall.otpLabel")}</Label>
                                <Input
                                    id="preview-otp"
                                    inputMode="numeric"
                                    autoComplete="one-time-code"
                                    value={otpCode}
                                    maxLength={6}
                                    onChange={(event) =>
                                        setOtpCode(event.target.value.replace(/\D/g, "").slice(0, 6))
                                    }
                                    placeholder="123456"
                                    disabled={busy !== null}
                                />
                            </div>
                        </div>
                    )}

                    {(step === "calling" || step === "complete") && (
                        <div className="rounded-md border border-teal-500/30 bg-teal-500/10 px-3 py-3 text-sm">
                            <div className="flex items-start gap-2">
                                {busy === "calling" || busy === "waiting" ? (
                                    <Loader2 className="mt-0.5 h-4 w-4 animate-spin text-teal-600" />
                                ) : (
                                    <CheckCircle2 className="mt-0.5 h-4 w-4 text-teal-600" />
                                )}
                                <div>
                                    <p className="font-medium">{t("phoneCall.callStatusTitle")}</p>
                                    <p className="text-muted-foreground">
                                        {success ?? (
                                            previewMode === "inbound"
                                                ? t("phoneCall.inboundWaiting")
                                                : t("phoneCall.callStarted")
                                        )}
                                    </p>
                                    {previewMode === "inbound" && inboundPhoneNumber && (
                                        <p className="mt-2 rounded bg-background px-2 py-1 font-mono text-base">
                                            {inboundPhoneNumber}
                                        </p>
                                    )}
                                    {workflowRunId && (
                                        <p className="mt-1 text-xs text-muted-foreground">
                                            {t("phoneCall.workflowRun")} {workflowRunId}
                                        </p>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}

                    {error && (
                        <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-600">
                            {error}
                        </div>
                    )}

                    {success && step !== "calling" && step !== "complete" && (
                        <div className="rounded-md border border-teal-500/30 bg-teal-500/10 px-3 py-2 text-sm text-teal-700">
                            {success}
                        </div>
                    )}
                </div>

                <DialogFooter className="gap-2 sm:gap-0">
                    {step === "entry" && (
                        <>
                            <DialogClose asChild>
                                <Button variant="outline" disabled={busy !== null}>
                                    {t("common.cancel")}
                                </Button>
                            </DialogClose>
                            <Button onClick={handleStartPreview} disabled={busy !== null || !phoneNumber.trim()}>
                                {busy ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        {busy === "saving" ? t("common.saving") : t("phoneCall.preparing")}
                                    </>
                                ) : (
                                    previewMode === "inbound"
                                        ? t("phoneCall.startInbound")
                                        : t("phoneCall.start")
                                )}
                            </Button>
                        </>
                    )}

                    {step === "otp" && (
                        <>
                            <Button variant="outline" onClick={resetToEntry} disabled={busy !== null}>
                                {t("phoneCall.changeNumber")}
                            </Button>
                            <Button onClick={handleVerifyAndCall} disabled={busy !== null || otpCode.length !== 6}>
                                {busy ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        {busy === "verifying" ? t("phoneCall.verifying") : t("phoneCall.calling")}
                                    </>
                                ) : (
                                    previewMode === "inbound"
                                        ? t("phoneCall.verifyAndWaitInbound")
                                        : t("phoneCall.verifyAndCall")
                                )}
                            </Button>
                        </>
                    )}

                    {(step === "calling" || step === "complete") && (
                        <>
                            <Button variant="outline" onClick={resetToEntry} disabled={busy !== null}>
                                {t("phoneCall.again")}
                            </Button>
                            <Button onClick={() => onOpenChange(false)} disabled={busy !== null}>
                                {t("phoneCall.close")}
                            </Button>
                        </>
                    )}
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
};
