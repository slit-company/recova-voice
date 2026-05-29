"use client";

import "react-international-phone/style.css";

import { CheckCircle2, Loader2, PhoneCall, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { PhoneInput } from "react-international-phone";

import { client } from "@/client/client.gen";
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
import { useLocale } from "@/context/LocaleContext";
import { useUserConfig } from "@/context/UserConfigContext";

type PreviewStep = "entry" | "otp" | "calling" | "complete";
type BusyState = "saving" | "starting" | "verifying" | "calling" | null;

type PhonePreviewResponse = {
    session_id?: number | string;
    sessionId?: number | string;
    id?: number | string;
    status?: string;
    otp_required?: boolean;
    otpRequired?: boolean;
    masked_phone?: string;
    maskedPhone?: string;
    expires_at?: string;
    expiresAt?: string;
    workflow_run_id?: number | string | null;
    workflowRunId?: number | string | null;
    provider_call_id?: string | null;
    providerCallId?: string | null;
    failure_reason?: string | null;
    failureReason?: string | null;
    message?: string;
};

interface PhoneCallDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    workflowId: number;
    user: { id: string; email?: string };
    hasUnsavedChanges?: boolean;
    saveLatestDraft?: () => Promise<void>;
}

const previewEndpoint = (action: "start" | "verify" | "call") => `/api/v1/phone-preview/${action}`;
const previewStatusEndpoint = (sessionId: number | string) => `/api/v1/phone-preview/status/${sessionId}`;

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
    const id = data.session_id ?? data.sessionId ?? data.id;
    return id === undefined || id === null ? "" : String(id);
};
const otpRequiredFrom = (data: PhonePreviewResponse) =>
    data.otp_required ?? data.otpRequired ?? data.status === "pending_verification";
const maskedPhoneFrom = (data: PhonePreviewResponse) => data.masked_phone ?? data.maskedPhone ?? "";
const expiresAtFrom = (data: PhonePreviewResponse) => data.expires_at ?? data.expiresAt ?? "";
const workflowRunIdFrom = (data: PhonePreviewResponse) => data.workflow_run_id ?? data.workflowRunId ?? null;
const providerCallIdFrom = (data: PhonePreviewResponse) => data.provider_call_id ?? data.providerCallId ?? null;
const failureReasonFrom = (data: PhonePreviewResponse) => data.failure_reason ?? data.failureReason ?? null;

export const PhoneCallDialog = ({
    open,
    onOpenChange,
    workflowId,
    user,
    hasUnsavedChanges = false,
    saveLatestDraft,
}: PhoneCallDialogProps) => {
    const { t } = useLocale();
    const { userConfig, saveUserConfig } = useUserConfig();

    const [displayName, setDisplayName] = useState("");
    const [phoneNumber, setPhoneNumber] = useState("");
    const [otpCode, setOtpCode] = useState("");
    const [sessionId, setSessionId] = useState("");
    const [maskedPhone, setMaskedPhone] = useState("");
    const [expiresAt, setExpiresAt] = useState("");
    const [workflowRunId, setWorkflowRunId] = useState<number | string | null>(null);
    const [providerCallId, setProviderCallId] = useState<string | null>(null);
    const [status, setStatus] = useState<string>("idle");
    const [step, setStep] = useState<PreviewStep>("entry");
    const [busy, setBusy] = useState<BusyState>(null);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<string | null>(null);
    const [phoneChanged, setPhoneChanged] = useState(false);

    const normalizedDisplayName = useMemo(() => displayName.trim(), [displayName]);

    useEffect(() => {
        if (!open) return;

        const savedPhone = userConfig?.test_phone_number || "";
        setDisplayName(user.email?.split("@")[0] ?? "");
        setPhoneNumber(savedPhone);
        setOtpCode("");
        setSessionId("");
        setMaskedPhone("");
        setExpiresAt("");
        setWorkflowRunId(null);
        setProviderCallId(null);
        setStatus("idle");
        setStep("entry");
        setBusy(null);
        setError(null);
        setSuccess(null);
        setPhoneChanged(false);
    }, [open, user.email, userConfig?.test_phone_number]);

    const formatError = useCallback((raw: unknown) => {
        const message = getDetailMessage(raw);
        const lower = message.toLowerCase();
        if (lower.includes("telephony_not_configured")) return t("phoneCall.errorTelephonyNotConfigured");
        if (lower.includes("draft_not_ready")) return t("phoneCall.errorDraftNotReady");
        if (lower.includes("rate") || lower.includes("cooldown")) return t("phoneCall.errorRateLimited");
        if (lower.includes("otp") || lower.includes("verification")) return t("phoneCall.errorVerification");
        return message;
    }, [t]);

    const applyPreviewStatus = useCallback((data: PhonePreviewResponse) => {
        const nextSessionId = sessionIdFrom(data);
        const nextMaskedPhone = maskedPhoneFrom(data);
        const nextExpiresAt = expiresAtFrom(data);
        const nextWorkflowRunId = workflowRunIdFrom(data);
        const nextProviderCallId = providerCallIdFrom(data);
        const failureReason = failureReasonFrom(data);

        if (nextSessionId) setSessionId(nextSessionId);
        if (nextMaskedPhone) setMaskedPhone(nextMaskedPhone);
        if (nextExpiresAt) setExpiresAt(nextExpiresAt);
        setStatus((current) => data.status ?? current);
        setWorkflowRunId(nextWorkflowRunId);
        setProviderCallId(nextProviderCallId);
        if (failureReason) {
            setError(formatError(failureReason));
            setSuccess(null);
        }
        if (data.status === "failed" || data.status === "completed") {
            setStep("complete");
        }
    }, [formatError]);

    const postPreview = useCallback(async (action: "start" | "verify" | "call", body: Record<string, unknown>) => {
        const response = (await client.post({
            url: previewEndpoint(action),
            body,
        })) as { data?: unknown; error?: unknown };

        if (response.error) {
            throw new Error(formatError(response.error));
        }
        return (response.data ?? {}) as PhonePreviewResponse;
    }, [formatError]);

    const getPreviewStatus = useCallback(async (targetSessionId: string) => {
        const response = (await client.get({
            url: previewStatusEndpoint(targetSessionId),
        })) as { data?: unknown; error?: unknown };

        if (response.error) {
            throw new Error(formatError(response.error));
        }
        return (response.data ?? {}) as PhonePreviewResponse;
    }, [formatError]);

    const savePhoneIfNeeded = async () => {
        if (!userConfig || !phoneChanged) return;
        await saveUserConfig({ ...userConfig, test_phone_number: phoneNumber });
        setPhoneChanged(false);
    };

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

        const data = await postPreview("call", { session_id: targetSessionId });
        const nextStatus = data.status ?? "calling";
        const nextWorkflowRunId = workflowRunIdFrom(data);
        const nextProviderCallId = providerCallIdFrom(data);
        const failureReason = failureReasonFrom(data);

        setStatus(nextStatus);
        setWorkflowRunId(nextWorkflowRunId);
        setProviderCallId(nextProviderCallId);
        setStep(nextStatus === "failed" ? "complete" : "calling");
        if (failureReason) {
            setError(formatError(failureReason));
            setSuccess(null);
        } else {
            setSuccess(data.message ?? t("phoneCall.callStarted"));
        }
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
            await savePhoneIfNeeded();

            setBusy("starting");
            const data = await postPreview("start", {
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

            await beginCall(nextSessionId);
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
            const verified = await postPreview("verify", {
                session_id: sessionId,
                otp_code: otpCode,
            });
            const nextSessionId = sessionIdFrom(verified) || sessionId;
            setSessionId(nextSessionId);
            setStatus(verified.status ?? "verified");
            await beginCall(nextSessionId);
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
        setExpiresAt("");
        setWorkflowRunId(null);
        setProviderCallId(null);
        setStatus("idle");
        setStep("entry");
        setError(null);
        setSuccess(null);
        setBusy(null);
    };

    const handlePhoneInputChange = (formattedValue: string) => {
        setPhoneNumber(formattedValue);
        setPhoneChanged(formattedValue !== (userConfig?.test_phone_number || ""));
        setError(null);
        setSuccess(null);
    };

    const statusLabel = (() => {
        if (busy === "saving") return t("phoneCall.statusSavingDraft");
        if (busy === "starting") return t("phoneCall.statusPreparing");
        if (busy === "verifying") return t("phoneCall.statusVerifying");
        if (busy === "calling") return t("phoneCall.statusCalling");
        if (step === "otp") return t("phoneCall.statusOtp");
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
                                {busy === "calling" ? (
                                    <Loader2 className="mt-0.5 h-4 w-4 animate-spin text-teal-600" />
                                ) : (
                                    <CheckCircle2 className="mt-0.5 h-4 w-4 text-teal-600" />
                                )}
                                <div>
                                    <p className="font-medium">{t("phoneCall.callStatusTitle")}</p>
                                    <p className="text-muted-foreground">{success ?? t("phoneCall.callStarted")}</p>
                                    {workflowRunId && (
                                        <p className="mt-1 text-xs text-muted-foreground">
                                            {t("phoneCall.workflowRun")} {workflowRunId}
                                        </p>
                                    )}
                                    {providerCallId && (
                                        <p className="text-xs text-muted-foreground">
                                            {t("phoneCall.providerCall")} {providerCallId}
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
                                    t("phoneCall.start")
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
                                    t("phoneCall.verifyAndCall")
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
