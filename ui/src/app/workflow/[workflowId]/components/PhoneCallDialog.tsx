"use client";

import "react-international-phone/style.css";

import { Loader2, PhoneCall, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { PhoneInput } from "react-international-phone";

import * as generatedPhonePreviewSdk from "@/client/sdk.gen";
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

type PreviewMode = "outbound" | "inbound";
type PreviewStep = "entry" | "otp" | "ready" | "pending";
type BusyState = "saving" | "starting" | "verifying" | "outbound" | "inbound" | "containing" | null;
type SafePreviewResponse = PhonePreviewResponse;
type SdkResult = { data?: SafePreviewResponse; error?: unknown };

interface PhoneCallDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    workflowId: number;
    user: { id: string; email?: string };
    hasUnsavedChanges?: boolean;
    saveLatestDraft?: () => Promise<void>;
}

const PHONE_NUMBER_FORMAT_CHARS = /[\s\-().]/g;
const STATUS_POLL_INTERVAL_MS = 1000;
const sdk = generatedPhonePreviewSdk;

const normalizeKoreanPreviewPhoneInput = (value: string) => {
    const compact = value.trim().replace(PHONE_NUMBER_FORMAT_CHARS, "");
    let normalized = compact;
    if (normalized.startsWith("+820")) normalized = `+82${normalized.slice(4)}`;
    else if (normalized.startsWith("820")) normalized = `+82${normalized.slice(3)}`;
    else if (normalized.startsWith("+82")) normalized = `+${normalized.slice(1).replace(/\D/g, "")}`;
    else if (normalized.startsWith("82")) normalized = `+${normalized.replace(/\D/g, "")}`;
    else {
        const digits = normalized.replace(/\D/g, "");
        if (digits.startsWith("010")) normalized = `+82${digits.slice(1)}`;
        else if (digits.startsWith("10") && digits.length === 10) normalized = `+82${digits}`;
    }
    return { normalized, isValid: /^\+8210\d{8}$/.test(normalized) };
};

const errorDetail = (error: unknown): string => {
    if (typeof error === "string") return error;
    if (!error || typeof error !== "object") return "request_failed";
    const detail = (error as { detail?: unknown }).detail;
    return typeof detail === "string" ? detail : JSON.stringify(detail ?? error);
};

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
    const [mode, setMode] = useState<PreviewMode>("outbound");
    const [step, setStep] = useState<PreviewStep>("entry");
    const [otpCode, setOtpCode] = useState("");
    const [sessionId, setSessionId] = useState<number | null>(null);
    const [status, setStatus] = useState("idle");
    const [maskedPhone, setMaskedPhone] = useState("");
    const [gateStates, setGateStates] = useState<Record<string, boolean>>({});
    const [remainingAttempts, setRemainingAttempts] = useState<number | null>(null);
    const [proofCurrent, setProofCurrent] = useState<boolean | null>(null);
    const [registrationFresh, setRegistrationFresh] = useState<boolean | null>(null);
    const [mediaFresh, setMediaFresh] = useState<boolean | null>(null);
    const [contained, setContained] = useState(false);
    const [terminalClass, setTerminalClass] = useState<string | null>(null);
    const [acknowledgementRequired, setAcknowledgementRequired] = useState(false);
    const [manualAcknowledged, setManualAcknowledged] = useState(false);
    const [busy, setBusy] = useState<BusyState>(null);
    const [message, setMessage] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);

    const phoneValidation = useMemo(() => normalizeKoreanPreviewPhoneInput(phoneNumber), [phoneNumber]);
    const gateRows = useMemo(() => Object.entries(gateStates).sort(([left], [right]) => left.localeCompare(right)), [gateStates]);
    const failed = status === "failed" || Boolean(terminalClass?.toLowerCase().includes("fail"));
    const gatesOpen = gateRows.length > 0 && gateRows.every(([, value]) => value);
    const authorityReady = gatesOpen
        && proofCurrent === true
        && registrationFresh === true
        && mediaFresh === true
        && remainingAttempts !== null
        && remainingAttempts > 0
        && !contained
        && !failed;
    const actionDisabled = busy !== null || !authorityReady;

    useEffect(() => {
        if (!open) return;
        setDisplayName(user.email?.split("@")[0] ?? "");
        setPhoneNumber("");
        setMode("outbound");
        setStep("entry");
        setOtpCode("");
        setSessionId(null);
        setStatus("idle");
        setMaskedPhone("");
        setGateStates({});
        setRemainingAttempts(null);
        setProofCurrent(null);
        setRegistrationFresh(null);
        setMediaFresh(null);
        setContained(false);
        setTerminalClass(null);
        setAcknowledgementRequired(false);
        setManualAcknowledged(false);
        setBusy(null);
        setMessage(null);
        setError(null);
    }, [open, user.email]);

    const formatError = useCallback((raw: unknown) => {
        const detail = errorDetail(raw);
        const lower = detail.toLowerCase();
        if (lower.includes("acknowledgement")) return t("phoneCall.errorAcknowledgementRequired");
        if (lower.includes("telephony_not_configured")) return t("phoneCall.errorTelephonyNotConfigured");
        if (lower.includes("proof")) return t("phoneCall.errorStaleProof");
        if (lower.includes("exhaust")) return t("phoneCall.errorExhausted");
        if (lower.includes("partition") || lower.includes("authority")) return t("phoneCall.errorAuthorityUnavailable");
        if (lower.includes("otp") || lower.includes("verification")) return t("phoneCall.errorVerification");
        return t("phoneCall.errorRequestFailed");
    }, [t]);

    const markAuthorityUnavailable = useCallback(() => {
        setGateStates({});
        setProofCurrent(false);
        setRegistrationFresh(false);
        setMediaFresh(false);
    }, []);

    const applyStatus = useCallback((data: SafePreviewResponse) => {
        setSessionId(data.session_id);
        setStatus(data.status);
        setMaskedPhone(data.masked_phone || "");
        if (data.gate_states) setGateStates(data.gate_states);
        if (data.remaining_attempts !== undefined) {
            setRemainingAttempts(data.remaining_attempts === null ? null : Math.min(3, Math.max(0, data.remaining_attempts)));
        }
        if (data.proof_current !== undefined) setProofCurrent(data.proof_current);
        if (data.registration_fresh !== undefined) setRegistrationFresh(data.registration_fresh);
        if (data.media_fresh !== undefined) setMediaFresh(data.media_fresh);
        if (data.contained !== undefined) setContained(Boolean(data.contained));
        if (data.terminal_class !== undefined) setTerminalClass(data.terminal_class);
        if (data.failure_reason) setError(formatError(data.failure_reason));
        if (data.status === "failed" || data.status === "completed" || data.contained) setStep("pending");
    }, [formatError]);

    const unwrap = useCallback((response: SdkResult) => {
        if (response.error) throw response.error;
        if (!response.data) throw new Error("missing_response");
        return response.data;
    }, []);

    const refreshStatus = useCallback(async (id: number) => {
        const response = await sdk.getPhonePreviewStatusByStatusPathApiV1PhonePreviewStatusSessionIdGet({
            path: { session_id: id },
        });
        const data = unwrap(response as SdkResult);
        applyStatus(data);
        return data;
    }, [applyStatus, unwrap]);

    useEffect(() => {
        if (!open || !sessionId || step !== "pending" || contained || failed || status === "completed") return;
        const interval = window.setInterval(() => {
            void refreshStatus(sessionId).catch((reason) => {
                markAuthorityUnavailable();
                setError(formatError(reason));
            });
        }, STATUS_POLL_INTERVAL_MS);
        return () => window.clearInterval(interval);
    }, [contained, failed, formatError, markAuthorityUnavailable, open, refreshStatus, sessionId, status, step]);

    const handleStart = async () => {
        if (!phoneValidation.isValid || busy) return;
        setBusy("starting");
        setError(null);
        setMessage(null);
        try {
            if (hasUnsavedChanges && saveLatestDraft) {
                setBusy("saving");
                await saveLatestDraft();
                setBusy("starting");
            }
            const response = await sdk.startPhonePreviewApiV1PhonePreviewStartPost({
                body: {
                    workflow_id: workflowId,
                    phone_number: phoneValidation.normalized,
                    display_name: displayName.trim() || null,
                },
            });
            const data = unwrap(response as SdkResult);
            applyStatus(data);
            setPhoneNumber("");
            setStep(data.otp_required ? "otp" : "ready");
            if (!data.otp_required) await refreshStatus(data.session_id);
        } catch (reason) {
            markAuthorityUnavailable();
            setError(formatError(reason));
        } finally {
            setBusy(null);
        }
    };

    const handleVerify = async () => {
        if (!sessionId || otpCode.length !== 6 || busy) return;
        setBusy("verifying");
        setError(null);
        try {
            const response = await sdk.verifyPhonePreviewApiV1PhonePreviewVerifyPost({
                body: { session_id: sessionId, otp_code: otpCode },
            });
            const data = unwrap(response as SdkResult);
            applyStatus(data);
            setOtpCode("");
            setStep("ready");
            await refreshStatus(sessionId);
        } catch (reason) {
            markAuthorityUnavailable();
            setError(formatError(reason));
        } finally {
            setBusy(null);
        }
    };

    const handleAttempt = async () => {
        if (!sessionId || actionDisabled || (acknowledgementRequired && !manualAcknowledged)) return;
        setBusy(mode);
        setError(null);
        setMessage(null);
        const body = {
            session_id: sessionId,
            ...(acknowledgementRequired && manualAcknowledged
                ? { manual_acknowledgement: "operator-confirmed-third-attempt" }
                : {}),
        };
        try {
            const response = mode === "outbound"
                ? await sdk.callPhonePreviewApiV1PhonePreviewCallPost({ body })
                : await sdk.waitForInboundPhonePreviewApiV1PhonePreviewWaitInboundPost({ body });
            const data = unwrap(response);
            applyStatus(data);
            setStep("pending");
            setMessage(mode === "inbound" ? t("phoneCall.inboundAuthorizedPending") : t("phoneCall.outboundRequested"));
        } catch (reason) {
            const detail = errorDetail(reason).toLowerCase();
            if (detail.includes("acknowledgement")) setAcknowledgementRequired(true);
            setError(formatError(reason));
            await refreshStatus(sessionId).catch(() => markAuthorityUnavailable());
        } finally {
            setBusy(null);
        }
    };

    const handleContain = async () => {
        if (!sessionId || busy || contained) return;
        setBusy("containing");
        setError(null);
        try {
            const data = unwrap(await sdk.containPhonePreviewApiV1PhonePreviewContainPost({
                body: {
                    session_id: sessionId,
                    terminal_class: "operator_containment",
                    terminal_reason: "operator_requested_containment",
                },
            }));
            applyStatus(data);
            setContained(true);
            setStep("pending");
            setMessage(t("phoneCall.containmentConfirmed"));
        } catch (reason) {
            setError(formatError(reason));
        } finally {
            setBusy(null);
        }
    };

    const terminalStateLabel = (() => {
        const value = terminalClass?.toLowerCase();
        if (!value) return t("phoneCall.terminalNone");
        if (value.includes("contain")) return t("phoneCall.terminalContained");
        if (value.includes("exhaust")) return t("phoneCall.terminalExhausted");
        if (value.includes("complete") || value.includes("success")) return t("phoneCall.terminalCompleted");
        return t("phoneCall.terminalFailed");
    })();

    const booleanLabel = (value: boolean | null) => value === null
        ? t("phoneCall.booleanUnknown")
        : value ? t("phoneCall.booleanYes") : t("phoneCall.booleanNo");

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-[600px]">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <PhoneCall className="h-5 w-5 text-teal-600" aria-hidden="true" />
                        {t("phoneCall.stagingTitle")}
                    </DialogTitle>
                    <DialogDescription>{t("phoneCall.stagingDescription")}</DialogDescription>
                </DialogHeader>

                <div className="space-y-4">
                    <section className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm" aria-labelledby="staging-safety-title">
                        <div className="flex gap-2">
                            <ShieldCheck className="mt-0.5 h-4 w-4 text-amber-700" aria-hidden="true" />
                            <div>
                                <h3 id="staging-safety-title" className="font-semibold">{t("phoneCall.waitingTitle")}</h3>
                                <p className="text-muted-foreground">{t("phoneCall.waitingDescription")}</p>
                                <p className="mt-1 font-medium">{t("phoneCall.hardLimits")}</p>
                            </div>
                        </div>
                    </section>

                    {step === "entry" && (
                        <>
                            <Tabs value={mode} onValueChange={(value) => setMode(value as PreviewMode)}>
                                <TabsList className="grid w-full grid-cols-2">
                                    <TabsTrigger value="outbound" disabled={busy !== null}>{t("phoneCall.modeOutbound")}</TabsTrigger>
                                    <TabsTrigger value="inbound" disabled={busy !== null}>{t("phoneCall.modeInbound")}</TabsTrigger>
                                </TabsList>
                            </Tabs>
                            <div className="space-y-1.5">
                                <Label htmlFor="preview-display-name">{t("phoneCall.nameLabel")}</Label>
                                <Input id="preview-display-name" value={displayName} onChange={(event) => setDisplayName(event.target.value)} disabled={busy !== null} />
                            </div>
                            <div className="space-y-1.5">
                                <Label htmlFor="preview-phone-number">{t("phoneCall.phoneLabel")}</Label>
                                <PhoneInput
                                    inputProps={{ id: "preview-phone-number", name: "preview-phone-number", placeholder: "010-****-****", "aria-describedby": "preview-phone-help" }}
                                    defaultCountry="kr"
                                    value={phoneNumber}
                                    onChange={(value) => { setPhoneNumber(value); setError(null); }}
                                    disabled={busy !== null}
                                />
                                <p id="preview-phone-help" className="text-xs text-muted-foreground">{t("phoneCall.phoneHelpPrivate")}</p>
                            </div>
                        </>
                    )}

                    {step === "otp" && (
                        <div className="space-y-2">
                            <p className="text-sm">{t("phoneCall.otpDescription")} <strong>{maskedPhone}</strong></p>
                            <Label htmlFor="preview-otp">{t("phoneCall.otpLabel")}</Label>
                            <Input id="preview-otp" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={otpCode} onChange={(event) => setOtpCode(event.target.value.replace(/\D/g, "").slice(0, 6))} disabled={busy !== null} />
                        </div>
                    )}

                    {step !== "entry" && (
                        <section className="space-y-3 rounded-lg border p-3 text-sm" aria-labelledby="authority-title" data-testid="staging-authority-panel">
                            <div className="flex items-center justify-between gap-3">
                                <h3 id="authority-title" className="font-semibold">{t("phoneCall.authorityTitle")}</h3>
                                <span className="rounded bg-muted px-2 py-1 font-medium">{maskedPhone || t("phoneCall.maskUnavailable")}</span>
                            </div>
                            <div className="grid grid-cols-2 gap-2">
                                <span>{t("phoneCall.remainingAttempts")}</span><strong data-testid="remaining-attempts">{remainingAttempts ?? "-"} / 3</strong>
                                <span>{t("phoneCall.proofCurrent")}</span><strong>{booleanLabel(proofCurrent)}</strong>
                                <span>{t("phoneCall.registrationFresh")}</span><strong>{booleanLabel(registrationFresh)}</strong>
                                <span>{t("phoneCall.mediaFresh")}</span><strong>{booleanLabel(mediaFresh)}</strong>
                                <span>{t("phoneCall.contained")}</span><strong>{booleanLabel(contained)}</strong>
                                <span>{t("phoneCall.terminalState")}</span><strong>{terminalStateLabel}</strong>
                            </div>
                            <div>
                                <p className="font-medium">{t("phoneCall.gates")}</p>
                                {gateRows.length === 0 ? (
                                    <p className="text-muted-foreground">{t("phoneCall.gatesUnavailable")}</p>
                                ) : (
                                    <ul className="mt-1 grid grid-cols-2 gap-1" aria-label={t("phoneCall.gates")}>
                                        {gateRows.map(([name, enabled]) => <li key={name}><span className="font-mono">{name}</span>: <strong>{booleanLabel(enabled)}</strong></li>)}
                                    </ul>
                                )}
                            </div>
                            {step === "pending" && mode === "inbound" && (
                                <p role="status" className="rounded bg-muted p-2">{t("phoneCall.inboundAuthorizedPending")}</p>
                            )}
                        </section>
                    )}

                    {acknowledgementRequired && (
                        <label className="flex items-start gap-2 rounded border border-amber-500/30 p-3 text-sm">
                            <input type="checkbox" checked={manualAcknowledged} onChange={(event) => setManualAcknowledged(event.target.checked)} disabled={busy !== null} />
                            <span>{t("phoneCall.thirdAttemptAcknowledgement")}</span>
                        </label>
                    )}
                    {message && <p role="status" className="rounded border border-teal-500/30 bg-teal-500/10 p-2 text-sm">{message}</p>}
                    {error && <p role="alert" className="rounded border border-red-500/30 bg-red-500/10 p-2 text-sm text-red-700">{error}</p>}
                </div>

                <DialogFooter className="gap-2 sm:gap-2">
                    <DialogClose asChild><Button variant="outline" disabled={busy !== null}>{t("common.cancel")}</Button></DialogClose>
                    {step === "entry" && <Button onClick={handleStart} disabled={busy !== null || !phoneValidation.isValid}>{busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}{t("phoneCall.prepareOnly")}</Button>}
                    {step === "otp" && <Button onClick={handleVerify} disabled={busy !== null || otpCode.length !== 6}>{t("phoneCall.verifyOnly")}</Button>}
                    {(step === "ready" || (acknowledgementRequired && step === "pending")) && (
                        <Button onClick={handleAttempt} disabled={actionDisabled || (acknowledgementRequired && !manualAcknowledged)}>
                            {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                            {mode === "outbound" ? t("phoneCall.requestOutbound") : t("phoneCall.authorizeInbound")}
                        </Button>
                    )}
                    {sessionId && !contained && <Button variant="destructive" onClick={handleContain} disabled={busy !== null}>{t("phoneCall.contain")}</Button>}
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
};
