"use client";

import { ArrowLeft } from "lucide-react";
import { useParams, useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import type { ITimezoneOption } from "react-timezone-select";
import { toast } from "sonner";

import {
  getCampaignApiV1CampaignCampaignIdGet,
  getCampaignDefaultsApiV1OrganizationsCampaignDefaultsGet,
  updateCampaignApiV1CampaignCampaignIdPatch,
} from "@/client/sdk.gen";
import type { CampaignResponse } from "@/client/types.gen";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { useLocale } from "@/context/LocaleContext";
import { useAuth } from "@/lib/auth";

import CampaignAdvancedSettings, {
  getTimezoneValue,
  type TimeSlot,
} from "../../CampaignAdvancedSettings";

export default function EditCampaignPage() {
  const { user, getAccessToken, redirectToLogin, loading } = useAuth();
  const { t } = useLocale();
  const router = useRouter();
  const params = useParams();
  const campaignId = parseInt(params.campaignId as string);

  // Loading state
  const [isLoading, setIsLoading] = useState(true);
  const [campaign, setCampaign] = useState<CampaignResponse | null>(null);

  // Form state
  const [campaignName, setCampaignName] = useState("");
  const [maxConcurrency, setMaxConcurrency] = useState<string>("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  // Limits state
  const [orgConcurrentLimit, setOrgConcurrentLimit] = useState<number>(2);
  const [fromNumbersCount, setFromNumbersCount] = useState<number>(0);

  // Retry config state
  const [retryEnabled, setRetryEnabled] = useState(true);
  const [maxRetries, setMaxRetries] = useState<string>("2");
  const [retryDelaySeconds, setRetryDelaySeconds] = useState<string>("120");
  const [retryOnBusy, setRetryOnBusy] = useState(true);
  const [retryOnNoAnswer, setRetryOnNoAnswer] = useState(true);
  const [retryOnVoicemail, setRetryOnVoicemail] = useState(true);

  // Schedule config state
  const [scheduleEnabled, setScheduleEnabled] = useState(false);
  const [scheduleTimezone, setScheduleTimezone] = useState<
    ITimezoneOption | string
  >("UTC");
  const [timeSlots, setTimeSlots] = useState<TimeSlot[]>([
    { day_of_week: 0, start_time: "09:00", end_time: "17:00" },
  ]);
  // Circuit breaker config state
  const [circuitBreakerEnabled, setCircuitBreakerEnabled] = useState(true);
  const [circuitBreakerFailureThreshold, setCircuitBreakerFailureThreshold] =
    useState<string>("50");
  const [circuitBreakerWindowSeconds, setCircuitBreakerWindowSeconds] =
    useState<string>("120");
  const [circuitBreakerMinCalls, setCircuitBreakerMinCalls] =
    useState<string>("5");

  // Redirect if not authenticated
  useEffect(() => {
    if (!loading && !user) {
      redirectToLogin();
    }
  }, [loading, user, redirectToLogin]);

  // Fetch campaign and populate form
  const fetchCampaign = useCallback(async () => {
    if (!user) return;
    try {
      const accessToken = await getAccessToken();
      const response = await getCampaignApiV1CampaignCampaignIdGet({
        path: { campaign_id: campaignId },
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      if (response.data) {
        const c = response.data;

        // Redirect if campaign is completed or failed
        if (["completed", "failed"].includes(c.state)) {
          router.replace(`/campaigns/${campaignId}`);
          return;
        }

        setCampaign(c);

        // Populate form state
        setCampaignName(c.name);
        setMaxConcurrency(c.max_concurrency ? String(c.max_concurrency) : "");

        // Retry config
        setRetryEnabled(c.retry_config.enabled);
        setMaxRetries(String(c.retry_config.max_retries));
        setRetryDelaySeconds(String(c.retry_config.retry_delay_seconds));
        setRetryOnBusy(c.retry_config.retry_on_busy);
        setRetryOnNoAnswer(c.retry_config.retry_on_no_answer);
        setRetryOnVoicemail(c.retry_config.retry_on_voicemail);

        // Schedule config
        if (c.schedule_config) {
          setScheduleEnabled(c.schedule_config.enabled);
          setScheduleTimezone(c.schedule_config.timezone);
          if (c.schedule_config.slots.length > 0) {
            setTimeSlots(
              c.schedule_config.slots.map((s: TimeSlot) => ({ ...s })),
            );
          }
        }

        // Circuit breaker config
        const cb = (
          c as unknown as {
            circuit_breaker?: {
              enabled: boolean;
              failure_threshold: number;
              window_seconds: number;
              min_calls_in_window: number;
            };
          }
        ).circuit_breaker;
        if (cb) {
          setCircuitBreakerEnabled(cb.enabled);
          setCircuitBreakerFailureThreshold(
            String(Math.round(cb.failure_threshold * 100)),
          );
          setCircuitBreakerWindowSeconds(String(cb.window_seconds));
          setCircuitBreakerMinCalls(String(cb.min_calls_in_window));
        }
      }
    } catch (error) {
      console.error("Failed to fetch campaign:", error);
      toast.error(t("campaignDetail.loadFailed"));
      router.replace(`/campaigns/${campaignId}`);
    } finally {
      setIsLoading(false);
    }
  }, [user, getAccessToken, campaignId, router, t]);

  // Fetch campaign limits
  const fetchCampaignDefaults = useCallback(async () => {
    if (!user) return;
    try {
      const accessToken = await getAccessToken();
      const response =
        await getCampaignDefaultsApiV1OrganizationsCampaignDefaultsGet({
          headers: { Authorization: `Bearer ${accessToken}` },
        });

      if (response.data) {
        setOrgConcurrentLimit(response.data.concurrent_call_limit);
        setFromNumbersCount(response.data.from_numbers_count);
      }
    } catch (error) {
      console.error("Failed to fetch campaign limits:", error);
    }
  }, [user, getAccessToken]);

  // Initial load
  useEffect(() => {
    if (user) {
      fetchCampaign();
      fetchCampaignDefaults();
    }
  }, [fetchCampaign, fetchCampaignDefaults, user]);

  // Effective concurrency limit
  const effectiveLimit =
    fromNumbersCount > 0
      ? Math.min(orgConcurrentLimit, fromNumbersCount)
      : orgConcurrentLimit;

  // Handle form submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitError(null);

    if (!campaignName.trim()) {
      toast.error(t("campaignDetail.nameRequired"));
      return;
    }

    // Validate max_concurrency if provided
    const maxConcurrencyValue = maxConcurrency
      ? parseInt(maxConcurrency)
      : null;
    if (maxConcurrencyValue !== null) {
      if (
        isNaN(maxConcurrencyValue) ||
        maxConcurrencyValue < 1 ||
        maxConcurrencyValue > 100
      ) {
        toast.error(t("campaignNew.maxConcurrentRange"));
        return;
      }
      if (maxConcurrencyValue > effectiveLimit) {
        if (fromNumbersCount > 0 && fromNumbersCount < orgConcurrentLimit) {
          toast.error(
            t("campaignNew.maxConcurrentPhoneLimit", {
              limit: effectiveLimit,
              count: fromNumbersCount,
            }),
          );
        } else {
          toast.error(
            t("campaignNew.maxConcurrentOrgLimit", { limit: effectiveLimit }),
          );
        }
        return;
      }
    }

    // Validate schedule slots if enabled
    if (scheduleEnabled) {
      if (timeSlots.length === 0) {
        toast.error(t("campaignDetail.addTimeSlot"));
        return;
      }
      for (const slot of timeSlots) {
        if (slot.start_time >= slot.end_time) {
          toast.error(t("campaignDetail.invalidTimeSlot"));
          return;
        }
      }
    }

    setIsSubmitting(true);

    try {
      const accessToken = await getAccessToken();

      const retryConfig = {
        enabled: retryEnabled,
        max_retries: parseInt(maxRetries) || 2,
        retry_delay_seconds: parseInt(retryDelaySeconds) || 120,
        retry_on_busy: retryOnBusy,
        retry_on_no_answer: retryOnNoAnswer,
        retry_on_voicemail: retryOnVoicemail,
      };

      const timezoneValue = getTimezoneValue(scheduleTimezone);
      const scheduleConfig =
        scheduleEnabled && timeSlots.length > 0
          ? {
              enabled: true,
              timezone: timezoneValue,
              slots: timeSlots,
            }
          : {
              enabled: false,
              timezone: timezoneValue,
              slots: [
                { day_of_week: 0, start_time: "09:00", end_time: "17:00" },
              ],
            };

      const circuitBreakerConfig = {
        enabled: circuitBreakerEnabled,
        failure_threshold:
          (parseInt(circuitBreakerFailureThreshold) || 50) / 100,
        window_seconds: parseInt(circuitBreakerWindowSeconds) || 120,
        min_calls_in_window: parseInt(circuitBreakerMinCalls) || 5,
      };

      const response = await updateCampaignApiV1CampaignCampaignIdPatch({
        path: { campaign_id: campaignId },
        body: {
          name: campaignName,
          retry_config: retryConfig,
          max_concurrency: maxConcurrencyValue,
          schedule_config: scheduleConfig,
          circuit_breaker: circuitBreakerConfig,
        },
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      if (response.error) {
        const errorDetail = (response.error as { detail?: string })?.detail;
        const errorMessage = errorDetail || t("campaignDetail.updateFailed");
        setSubmitError(errorMessage);
        toast.error(errorMessage);
        return;
      }

      if (response.data) {
        toast.success(t("campaignDetail.updateSuccess"));
        router.push(`/campaigns/${campaignId}`);
      }
    } catch (error) {
      console.error("Failed to update campaign:", error);
      const errorMessage = t("campaignDetail.updateFailed");
      setSubmitError(errorMessage);
      toast.error(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleBack = () => {
    router.push(`/campaigns/${campaignId}`);
  };

  if (isLoading) {
    return (
      <div className="container mx-auto p-6 space-y-6 max-w-2xl">
        <div className="animate-pulse">
          <div className="h-8 bg-muted rounded w-1/4 mb-4"></div>
          <div className="h-64 bg-muted rounded"></div>
        </div>
      </div>
    );
  }

  if (!campaign) {
    return (
      <div className="container mx-auto p-6 space-y-6 max-w-2xl">
        <p className="text-center text-muted-foreground">
          {t("campaignDetail.notFound")}
        </p>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 pb-12 space-y-6 max-w-2xl">
      <div>
        <Button variant="ghost" onClick={handleBack} className="mb-4">
          <ArrowLeft className="h-4 w-4 mr-2" />
          {t("campaignDetail.backToCampaign")}
        </Button>
        <h1 className="text-3xl font-bold mb-2">
          {t("campaignDetail.editTitle")}
        </h1>
        <p className="text-muted-foreground">
          {t("campaignDetail.editDescription")}
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t("campaignDetail.settings")}</CardTitle>
          <CardDescription>
            {t("campaignDetail.editSettingsDescription")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Campaign Name */}
            <div className="space-y-2">
              <Label htmlFor="campaign-name">{t("campaignNew.name")}</Label>
              <Input
                id="campaign-name"
                placeholder={t("campaignNew.namePlaceholder")}
                value={campaignName}
                onChange={(e) => setCampaignName(e.target.value)}
                maxLength={255}
                required
              />
            </div>

            <Separator />

            <CampaignAdvancedSettings
              maxConcurrency={maxConcurrency}
              onMaxConcurrencyChange={setMaxConcurrency}
              effectiveLimit={effectiveLimit}
              orgConcurrentLimit={orgConcurrentLimit}
              fromNumbersCount={fromNumbersCount}
              retryEnabled={retryEnabled}
              onRetryEnabledChange={setRetryEnabled}
              maxRetries={maxRetries}
              onMaxRetriesChange={setMaxRetries}
              retryDelaySeconds={retryDelaySeconds}
              onRetryDelaySecondsChange={setRetryDelaySeconds}
              retryOnBusy={retryOnBusy}
              onRetryOnBusyChange={setRetryOnBusy}
              retryOnNoAnswer={retryOnNoAnswer}
              onRetryOnNoAnswerChange={setRetryOnNoAnswer}
              retryOnVoicemail={retryOnVoicemail}
              onRetryOnVoicemailChange={setRetryOnVoicemail}
              scheduleEnabled={scheduleEnabled}
              onScheduleEnabledChange={setScheduleEnabled}
              scheduleTimezone={scheduleTimezone}
              onScheduleTimezoneChange={setScheduleTimezone}
              timeSlots={timeSlots}
              onTimeSlotsChange={setTimeSlots}
              circuitBreakerEnabled={circuitBreakerEnabled}
              onCircuitBreakerEnabledChange={setCircuitBreakerEnabled}
              circuitBreakerFailureThreshold={circuitBreakerFailureThreshold}
              onCircuitBreakerFailureThresholdChange={
                setCircuitBreakerFailureThreshold
              }
              circuitBreakerWindowSeconds={circuitBreakerWindowSeconds}
              onCircuitBreakerWindowSecondsChange={
                setCircuitBreakerWindowSeconds
              }
              circuitBreakerMinCalls={circuitBreakerMinCalls}
              onCircuitBreakerMinCallsChange={setCircuitBreakerMinCalls}
            />

            {submitError && (
              <div className="rounded-md bg-destructive/15 p-3 text-sm text-destructive">
                {submitError}
              </div>
            )}

            <div className="flex gap-4 pt-4">
              <Button
                type="submit"
                disabled={isSubmitting || !campaignName.trim()}
              >
                {isSubmitting
                  ? t("common.saving")
                  : t("campaignDetail.saveChanges")}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={handleBack}
                disabled={isSubmitting}
              >
                Cancel
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
