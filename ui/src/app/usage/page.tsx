"use client";

import { ChevronLeft, ChevronRight, Download, Globe } from 'lucide-react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useCallback, useEffect, useId, useState } from 'react';
import TimezoneSelect, { type ITimezoneOption } from 'react-timezone-select';
import { toast } from 'sonner';

import { downloadUsageRunsReportApiV1OrganizationsUsageRunsReportGet, getDailyUsageBreakdownApiV1OrganizationsUsageDailyBreakdownGet, getMpsCreditsApiV1OrganizationsUsageMpsCreditsGet, getUsageHistoryApiV1OrganizationsUsageRunsGet } from '@/client/sdk.gen';
import type { DailyUsageBreakdownResponse, MpsCreditsResponse, UsageHistoryResponse, WorkflowRunUsageResponse } from '@/client/types.gen';
import { CallTypeCell } from '@/components/CallTypeCell';
import { DailyUsageTable } from '@/components/DailyUsageTable';
import { FilterBuilder } from '@/components/filters/FilterBuilder';
import { MediaPreviewButton, MediaPreviewDialog } from '@/components/MediaPreviewDialog';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import { useLocale } from '@/context/LocaleContext';
import { useUserConfig } from '@/context/UserConfigContext';
import { useAuth } from '@/lib/auth';
import { usageFilterAttributes } from '@/lib/filterAttributes';
import { decodeFiltersFromURL, encodeFiltersToURL } from '@/lib/filters';
import { ActiveFilter, DateRangeValue } from '@/types/filters';

// Get local timezone
const getLocalTimezone = () => Intl.DateTimeFormat().resolvedOptions().timeZone;

export default function UsagePage() {
    const router = useRouter();
    const searchParams = useSearchParams();
    const { userConfig, saveUserConfig, loading: userConfigLoading, organizationPricing } = useUserConfig();
    const { t, formatCurrency, formatDateTime, formatNumber } = useLocale();
    const auth = useAuth();

    // MPS credits state
    const [mpsCredits, setMpsCredits] = useState<MpsCreditsResponse | null>(null);
    const [isLoadingCredits, setIsLoadingCredits] = useState(true);

    // Usage history state
    const [usageHistory, setUsageHistory] = useState<UsageHistoryResponse | null>(null);
    const [isLoadingHistory, setIsLoadingHistory] = useState(false);
    const [currentPage, setCurrentPage] = useState(() => {
        const pageParam = searchParams.get('page');
        return pageParam ? parseInt(pageParam, 10) : 1;
    });
    const [isExecutingFilters, setIsExecutingFilters] = useState(false);
    const [isDownloadingReport, setIsDownloadingReport] = useState(false);

    // Daily usage breakdown state (only for paid orgs)
    const [dailyUsage, setDailyUsage] = useState<DailyUsageBreakdownResponse | null>(null);
    const [isLoadingDaily, setIsLoadingDaily] = useState(false);

    // Initialize filters from URL. `activeFilters` tracks the in-progress
    // edits in the FilterBuilder; `appliedFilters` is what's actually been
    // committed via Apply (and what drives fetching + the download button).
    const [activeFilters, setActiveFilters] = useState<ActiveFilter[]>(() => {
        return decodeFiltersFromURL(searchParams, usageFilterAttributes);
    });
    const [appliedFilters, setAppliedFilters] = useState<ActiveFilter[]>(() => {
        return decodeFiltersFromURL(searchParams, usageFilterAttributes);
    });

    // Media preview dialog
    const mediaPreview = MediaPreviewDialog();

    // Timezone state - initialize with empty string to avoid hydration mismatch
    const localTimezone = getLocalTimezone();
    const [selectedTimezone, setSelectedTimezone] = useState<ITimezoneOption | string>('');
    const [savingTimezone, setSavingTimezone] = useState(false);
    const timezoneSelectId = useId(); // Stable ID for react-select to prevent hydration mismatch

    // Fetch MPS credits
    const fetchMpsCredits = useCallback(async () => {
        if (!auth.isAuthenticated) return;
        try {
            const response = await getMpsCreditsApiV1OrganizationsUsageMpsCreditsGet();
            if (response.data) {
                setMpsCredits(response.data);
            }
        } catch (error) {
            console.error('Failed to fetch MPS credits:', error);
        } finally {
            setIsLoadingCredits(false);
        }
    }, [auth.isAuthenticated]);

    // Translate the FilterBuilder state into the query-param shape the
    // backend expects. Shared between the listing fetch and the CSV export
    // so they stay in lockstep.
    const buildUsageQueryParams = (filters?: ActiveFilter[]) => {
        let filterParam: string | undefined;
        let startDate = '';
        let endDate = '';

        if (filters && filters.length > 0) {
            const dateRangeFilter = filters.find(f => f.attribute.id === 'dateRange');
            if (dateRangeFilter && dateRangeFilter.value) {
                const dateValue = dateRangeFilter.value as DateRangeValue;
                if (dateValue.from) startDate = dateValue.from.toISOString();
                if (dateValue.to) endDate = dateValue.to.toISOString();
            }

            const otherFilters = filters.filter(f => f.attribute.id !== 'dateRange');
            if (otherFilters.length > 0) {
                const filterData = otherFilters.map(filter => ({
                    attribute: filter.attribute.id,
                    type: filter.attribute.type,
                    value: filter.value,
                }));
                filterParam = JSON.stringify(filterData);
            }
        }

        return {
            ...(startDate && { start_date: startDate }),
            ...(endDate && { end_date: endDate }),
            ...(filterParam && { filters: filterParam }),
        };
    };

    // Fetch usage history
    const fetchUsageHistory = useCallback(async (page: number, filters?: ActiveFilter[]) => {
        if (!auth.isAuthenticated) return;
        setIsLoadingHistory(true);
        try {
            const response = await getUsageHistoryApiV1OrganizationsUsageRunsGet({
                query: {
                    page,
                    limit: 50,
                    ...buildUsageQueryParams(filters),
                },
            });

            if (response.data) {
                setUsageHistory(response.data);
            }
        } catch (error) {
            console.error('Failed to fetch usage history:', error);
        } finally {
            setIsLoadingHistory(false);
        }
    }, [auth.isAuthenticated]);

    // Fetch daily usage breakdown
    const fetchDailyUsage = useCallback(async () => {
        if (!auth.isAuthenticated || !organizationPricing?.price_per_second_usd) return;

        setIsLoadingDaily(true);
        try {
            const response = await getDailyUsageBreakdownApiV1OrganizationsUsageDailyBreakdownGet({
                query: { days: 7 },
            });

            if (response.data) {
                setDailyUsage(response.data);
            }
        } catch (error) {
            console.error('Failed to fetch daily usage:', error);
        } finally {
            setIsLoadingDaily(false);
        }
    }, [auth.isAuthenticated, organizationPricing]);

    // Download a CSV of all runs matching the current filters.
    const handleDownloadReport = async () => {
        if (!auth.isAuthenticated) return;
        setIsDownloadingReport(true);
        try {
            const response = await downloadUsageRunsReportApiV1OrganizationsUsageRunsReportGet({
                query: buildUsageQueryParams(appliedFilters),
                parseAs: 'blob',
            });

            if (response.data) {
                const blob = response.data as Blob;
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'usage_runs_report.csv';
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
            } else {
                toast.error(t('usage.downloadFailed'))
            }
        } catch (error) {
            console.error('Failed to download usage report:', error);
            toast.error(t('usage.downloadFailed'))
        } finally {
            setIsDownloadingReport(false);
        }
    };

    // Handle timezone change
    const handleTimezoneChange = async (timezone: ITimezoneOption | string) => {
        setSelectedTimezone(timezone);
        setSavingTimezone(true);
        try {
            const tzValue = typeof timezone === 'string' ? timezone : timezone.value;
            await saveUserConfig({ timezone: tzValue });
        } catch (error) {
            console.error('Failed to save timezone:', error);
            // Revert to previous timezone on error
            const prevTz = userConfig?.timezone || localTimezone;
            setSelectedTimezone(prevTz);
        } finally {
            setSavingTimezone(false);
        }
    };

    // Update timezone when userConfig loads
    useEffect(() => {
        if (!userConfigLoading) {
            // Config has loaded - set the timezone
            if (userConfig?.timezone) {
                setSelectedTimezone(userConfig.timezone);
            } else {
                // No saved timezone, use local
                setSelectedTimezone(localTimezone);
            }
        }
    }, [userConfig, userConfigLoading, localTimezone]);

    // Initial load - fetch when auth becomes available
    useEffect(() => {
        if (auth.isAuthenticated) {
            fetchMpsCredits();
            fetchUsageHistory(currentPage, appliedFilters);
        }
    }, [auth.isAuthenticated, currentPage, appliedFilters, fetchUsageHistory, fetchMpsCredits]);

    // Fetch daily usage when organizationPricing becomes available
    useEffect(() => {
        if (auth.isAuthenticated && organizationPricing?.price_per_second_usd) {
            fetchDailyUsage();
        }
    }, [auth.isAuthenticated, organizationPricing, fetchDailyUsage]);

    // Update URL with query parameters
    const updateUrlParams = useCallback((params: { page?: number; filters?: ActiveFilter[] }) => {
        const newParams = new URLSearchParams();

        if (params.page !== undefined) {
            newParams.set('page', params.page.toString());
        }

        // Add filters to URL if present
        if (params.filters && params.filters.length > 0) {
            const filterString = encodeFiltersToURL(params.filters);
            if (filterString) {
                const filterParams = new URLSearchParams(filterString);
                filterParams.forEach((value, key) => newParams.set(key, value));
            }
        }

        router.push(`/usage?${newParams.toString()}`);
    }, [router]);

    const handleApplyFilters = useCallback(async () => {
        setIsExecutingFilters(true);
        setCurrentPage(1); // Reset to first page when applying filters
        setAppliedFilters(activeFilters);
        updateUrlParams({ page: 1, filters: activeFilters });
        await fetchUsageHistory(1, activeFilters);
        setIsExecutingFilters(false);
    }, [activeFilters, fetchUsageHistory, updateUrlParams]);

    const handleFiltersChange = useCallback((filters: ActiveFilter[]) => {
        setActiveFilters(filters);
    }, []);

    const handleClearFilters = useCallback(async () => {
        setIsExecutingFilters(true);
        setCurrentPage(1);
        setActiveFilters([]);
        setAppliedFilters([]);
        updateUrlParams({ page: 1, filters: [] }); // Clear filters from URL
        await fetchUsageHistory(1, []); // Fetch all runs without filters
        setIsExecutingFilters(false);
    }, [fetchUsageHistory, updateUrlParams]);

    // Handle page change
    const handlePageChange = (newPage: number) => {
        setCurrentPage(newPage);
        updateUrlParams({ page: newPage, filters: appliedFilters });
        fetchUsageHistory(newPage, appliedFilters);
    };

    // Handle row click to navigate to workflow run
    const handleRowClick = (run: WorkflowRunUsageResponse) => {
        router.push(`/workflow/${run.workflow_id}/run/${run.id}`);
    };

    const formatRunDateTime = (dateString: string) => {
        const tzValue = typeof selectedTimezone === 'string' ? selectedTimezone : selectedTimezone.value;
        const effectiveTz = tzValue || localTimezone;
        return formatDateTime(dateString, {
            timeZone: effectiveTz,
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        });
    };

    const formatDuration = (seconds: number) => {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        if (minutes === 0) return `${formatNumber(remainingSeconds)}s`;
        if (remainingSeconds === 0) return `${formatNumber(minutes)}m`;
        return `${formatNumber(minutes)}m ${formatNumber(remainingSeconds)}s`;
    };

    return (
        <div className="container mx-auto p-6 space-y-6">
            <div>
                <div className="flex justify-between items-start">
                    <div>
                        <h1 className="text-3xl font-bold mb-2">{t('usage.title')}</h1>
                        <p className="text-muted-foreground">{t('usage.description')}</p>
                    </div>
                        <div className="flex items-center gap-2">
                            <Globe className="h-4 w-4 text-muted-foreground" />
                            <div className="w-[300px]">
                                <TimezoneSelect
                                    instanceId={timezoneSelectId}
                                    value={selectedTimezone}
                                    onChange={handleTimezoneChange}
                                    isDisabled={savingTimezone || userConfigLoading}
                                    placeholder={userConfigLoading ? t('common.loading') : t('usage.timezonePlaceholder')}
                                    styles={{
                                        control: (base, state) => ({
                                            ...base,
                                            minHeight: '36px',
                                            fontSize: '14px',
                                            backgroundColor: 'var(--background)',
                                            borderColor: state.isFocused ? 'var(--ring)' : 'var(--border)',
                                            boxShadow: state.isFocused ? '0 0 0 2px color-mix(in srgb, var(--ring) 20%, transparent)' : 'none',
                                            '&:hover': {
                                                borderColor: 'var(--border)',
                                            },
                                        }),
                                        menu: (base) => ({
                                            ...base,
                                            zIndex: 9999,
                                            backgroundColor: 'var(--popover)',
                                            border: '1px solid var(--border)',
                                            boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1)',
                                        }),
                                        menuList: (base) => ({
                                            ...base,
                                            backgroundColor: 'var(--popover)',
                                            padding: 0,
                                        }),
                                        option: (base, state) => ({
                                            ...base,
                                            backgroundColor: state.isSelected
                                                ? 'var(--accent)'
                                                : state.isFocused
                                                ? 'var(--accent)'
                                                : 'var(--popover)',
                                            color: 'var(--foreground)',
                                            cursor: 'pointer',
                                            '&:active': {
                                                backgroundColor: 'var(--accent)',
                                            },
                                        }),
                                        singleValue: (base) => ({
                                            ...base,
                                            color: 'var(--foreground)',
                                        }),
                                        input: (base) => ({
                                            ...base,
                                            color: 'var(--foreground)',
                                        }),
                                        placeholder: (base) => ({
                                            ...base,
                                            color: 'var(--muted-foreground)',
                                        }),
                                        indicatorSeparator: (base) => ({
                                            ...base,
                                            backgroundColor: 'var(--border)',
                                        }),
                                        dropdownIndicator: (base) => ({
                                            ...base,
                                            color: 'var(--muted-foreground)',
                                            '&:hover': {
                                                color: 'var(--foreground)',
                                            },
                                        }),
                                    }}
                                />
                            </div>
                        </div>
                    </div>
                </div>

                {/* MPS Credits Card */}
                <Card className="mb-6">
                    <CardHeader>
                        <CardTitle>{t('usage.creditsTitle')}</CardTitle>
                        <CardDescription>
                            {t('usage.creditsDescription')}
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        {isLoadingCredits ? (
                            <div className="animate-pulse space-y-4">
                                <div className="h-4 bg-muted rounded w-1/4"></div>
                                <div className="h-8 bg-muted rounded"></div>
                                <div className="h-4 bg-muted rounded w-1/3"></div>
                            </div>
                        ) : mpsCredits ? (
                            <div className="space-y-4">
                                <div className="flex justify-between items-baseline">
                                    <div>
                                        <p className="text-2xl font-bold">
                                            {formatNumber(mpsCredits.total_credits_used, { minimumFractionDigits: 2, maximumFractionDigits: 2 })} <span className="text-lg font-normal text-muted-foreground">/ {formatNumber(mpsCredits.total_quota, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</span>
                                        </p>
                                        <p className="text-sm text-muted-foreground">{t('usage.creditsUsed')}</p>
                                    </div>
                                    <div className="text-right">
                                        <p className="text-lg font-semibold">{formatNumber(mpsCredits.remaining_credits, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</p>
                                        <p className="text-sm text-muted-foreground">{t('usage.remaining')}</p>
                                    </div>
                                </div>

                                {mpsCredits.total_quota > 0 && (
                                    <Progress value={(mpsCredits.total_credits_used / mpsCredits.total_quota) * 100} className="h-3" />
                                )}
                            </div>
                        ) : (
                            <p className="text-muted-foreground">{t('usage.noServiceKeys')}</p>
                        )}
                    </CardContent>
                </Card>

                {/* Daily Usage Table - Only for paid organizations */}
                {organizationPricing?.price_per_second_usd && (
                    <div className="mb-6">
                        <DailyUsageTable
                            data={dailyUsage}
                            isLoading={isLoadingDaily}
                        />
                    </div>
                )}

                {/* Filter Builder */}
                <div className="mb-6 space-y-3">
                    <FilterBuilder
                        availableAttributes={usageFilterAttributes}
                        activeFilters={activeFilters}
                        onFiltersChange={handleFiltersChange}
                        onApplyFilters={handleApplyFilters}
                        onClearFilters={handleClearFilters}
                        isExecuting={isExecutingFilters}
                    />
                    {appliedFilters.length > 0 && (
                        <div className="flex justify-end">
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={handleDownloadReport}
                                disabled={isDownloadingReport}
                            >
                                <Download className="h-4 w-4 mr-2" />
                                {isDownloadingReport ? t('usage.preparing') : t('usage.downloadFilteredResults')}
                            </Button>
                        </div>
                    )}
                </div>

                {/* Usage History */}
                <Card>
                    <CardHeader>
                        <div className="flex justify-between items-start">
                            <div className="space-y-1.5">
                                <CardTitle>{t('usage.allRunsTitle')}</CardTitle>
                                <CardDescription>
                                    {t('usage.allRunsDescription')}
                                </CardDescription>
                            </div>
                        </div>
                    </CardHeader>
                    <CardContent>
                        {isLoadingHistory ? (
                            <div className="animate-pulse space-y-3">
                                {[...Array(5)].map((_, i) => (
                                    <div key={i} className="h-12 bg-muted rounded"></div>
                                ))}
                            </div>
                        ) : usageHistory && usageHistory.runs.length > 0 ? (
                            <>
                                <div className="bg-card border rounded-lg overflow-hidden shadow-sm">
                                    <Table>
                                        <TableHeader>
                                            <TableRow className="bg-muted/50">
                                                <TableHead className="font-semibold">{t('usage.runId')}</TableHead>
                                                <TableHead className="font-semibold">{t('usage.agentName')}</TableHead>
                                                <TableHead className="font-semibold">{t('usage.callType')}</TableHead>
                                                <TableHead className="font-semibold">{t('usage.phoneNumber')}</TableHead>
                                                <TableHead className="font-semibold">{t('usage.disposition')}</TableHead>
                                                <TableHead className="font-semibold">{t('common.date')}</TableHead>
                                                <TableHead className="font-semibold text-right">{t('common.duration')}</TableHead>
                                                <TableHead className="font-semibold text-right">
                                                    {organizationPricing?.price_per_second_usd ? t('usage.costUsd') : t('usage.tokens')}
                                                </TableHead>
                                                <TableHead className="font-semibold">{t('common.actions')}</TableHead>
                                            </TableRow>
                                        </TableHeader>
                                        <TableBody>
                                            {usageHistory.runs.map((run) => (
                                                <TableRow
                                                    key={run.id}
                                                >
                                                    <TableCell
                                                        className="font-mono text-sm cursor-pointer hover:underline"
                                                        onClick={() => handleRowClick(run)}
                                                    >
                                                        #{run.id}
                                                    </TableCell>
                                                    <TableCell>{run.workflow_name || t('common.unknown')}</TableCell>
                                                    <TableCell>
                                                        <CallTypeCell mode={run.mode} callType={run.call_type} />
                                                    </TableCell>
                                                    <TableCell className="text-sm">
                                                        {(run.call_type === 'inbound'
                                                            ? run.caller_number
                                                            : run.called_number) || '-'}
                                                    </TableCell>
                                                    <TableCell>
                                                        {run.disposition ? (
                                                            <Badge variant="default">
                                                                {run.disposition}
                                                            </Badge>
                                                        ) : (
                                                            <span className="text-sm text-muted-foreground">-</span>
                                                        )}
                                                    </TableCell>
                                                    <TableCell>{formatRunDateTime(run.created_at)}</TableCell>
                                                    <TableCell className="text-right">
                                                        {formatDuration(run.call_duration_seconds)}
                                                    </TableCell>
                                                    <TableCell className="text-right font-medium">
                                                        {organizationPricing?.price_per_second_usd && run.charge_usd !== undefined && run.charge_usd !== null
                                                            ? formatCurrency(run.charge_usd)
                                                            : formatNumber(run.dograh_token_usage)
                                                        }
                                                    </TableCell>
                                                    <TableCell>
                                                        <MediaPreviewButton
                                                            recordingUrl={run.recording_url}
                                                            transcriptUrl={run.transcript_url}
                                                            runId={run.id}
                                                            onOpenPreview={mediaPreview.openPreview}
                                                        />
                                                    </TableCell>
                                                </TableRow>
                                            ))}
                                        </TableBody>
                                    </Table>
                                </div>

                                {/* Summary */}
                                {appliedFilters.length > 0 && (
                                    <div className="mt-4 p-3 bg-muted rounded-md">
                                        <p className="text-sm text-muted-foreground">
                                            {t('usage.totalFilteredPeriod')} <span className="font-semibold text-foreground">
                                                {formatNumber(usageHistory.total_dograh_tokens)} {t('usage.dograhTokens')}
                                            </span>
                                            {' • '}
                                            <span className="font-semibold text-foreground">
                                                {formatDuration(usageHistory.total_duration_seconds)}
                                            </span>
                                        </p>
                                    </div>
                                )}

                                {/* Pagination */}
                                {usageHistory.total_pages > 1 && (
                                    <div className="flex items-center justify-between mt-6">
                                        <p className="text-sm text-muted-foreground">
                                            {t('usage.pageSummary', { page: usageHistory.page, totalPages: usageHistory.total_pages, totalCount: formatNumber(usageHistory.total_count) })}
                                        </p>
                                        <div className="flex gap-2">
                                            <Button
                                                variant="outline"
                                                size="sm"
                                                onClick={() => handlePageChange(currentPage - 1)}
                                                disabled={currentPage === 1}
                                            >
                                                <ChevronLeft className="h-4 w-4" />
                                                {t('common.previous')}
                                            </Button>
                                            <Button
                                                variant="outline"
                                                size="sm"
                                                onClick={() => handlePageChange(currentPage + 1)}
                                                disabled={currentPage === usageHistory.total_pages}
                                            >
                                                {t('common.next')}
                                                <ChevronRight className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    </div>
                                )}
                            </>
                        ) : (
                            <p className="text-center py-8 text-muted-foreground">{t('usage.noRuns')}</p>
                        )}
                    </CardContent>
                </Card>

                {/* Media Preview Dialog */}
                {mediaPreview.dialog}
        </div>
    );
}
