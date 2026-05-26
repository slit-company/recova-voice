import type { DailyUsageBreakdownResponse } from '@/client/types.gen';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
    Table,
    TableBody,
    TableCell,
    TableFooter,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import { useLocale } from '@/context/LocaleContext';

interface DailyUsageTableProps {
    data: DailyUsageBreakdownResponse | null;
    isLoading: boolean;
}

export function DailyUsageTable({ data, isLoading }: DailyUsageTableProps) {
    const { t, formatCurrency, formatDate, formatNumber } = useLocale();

    if (isLoading) {
        return (
            <Card>
                <CardHeader>
                    <CardTitle>{t('dailyUsage.title')}</CardTitle>
                    <CardDescription>{t('dailyUsage.description')}</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="animate-pulse space-y-3">
                        {[...Array(7)].map((_, i) => (
                            <div key={i} className="h-12 bg-gray-200 rounded"></div>
                        ))}
                    </div>
                </CardContent>
            </Card>
        );
    }

    if (!data || !data.breakdown || data.breakdown.length === 0) {
        return (
            <Card>
                <CardHeader>
                    <CardTitle>{t('dailyUsage.title')}</CardTitle>
                    <CardDescription>{t('dailyUsage.description')}</CardDescription>
                </CardHeader>
                <CardContent>
                    <p className="text-center py-8 text-gray-500">{t('dailyUsage.noData')}</p>
                </CardContent>
            </Card>
        );
    }

    return (
        <Card>
            <CardHeader>
                <CardTitle>{t('dailyUsage.title')}</CardTitle>
                <CardDescription>{t('dailyUsage.description')}</CardDescription>
            </CardHeader>
            <CardContent>
                <div className="bg-white border rounded-lg overflow-hidden shadow-sm">
                    <Table>
                        <TableHeader>
                            <TableRow className="bg-gray-50">
                                <TableHead className="font-semibold">{t('common.date')}</TableHead>
                                <TableHead className="font-semibold text-right">{t('dailyUsage.usageMinutes')}</TableHead>
                                <TableHead className="font-semibold text-right">{t('dailyUsage.costUsd')}</TableHead>
                                <TableHead className="font-semibold text-right">{t('dailyUsage.calls')}</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {data.breakdown.map((day) => (
                                <TableRow key={day.date}>
                                    <TableCell className="font-medium">
                                        {formatDate(day.date, {
                                            month: 'short',
                                            day: 'numeric',
                                            year: 'numeric',
                                        })}
                                    </TableCell>
                                    <TableCell className="text-right">
                                        {formatNumber(day.minutes, { minimumFractionDigits: 1, maximumFractionDigits: 1 })}
                                    </TableCell>
                                    <TableCell className="text-right font-medium">
                                        {formatCurrency(day.cost_usd || 0)}
                                    </TableCell>
                                    <TableCell className="text-right">
                                        {formatNumber(day.call_count)}
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                        <TableFooter>
                            <TableRow className="bg-gray-50 font-semibold">
                                <TableCell>{t('common.total')}</TableCell>
                                <TableCell className="text-right">
                                    {formatNumber(data.total_minutes, { minimumFractionDigits: 1, maximumFractionDigits: 1 })}
                                </TableCell>
                                <TableCell className="text-right">
                                    {formatCurrency(data.total_cost_usd || 0)}
                                </TableCell>
                                <TableCell className="text-right">
                                    {formatNumber(data.breakdown.reduce((sum, day) => sum + day.call_count, 0))}
                                </TableCell>
                            </TableRow>
                        </TableFooter>
                    </Table>
                </div>
            </CardContent>
        </Card>
    );
}
