'use client';

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useLocale } from '@/context/LocaleContext';

interface DurationData {
  bucket: string;
  range_start: number;
  range_end: number | null;
  count: number;
  percentage: number;
}

interface DurationChartProps {
  data: DurationData[];
}

const COLORS = {
  '0-10': '#dcfce7',
  '10-30': '#bbf7d0',
  '30-60': '#86efac',
  '60-120': '#4ade80',
  '120-180': '#22c55e',
  '>180': '#16a34a',
};

export function DurationChart({ data }: DurationChartProps) {
  const { t, formatNumber } = useLocale();
  const chartData = data.map((item) => ({
    ...item,
    label: `${item.bucket}s`,
    fill: COLORS[item.bucket as keyof typeof COLORS] || '#6b7280',
  }));

  const CustomTooltip = ({ active, payload }: { active?: boolean; payload?: Array<{ payload: DurationData & { label: string; fill: string } }> }) => {
    if (active && payload && payload[0]) {
      const tooltipData = payload[0].payload;
      return (
        <div className="bg-background border rounded-lg shadow-lg p-3">
          <p className="font-semibold">{tooltipData.label}</p>
          <p className="text-sm">{t('reports.calls', { count: formatNumber(tooltipData.count) })}</p>
          <p className="text-sm">{t('reports.percentOfTotal', { percentage: tooltipData.percentage })}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('reports.durationDistribution')}</CardTitle>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <div className="h-[300px] flex items-center justify-center text-muted-foreground">
            {t('reports.noDurationData')}
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={300}>
            <BarChart
              data={chartData}
              margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" opacity={0.1} />
              <XAxis dataKey="label" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
