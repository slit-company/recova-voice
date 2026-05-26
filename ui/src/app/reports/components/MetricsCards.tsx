import { Phone, PhoneForwarded } from 'lucide-react';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useLocale } from '@/context/LocaleContext';

interface MetricsCardsProps {
  metrics: {
    total_runs: number;
    xfer_count: number;
  };
}

export function MetricsCards({ metrics }: MetricsCardsProps) {
  const { t, formatNumber } = useLocale();

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">{t('reports.metrics.totalRuns')}</CardTitle>
          <Phone className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{formatNumber(metrics.total_runs)}</div>
          <p className="text-xs text-muted-foreground">
            {t('reports.metrics.totalRunsDescription')}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">{t('reports.metrics.transferDispositions')}</CardTitle>
          <PhoneForwarded className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{formatNumber(metrics.xfer_count)}</div>
          <p className="text-xs text-muted-foreground">
            {t('reports.metrics.transferDispositionsDescription')}
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
