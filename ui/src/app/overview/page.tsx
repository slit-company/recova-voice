"use client";

import Link from 'next/link';

import { GitHubStarBadge } from '@/components/layout/GitHubStarBadge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useLocale } from '@/context/LocaleContext';
import { useAuth } from '@/lib/auth';

export default function OverviewPage() {
    const { user, provider } = useAuth();
    const { t } = useLocale();
    const isOSSMode = provider !== 'stack';
    const firstName = user?.displayName ? user.displayName.split(' ')[0] : '';

    return (
        <div className="container mx-auto px-4 py-8">
            <div className="max-w-4xl mx-auto">
                <Card className="mb-8">
                    <CardHeader>
                        <CardTitle className="text-3xl">
                            {isOSSMode
                                ? t('overview.welcomeOss')
                                : t('overview.welcomeUser', { suffix: firstName ? `, ${firstName}` : '' })}
                        </CardTitle>
                        <CardDescription className="text-lg mt-2">
                            {isOSSMode ? t('overview.ossDescription') : t('overview.cloudDescription')}
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        {isOSSMode && (
                            <div className="mb-6">
                                <GitHubStarBadge label={t('overview.starOnGitHub')} showCount source="overview_page" />
                            </div>
                        )}
                    </CardContent>
                </Card>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <Card>
                        <CardHeader>
                            <CardTitle>{t('overview.agentsTitle')}</CardTitle>
                            <CardDescription>
                                {t('overview.agentsDescription')}
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            <Button asChild>
                                <Link href="/workflow">
                                    {t('overview.goToAgents')}
                                </Link>
                            </Button>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader>
                            <CardTitle>{t('overview.servicesTitle')}</CardTitle>
                            <CardDescription>
                                {t('overview.servicesDescription')}
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            <Button asChild variant="outline">
                                <Link href="/model-configurations">
                                    {t('overview.configureModels')}
                                </Link>
                            </Button>
                        </CardContent>
                    </Card>
                </div>

                <Card className="mt-8">
                    <CardHeader>
                        <CardTitle>{t('overview.resourcesTitle')}</CardTitle>
                        <CardDescription>
                            {t('overview.resourcesDescription')}
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="flex flex-wrap gap-4">
                            <Button asChild variant="outline">
                                <a
                                    href="https://docs.dograh.com"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    {t('overview.documentation')}
                                </a>
                            </Button>
                            <Button asChild variant="outline">
                                <a
                                    href="https://github.com/dograh-hq/dograh/issues"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    {t('overview.reportIssue')}
                                </a>
                            </Button>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}
