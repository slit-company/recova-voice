'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';

import { createWorkflowFromTemplateApiV1WorkflowCreateTemplatePost } from '@/client/sdk.gen';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { useLocale } from '@/context/LocaleContext';
import { useAuth } from '@/lib/auth';
import logger from '@/lib/logger';

export default function CreateWorkflowPage() {
    const router = useRouter();
    const { t } = useLocale();
    const { user, getAccessToken } = useAuth();
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [showSuccessModal, setShowSuccessModal] = useState(false);
    const [workflowId, setWorkflowId] = useState<string | null>(null);

    const [callType, setCallType] = useState<'inbound' | 'outbound'>('inbound');
    const [useCase, setUseCase] = useState('');
    const [activityDescription, setActivityDescription] = useState('');

    const handleCreateWorkflow = async () => {
        if (!useCase || !activityDescription) {
            setError(t('workflowCreate.fillAllFields'));
            return;
        }

        if (!user) {
            setError(t('workflowCreate.loginRequired'));
            return;
        }

        setIsLoading(true);
        setError(null);

        try {
            const accessToken = await getAccessToken();

            // Call the API to create workflow from template
            const response = await createWorkflowFromTemplateApiV1WorkflowCreateTemplatePost({
                body: {
                    call_type: callType,
                    use_case: useCase,
                    activity_description: activityDescription,
                },
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                },
            });

            if (response.data?.id) {
                setWorkflowId(String(response.data.id));
                setShowSuccessModal(true);
            }
        } catch (err) {
            setError(t('workflowCreate.createFailed'));
            logger.error(`Error creating workflow: ${err}`);
        } finally {
            setIsLoading(false);
        }
    };

    const handleModalContinue = () => {
        if (!workflowId) return;
        router.push(`/workflow/${workflowId}?onboarding=web_call`);
    };

    return (
        <div className="min-h-screen bg-background">
            <div className="container mx-auto px-4 py-8 max-w-2xl">
                <div className="mb-6">
                    <h1 className="text-3xl font-bold mb-2">{t('workflowCreate.title')}</h1>
                    <p className="text-muted-foreground">
                        {t('workflowCreate.description')}
                    </p>
                </div>

                <Card>
                    <CardHeader>
                        <CardTitle>{t('workflowCreate.detailsTitle')}</CardTitle>
                        <CardDescription>
                            {t('workflowCreate.detailsDescription')}
                        </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-6">
                        <div className="space-y-2">
                            <Label htmlFor="call-type">{t('workflowCreate.callType')}</Label>
                            <Select value={callType} onValueChange={(value) => setCallType(value as 'inbound' | 'outbound')}>
                                <SelectTrigger id="call-type">
                                    <SelectValue placeholder={t('workflowCreate.selectType')} />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="inbound">
                                        {t('workflowCreate.inbound')}
                                    </SelectItem>
                                    <SelectItem value="outbound">
                                        {t('workflowCreate.outbound')}
                                    </SelectItem>
                                </SelectContent>
                            </Select>
                            <p className="text-sm text-muted-foreground">
                                {t('workflowCreate.callTypeHelp')}
                            </p>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="use-case">{t('workflowCreate.useCase')}</Label>
                            <Input
                                id="use-case"
                                placeholder={t('workflowCreate.useCasePlaceholder')}
                                value={useCase}
                                onChange={(e) => setUseCase(e.target.value)}
                            />
                            <p className="text-sm text-muted-foreground">
                                {t('workflowCreate.useCaseHelp')}
                            </p>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="activity-description">{t('workflowCreate.activityDescription')}</Label>
                            <Textarea
                                id="activity-description"
                                placeholder={t('workflowCreate.activityPlaceholder')}
                                value={activityDescription}
                                onChange={(e) => setActivityDescription(e.target.value)}
                                className="min-h-[100px]"
                            />
                            <p className="text-sm text-muted-foreground">
                                {t('workflowCreate.activityHelp')}
                            </p>
                        </div>

                        {error && (
                            <p className="text-sm text-red-500">{error}</p>
                        )}

                        <div className="pt-4">
                            <Button
                                onClick={handleCreateWorkflow}
                                disabled={isLoading || !useCase || !activityDescription}
                                className="w-full"
                            >
                                {isLoading ? t('workflowCreate.creating') : t('workflowCreate.createAgent')}
                            </Button>
                        </div>
                    </CardContent>
                </Card>
            </div>

            {/* Loading Overlay */}
            {isLoading && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
                    <Card className="w-full max-w-md p-8">
                        <div className="flex flex-col items-center space-y-6">
                            {/* Animated spinner */}
                            <div className="relative">
                                <div className="w-16 h-16 border-4 border-muted rounded-full"></div>
                                <div className="absolute top-0 left-0 w-16 h-16 border-4 border-transparent border-t-primary rounded-full animate-spin"></div>
                            </div>

                            <div className="text-center space-y-2">
                                <h3 className="text-lg font-semibold">
                                    {t('workflowCreate.loadingTitle')}
                                </h3>
                                <p className="text-sm text-muted-foreground max-w-xs">
                                    {t('workflowCreate.loadingDescription')}
                                </p>
                            </div>
                        </div>
                    </Card>
                </div>
            )}

            {/* Success Modal */}
            <Dialog open={showSuccessModal} onOpenChange={setShowSuccessModal}>
                <DialogContent className="sm:max-w-lg">
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2">
                            <svg className="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            {t('workflowCreate.successTitle')}
                        </DialogTitle>
                        <DialogDescription asChild>
                            <div className="mt-4 space-y-3">
                                <p>
                                    {t('workflowCreate.successBody1')}
                                </p>
                                <p>
                                    {t('workflowCreate.successBody2')}
                                </p>
                                <p>
                                    {t('workflowCreate.successBody3')}
                                </p>
                            </div>
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter className="mt-6">
                        <Button
                            onClick={handleModalContinue}
                            className="w-full"
                        >
                            {t('workflowCreate.openAndTest')}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}
