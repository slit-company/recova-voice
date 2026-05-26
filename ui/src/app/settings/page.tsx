"use client";

import { ExternalLink } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { MCPSection } from "@/components/MCPSection";
import { TelemetrySection } from "@/components/TelemetrySection";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useLocale } from "@/context/LocaleContext";
import { useUserConfig } from "@/context/UserConfigContext";
import { UI_LANGUAGE_LABELS, type UiLanguage } from "@/lib/i18n";

export default function SettingsPage() {
  const { t, language } = useLocale();
  const { saveUserConfig } = useUserConfig();
  const [savingLanguage, setSavingLanguage] = useState(false);

  const handleLanguageChange = async (nextLanguage: UiLanguage) => {
    if (nextLanguage === language) return;
    setSavingLanguage(true);
    try {
      await saveUserConfig({ ui_language: nextLanguage });
      toast.success(t('settings.language.updated'));
    } catch {
      toast.error(t('settings.language.failed'));
    } finally {
      setSavingLanguage(false);
    }
  };

  return (
    <div className="flex justify-center py-12 px-4">
      <div className="w-full max-w-2xl space-y-6">
        <div>
          <h1 className="text-2xl font-bold">{t('settings.title')}</h1>
          <p className="text-muted-foreground">{t('settings.description')}</p>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>{t('settings.language.title')}</CardTitle>
            <CardDescription>{t('settings.language.description')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <Label htmlFor="ui-language">{t('settings.language.label')}</Label>
            <Select value={language} onValueChange={(value) => handleLanguageChange(value as UiLanguage)} disabled={savingLanguage}>
              <SelectTrigger id="ui-language">
                <SelectValue placeholder={t('settings.language.placeholder')} />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(UI_LANGUAGE_LABELS).map(([value, label]) => (
                  <SelectItem key={value} value={value}>
                    {label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>{t('settings.mcp.title')}</CardTitle>
            <CardDescription>
              {t('settings.mcp.description')}{" "}
              <a
                href="https://docs.dograh.com/integrations/mcp"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-0.5 underline"
              >
                {t('settings.learnMore')} <ExternalLink className="h-3 w-3" />
              </a>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <MCPSection />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>{t('settings.telemetry.title')}</CardTitle>
            <CardDescription>
              {t('settings.telemetry.description')}{" "}
              <a
                href="https://docs.dograh.com/configurations/tracing"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-0.5 underline"
              >
                {t('settings.learnMore')} <ExternalLink className="h-3 w-3" />
              </a>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TelemetrySection />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
