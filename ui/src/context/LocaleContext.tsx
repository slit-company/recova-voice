'use client';

import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

import { useUserConfig } from '@/context/UserConfigContext';
import {
  DEFAULT_UI_LANGUAGE,
  getLocaleTag,
  isUiLanguage,
  translate,
  type TranslationKey,
  type UiLanguage,
} from '@/lib/i18n';
import { applyKoreanDomOverrides } from '@/lib/ko-dom-overrides';

type FormatDateOptions = Intl.DateTimeFormatOptions & {
  timeZone?: string;
};

function normalizeDateValue(value: string | Date): Date {
  if (value instanceof Date) {
    return value;
  }

  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    const [year, month, day] = value.split('-').map(Number);
    return new Date(year, month - 1, day);
  }

  return new Date(value);
}

interface LocaleContextValue {
  language: UiLanguage;
  locale: string;
  t: (key: TranslationKey, values?: Record<string, string | number>) => string;
  formatDate: (value: string | Date, options?: FormatDateOptions) => string;
  formatDateTime: (value: string | Date, options?: FormatDateOptions) => string;
  formatNumber: (value: number, options?: Intl.NumberFormatOptions) => string;
  formatCurrency: (value: number, currency?: string) => string;
}

const LocaleContext = createContext<LocaleContextValue | null>(null);

export function LocaleProvider({ children }: { children: ReactNode }) {
  const { userConfig } = useUserConfig();
  const [language, setLanguage] = useState<UiLanguage>(() => {
    if (typeof window === 'undefined') {
      return DEFAULT_UI_LANGUAGE;
    }

    const stored = window.localStorage.getItem('ui_language');
    return isUiLanguage(stored) ? stored : DEFAULT_UI_LANGUAGE;
  });

  useEffect(() => {
    const nextLanguage = userConfig?.ui_language;
    if (isUiLanguage(nextLanguage)) {
      setLanguage(nextLanguage);
      window.localStorage.setItem('ui_language', nextLanguage);
      return;
    }

    if (!userConfig?.ui_language) {
      setLanguage((current) => current || DEFAULT_UI_LANGUAGE);
    }
  }, [userConfig?.ui_language]);

  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);

  useEffect(() => {
    if (language !== 'ko') return undefined;
    return applyKoreanDomOverrides();
  }, [language]);

  const locale = useMemo(() => getLocaleTag(language), [language]);

  const t = useCallback(
    (key: TranslationKey, values?: Record<string, string | number>) =>
      translate(language, key, values),
    [language],
  );

  const formatDate = useCallback(
    (value: string | Date, options?: FormatDateOptions) =>
      new Intl.DateTimeFormat(locale, options).format(normalizeDateValue(value)),
    [locale],
  );

  const formatDateTime = useCallback(
    (value: string | Date, options?: FormatDateOptions) =>
      new Intl.DateTimeFormat(
        locale,
        options ?? {
          year: 'numeric',
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
        },
      ).format(normalizeDateValue(value)),
    [locale],
  );

  const formatNumber = useCallback(
    (value: number, options?: Intl.NumberFormatOptions) =>
      new Intl.NumberFormat(locale, options).format(value),
    [locale],
  );

  const formatCurrency = useCallback(
    (value: number, currency = 'USD') =>
      new Intl.NumberFormat(locale, {
        style: 'currency',
        currency,
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
      }).format(value),
    [locale],
  );

  return (
    <LocaleContext.Provider
      value={{
        language,
        locale,
        t,
        formatDate,
        formatDateTime,
        formatNumber,
        formatCurrency,
      }}
    >
      {children}
    </LocaleContext.Provider>
  );
}

export function useLocale() {
  const context = useContext(LocaleContext);
  if (!context) {
    throw new Error('useLocale must be used within a LocaleProvider');
  }
  return context;
}
