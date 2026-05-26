"use client";

import { Moon, Sun } from "lucide-react";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { useLocale } from "@/context/LocaleContext";
import { cn } from "@/lib/utils";

interface ThemeToggleProps {
  className?: string;
  showLabel?: boolean;
  variant?: "ghost" | "outline" | "default";
  size?: "default" | "sm" | "lg" | "icon";
}

export default function ThemeToggle({
  className,
  showLabel = false,
  variant = "ghost",
  size = "icon"
}: ThemeToggleProps) {
  const { t } = useLocale();
  const [theme, setTheme] = useState<"light" | "dark" | null>(null);

  useEffect(() => {
    const isDark = document.documentElement.classList.contains("dark");
    setTheme(isDark ? "dark" : "light");
  }, []);

  const toggleTheme = () => {
    const newTheme = theme === "light" ? "dark" : "light";
    setTheme(newTheme);
    localStorage.setItem("theme", newTheme);
    document.documentElement.classList.toggle("dark", newTheme === "dark");
  };

  return (
    <Button
      variant={variant}
      size={size}
      className={cn(
        showLabel && "w-full justify-start",
        className
      )}
      onClick={toggleTheme}
    >
      <Sun className={cn(
        "h-4 w-4 rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0",
        showLabel && "absolute"
      )} />
      <Moon className={cn(
        "h-4 w-4 rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100",
        !showLabel && "absolute"
      )} />
      {showLabel && theme && (
        <span className="ml-2">
          {theme === "light" ? t('theme.lightMode') : t('theme.darkMode')}
        </span>
      )}
      <span className="sr-only">{t('theme.toggle')}</span>
    </Button>
  );
}
