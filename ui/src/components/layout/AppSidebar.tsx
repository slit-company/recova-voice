"use client";

import type { Team } from "@stackframe/stack";
import {
  AlertTriangle,
  ArrowUpCircle,
  AudioLines,
  Brain,
  ChevronLeft,
  ChevronRight,
  CircleDollarSign,
  Database,
  FileText,
  Home,
  Key,
  LogOut,
  type LucideIcon,
  Megaphone,
  Phone,
  Settings,
  TrendingUp,
  Workflow,
  Wrench,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import React, { useMemo, useRef } from "react";

import ThemeToggle from "@/components/ThemeSwitcher";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useAppConfig } from "@/context/AppConfigContext";
import { useLocale } from "@/context/LocaleContext";
import { useTelephonyConfigWarnings } from "@/context/TelephonyConfigWarningsContext";
import { useLatestReleaseVersion } from "@/hooks/useLatestReleaseVersion";
import type { LocalUser } from "@/lib/auth";
import { useAuth } from "@/lib/auth";
import { cn } from "@/lib/utils";

type SidebarNavItem = {
  titleKey: string;
  url: string;
  icon: LucideIcon;
  showsTelephonyWarning?: boolean;
};

type SidebarNavSection = {
  labelKey?: string;
  items: SidebarNavItem[];
};

const NAV_SECTIONS: SidebarNavSection[] = [
  {
    items: [
      {
        titleKey: "sidebar.overview",
        url: "/overview",
        icon: Home,
      },
    ],
  },
  {
    labelKey: "sidebar.section.build",
    items: [
      { titleKey: "sidebar.voiceAgents", url: "/workflow", icon: Workflow },
      { titleKey: "sidebar.campaigns", url: "/campaigns", icon: Megaphone },
      { titleKey: "sidebar.models", url: "/model-configurations", icon: Brain },
      { titleKey: "sidebar.telephony", url: "/telephony-configurations", icon: Phone, showsTelephonyWarning: true },
      { titleKey: "sidebar.tools", url: "/tools", icon: Wrench },
      { titleKey: "sidebar.files", url: "/files", icon: Database },
      { titleKey: "sidebar.recordings", url: "/recordings", icon: AudioLines },
      { titleKey: "sidebar.developers", url: "/api-keys", icon: Key },
    ],
  },
  {
    labelKey: "sidebar.section.observe",
    items: [
      { titleKey: "sidebar.agentRuns", url: "/usage", icon: TrendingUp },
      { titleKey: "sidebar.reports", url: "/reports", icon: FileText },
    ],
  },
];

const StackTeamSwitcher = React.lazy(() =>
  import("@stackframe/stack").then((mod) => ({
    default: mod.SelectedTeamSwitcher,
  }))
);

export function AppSidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const { state, isMobile, setOpenMobile } = useSidebar();
  const { provider, getSelectedTeam, logout, user } = useAuth();
  const { config } = useAppConfig();
  const { t } = useLocale();
  const { telnyxMissingWebhookPublicKeyCount } = useTelephonyConfigWarnings();
  const hasTelephonyWarning = telnyxMissingWebhookPublicKeyCount > 0;
  const isCollapsed = !isMobile && state === "collapsed";

  const selectedTeamRef = useRef<Team | null>(null);
  const rawSelectedTeam = provider === "stack" && getSelectedTeam ? getSelectedTeam() as Team | null : null;
  if (rawSelectedTeam?.id !== selectedTeamRef.current?.id) {
    selectedTeamRef.current = rawSelectedTeam;
  }
  const selectedTeam = selectedTeamRef.current;

  const versionInfo = config ? { ui: config.uiVersion, api: config.apiVersion } : null;

  const { latest: latestRelease, isBehind, isLatest } = useLatestReleaseVersion(
    versionInfo?.ui,
    { enabled: config?.deploymentMode === "oss" },
  );

  const translatedSections = useMemo(
    () => NAV_SECTIONS.map((section) => ({
      label: section.labelKey ? t(section.labelKey as never) : undefined,
      items: section.items.map((item) => ({
        ...item,
        title: t(item.titleKey as never),
      })),
    })),
    [t],
  );

  const isActive = (path: string) => pathname.startsWith(path);

  const handleMobileNavClick = () => {
    if (isMobile) {
      setOpenMobile(false);
    }
  };

  const SidebarLink = ({ item }: { item: SidebarNavItem & { title: string } }) => {
    const isItemActive = isActive(item.url);
    const Icon = item.icon;
    const showWarningDot = item.showsTelephonyWarning && hasTelephonyWarning;
    const tooltip = {
      children: (
        <div>
          <p>{item.title}</p>
          {showWarningDot && (
            <p className="text-amber-600 dark:text-amber-400">{t('sidebar.actionRequired')}</p>
          )}
        </div>
      ),
    };
    const warningIndicator = (
      <AlertTriangle
        aria-label={t('sidebar.actionRequired')}
        className={cn(
          "text-amber-500",
          isCollapsed ? "absolute -right-0.5 -top-0.5 h-3 w-3" : "ml-auto h-3.5 w-3.5"
        )}
      />
    );

    return (
      <SidebarMenuButton
        asChild
        tooltip={tooltip}
        className={cn(
          "hover:bg-accent hover:text-accent-foreground",
          isItemActive && "bg-accent text-accent-foreground"
        )}
      >
        <Link href={item.url} onClick={handleMobileNavClick} className={cn("relative", isCollapsed && "justify-center")}>
          <Icon className="h-4 w-4 shrink-0" />
          <span className={cn("min-w-0 flex-1 truncate", isCollapsed && "sr-only")}>
            {item.title}
          </span>
          {showWarningDot && (
            isCollapsed ? (
              warningIndicator
            ) : (
              <Tooltip>
                <TooltipTrigger asChild>
                  {warningIndicator}
                </TooltipTrigger>
                <TooltipContent side="right">
                  <p>{t('sidebar.actionRequired')}</p>
                </TooltipContent>
              </Tooltip>
            )
          )}
        </Link>
      </SidebarMenuButton>
    );
  };

  return (
    <Sidebar collapsible="icon" className="border-r">
      <SidebarHeader className="border-b px-2 py-3" translate="no">
        <div className="flex items-center justify-between">
          <div className={cn("flex items-center gap-2", isCollapsed && "hidden")}>
            <Link href="/" className="notranslate flex items-center gap-2 px-2 text-xl font-bold" translate="no">
              Recova
              {versionInfo && (
                <span className="notranslate text-xs font-normal text-muted-foreground" translate="no">
                  v{versionInfo.ui}
                </span>
              )}
            </Link>
            {isBehind && latestRelease && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <a
                    href="https://docs.dograh.com/deployment/update"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 rounded-md border bg-amber-50 px-1.5 py-0.5 text-[10px] font-medium leading-none text-amber-900 transition-opacity hover:opacity-80 dark:bg-amber-950 dark:text-amber-200"
                  >
                    <ArrowUpCircle className="h-3 w-3" />
                    {t('sidebar.update')}
                  </a>
                </TooltipTrigger>
                <TooltipContent side="bottom">
                  <p>{t('sidebar.latestReleaseTooltip', { version: latestRelease })}</p>
                </TooltipContent>
              </Tooltip>
            )}
            {isLatest && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="inline-flex items-center rounded-md border bg-emerald-50 px-1.5 py-0.5 text-[10px] font-medium leading-none text-emerald-900 dark:bg-emerald-950 dark:text-emerald-200">
                    {t('sidebar.latest')}
                  </span>
                </TooltipTrigger>
                <TooltipContent side="bottom">
                  <p>{t('sidebar.runningLatestRelease')}</p>
                </TooltipContent>
              </Tooltip>
            )}
          </div>

          <SidebarTrigger className={cn("hover:bg-accent", isCollapsed && "mx-auto")}>
            {isCollapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          </SidebarTrigger>
        </div>

        {provider === "stack" && (
          <div className={cn("mt-3", isCollapsed && "hidden")} translate="no">
            <React.Suspense fallback={<div className="h-9 w-full animate-pulse rounded bg-muted" />}>
              <StackTeamSwitcher
                selectedTeam={selectedTeam || undefined}
                onChange={() => {
                  router.refresh();
                }}
              />
            </React.Suspense>
          </div>
        )}
      </SidebarHeader>

      <SidebarContent className={cn(isCollapsed && "px-0")}>
        {translatedSections.map((section, index) => (
          <SidebarGroup key={section.label ?? "overview"} className={index === 0 ? "mt-2" : "mt-6"}>
            {section.label && (
              <SidebarGroupLabel
                className={cn(
                  "text-xs font-semibold uppercase tracking-wider text-muted-foreground",
                  isCollapsed && "hidden"
                )}
              >
                {section.label}
              </SidebarGroupLabel>
            )}
            <SidebarMenu>
              {section.items.map((item) => (
                <SidebarMenuItem key={item.url}>
                  <SidebarLink item={item} />
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroup>
        ))}
      </SidebarContent>

      <SidebarFooter className={cn("border-t p-4", isCollapsed && "p-2")}>
        <div className="space-y-2">
          {provider !== "stack" && (
            <div className={cn("flex", isCollapsed ? "justify-center" : "justify-start")}>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon" className="h-8 w-8 cursor-pointer rounded-full">
                    <span className="text-xs font-medium">
                      {(user?.displayName || (user as LocalUser | undefined)?.email || "")
                        .split(/[\s@]/)
                        .filter(Boolean)
                        .slice(0, 2)
                        .map((s: string) => s[0]?.toUpperCase())
                        .join("") || "U"}
                    </span>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent side="top" align="start" className="w-56">
                  <DropdownMenuLabel className="font-normal">
                    <div className="flex flex-col space-y-1">
                      {(user as LocalUser | undefined)?.email && (
                        <p className="text-xs text-muted-foreground">{(user as LocalUser).email}</p>
                      )}
                    </div>
                  </DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={() => router.push("/settings")} className="cursor-pointer">
                    <Settings className="mr-2 h-4 w-4" />
                    {t('sidebar.platformSettings')}
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => logout()} className="cursor-pointer">
                    <LogOut className="mr-2 h-4 w-4" />
                    {t('common.signOut')}
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          )}

          {provider === "stack" && (
            <div className={cn("flex", isCollapsed ? "justify-center" : "justify-start")}>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon" className="h-8 w-8 cursor-pointer rounded-full">
                    <span className="text-xs font-medium">
                      {(user?.displayName || (user as { primaryEmail?: string })?.primaryEmail || "")
                        .split(/[\s@]/)
                        .filter(Boolean)
                        .slice(0, 2)
                        .map((s: string) => s[0]?.toUpperCase())
                        .join("") || "U"}
                    </span>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent side="top" align="start" className="w-56">
                  <DropdownMenuLabel className="font-normal">
                    <div className="flex flex-col space-y-1">
                      {user?.displayName && <p className="text-sm font-medium">{user.displayName}</p>}
                      {(user as { primaryEmail?: string })?.primaryEmail && (
                        <p className="text-xs text-muted-foreground">{(user as { primaryEmail?: string }).primaryEmail}</p>
                      )}
                    </div>
                  </DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={() => router.push("/handler/account-settings")} className="cursor-pointer">
                    <Settings className="mr-2 h-4 w-4" />
                    {t('sidebar.accountSettings')}
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => router.push("/settings")} className="cursor-pointer">
                    <Settings className="mr-2 h-4 w-4" />
                    {t('sidebar.platformSettings')}
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => router.push("/usage")} className="cursor-pointer">
                    <CircleDollarSign className="mr-2 h-4 w-4" />
                    {t('common.usage')}
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => logout()} className="cursor-pointer">
                    <LogOut className="mr-2 h-4 w-4" />
                    {t('common.signOut')}
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          )}

          <div className={cn("mt-2 border-t pt-2", isCollapsed && "flex justify-center")}>
            {isCollapsed ? (
              <Tooltip>
                <TooltipTrigger asChild>
                  <div>
                    <ThemeToggle showLabel={false} className="hover:bg-accent hover:text-accent-foreground" />
                  </div>
                </TooltipTrigger>
                <TooltipContent side="right">
                  <p>{t('theme.toggle')}</p>
                </TooltipContent>
              </Tooltip>
            ) : (
              <div>
                <ThemeToggle showLabel={true} className="hover:bg-accent hover:text-accent-foreground" />
              </div>
            )}
          </div>
        </div>
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}
