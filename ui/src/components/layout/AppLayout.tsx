"use client";

import { Menu } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import React, { ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { SidebarInset, SidebarProvider, useSidebar } from "@/components/ui/sidebar";
import { useLocale } from "@/context/LocaleContext";

import { AppSidebar } from "./AppSidebar";

function AppHeader() {
  const { toggleSidebar } = useSidebar();
  const { t } = useLocale();

  return (
    <header className="sticky top-0 z-50 flex items-center justify-between border-b bg-background px-4 py-2">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="icon" onClick={toggleSidebar} aria-label={t('header.openMenu')} className="md:hidden">
          <Menu className="h-5 w-5" />
        </Button>
        <Link href="/" className="text-lg font-bold md:hidden">Recova</Link>
      </div>
    </header>
  );
}

interface AppLayoutProps {
  children: ReactNode;
  headerActions?: ReactNode;
  stickyTabs?: ReactNode;
}

const AppLayout: React.FC<AppLayoutProps> = ({
  children,
  headerActions,
  stickyTabs,
}) => {
  const pathname = usePathname();
  const shouldShowSidebar = pathname !== "/" && !pathname.startsWith("/handler") && !pathname.startsWith("/auth");
  const isWorkflowEditor = /^\/workflow\/\d+$/.test(pathname);

  return (
    <SidebarProvider defaultOpen>
      {shouldShowSidebar ? (
        <div className="flex min-h-screen w-full">
          <AppSidebar />
          <SidebarInset className="flex-1">
            {!isWorkflowEditor && <AppHeader />}
            {headerActions && (
              <header className="sticky top-0 z-50 w-full border-b bg-background">
                <div className="container mx-auto px-4 py-4">
                  <div className="flex items-center justify-center">
                    {headerActions}
                  </div>
                </div>
              </header>
            )}

            {stickyTabs && (
              <div className="sticky top-0 z-40 bg-[#2a2e39] border-b border-gray-700">
                <div className="container mx-auto px-4">
                  <div className="flex items-center justify-center py-2">
                    {stickyTabs}
                  </div>
                </div>
              </div>
            )}

            <main className="flex-1">
              {children}
            </main>
          </SidebarInset>
        </div>
      ) : (
        <div className="flex-1 w-full">
          {children}
        </div>
      )}
    </SidebarProvider>
  );
};

export default AppLayout;
