"use client";

import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";

import { loginApiV1AuthLoginPost, signupApiV1AuthSignupPost } from "@/client/sdk.gen";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useLocale } from "@/context/LocaleContext";

export default function LoginPage() {
  const { t } = useLocale();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const developerLoginEnabled = process.env.NODE_ENV === "development";

  const persistSession = async (data: { token: string; user: unknown }) => {
    const response = await fetch("/api/auth/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      throw new Error("Failed to create login session");
    }

    window.location.href = "/after-sign-in";
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const res = await loginApiV1AuthLoginPost({
        body: { email, password },
      });

      if (res.error || !res.data) {
        const detail = (res.error as { detail?: string })?.detail;
        toast.error(detail || t("auth.login.failed"));
        return;
      }

      await persistSession(res.data);
    } catch {
      toast.error(t("auth.genericError"));
    } finally {
      setLoading(false);
    }
  };
  const handleDeveloperLogin = async () => {
    const developerEmail = "developer@recova.dev";
    const developerPassword = "recova-local-developer";

    setLoading(true);

    try {
      let authResponse = await loginApiV1AuthLoginPost({
        body: { email: developerEmail, password: developerPassword },
      });

      if (authResponse.error || !authResponse.data) {
        const signupResponse = await signupApiV1AuthSignupPost({
          body: {
            email: developerEmail,
            password: developerPassword,
            name: "Recova Developer",
          },
        });

        if (signupResponse.error || !signupResponse.data) {
          const detail = (signupResponse.error as { detail?: unknown })?.detail;
          toast.error(
            typeof detail === "string" ? detail : t("auth.login.developerFailed"),
          );
          return;
        }

        authResponse = signupResponse;
      }

      await persistSession(authResponse.data);
    } catch {
      toast.error(t("auth.genericError"));
    } finally {
      setLoading(false);
    }
  };


  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <CardTitle className="text-2xl">{t("auth.login.title")}</CardTitle>
          <CardDescription>{t("auth.login.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">{t("auth.email")}</Label>
              <Input
                id="email"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">{t("auth.password")}</Label>
              <Input
                id="password"
                type="password"
                placeholder={t("auth.login.passwordPlaceholder")}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? t("auth.login.submitting") : t("auth.login.submit")}
            </Button>
            {developerLoginEnabled && (
              <Button
                type="button"
                variant="outline"
                className="w-full"
                disabled={loading}
                onClick={handleDeveloperLogin}
              >
                {t("auth.login.developerSubmit")}
              </Button>
            )}
          </form>
          <p className="mt-4 text-center text-sm text-muted-foreground">
            {t("auth.login.noAccount")}{" "}
            <Link href="/auth/signup" className="text-primary underline-offset-4 hover:underline">
              {t("auth.login.signupLink")}
            </Link>
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
