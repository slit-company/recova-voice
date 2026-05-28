"use client";

import { ExternalLink, Upload } from "lucide-react";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { useLocale } from "@/context/LocaleContext";
import { useAuth } from "@/lib/auth";

import DocumentList from "./DocumentList";
import DocumentUpload from "./DocumentUpload";

export default function FilesPage() {
  const { user, redirectToLogin, loading } = useAuth();
  const { t } = useLocale();
  const [refreshKey, setRefreshKey] = useState(0);
  const [isUploadOpen, setIsUploadOpen] = useState(false);

  // Redirect if not authenticated
  useEffect(() => {
    if (!loading && !user) {
      redirectToLogin();
    }
  }, [loading, user, redirectToLogin]);

  const handleUploadSuccess = () => {
    setRefreshKey((prev) => prev + 1);
    setIsUploadOpen(false);
  };

  if (loading || !user) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="space-y-4">
          <Skeleton className="h-12 w-64" />
          <Skeleton className="h-64 w-full" />
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">{t("files.title")}</h1>
        <p className="text-muted-foreground">
          {t("files.descriptionStart")}{" "}
          <a
            href="https://docs.dograh.com/voice-agent/knowledge-base"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-0.5 underline"
          >
            {t("files.learnMore")} <ExternalLink className="h-3 w-3" />
          </a>
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <div>
              <CardTitle>{t("files.yourDocuments")}</CardTitle>
              <CardDescription>{t("files.cardDescription")}</CardDescription>
            </div>
            <Button onClick={() => setIsUploadOpen(true)}>
              <Upload className="w-4 h-4 mr-2" />
              {t("files.uploadDocument")}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <DocumentList refreshTrigger={refreshKey} />
        </CardContent>
      </Card>

      <Dialog open={isUploadOpen} onOpenChange={setIsUploadOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("files.uploadDocument")}</DialogTitle>
            <DialogDescription>
              {t("files.uploadDescription")}
            </DialogDescription>
          </DialogHeader>
          <DocumentUpload onUploadSuccess={handleUploadSuccess} />
        </DialogContent>
      </Dialog>
    </div>
  );
}
