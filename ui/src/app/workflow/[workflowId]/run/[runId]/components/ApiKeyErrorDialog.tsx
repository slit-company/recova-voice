import { AlertCircle, CreditCard, Key } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useLocale } from "@/context/LocaleContext";

interface ApiKeyErrorDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  error: string | null;
  errorCode: string | null;
  onNavigateToCredits: () => void;
  onNavigateToModelConfig: () => void;
}

export const ApiKeyErrorDialog = ({
  open,
  onOpenChange,
  error,
  errorCode,
  onNavigateToCredits,
  onNavigateToModelConfig,
}: ApiKeyErrorDialogProps) => {
  const { t } = useLocale();
  const isQuotaError = errorCode === "quota_exceeded";

  const title = isQuotaError
    ? t("runDetail.apiInsufficientCredits")
    : t("runDetail.apiConfigError");
  const icon = isQuotaError ? (
    <CreditCard className="h-5 w-5 text-orange-500" />
  ) : (
    <Key className="h-5 w-5 text-red-500" />
  );
  const buttonText = isQuotaError
    ? t("runDetail.addCredits")
    : t("runDetail.goToModels");
  const onNavigate = isQuotaError
    ? onNavigateToCredits
    : onNavigateToModelConfig;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {icon}
            {title}
          </DialogTitle>
          <DialogDescription className="pt-3" asChild>
            <div className="flex items-start gap-2">
              <AlertCircle className="h-4 w-4 text-muted-foreground mt-0.5 flex-shrink-0" />
              <div className="text-sm space-y-1">
                <p className="font-medium text-foreground">{error}</p>
                {isQuotaError && (
                  <p className="text-muted-foreground">
                    {t("runDetail.lowCredits")}
                  </p>
                )}
              </div>
            </div>
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("common.cancel")}
          </Button>
          <Button onClick={onNavigate}>{buttonText}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
