"use client";

import { Link as LinkIcon, RefreshCw, Unlink } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { getWorkflowsSummaryApiV1WorkflowSummaryGet } from "@/client/sdk.gen";
import type { WorkflowSummaryResponse } from "@/client/types.gen";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useLocale } from "@/context/LocaleContext";
import { useAuth } from "@/lib/auth";

const API_BASE = process.env.NEXT_PUBLIC_BACKEND_URL ?? "";

type AssignedNumber = {
  inventory_id: number;
  provider: string;
  address_masked: string | null;
  address_type: string;
  country_code: string | null;
  label: string | null;
  status: string;
  telephony_configuration_id: number | null;
  telephony_phone_number_id: number | null;
  inbound_workflow_id: number | null;
  inbound_workflow_name: string | null;
  is_active: boolean;
  is_default_caller_id: boolean;
  created_at: string;
  updated_at: string;
};

type AssignedNumberListResponse = {
  numbers: AssignedNumber[];
};

type AssignedNumbersBinderProps = {
  targetWorkflowId?: number;
  targetWorkflowName?: string;
  title?: string;
  description?: string;
};

export function AssignedNumbersBinder({
  targetWorkflowId,
  targetWorkflowName,
  title,
  description,
}: AssignedNumbersBinderProps) {
  const { user, getAccessToken, loading: authLoading } = useAuth();
  const { t } = useLocale();
  const [numbers, setNumbers] = useState<AssignedNumber[]>([]);
  const [workflowInputs, setWorkflowInputs] = useState<Record<number, string>>({});
  const [workflows, setWorkflows] = useState<WorkflowSummaryResponse[]>([]);
  const [loadingWorkflows, setLoadingWorkflows] = useState(targetWorkflowId == null);
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState<number | null>(null);

  const workflowScoped = targetWorkflowId != null;

  const fetchNumbers = useCallback(async () => {
    if (authLoading || !user) return;
    setLoading(true);
    try {
      const data = await apiRequest<AssignedNumberListResponse>(
        "/api/v1/organizations/telephony-numbers/assigned",
        await getAccessToken(),
      );
      setNumbers(data.numbers ?? []);
      setWorkflowInputs(
        Object.fromEntries(
          (data.numbers ?? []).map((number) => [
            number.inventory_id,
            number.inbound_workflow_id ? String(number.inbound_workflow_id) : "",
          ]),
        ),
      );
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t("telephonyNumbers.loadAssignedFailed"));
    } finally {
      setLoading(false);
    }
  }, [authLoading, user, getAccessToken, t]);

  const fetchWorkflows = useCallback(async () => {
    if (targetWorkflowId != null) {
      setLoadingWorkflows(false);
      return;
    }
    if (authLoading || !user) return;
    setLoadingWorkflows(true);
    try {
      const response = await getWorkflowsSummaryApiV1WorkflowSummaryGet({
        headers: {
          authorization: `Bearer ${await getAccessToken()}`,
        },
        query: {
          status: "active",
        },
      });
      setWorkflows(response.data ?? []);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t("telephonyNumbers.loadWorkflowsFailed"));
    } finally {
      setLoadingWorkflows(false);
    }
  }, [authLoading, user, getAccessToken, targetWorkflowId, t]);

  useEffect(() => {
    void fetchNumbers();
    void fetchWorkflows();
  }, [fetchNumbers, fetchWorkflows]);

  const boundToTargetCount = useMemo(
    () => numbers.filter((number) => number.inbound_workflow_id === targetWorkflowId).length,
    [numbers, targetWorkflowId],
  );

  const bindNumber = async (inventoryId: number, workflowId: number) => {
    if (!Number.isInteger(workflowId) || workflowId <= 0) {
      toast.error(t("telephonyNumbers.selectInboundWorkflow"));
      return;
    }
    setSavingId(inventoryId);
    try {
      await apiRequest<AssignedNumber>(
        `/api/v1/organizations/telephony-numbers/assigned/${inventoryId}/bind`,
        await getAccessToken(),
        {
          method: "POST",
          body: JSON.stringify({ workflow_id: workflowId }),
        },
      );
      toast.success(t("telephonyNumbers.bindSuccess"));
      await fetchNumbers();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t("telephonyNumbers.bindFailed"));
    } finally {
      setSavingId(null);
    }
  };

  const unbindNumber = async (inventoryId: number) => {
    setSavingId(inventoryId);
    try {
      await apiRequest<AssignedNumber>(
        `/api/v1/organizations/telephony-numbers/assigned/${inventoryId}/bind`,
        await getAccessToken(),
        { method: "DELETE" },
      );
      toast.success(t("telephonyNumbers.unbindSuccess"));
      await fetchNumbers();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t("telephonyNumbers.unbindFailed"));
    } finally {
      setSavingId(null);
    }
  };

  const workflowOptionsForNumber = (number: AssignedNumber) => {
    if (
      number.inbound_workflow_id &&
      !workflows.some((workflow) => workflow.id === number.inbound_workflow_id)
    ) {
      return [
        {
          id: number.inbound_workflow_id,
          name: number.inbound_workflow_name ?? t("telephonyNumbers.workflowNumber", { id: number.inbound_workflow_id }),
        },
        ...workflows,
      ];
    }
    return workflows;
  };

  const renderWorkflowCell = (number: AssignedNumber) => {
    if (!number.inbound_workflow_id) {
      return <span className="text-muted-foreground">{t("telephonyNumbers.unbound")}</span>;
    }
    return (
      <Link
        href={`/workflow/${number.inbound_workflow_id}`}
        className="inline-flex items-center gap-1 hover:underline"
      >
        #{number.inbound_workflow_id}
        {number.inbound_workflow_name && (
          <span className="text-muted-foreground">{number.inbound_workflow_name}</span>
        )}
      </Link>
    );
  };

  const renderActionCell = (number: AssignedNumber) => {
    if (targetWorkflowId != null) {
      const isBoundHere = number.inbound_workflow_id === targetWorkflowId;
      const isBoundElsewhere = Boolean(
        number.inbound_workflow_id && number.inbound_workflow_id !== targetWorkflowId,
      );
      return (
        <div className="flex items-center gap-2">
          {isBoundHere ? (
            <Button
              size="sm"
              variant="outline"
              onClick={() => unbindNumber(number.inventory_id)}
              disabled={savingId === number.inventory_id}
            >
              <Unlink className="h-4 w-4 mr-1" /> {t("telephonyNumbers.unbind")}
            </Button>
          ) : (
            <Button
              size="sm"
              onClick={() => bindNumber(number.inventory_id, targetWorkflowId)}
              disabled={savingId === number.inventory_id || isBoundElsewhere}
            >
              <LinkIcon className="h-4 w-4 mr-1" /> {t("telephonyNumbers.bindHere")}
            </Button>
          )}
          {isBoundElsewhere && (
            <span className="text-xs text-muted-foreground">
              {t("telephonyNumbers.alreadyBound", { id: number.inbound_workflow_id ?? "" })}
            </span>
          )}
        </div>
      );
    }

    return (
      <div className="flex items-center gap-2">
        <Select
          value={workflowInputs[number.inventory_id] ?? ""}
          onValueChange={(value) =>
            setWorkflowInputs((prev) => ({
              ...prev,
              [number.inventory_id]: value,
            }))
          }
          disabled={loadingWorkflows}
        >
          <SelectTrigger className="h-8 min-w-[220px]">
            <SelectValue
              placeholder={loadingWorkflows
                ? t("telephonyNumbers.loadingWorkflows")
                : t("telephonyNumbers.selectWorkflow")}
            />
          </SelectTrigger>
          <SelectContent>
            {loadingWorkflows ? (
              <SelectItem value="loading" disabled>
                {t("telephonyNumbers.loadingWorkflows")}
              </SelectItem>
            ) : workflowOptionsForNumber(number).length === 0 ? (
              <SelectItem value="none" disabled>
                {t("telephonyNumbers.noActiveWorkflows")}
              </SelectItem>
            ) : (
              workflowOptionsForNumber(number).map((workflow) => (
                <SelectItem key={workflow.id} value={workflow.id.toString()}>
                  {workflow.name} (#{workflow.id})
                </SelectItem>
              ))
            )}
          </SelectContent>
        </Select>
        <Button
          size="sm"
          onClick={() => bindNumber(number.inventory_id, Number(workflowInputs[number.inventory_id]))}
          disabled={
            savingId === number.inventory_id ||
            loadingWorkflows ||
            !workflowInputs[number.inventory_id]
          }
        >
          <LinkIcon className="h-4 w-4" />
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={() => unbindNumber(number.inventory_id)}
          disabled={savingId === number.inventory_id || !number.inbound_workflow_id}
        >
          <Unlink className="h-4 w-4" />
        </Button>
      </div>
    );
  };

  return (
    <Card id={workflowScoped ? "phone-numbers" : undefined}>
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div>
            <CardTitle>{title ?? t("telephonyNumbers.title")}</CardTitle>
            <CardDescription className="mt-1">
              {description ?? t("telephonyNumbers.description")}
            </CardDescription>
            {workflowScoped && (
              <p className="mt-2 text-xs text-muted-foreground">
                {boundToTargetCount > 0
                  ? t("telephonyNumbers.routingCount", {
                    count: boundToTargetCount,
                    workflow: targetWorkflowName ?? t("telephonyNumbers.thisWorkflow"),
                  })
                  : t("telephonyNumbers.scopedEmpty")}
              </p>
            )}
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              void fetchNumbers();
              void fetchWorkflows();
            }}
            disabled={loading || loadingWorkflows}
          >
            <RefreshCw className="h-4 w-4 mr-2" /> {t("telephonyNumbers.refresh")}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : numbers.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {t("telephonyNumbers.empty")}
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("telephonyNumbers.number")}</TableHead>
                <TableHead>{t("telephonyNumbers.provider")}</TableHead>
                <TableHead>{t("telephonyNumbers.status")}</TableHead>
                <TableHead>{t("telephonyNumbers.inboundWorkflow")}</TableHead>
                <TableHead className={workflowScoped ? "w-[280px]" : "w-[340px]"}>
                  {workflowScoped
                    ? t("telephonyNumbers.thisWorkflow")
                    : t("telephonyNumbers.bindWorkflow")}
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {numbers.map((number) => (
                <TableRow key={number.inventory_id}>
                  <TableCell>
                    <div className="space-y-1">
                      <div className="font-mono">
                        {number.address_masked ?? t("telephonyNumbers.masked")}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {number.label ?? t("telephonyNumbers.noLabel")} · {number.address_type}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary">{number.provider}</Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      <Badge variant={number.is_active ? "secondary" : "outline"}>
                        {number.is_active
                          ? t("telephonyNumbers.active")
                          : t("telephonyNumbers.inactive")}
                      </Badge>
                      {number.is_default_caller_id && (
                        <Badge>{t("telephonyNumbers.defaultCaller")}</Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>{renderWorkflowCell(number)}</TableCell>
                  <TableCell>{renderActionCell(number)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

async function apiRequest<T>(path: string, token: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  headers.set("Authorization", `Bearer ${token}`);

  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
  });
  if (!response.ok) {
    throw new Error(await detailFromResponse(response));
  }
  return (await response.json()) as T;
}

async function detailFromResponse(response: Response): Promise<string> {
  try {
    const payload = await response.json();
    if (typeof payload?.detail === "string") return payload.detail;
    if (Array.isArray(payload?.detail) && payload.detail[0]?.msg) {
      return payload.detail[0].msg;
    }
  } catch {
    // Fall through to status text.
  }
  return response.statusText || "Request failed";
}
