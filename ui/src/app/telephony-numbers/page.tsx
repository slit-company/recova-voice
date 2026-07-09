"use client";

import { Link as LinkIcon, RefreshCw, Unlink } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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

export default function TelephonyNumbersPage() {
  const { user, getAccessToken, loading: authLoading } = useAuth();
  const [numbers, setNumbers] = useState<AssignedNumber[]>([]);
  const [workflowInputs, setWorkflowInputs] = useState<Record<number, string>>({});
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState<number | null>(null);

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
      toast.error(err instanceof Error ? err.message : "Failed to load assigned numbers");
    } finally {
      setLoading(false);
    }
  }, [authLoading, user, getAccessToken]);

  useEffect(() => {
    fetchNumbers();
  }, [fetchNumbers]);

  const bindNumber = async (inventoryId: number) => {
    const workflowId = Number(workflowInputs[inventoryId]);
    if (!Number.isInteger(workflowId) || workflowId <= 0) {
      toast.error("Enter a valid workflow ID");
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
      toast.success("Inbound workflow bound");
      await fetchNumbers();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to bind workflow");
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
      toast.success("Inbound workflow removed");
      await fetchNumbers();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to unbind workflow");
    } finally {
      setSavingId(null);
    }
  };

  return (
    <div className="container mx-auto px-4 py-8 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold mb-2">Assigned phone numbers</h1>
          <p className="text-muted-foreground">
            Recova-managed numbers assigned to your organization. Bind a number to an
            inbound workflow without exposing carrier credentials.
          </p>
        </div>
        <Button variant="outline" onClick={fetchNumbers} disabled={loading}>
          <RefreshCw className="h-4 w-4 mr-2" /> Refresh
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Numbers</CardTitle>
          <CardDescription>
            Outbound caller IDs and inbound routes controlled by Recova inventory.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="space-y-3">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : numbers.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No Recova-managed numbers are assigned to this organization yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Number</TableHead>
                  <TableHead>Provider</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Inbound workflow</TableHead>
                  <TableHead className="w-[280px]">Bind workflow ID</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {numbers.map((number) => (
                  <TableRow key={number.inventory_id}>
                    <TableCell>
                      <div className="space-y-1">
                        <div className="font-mono">{number.address_masked ?? "Masked"}</div>
                        <div className="text-xs text-muted-foreground">
                          {number.label ?? "No label"} · {number.address_type}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">{number.provider}</Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        <Badge variant={number.is_active ? "secondary" : "outline"}>
                          {number.is_active ? "Active" : "Inactive"}
                        </Badge>
                        {number.is_default_caller_id && <Badge>Default caller</Badge>}
                      </div>
                    </TableCell>
                    <TableCell>
                      {number.inbound_workflow_id ? (
                        <Link
                          href={`/workflow/${number.inbound_workflow_id}`}
                          className="inline-flex items-center gap-1 hover:underline"
                        >
                          #{number.inbound_workflow_id}
                          {number.inbound_workflow_name && (
                            <span className="text-muted-foreground">
                              {number.inbound_workflow_name}
                            </span>
                          )}
                        </Link>
                      ) : (
                        <span className="text-muted-foreground">Unbound</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Input
                          inputMode="numeric"
                          value={workflowInputs[number.inventory_id] ?? ""}
                          onChange={(event) =>
                            setWorkflowInputs((prev) => ({
                              ...prev,
                              [number.inventory_id]: event.target.value,
                            }))
                          }
                          placeholder="Workflow ID"
                          className="h-8"
                        />
                        <Button
                          size="sm"
                          onClick={() => bindNumber(number.inventory_id)}
                          disabled={savingId === number.inventory_id}
                        >
                          <LinkIcon className="h-4 w-4" />
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => unbindNumber(number.inventory_id)}
                          disabled={
                            savingId === number.inventory_id || !number.inbound_workflow_id
                          }
                        >
                          <Unlink className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
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
