"use client";

import { RefreshCw, Upload } from "lucide-react";
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
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/lib/auth";

const API_BASE = process.env.NEXT_PUBLIC_BACKEND_URL ?? "";

type AssignmentMetadata = {
  managed_by: string | null;
  recova_inventory_state: string | null;
  inventory_id: number | null;
  binding_metadata_consistent: boolean;
};

type ReadinessMetadata = {
  contract_version: string | null;
  is_contract_fixture: boolean;
  live_trunk_validated: boolean;
  live_validation_source: string | null;
  live_validation_evidence_id: string | null;
  provider_config_id: string | null;
  phone_number_id: number | null;
  inventory_id: number | null;
  call_attempt_id: string | null;
};


type InventoryNumber = {
  id: number;
  provider: string;
  trunk_group: string | null;
  organization_id: number | null;
  telephony_configuration_id: number | null;
  telephony_phone_number_id: number | null;
  address_masked: string | null;
  address_type: string;
  country_code: string | null;
  label: string | null;
  status: string;
  reservation_expires_at: string | null;
  quarantined_reason: string | null;
  retired_reason: string | null;
  extra_metadata: Record<string, unknown>;
  assignment_metadata: AssignmentMetadata;
  readiness_metadata: ReadinessMetadata;
  created_at: string;
  updated_at: string;
};

type InventoryListResponse = {
  numbers: InventoryNumber[];
  total_count: number;
  limit: number;
  offset: number;
};

type InventoryImportResponse = {
  imported: InventoryNumber[];
  skipped: { address_masked: string; reason: string; inventory_id?: number }[];
};

type AuditItem = {
  id: number;
  action: string;
  from_status: string | null;
  to_status: string | null;
  details: Record<string, unknown>;
  created_at: string;
};

export default function TelephonyNumberInventoryPage() {
  const { user, getAccessToken, loading: authLoading } = useAuth();
  const [numbers, setNumbers] = useState<InventoryNumber[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState<number | null>(null);
  const [importText, setImportText] = useState("");
  const [orgInputs, setOrgInputs] = useState<Record<number, string>>({});
  const [audit, setAudit] = useState<AuditItem[]>([]);

  const fetchNumbers = useCallback(async () => {
    if (authLoading || !user) return;
    setLoading(true);
    try {
      const data = await apiRequest<InventoryListResponse>(
        "/api/v1/telephony-number-inventory?limit=200",
        await getAccessToken(),
      );
      setNumbers(data.numbers ?? []);
      setTotalCount(data.total_count ?? 0);
      setOrgInputs((prev) => ({
        ...Object.fromEntries(
          (data.numbers ?? []).map((number) => [
            number.id,
            number.organization_id ? String(number.organization_id) : "",
          ]),
        ),
        ...prev,
      }));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load inventory");
    } finally {
      setLoading(false);
    }
  }, [authLoading, user, getAccessToken]);

  useEffect(() => {
    fetchNumbers();
  }, [fetchNumbers]);

  const importNumbers = async () => {
    const numbersToImport = importText
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    if (numbersToImport.length === 0) {
      toast.error("Enter at least one phone number");
      return;
    }
    try {
      const result = await apiRequest<InventoryImportResponse>(
        "/api/v1/telephony-number-inventory/import",
        await getAccessToken(),
        {
          method: "POST",
          body: JSON.stringify({
            numbers: numbersToImport.map((address) => ({
              address,
              provider: "jambonz",
              country_code: "KR",
            })),
          }),
        },
      );
      toast.success(
        `Imported ${result.imported.length}, skipped ${result.skipped.length}`,
      );
      setImportText("");
      await fetchNumbers();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to import numbers");
    }
  };

  const transition = async (
    inventoryId: number,
    action: "reserve" | "assign" | "quarantine" | "retire",
  ) => {
    const organizationId = Number(orgInputs[inventoryId]);
    const body: Record<string, unknown> = {};
    if (action === "reserve" || action === "assign") {
      if (!Number.isInteger(organizationId) || organizationId <= 0) {
        toast.error("Enter a valid organization ID");
        return;
      }
      body.organization_id = organizationId;
      if (action === "assign") body.set_default_caller_id = true;
    } else {
      const reason = window.prompt(`Reason to ${action} this number`);
      if (!reason) return;
      body.reason = reason;
    }

    setSavingId(inventoryId);
    try {
      await apiRequest<InventoryNumber>(
        `/api/v1/telephony-number-inventory/${inventoryId}/${action}`,
        await getAccessToken(),
        { method: "POST", body: JSON.stringify(body) },
      );
      toast.success(`Number ${action}d`);
      await fetchNumbers();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : `Failed to ${action} number`);
    } finally {
      setSavingId(null);
    }
  };

  const loadAudit = async (inventoryId: number) => {
    try {
      const data = await apiRequest<{ audit: AuditItem[] }>(
        `/api/v1/telephony-number-inventory/${inventoryId}/audit`,
        await getAccessToken(),
      );
      setAudit(data.audit ?? []);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load audit");
    }
  };

  return (
    <main className="container mx-auto p-6 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold mb-2">Telephony number inventory</h1>
          <p className="text-muted-foreground">
            Import Recova-owned numbers and assign them transactionally to customer
            organizations without exposing the hidden Jambonz carrier configuration.
          </p>
        </div>
        <Button variant="outline" onClick={fetchNumbers} disabled={loading}>
          <RefreshCw className="h-4 w-4 mr-2" /> Refresh
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Import KR numbers</CardTitle>
          <CardDescription>
            One number per line. Numbers are stored as masked/hash/encrypted inventory
            fields; responses never expose raw addresses.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-2">
            <Label htmlFor="inventory-import">Phone numbers</Label>
            <Textarea
              id="inventory-import"
              value={importText}
              onChange={(event) => setImportText(event.target.value)}
              placeholder="07012345678\n+827012345679"
              rows={4}
            />
          </div>
          <Button onClick={importNumbers}>
            <Upload className="h-4 w-4 mr-2" /> Import as Jambonz inventory
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Inventory ({totalCount})</CardTitle>
          <CardDescription>
            Reserve before sales handoff, assign when the customer is ready, and
            quarantine or retire unsafe numbers.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="space-y-3">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Number</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Readiness</TableHead>
                  <TableHead>Organization</TableHead>
                  <TableHead>Backing rows</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {numbers.map((number) => (
                  <TableRow key={number.id}>
                    <TableCell className="font-mono">{number.id}</TableCell>
                    <TableCell>
                      <div className="space-y-1">
                        <div className="font-mono">{number.address_masked ?? "Masked"}</div>
                        <div className="text-xs text-muted-foreground">
                          {number.provider} · {number.address_type} · {number.country_code ?? "-"}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="space-y-1">
                        <Badge
                          variant={
                            number.status === "assigned" ? "secondary" : "outline"
                          }
                        >
                          {number.status}
                        </Badge>
                        {number.quarantined_reason && (
                          <div className="text-xs text-muted-foreground">
                            Quarantine: {number.quarantined_reason}
                          </div>
                        )}
                        {number.retired_reason && (
                          <div className="text-xs text-muted-foreground">
                            Retired: {number.retired_reason}
                          </div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="space-y-1 text-xs text-muted-foreground">
                        <Badge
                          variant={
                            number.readiness_metadata.live_trunk_validated
                              ? "secondary"
                              : "outline"
                          }
                        >
                          {number.readiness_metadata.live_trunk_validated
                            ? "Live evidence"
                            : number.readiness_metadata.is_contract_fixture
                              ? "Fixture only"
                              : "No live evidence"}
                        </Badge>
                        {number.readiness_metadata.contract_version && (
                          <div>
                            Contract {number.readiness_metadata.contract_version}
                          </div>
                        )}
                        {number.readiness_metadata.live_validation_source && (
                          <div>
                            {number.readiness_metadata.live_validation_source}
                            {number.readiness_metadata.live_validation_evidence_id
                              ? ` · ${number.readiness_metadata.live_validation_evidence_id}`
                              : ""}
                          </div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Input
                        inputMode="numeric"
                        className="h-8 w-28"
                        placeholder="Org ID"
                        value={orgInputs[number.id] ?? ""}
                        onChange={(event) =>
                          setOrgInputs((prev) => ({
                            ...prev,
                            [number.id]: event.target.value,
                          }))
                        }
                      />
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      <div className="space-y-1">
                        <div>
                          cfg {number.telephony_configuration_id ?? "-"} / phone{" "}
                          {number.telephony_phone_number_id ?? "-"}
                        </div>
                        <div>trunk {number.trunk_group ?? "-"}</div>
                        <div>
                          marker {number.assignment_metadata.managed_by ?? "-"} /
                          inv {number.assignment_metadata.inventory_id ?? "-"}
                        </div>
                        <Badge
                          variant={
                            number.assignment_metadata.binding_metadata_consistent
                              ? "secondary"
                              : "outline"
                          }
                        >
                          {number.assignment_metadata.binding_metadata_consistent
                            ? "marker complete"
                            : "marker incomplete"}
                        </Badge>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-1">
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={savingId === number.id}
                          onClick={() => transition(number.id, "reserve")}
                        >
                          Reserve
                        </Button>
                        <Button
                          size="sm"
                          disabled={savingId === number.id}
                          onClick={() => transition(number.id, "assign")}
                        >
                          Assign
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={savingId === number.id}
                          onClick={() => transition(number.id, "quarantine")}
                        >
                          Quarantine
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={savingId === number.id}
                          onClick={() => transition(number.id, "retire")}
                        >
                          Retire
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => loadAudit(number.id)}>
                          Audit
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

      {audit.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Latest audit</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="max-h-72 overflow-auto rounded bg-muted p-3 text-xs">
              {JSON.stringify(audit, null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}
    </main>
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
