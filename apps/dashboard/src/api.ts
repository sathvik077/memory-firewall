/** Thin API client.
 *
 *  Identity is a bearer token and nothing else. The dashboard holds the demo tokens that
 *  `make setup` generated and sends one per request; it never sends a `tenant_id`, `principal` or
 *  `trust_tier` field, and if it did the server would strip and audit it. Switching the "Acting as"
 *  selector switches the token, which is the only way to change who you are.
 */

import type {
  ConflictRow,
  ContextPack,
  ExposureRow,
  Health,
  IngestResult,
  LedgerRow,
  QuarantineItem,
  ReplayResult,
  RetrievalResult,
  ScenarioMeta,
  ScenarioResult,
  SnapshotRow,
  SourceRow,
  Stats,
  UnguardedComparison,
  WhoAmI,
} from "./types.js";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export interface Principal {
  id: string;
  label: string;
  token: string;
  role: string;
  tenant: string;
}

let activeToken = "";

export function setToken(token: string): void {
  activeToken = token;
}

async function request<T>(
  path: string,
  options: { method?: string; body?: unknown; query?: Record<string, string | number> } = {},
): Promise<T> {
  const url = new URL(path, window.location.origin);
  for (const [key, value] of Object.entries(options.query ?? {})) {
    url.searchParams.set(key, String(value));
  }
  const headers: Record<string, string> = { Accept: "application/json" };
  if (activeToken) headers.Authorization = `Bearer ${activeToken}`;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";

  let response: Response;
  try {
    response = await fetch(url.toString(), {
      method: options.method ?? "GET",
      headers,
      body: options.body === undefined ? null : JSON.stringify(options.body),
    });
  } catch (cause) {
    throw new ApiError(0, "network_error", `cannot reach the API at ${url.origin}`);
  }

  const text = await response.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = { message: text.slice(0, 400) };
    }
  }
  if (!response.ok) {
    const detail = (payload as { detail?: unknown; code?: string; message?: string }) ?? {};
    const inner = (detail.detail ?? detail) as { code?: string; message?: string };
    throw new ApiError(
      response.status,
      inner.code ?? "error",
      inner.message ?? `request failed with status ${response.status}`,
    );
  }
  return payload as T;
}

export const api = {
  health: () => request<Health>("/healthz"),
  whoami: () => request<WhoAmI>("/api/whoami"),
  stats: () => request<Stats>("/api/stats"),
  sources: () => request<{ sources: SourceRow[] }>("/api/sources"),
  revokeSource: (id: string, reason: string) =>
    request<Record<string, unknown>>(`/api/sources/${encodeURIComponent(id)}/revoke`, {
      method: "POST",
      body: { reason },
    }),
  ingest: (body: { source_id: string; text: string; title?: string }) =>
    request<IngestResult>("/api/documents", { method: "POST", body }),
  retrieve: (body: {
    query: string;
    limit?: number;
    as_of_valid?: string;
    as_of_recorded?: string;
    include_trace?: boolean;
  }) => request<RetrievalResult>("/api/retrieve", { method: "POST", body }),
  contextPack: (body: { query: string; limit?: number }) =>
    request<ContextPack>("/api/context-packs", { method: "POST", body }),
  quarantine: () => request<{ items: QuarantineItem[]; count: number }>("/api/quarantine"),
  review: (chunkId: string, decision: "approve" | "reject", reason: string) =>
    request<Record<string, unknown>>(
      `/api/quarantine/${encodeURIComponent(chunkId)}/${decision}`,
      { method: "POST", body: { reason } },
    ),
  conflicts: () => request<{ items: ConflictRow[]; count: number; note: string }>("/api/conflicts"),
  resolveConflict: (id: string, resolution: string, reason: string) =>
    request<Record<string, unknown>>(`/api/conflicts/${encodeURIComponent(id)}/resolve`, {
      method: "POST",
      body: { resolution, reason },
    }),
  ledger: () => request<{ items: LedgerRow[] }>("/api/ledger"),
  exposures: () => request<{ items: ExposureRow[] }>("/api/exposures"),
  snapshots: () => request<{ items: SnapshotRow[] }>("/api/snapshots"),
  createSnapshot: (body: { label: string; note?: string; as_of_valid?: string }) =>
    request<SnapshotRow>("/api/snapshots", { method: "POST", body }),
  replay: (id: string, query: string) =>
    request<ReplayResult>(`/api/snapshots/${encodeURIComponent(id)}/diff`, {
      method: "POST",
      body: { query },
    }),
  scenarios: () => request<{ items: ScenarioMeta[]; note: string }>("/api/scenarios"),
  runScenario: (scenarioId: string) =>
    request<ScenarioResult>("/api/scenarios/run", { method: "POST", body: { scenario_id: scenarioId } }),
  unguardedComparison: (query: string) =>
    request<UnguardedComparison>("/api/demo/unguarded-comparison", {
      method: "POST",
      body: { query },
    }),
  principals: () => request<{ items: Principal[] }>("/api/dev/principals"),
};
