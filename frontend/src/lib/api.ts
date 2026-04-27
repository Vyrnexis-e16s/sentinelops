/**
 * Tiny typed fetch wrapper. Talks to the FastAPI backend through the Next.js
 * rewrite, so the same URL works in dev (rewritten) and prod (same-origin).
 */

import { getAccessToken } from "@/lib/auth";

export type ApiError = { status: number; detail: string };

async function request<T>(
  path: string,
  init: RequestInit = {}
): Promise<T> {
  const token = getAccessToken();
  const res = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init.headers || {})
    },
    credentials: "include"
  });
  if (!res.ok) {
    let detail: string;
    try {
      const body = await res.json();
      detail =
        typeof body?.detail === "string"
          ? body.detail
          : typeof body?.message === "string"
            ? body.message
            : body?.detail
              ? JSON.stringify(body.detail)
              : res.statusText;
    } catch {
      detail = res.statusText;
    }
    // Auth routes can 401 for wrong password — keep their detail. Normalize JWT/session 401s elsewhere.
    const isAuthCall = /\/api\/v1\/auth\//.test(path);
    if (
      res.status === 401 &&
      !isAuthCall &&
      /invalid token|signature|expired|missing authorization|not authenticated|bearer|jwt/i.test(detail)
    ) {
      detail = "Your session expired. Please sign in again.";
    }
    if (res.status >= 500 && /^an unexpected error occurred$/i.test(detail.trim())) {
      detail =
        "Server error — check API logs, database, and run `alembic upgrade head` if tables are missing. " +
        "The VAPT page can still load partial data if only one service fails.";
    }
    const err: ApiError = { status: res.status, detail };
    throw err;
  }
  if (res.status === 204) return undefined as unknown as T;
  return (await res.json()) as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path, { method: "GET" }),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PUT", body: body ? JSON.stringify(body) : undefined }),
  del: <T>(path: string) => request<T>(path, { method: "DELETE" })
};

// ---------- module-typed wrappers ----------

export type Alert = {
  id: string;
  event_id: string;
  rule_id: string | null;
  rule_name: string | null;
  score: number;
  status: "new" | "ack" | "resolved" | "false_positive";
  created_at: string;
  alert_kind?: string | null;
};

export type Paginated<T> = { items: T[]; page: number; size: number; total: number };

export type ReconTarget = {
  id: string;
  kind: string;
  value: string;
  created_at: string;
  owner_id: string;
};

export type ReconJob = {
  id: string;
  target_id: string;
  kind: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  result_json: Record<string, unknown>;
};

export type ReconFinding = {
  id: string;
  job_id: string;
  severity: string;
  title: string;
  description: string;
  evidence_json: Record<string, unknown>;
};

export type Inference = {
  id: string;
  timestamp: string;
  prediction: string;
  probability: number;
  label: string;
  attack_class: string | null;
};

export type VaultObject = {
  id: string;
  name: string;
  size: number;
  mime_type: string;
  created_at: string;
};

export type VaultAuditEntry = {
  id: string;
  timestamp: string;
  actor_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  metadata: Record<string, unknown>;
  entry_hash: string;
};

export type IdsModelInfo = {
  trained_at: string | null;
  accuracy: number | null;
  feature_count: number;
  feature_list: string[];
  classes: string[];
  artifact_present: boolean;
  artifact_path: string;
  notes: string | null;
};

export type IdsInferenceResult = Inference & {
  explanation?: Record<string, unknown> | null;
};

/** Multipart upload (does not set Content-Type so the browser can set the boundary). */
export async function vaultUpload(file: File): Promise<VaultObject> {
  const token = getAccessToken();
  const fd = new FormData();
  fd.append("file", file);
  const res = await fetch("/api/v1/vault/files", {
    method: "POST",
    body: fd,
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    credentials: "include"
  });
  if (!res.ok) {
    let detail: string;
    try {
      const body = (await res.json()) as { detail?: string; message?: string };
      detail =
        typeof body?.detail === "string"
          ? body.detail
          : typeof body?.message === "string"
            ? body.message
            : res.statusText;
    } catch {
      detail = res.statusText;
    }
    if (res.status === 401) {
      detail = "Your session expired. Please sign in again.";
    }
    throw { status: res.status, detail } satisfies ApiError;
  }
  return (await res.json()) as VaultObject;
}

export async function vaultDownloadBlob(objectId: string): Promise<Blob> {
  const token = getAccessToken();
  const res = await fetch(`/api/v1/vault/files/${objectId}/download`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    credentials: "include"
  });
  if (!res.ok) {
    let detail: string;
    try {
      const body = (await res.json()) as { detail?: string; message?: string };
      detail =
        typeof body?.detail === "string"
          ? body.detail
          : typeof body?.message === "string"
            ? body.message
            : res.statusText;
    } catch {
      detail = res.statusText;
    }
    if (res.status === 401) {
      detail = "Your session expired. Please sign in again.";
    }
    throw { status: res.status, detail } satisfies ApiError;
  }
  return res.blob();
}

/** GET /api/v1/platform/status — unauthenticated ops probe. */
export type PlatformStatus = {
  database: string;
  redis: string;
  ids_model: string;
  modules: string[];
};

export type VaptSurface = {
  siem_alerts_new: number;
  siem_alerts_ack: number;
  siem_events_24h: number;
  recon_jobs_queued: number;
  recon_jobs_running: number;
  recon_findings_total: number;
  ids_inferences_24h: number;
  ids_attacks_24h: number;
  vault_files: number;
  investigations_open: number;
};

export type VaptBrief = {
  id: string;
  title: string;
  body: string;
  created_at: string;
};

export type LlmSummarizeResult = { summary: string; model: string };

export type MitreFoundationItem = { id: string; name: string; tactic: string };
export type MitreFoundationOut = { items: MitreFoundationItem[] };

export type VaptTtpMemory = {
  id: string;
  technique_id: string;
  name: string;
  body: string;
  narrative: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type VaptGraphEdge = {
  id: string;
  from_technique_id: string;
  to_technique_id: string;
  relation: string;
  note: string;
  created_at: string;
};

export type VaptCypherExport = { cypher: string; node_count: number; edge_count: number };

export type VaptAnalystFeedback = {
  id: string;
  ref_type: "ttp" | "edge" | "brief" | "other";
  ref_key: string;
  body: string;
  created_at: string;
};

export type VaptOrchestrateResult = { jobs: { id: string; kind: string; status: string }[]; target_id: string };

const RECON_KINDS = [
  "subdomain",
  "port",
  "cve",
  "webfuzz",
  "dns",
  "httprobe",
  "http_headers",
  "tls_cert"
] as const;

export { RECON_KINDS };
