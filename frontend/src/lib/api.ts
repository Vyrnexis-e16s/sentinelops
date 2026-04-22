/**
 * Tiny typed fetch wrapper. Talks to the FastAPI backend through the Next.js
 * rewrite, so the same URL works in dev (rewritten) and prod (same-origin).
 */

export type ApiError = { status: number; detail: string };

async function request<T>(
  path: string,
  init: RequestInit = {}
): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...(init.headers || {})
    },
    credentials: "include"
  });
  if (!res.ok) {
    let detail: string;
    try {
      const body = await res.json();
      detail = body?.detail || res.statusText;
    } catch {
      detail = res.statusText;
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
  score: number;
  status: "new" | "ack" | "resolved" | "false_positive";
  created_at: string;
};

export type Inference = {
  id: string;
  timestamp: string;
  prediction: string;
  probability: number;
  label: "benign" | "attack";
  attack_class: string | null;
};

export type VaultObject = {
  id: string;
  name: string;
  size: number;
  mime_type: string;
  created_at: string;
};
