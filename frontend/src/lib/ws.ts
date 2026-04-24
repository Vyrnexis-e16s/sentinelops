const env = (globalThis as { process?: { env?: Record<string, string | undefined> } })
  .process?.env;

/**
 * WebSocket URL for the backend `/ws/alerts` stream.
 * `NEXT_PUBLIC_WS_URL` can be a full base such as `ws://localhost:8000` (no path),
 * or include `/ws` — we always append `/alerts?token=…`.
 */
export function getAlertStreamUrl(accessToken: string): string {
  const explicit = env?.NEXT_PUBLIC_WS_URL;
  if (explicit) {
    const base = explicit.replace(/\/$/, "");
    if (base.endsWith("/alerts")) {
      return `${base}?token=${encodeURIComponent(accessToken)}`;
    }
    if (base.endsWith("/ws")) {
      return `${base}/alerts?token=${encodeURIComponent(accessToken)}`;
    }
    return `${base}/ws/alerts?token=${encodeURIComponent(accessToken)}`;
  }
  const api = env?.NEXT_PUBLIC_API_URL || "http://localhost:8000";
  const ws = api.replace(/^https:/i, "wss:").replace(/^http:/i, "ws:");
  return `${ws}/ws/alerts?token=${encodeURIComponent(accessToken)}`;
}
