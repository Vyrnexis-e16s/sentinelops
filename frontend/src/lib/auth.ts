const TOKEN_KEY = "sentinelops_access_token";

function readNextPublic(name: "NEXT_PUBLIC_DEV_TOKEN"): string | null {
  const p = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
  const t = p?.env?.[name];
  return typeof t === "string" && t.length > 0 ? t : null;
}

/**
 * After WebAuthn login, persist the JWT here so `fetch` and WebSocket can attach it.
 * Also accept `NEXT_PUBLIC_DEV_TOKEN` in `.env.local` for local development.
 */
export function getAccessToken(): string | null {
  if (typeof window === "undefined") {
    return readNextPublic("NEXT_PUBLIC_DEV_TOKEN");
  }
  return localStorage.getItem(TOKEN_KEY) || readNextPublic("NEXT_PUBLIC_DEV_TOKEN");
}

export function setAccessToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearAccessToken() {
  localStorage.removeItem(TOKEN_KEY);
}
