const TOKEN_KEY = "sentinelops_access_token";

/**
 * After WebAuthn login, persist the JWT here so `fetch` and WebSocket can attach it.
 * Also accept `NEXT_PUBLIC_DEV_TOKEN` in `.env.local` for local UI-only demos.
 */
export function getAccessToken(): string | null {
  if (typeof window === "undefined") {
    return process.env.NEXT_PUBLIC_DEV_TOKEN || null;
  }
  return (
    localStorage.getItem(TOKEN_KEY) || process.env.NEXT_PUBLIC_DEV_TOKEN || null
  );
}

export function setAccessToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearAccessToken() {
  localStorage.removeItem(TOKEN_KEY);
}
