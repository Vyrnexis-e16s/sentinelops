import { isJwtExpired, isLikelyJwt } from "@/lib/jwt-helpers";

const TOKEN_KEY = "sentinelops_access_token";

/** Custom DOM event fired whenever the access token is set or cleared.
 *  We need this because the standard `storage` event only fires in *other*
 *  tabs/windows — never in the tab that mutated localStorage. Listening for
 *  this in addition to `storage` lets the Topbar (and any other consumer)
 *  react instantly in the same tab right after sign-in / sign-out. */
export const AUTH_CHANGED_EVENT = "sentinelops:auth-changed";

export type AuthChangedDetail = { hasToken: boolean };

function emitAuthChanged(hasToken: boolean) {
  if (typeof window === "undefined") return;
  window.dispatchEvent(
    new CustomEvent<AuthChangedDetail>(AUTH_CHANGED_EVENT, {
      detail: { hasToken }
    })
  );
}

function readNextPublic(name: "NEXT_PUBLIC_DEV_TOKEN"): string | null {
  const p = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
  const t = p?.env?.[name];
  return typeof t === "string" && t.length > 0 ? t : null;
}

/**
 * After WebAuthn login, persist the JWT here so `fetch` and WebSocket can attach it.
 * Also accept `NEXT_PUBLIC_DEV_TOKEN` in `.env.local` for local development.
 */
function freshTokenOrNull(raw: string | null): string | null {
  if (!raw || !raw.trim()) return null;
  const t = raw.trim();
  if (isLikelyJwt(t) && isJwtExpired(t)) {
    return null;
  }
  return t;
}

export function getAccessToken(): string | null {
  if (typeof window === "undefined") {
    return freshTokenOrNull(readNextPublic("NEXT_PUBLIC_DEV_TOKEN"));
  }
  const fromLs = localStorage.getItem(TOKEN_KEY);
  const a = freshTokenOrNull(fromLs);
  if (fromLs && a === null && isLikelyJwt(fromLs)) {
    clearAccessToken();
  }
  if (a) return a;
  return freshTokenOrNull(readNextPublic("NEXT_PUBLIC_DEV_TOKEN"));
}

export function setAccessToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
  emitAuthChanged(true);
}

export function clearAccessToken() {
  localStorage.removeItem(TOKEN_KEY);
  emitAuthChanged(false);
}
