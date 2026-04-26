/**
 * 401 handling: JWT expires (default ~JWT_EXPIRE_MINUTES); show a clear path to re-auth.
 */
import type { ApiError } from "@/lib/api";
import { clearAccessToken } from "@/lib/auth";

export function isUnauthorized(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as ApiError).status === 401;
}

/** Human-readable string from API errors; masks raw JWT text for 401. */
export function getApiErrorMessage(err: unknown, fallback: string): string {
  if (!err || typeof err !== "object" || !("status" in err)) return fallback;
  const a = err as ApiError;
  if (a.status === 401) {
    return "Your session expired. Sign in again to continue.";
  }
  return a.detail || fallback;
}

/**
 * Clears the token and sends the user to /login with return URL.
 * Call when any authenticated API returns 401.
 */
export function redirectToReauth() {
  if (typeof window === "undefined") return;
  clearAccessToken();
  const next = `${window.location.pathname}${window.location.search || ""}` || "/dashboard";
  window.location.replace(
    `/login?next=${encodeURIComponent(next === "/login" ? "/dashboard" : next)}&session=expired`
  );
}
