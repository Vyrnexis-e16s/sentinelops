/** Minimal JWT `exp` check without pulling a dependency. */

function b64urlToJson(segment: string): Record<string, unknown> | null {
  try {
    const b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    if (typeof atob === "undefined") return null;
    const json = atob(pad);
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * @param skewSec — treat token as expired this many seconds before `exp` (clock skew)
 */
export function isJwtExpired(token: string, skewSec = 60): boolean {
  const parts = token.split(".");
  if (parts.length < 2) return false;
  const p = b64urlToJson(parts[1]);
  if (!p) return false;
  const exp = p.exp;
  if (typeof exp !== "number") return false;
  return Date.now() / 1000 >= exp - skewSec;
}

export function isLikelyJwt(token: string): boolean {
  const parts = token.split(".");
  return parts.length === 3 && parts.every((p) => p.length > 0);
}
