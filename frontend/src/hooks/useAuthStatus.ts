import { useEffect, useState } from "react";
import {
  AUTH_CHANGED_EVENT,
  getAccessToken,
  type AuthChangedDetail
} from "@/lib/auth";
import { runDeferred } from "@/lib/schedule-deferred";

/**
 * Tracks whether a JWT (or `NEXT_PUBLIC_DEV_TOKEN`) is present.
 * Subscribes to the same `sentinelops:auth-changed` event as `Topbar` so
 * the UI updates in-tab immediately after sign-in or sign-out.
 */
export function useAuthStatus(): boolean {
  const [authed, setAuthed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const t = runDeferred(() => {
      if (!cancelled) setAuthed(!!getAccessToken());
    });
    const onStorage = (e: StorageEvent) => {
      if (e.key === "sentinelops_access_token") {
        setAuthed(!!getAccessToken());
      }
    };
    const onAuth = (e: Event) => {
      const d = (e as CustomEvent<AuthChangedDetail>).detail;
      setAuthed(d?.hasToken ?? !!getAccessToken());
    };
    if (typeof window !== "undefined") {
      window.addEventListener("storage", onStorage);
      window.addEventListener(AUTH_CHANGED_EVENT, onAuth);
    }
    return () => {
      cancelled = true;
      clearTimeout(t);
      if (typeof window !== "undefined") {
        window.removeEventListener("storage", onStorage);
        window.removeEventListener(AUTH_CHANGED_EVENT, onAuth);
      }
    };
  }, []);

  return authed;
}
