"use client";

import { useEffect, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { api, type Alert, type ApiError, type Paginated } from "@/lib/api";
import { getAccessToken } from "@/lib/auth";
import { getAlertStreamUrl } from "@/lib/ws";
import { runDeferred } from "@/lib/schedule-deferred";

type Live = { id: string; title: string; detail: string; severity: string };

const sevColor = (s: string) =>
  s === "high" || s === "critical"
    ? "text-danger"
    : s === "medium"
      ? "text-warn"
      : "text-ok";

const NO_TOKEN_MSG =
  "Add JWT in localStorage sentinelops_access_token for the WebSocket alert stream.";

type PanelMode = "empty" | "api" | "live" | "error" | "unauthenticated";

export function LiveAlertsPanel() {
  const [rows, setRows] = useState<Live[]>([]);
  const [mode, setMode] = useState<PanelMode>("empty");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [wsNote, setWsNote] = useState<string | null>(null);
  const hasToken = Boolean(getAccessToken());
  const tokenHint = !hasToken ? NO_TOKEN_MSG : null;

  useEffect(() => {
    let cancelled = false;

    const loadRest = async () => {
      try {
        const p = await api.get<Paginated<Alert>>("/api/v1/siem/alerts?size=5");
        if (cancelled) return;
        if (!p.items.length) {
          setRows([]);
          setMode("empty");
          setLoadError(null);
          return;
        }
        setMode("api");
        setLoadError(null);
        setRows(
          p.items.map((a) => ({
            id: a.id.slice(0, 8),
            title: a.rule_name || (a.alert_kind === "threat_intel" ? "Threat intel (IOC)" : "Alert"),
            severity: a.score >= 7 ? "high" : a.score >= 4 ? "medium" : "low",
            detail: `${a.status} · score ${a.score.toFixed(2)}`
          }))
        );
      } catch (e) {
        if (cancelled) return;
        const a = e as ApiError;
        if (a.status === 401) {
          setMode("unauthenticated");
          setRows([]);
          setLoadError("Sign in to load alerts from the API.");
        } else {
          setMode("error");
          setRows([]);
          setLoadError(a.detail || "Could not load alerts.");
        }
      }
    };

    const start = runDeferred(() => {
      void loadRest();
    });

    const token = getAccessToken();
    let ws: WebSocket | undefined;
    if (token) {
      try {
        ws = new WebSocket(getAlertStreamUrl(token));
      } catch {
        setWsNote("Could not open WebSocket URL.");
      }
    }
    if (!ws) {
      return () => {
        cancelled = true;
        clearTimeout(start);
      };
    }

    ws.onopen = () => {
      if (!cancelled) setMode("live");
    };
    ws.onmessage = (ev) => {
      try {
        const j = JSON.parse(ev.data as string) as {
          id?: string;
          rule?: string;
          severity?: string;
          score?: number;
        };
        const id = (j.id || "").slice(0, 8) || "live";
        const title = j.rule || "Incoming alert";
        const severity =
          j.severity === "high" || j.severity === "critical" ? "high" : "medium";
        const detail = `live · score ${typeof j.score === "number" ? j.score.toFixed(2) : "—"}`;
        setMode("live");
        setRows((prev: Live[]) => [{ id, title, severity, detail }, ...prev].slice(0, 8));
      } catch {
        /* ignore */
      }
    };
    ws.onerror = () => setWsNote("WebSocket error (check Redis + token).");
    ws.onclose = () => {};

    return () => {
      cancelled = true;
      clearTimeout(start);
      ws?.close();
    };
  }, []);

  const modeLabel =
    mode === "live" ? "live · ws" : mode === "api" ? "rest" : mode === "empty" ? "no rows" : mode;

  return (
    <div className="glass rounded-xl p-4">
      <div className="flex items-center justify-between mb-3 gap-2">
        <div className="text-sm font-semibold flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-warn" /> Recent alerts
        </div>
        <div className="text-[10px] text-muted">{modeLabel}</div>
      </div>
      {(tokenHint || wsNote) && (
        <div className="text-[10px] text-muted mb-2">{tokenHint ?? wsNote}</div>
      )}
      {loadError && <div className="text-[11px] text-warn/90 mb-2">{loadError}</div>}
      <ul className="space-y-2 text-sm">
        {rows.length === 0 && !loadError && mode === "empty" && (
          <li className="text-xs text-muted px-1 py-2">
            No alerts yet. Ingest events into the SIEM, or use `make seed` in a dev environment to load
            development telemetry.
          </li>
        )}
        {rows.map((a: Live) => (
          <li
            key={a.id + a.detail}
            className="flex items-start gap-3 rounded-md border border-border/50 px-3 py-2 hover:border-accent/50 transition-colors"
          >
            <span
              className={`mt-1 inline-block h-2 w-2 rounded-full ${sevColor(a.severity).replace("text", "bg")}`}
            />
            <div className="min-w-0">
              <div className="truncate">{a.title}</div>
              <div className="text-[11px] text-muted">
                <span className="font-mono">{a.id}</span> · {a.detail}
              </div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
