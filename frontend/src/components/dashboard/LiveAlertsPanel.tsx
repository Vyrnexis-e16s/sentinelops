"use client";

import { useEffect, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { api, type Alert, type ApiError, type Paginated } from "@/lib/api";
import { getAccessToken } from "@/lib/auth";
import { getAlertStreamUrl } from "@/lib/ws";
import { runDeferred } from "@/lib/schedule-deferred";

type Live = {
  id: string;
  title: string;
  detail: string;
  severity: string;
  ts: number;
};

const sevColor = (s: string) =>
  s === "high" || s === "critical"
    ? "text-danger"
    : s === "medium"
      ? "text-warn"
      : "text-ok";

type PanelMode = "loading" | "empty" | "rest" | "live" | "error" | "unauthenticated";

const MODE_LABEL: Record<PanelMode, string> = {
  loading: "loading",
  empty: "no alerts",
  rest: "api",
  live: "live ws",
  error: "error",
  unauthenticated: "sign in"
};

function toLive(a: Alert): Live {
  return {
    id: a.id.slice(0, 8),
    title:
      a.rule_name ||
      (a.alert_kind === "threat_intel" ? "Threat intel match" : "SIEM alert"),
    severity: a.score >= 7 ? "high" : a.score >= 4 ? "medium" : "low",
    detail: `${a.status} · score ${a.score.toFixed(2)}`,
    ts: a.created_at ? Date.parse(a.created_at) : Date.now()
  };
}

const POLL_INTERVAL_MS = 15000;

export function LiveAlertsPanel() {
  const [rows, setRows] = useState<Live[]>([]);
  const [mode, setMode] = useState<PanelMode>("loading");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [wsNote, setWsNote] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const loadRest = async (): Promise<void> => {
      try {
        const p = await api.get<Paginated<Alert>>("/api/v1/siem/alerts?size=8");
        if (cancelled) return;
        const next = p.items.map(toLive);
        setRows(next);
        setLoadError(null);
        setMode((prev) => (prev === "live" ? "live" : next.length ? "rest" : "empty"));
      } catch (e) {
        if (cancelled) return;
        const a = e as ApiError;
        if (a.status === 401) {
          setMode("unauthenticated");
          setRows([]);
          setLoadError("Sign in with your passkey to read alerts from the API.");
        } else {
          setMode("error");
          setRows([]);
          setLoadError(a.detail || "Could not load alerts from /api/v1/siem/alerts.");
        }
      }
    };

    const kick = runDeferred(() => {
      void loadRest();
    });
    const poll = setInterval(() => {
      void loadRest();
    }, POLL_INTERVAL_MS);

    const token = getAccessToken();
    let ws: WebSocket | undefined;
    let wsNoteTimer: ReturnType<typeof setTimeout> | undefined;
    if (!token) {
      wsNoteTimer = runDeferred(() => {
        if (!cancelled) {
          setWsNote(
            "No access token found. REST polling every 15s; sign in with your passkey to receive the WebSocket stream."
          );
        }
      });
    } else {
      try {
        ws = new WebSocket(getAlertStreamUrl(token));
      } catch {
        wsNoteTimer = runDeferred(() => {
          if (!cancelled) setWsNote("Could not open WebSocket URL.");
        });
      }
    }

    if (!ws) {
      return () => {
        cancelled = true;
        clearTimeout(kick);
        clearInterval(poll);
        if (wsNoteTimer) clearTimeout(wsNoteTimer);
      };
    }

    ws.onopen = () => {
      if (!cancelled) {
        setMode("live");
        setWsNote(null);
      }
    };
    ws.onmessage = (ev) => {
      try {
        const j = JSON.parse(ev.data as string) as Partial<Alert> & {
          rule?: string;
          severity?: string;
        };
        const incoming: Live = {
          id: (j.id || "").slice(0, 8) || `evt-${Date.now()}`,
          title: j.rule || j.rule_name || "Incoming alert",
          severity:
            j.severity === "high" || j.severity === "critical"
              ? "high"
              : j.severity === "medium"
                ? "medium"
                : typeof j.score === "number" && j.score >= 7
                  ? "high"
                  : typeof j.score === "number" && j.score >= 4
                    ? "medium"
                    : "low",
          detail: `live · score ${typeof j.score === "number" ? j.score.toFixed(2) : "—"}`,
          ts: Date.now()
        };
        setMode("live");
        setRows((prev) => [incoming, ...prev].slice(0, 8));
      } catch {
        /* ignore malformed frames */
      }
    };
    ws.onerror = () => {
      if (!cancelled) setWsNote("WebSocket error. Falling back to REST polling.");
    };
    ws.onclose = () => {
      if (!cancelled) setMode((prev) => (prev === "live" ? "rest" : prev));
    };

    return () => {
      cancelled = true;
      clearTimeout(kick);
      clearInterval(poll);
      if (wsNoteTimer) clearTimeout(wsNoteTimer);
      ws?.close();
    };
  }, []);

  return (
    <div className="glass rounded-xl p-4">
      <div className="flex items-center justify-between mb-3 gap-2">
        <div className="text-sm font-semibold flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-warn" /> Recent alerts
        </div>
        <div className="text-[10px] text-muted uppercase tracking-wider">
          {MODE_LABEL[mode]}
        </div>
      </div>
      {wsNote && <div className="text-[10px] text-muted mb-2">{wsNote}</div>}
      {loadError && <div className="text-[11px] text-warn/90 mb-2">{loadError}</div>}
      <ul className="space-y-2 text-sm">
        {rows.length === 0 && mode === "loading" && (
          <li className="text-xs text-muted px-1 py-2">Loading alerts…</li>
        )}
        {rows.length === 0 && mode === "empty" && (
          <li className="text-xs text-muted px-1 py-2">
            No alerts yet. Ingest SIEM events via POST /api/v1/siem/events or ship logs from
            Filebeat/Vector to the ingest endpoint; matching rules will populate this feed.
          </li>
        )}
        {rows.map((a) => (
          <li
            key={`${a.id}-${a.ts}`}
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
