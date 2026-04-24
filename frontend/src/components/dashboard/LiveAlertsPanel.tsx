"use client";

import { useEffect, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { api, type Alert, type Paginated } from "@/lib/api";
import { getAccessToken } from "@/lib/auth";
import { getAlertStreamUrl } from "@/lib/ws";

type Live = { id: string; title: string; detail: string; severity: string };

const sevColor = (s: string) =>
  s === "high" || s === "critical"
    ? "text-danger"
    : s === "medium"
      ? "text-warn"
      : "text-ok";

const NO_TOKEN_MSG =
  "Set JWT in localStorage sentinelops_access_token for live WebSocket alerts.";

export function LiveAlertsPanel() {
  const [rows, setRows] = useState<Live[]>([]);
  const [mode, setMode] = useState<"sample" | "api" | "live">("sample");
  const [wsNote, setWsNote] = useState<string | null>(null);
  const hasToken = Boolean(getAccessToken());
  const tokenHint = !hasToken ? NO_TOKEN_MSG : null;

  useEffect(() => {
    const sample: Live[] = [
      {
        id: "a-7841",
        title: "SSH brute force from 203.0.113.4",
        severity: "high",
        detail: "sample · shown until API data loads"
      },
      {
        id: "a-7840",
        title: "Suspicious PowerShell -enc payload",
        severity: "medium",
        detail: "sample"
      }
    ];

    let cancelled = false;
    const load = async () => {
      try {
        const p = await api.get<Paginated<Alert>>("/api/v1/siem/alerts?size=5");
        if (cancelled || !p.items.length) {
          setRows(sample);
          return;
        }
        setMode("api");
        setRows(
          p.items.map((a) => ({
            id: a.id.slice(0, 8),
            title: a.rule_name || (a.alert_kind === "threat_intel" ? "Threat intel (IOC)" : "Alert"),
            severity: a.score >= 7 ? "high" : a.score >= 4 ? "medium" : "low",
            detail: `${a.status} · score ${a.score.toFixed(2)}`
          }))
        );
      } catch {
        if (!cancelled) {
          setRows(sample);
          setMode("sample");
        }
      }
    };
    void load();

    const token = getAccessToken();
    if (!token) {
      return () => {
        cancelled = true;
      };
    }

    let ws: WebSocket | undefined;
    try {
      ws = new WebSocket(getAlertStreamUrl(token));
    } catch {
      queueMicrotask(() => {
        if (!cancelled) setWsNote("Could not open WebSocket URL.");
      });
      return () => {
        cancelled = true;
      };
    }

    ws.onopen = () => setMode("live");
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
        setRows((prev: Live[]) => [{ id, title, severity, detail }, ...prev].slice(0, 8));
      } catch {
        /* ignore */
      }
    };
    ws.onerror = () => setWsNote("WebSocket error (check Redis + token).");
    ws.onclose = () => {};

    return () => {
      cancelled = true;
      ws?.close();
    };
  }, []);

  return (
    <div className="glass rounded-xl p-4">
      <div className="flex items-center justify-between mb-3 gap-2">
        <div className="text-sm font-semibold flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-warn" /> Recent alerts
        </div>
        <div className="text-[10px] text-muted">
          {mode === "live" ? "live · ws" : mode === "api" ? "rest" : "sample"}
        </div>
      </div>
      {(tokenHint || wsNote) && (
        <div className="text-[10px] text-muted mb-2">{tokenHint ?? wsNote}</div>
      )}
      <ul className="space-y-2 text-sm">
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
