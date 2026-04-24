"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Filter, Plus, Search } from "lucide-react";
import SectionHeader from "@/components/shared/SectionHeader";
import { api, type Alert, type ApiError, type Paginated } from "@/lib/api";
import { runDeferred } from "@/lib/schedule-deferred";

type Rule = {
  id: string;
  name: string;
  attack_technique_ids_array: string[];
  enabled: boolean;
};

type RuleCreate = {
  name: string;
  description?: string;
  query_dsl: {
    all_of?: Array<{ field: string; op: string; value?: unknown }>;
    any_of?: Array<{ field: string; op: string; value?: unknown }>;
    none_of?: Array<{ field: string; op: string; value?: unknown }>;
    score?: number;
    severity?: string;
  };
  enabled?: boolean;
  attack_technique_ids?: string[];
};

export default function SiemPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<"all" | Alert["status"]>("all");

  const load = useCallback(async () => {
    const errors: string[] = [];
    try {
      const a = await api.get<Paginated<Alert>>("/api/v1/siem/alerts?size=50");
      setAlerts(a.items);
    } catch (e: unknown) {
      const a = e as ApiError;
      errors.push(`alerts: ${a.detail || "API request failed"}`);
      setAlerts([]);
    }
    try {
      const r = await api.get<Rule[]>("/api/v1/siem/rules");
      setRules(r);
    } catch (e: unknown) {
      const a = e as ApiError;
      errors.push(`rules: ${a.detail || "API request failed"}`);
      setRules([]);
    }
    setErr(errors.length ? errors.join(" | ") : null);
  }, []);

  useEffect(() => {
    const t = runDeferred(() => void load());
    return () => clearTimeout(t);
  }, [load]);

  const displayAlerts = useMemo(() => {
    const q = query.trim().toLowerCase();
    return alerts.filter((a) => {
      if (status !== "all" && a.status !== status) return false;
      if (!q) return true;
      return [a.id, a.rule_name || "", a.alert_kind || "", a.status]
        .join(" ")
        .toLowerCase()
        .includes(q);
    });
  }, [alerts, query, status]);

  const techniqueCounts = useMemo(() => {
    const counts = new Map<string, number>();
    rules.forEach((r) => {
      r.attack_technique_ids_array.forEach((id) => {
        counts.set(id, (counts.get(id) || 0) + 1);
      });
    });
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [rules]);

  const createRule = async () => {
    setErr(null);
    const raw = window.prompt(
      "Paste RuleCreate JSON",
      JSON.stringify(
        {
          name: "high.severity.event",
          description: "Alert when parsed severity is high.",
          query_dsl: {
            any_of: [{ field: "severity", op: "in", value: ["high", "critical"] }],
            score: 7,
            severity: "high"
          },
          enabled: true,
          attack_technique_ids: []
        },
        null,
        2
      )
    );
    if (!raw) return;
    try {
      const payload = JSON.parse(raw) as RuleCreate;
      await api.post<Rule>("/api/v1/siem/rules", payload);
      await load();
    } catch (e) {
      const a = e as ApiError;
      setErr(a.detail || "Rule creation failed. Check JSON and API validation.");
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        eyebrow="Blue team"
        title="SIEM"
        description="Events, detection rules, alerts. Wired through MITRE ATT&CK so triage stops being grep. Rules list from the API; SIGMA/STIX under /docs."
        right={
          <button
            type="button"
            onClick={() => void createRule()}
            className="text-xs px-3 py-1.5 rounded-md border border-border/70 hover:border-accent/60 inline-flex items-center gap-1"
          >
            <Plus className="h-3.5 w-3.5" /> New rule
          </button>
        }
      />

      {err && <div className="text-xs text-warn/90">{err}</div>}

      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-2 px-2 py-1.5 rounded-md border border-border/60 text-xs text-muted w-full sm:w-72">
          <Search className="h-3.5 w-3.5" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter alerts…"
            className="bg-transparent outline-none flex-1 placeholder:text-muted text-text"
          />
        </div>
        <label className="text-xs px-3 py-1.5 rounded-md border border-border/70 inline-flex items-center gap-1">
          <Filter className="h-3.5 w-3.5" />
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value as typeof status)}
            className="bg-transparent outline-none"
          >
            <option value="all">All statuses</option>
            <option value="new">New</option>
            <option value="ack">Ack</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False positive</option>
          </select>
        </label>
      </div>

      <div className="glass rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="text-[11px] uppercase tracking-wider text-muted bg-panel/40">
            <tr>
              <th className="text-left px-4 py-2">Alert</th>
              <th className="text-left px-4 py-2">Rule / kind</th>
              <th className="text-left px-4 py-2">Score</th>
              <th className="text-left px-4 py-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {displayAlerts.map((a: Alert, i: number) => (
              <motion.tr
                key={a.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: i * 0.03 }}
                className="border-t border-border/40 hover:bg-panel/30"
              >
                <td className="px-4 py-2 font-mono text-xs">{a.id}</td>
                <td className="px-4 py-2">
                  <span className="font-mono text-xs">
                    {a.rule_name || a.alert_kind || "—"}
                  </span>
                </td>
                <td className="px-4 py-2">
                  <ScoreBar value={a.score} />
                </td>
                <td className="px-4 py-2">
                  <StatusPill value={a.status} />
                </td>
              </motion.tr>
            ))}
            {displayAlerts.length === 0 && (
              <tr className="border-t border-border/40">
                <td colSpan={4} className="px-4 py-6 text-center text-xs text-muted">
                  No alerts match the current filters. Ingest events or enable detection rules to populate this table.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="glass rounded-xl p-4 lg:col-span-2">
          <div className="text-sm font-semibold mb-2">Detection rules</div>
          <ul className="text-sm divide-y divide-border/40">
            {rules.map((r: Rule) => (
              <li key={r.id} className="py-2 flex items-center gap-3">
                <span className={`h-2 w-2 rounded-full ${r.enabled ? "bg-ok" : "bg-muted"}`} />
                <span className="font-mono text-xs">{r.name}</span>
                <span className="text-[11px] text-muted">{(r.attack_technique_ids_array || []).join(", ")}</span>
                <span className="ml-auto text-[11px] text-muted">
                  {r.enabled ? "enabled" : "disabled"}
                </span>
              </li>
            ))}
            {rules.length === 0 && (
              <li className="py-3 text-xs text-muted">No rules returned by the API.</li>
            )}
          </ul>
        </div>

        <div className="glass rounded-xl p-4">
          <div className="text-sm font-semibold mb-3">MITRE technique coverage</div>
          <ul className="text-sm space-y-2">
            {techniqueCounts.map(([k, v]) => (
              <li key={k as string} className="flex items-center gap-3">
                <span className="text-xs text-muted w-36 truncate">{k as string}</span>
                <div className="flex-1 h-1.5 rounded-full bg-border/40 overflow-hidden">
                  <div className="h-full bg-accent" style={{ width: `${Math.min(100, (v as number) * 20)}%` }} />
                </div>
                <span className="text-xs text-muted w-6 text-right">{v as number}</span>
              </li>
            ))}
            {techniqueCounts.length === 0 && (
              <li className="text-xs text-muted">No MITRE techniques are attached to current rules.</li>
            )}
          </ul>
        </div>
      </div>
    </div>
  );
}

function ScoreBar({ value }: { value: number }) {
  return (
    <div className="flex items-center gap-2">
      <div className="w-24 h-1.5 rounded-full bg-border/40 overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-accent to-accent2"
          style={{ width: `${Math.min(100, (value / 10) * 100)}%` }}
        />
      </div>
      <span className="font-mono text-xs">{value.toFixed(2)}</span>
    </div>
  );
}

function StatusPill({ value }: { value: string }) {
  const tone =
    value === "new"
      ? "bg-warn/15 text-warn"
      : value === "ack"
        ? "bg-accent/15 text-accent"
        : "bg-ok/15 text-ok";
  return <span className={`px-2 py-0.5 rounded-full text-[11px] ${tone}`}>{value}</span>;
}
