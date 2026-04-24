"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Filter, Plus, Search } from "lucide-react";
import SectionHeader from "@/components/shared/SectionHeader";
import { api, type Alert, type Paginated } from "@/lib/api";

type Rule = {
  id: string;
  name: string;
  attack_technique_ids_array: string[];
  enabled: boolean;
};

export default function SiemPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancel = false;
    (async () => {
      try {
        const [a, r] = await Promise.all([
          api.get<Paginated<Alert>>("/api/v1/siem/alerts?size=12"),
          api.get<Rule[]>("/api/v1/siem/rules")
        ]);
        if (!cancel) {
          setAlerts(a.items);
          setRules(r);
        }
      } catch (e: unknown) {
        if (!cancel) {
          setErr(
            e && typeof e === "object" && "detail" in e
              ? String((e as { detail: string }).detail)
              : "Not connected (auth + API required). Demo table below."
          );
        }
      }
    })();
    return () => {
      cancel = true;
    };
  }, []);

  const fallbackAlerts: Alert[] = [
    {
      id: "00000000-0000-0000-0000-0000000000a0",
      event_id: "00000000-0000-0000-0000-0000000000e0",
      rule_id: null,
      rule_name: "dns.tunneling",
      score: 0.74,
      status: "ack",
      created_at: new Date().toISOString(),
      alert_kind: "detection"
    },
    {
      id: "00000000-0000-0000-0000-0000000000a1",
      event_id: "00000000-0000-0000-0000-0000000000e1",
      rule_id: null,
      rule_name: "threat.intel.ioc",
      score: 0.9,
      status: "new",
      created_at: new Date().toISOString(),
      alert_kind: "threat_intel"
    }
  ];

  const displayAlerts = alerts.length > 0 ? alerts : fallbackAlerts;

  const fallbackRules: Rule[] = [
    { id: "1", name: "ssh.bruteforce", attack_technique_ids_array: ["T1110"], enabled: true },
    { id: "2", name: "ps.encoded_command", attack_technique_ids_array: ["T1059.001"], enabled: true }
  ];

  const displayRules = rules.length > 0 ? rules : fallbackRules;

  return (
    <div className="space-y-6">
      <SectionHeader
        eyebrow="Blue team"
        title="SIEM"
        description="Events, detection rules, alerts. Wired through MITRE ATT&CK so triage stops being grep. Rules list from the API; SIGMA/STIX under /docs."
        right={
          <button
            type="button"
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
            placeholder="Filter alerts…"
            className="bg-transparent outline-none flex-1 placeholder:text-muted text-text"
          />
        </div>
        <button
          type="button"
          className="text-xs px-3 py-1.5 rounded-md border border-border/70 hover:border-accent/60 inline-flex items-center gap-1"
        >
          <Filter className="h-3.5 w-3.5" /> All severities
        </button>
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
          </tbody>
        </table>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="glass rounded-xl p-4 lg:col-span-2">
          <div className="text-sm font-semibold mb-2">Detection rules</div>
          <ul className="text-sm divide-y divide-border/40">
            {displayRules.map((r: Rule) => (
              <li key={r.id} className="py-2 flex items-center gap-3">
                <span className={`h-2 w-2 rounded-full ${r.enabled ? "bg-ok" : "bg-muted"}`} />
                <span className="font-mono text-xs">{r.name}</span>
                <span className="text-[11px] text-muted">{(r.attack_technique_ids_array || []).join(", ")}</span>
                <span className="ml-auto text-[11px] text-muted">
                  {r.enabled ? "enabled" : "disabled"}
                </span>
              </li>
            ))}
          </ul>
        </div>

        <div className="glass rounded-xl p-4">
          <div className="text-sm font-semibold mb-3">Top tactics today</div>
          <ul className="text-sm space-y-2">
            {[
              ["Initial Access", 12],
              ["Execution", 9],
              ["Lateral Movement", 7],
              ["Credential Access", 5],
              ["C2", 4]
            ].map(([k, v]) => (
              <li key={k as string} className="flex items-center gap-3">
                <span className="text-xs text-muted w-36 truncate">{k as string}</span>
                <div className="flex-1 h-1.5 rounded-full bg-border/40 overflow-hidden">
                  <div className="h-full bg-accent" style={{ width: `${(v as number) * 7}%` }} />
                </div>
                <span className="text-xs text-muted w-6 text-right">{v as number}</span>
              </li>
            ))}
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
