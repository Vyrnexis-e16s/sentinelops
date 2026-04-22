"use client";

import { motion } from "framer-motion";
import { Filter, Plus, Search } from "lucide-react";
import SectionHeader from "@/components/shared/SectionHeader";

const ALERTS = [
  { id: "a-7841", rule: "ssh.bruteforce", attack: "T1110", score: 0.92, status: "new", at: "12:04" },
  { id: "a-7840", rule: "ps.encoded_command", attack: "T1059", score: 0.81, status: "new", at: "11:55" },
  { id: "a-7839", rule: "dns.tunneling", attack: "T1071.004", score: 0.74, status: "ack", at: "11:43" },
  { id: "a-7838", rule: "smb.lateral", attack: "T1021.002", score: 0.88, status: "new", at: "11:25" },
  { id: "a-7837", rule: "web.shell_upload", attack: "T1190", score: 0.95, status: "new", at: "10:32" },
  { id: "a-7836", rule: "cred.dump", attack: "T1003", score: 0.79, status: "resolved", at: "09:11" }
];

const RULES = [
  { name: "ssh.bruteforce", techniques: ["T1110"], enabled: true },
  { name: "ps.encoded_command", techniques: ["T1059.001"], enabled: true },
  { name: "dns.tunneling", techniques: ["T1071.004"], enabled: true },
  { name: "smb.lateral", techniques: ["T1021.002"], enabled: true },
  { name: "web.shell_upload", techniques: ["T1190"], enabled: true },
  { name: "cred.dump", techniques: ["T1003"], enabled: false }
];

export default function SiemPage() {
  return (
    <div className="space-y-6">
      <SectionHeader
        eyebrow="Blue team"
        title="SIEM"
        description="Events, detection rules, alerts. Wired through MITRE ATT&CK so triage stops being grep."
        right={
          <button className="text-xs px-3 py-1.5 rounded-md border border-border/70 hover:border-accent/60 inline-flex items-center gap-1">
            <Plus className="h-3.5 w-3.5" /> New rule
          </button>
        }
      />

      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-2 px-2 py-1.5 rounded-md border border-border/60 text-xs text-muted w-full sm:w-72">
          <Search className="h-3.5 w-3.5" />
          <input
            placeholder="Filter alerts…"
            className="bg-transparent outline-none flex-1 placeholder:text-muted text-text"
          />
        </div>
        <button className="text-xs px-3 py-1.5 rounded-md border border-border/70 hover:border-accent/60 inline-flex items-center gap-1">
          <Filter className="h-3.5 w-3.5" /> All severities
        </button>
      </div>

      <div className="glass rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="text-[11px] uppercase tracking-wider text-muted bg-panel/40">
            <tr>
              <th className="text-left px-4 py-2">Alert</th>
              <th className="text-left px-4 py-2">Rule</th>
              <th className="text-left px-4 py-2">ATT&CK</th>
              <th className="text-left px-4 py-2">Score</th>
              <th className="text-left px-4 py-2">Status</th>
              <th className="text-left px-4 py-2">When</th>
            </tr>
          </thead>
          <tbody>
            {ALERTS.map((a, i) => (
              <motion.tr
                key={a.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: i * 0.03 }}
                className="border-t border-border/40 hover:bg-panel/30"
              >
                <td className="px-4 py-2 font-mono text-xs">{a.id}</td>
                <td className="px-4 py-2">{a.rule}</td>
                <td className="px-4 py-2">
                  <span className="font-mono text-xs px-1.5 py-0.5 rounded bg-accent/10 text-accent">
                    {a.attack}
                  </span>
                </td>
                <td className="px-4 py-2">
                  <ScoreBar value={a.score} />
                </td>
                <td className="px-4 py-2">
                  <StatusPill value={a.status} />
                </td>
                <td className="px-4 py-2 text-muted">{a.at}</td>
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="glass rounded-xl p-4 lg:col-span-2">
          <div className="text-sm font-semibold mb-2">Detection rules</div>
          <ul className="text-sm divide-y divide-border/40">
            {RULES.map((r) => (
              <li key={r.name} className="py-2 flex items-center gap-3">
                <span className={`h-2 w-2 rounded-full ${r.enabled ? "bg-ok" : "bg-muted"}`} />
                <span className="font-mono text-xs">{r.name}</span>
                <span className="text-[11px] text-muted">{r.techniques.join(", ")}</span>
                <span className="ml-auto text-[11px] text-muted">{r.enabled ? "enabled" : "disabled"}</span>
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
                <span className="text-xs text-muted w-36 truncate">{k}</span>
                <div className="flex-1 h-1.5 rounded-full bg-border/40 overflow-hidden">
                  <div
                    className="h-full bg-accent"
                    style={{ width: `${(v as number) * 7}%` }}
                  />
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
        <div className="h-full bg-gradient-to-r from-accent to-accent2" style={{ width: `${value * 100}%` }} />
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
  return (
    <span className={`px-2 py-0.5 rounded-full text-[11px] ${tone}`}>{value}</span>
  );
}
