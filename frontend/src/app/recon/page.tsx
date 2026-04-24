"use client";

import { useState } from "react";
import type { ElementType } from "react";
import { motion } from "framer-motion";
import { Crosshair, Globe2, Plug, Plus } from "lucide-react";
import SectionHeader from "@/components/shared/SectionHeader";

export default function ReconPage() {
  const [target, setTarget] = useState("example.com");

  return (
    <div className="space-y-6">
      <SectionHeader
        eyebrow="Red team"
        title="Recon"
        description="Subdomain enum, port scan, CVE lookup, web fuzzing. Test what you own."
      />

      <div className="glass rounded-xl p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex-1 min-w-[260px]">
            <label className="text-[11px] text-muted uppercase tracking-wider">Target</label>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm font-mono outline-none focus:border-accent/60"
              placeholder="domain, host, or CIDR"
            />
          </div>
          <Action label="Subdomain enum" icon={Globe2} />
          <Action label="Port scan" icon={Plug} />
          <Action label="CVE lookup" icon={Crosshair} />
          <button className="text-xs px-3 py-2 rounded-md bg-accent/15 text-accent border border-accent/40 hover:bg-accent/25 inline-flex items-center gap-1">
            <Plus className="h-3.5 w-3.5" /> Run job
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <FindingsCard />
        <JobsCard />
      </div>
    </div>
  );
}

function Action({ label, icon: Icon }: { label: string; icon: ElementType }) {
  return (
    <button className="text-xs px-3 py-2 rounded-md border border-border/60 hover:border-accent/60 inline-flex items-center gap-1.5">
      <Icon className="h-3.5 w-3.5 text-accent" />
      {label}
    </button>
  );
}

const FINDINGS = [
  { sev: "high", title: "CVE-2024-3094 in xz-utils on db-01", evidence: "CPE: cpe:2.3:a:tukaani:xz" },
  { sev: "medium", title: "Open SMB share on 10.0.4.21", evidence: "Anonymous read-only" },
  { sev: "low", title: "robots.txt exposes /admin paths", evidence: "Disallow: /admin/api" },
  { sev: "high", title: "Outdated nginx 1.18.0 on web-02", evidence: "Banner match" }
];
const sevDot = (s: string) => (s === "high" ? "bg-danger" : s === "medium" ? "bg-warn" : "bg-ok");

function FindingsCard() {
  return (
    <div className="glass rounded-xl p-4">
      <div className="text-sm font-semibold mb-3">Findings</div>
      <ul className="space-y-2 text-sm">
        {FINDINGS.map((f, i) => (
          <motion.li
            key={i}
            initial={{ opacity: 0, x: -6 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.04 }}
            className="rounded-md border border-border/50 px-3 py-2 hover:border-accent/50"
          >
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${sevDot(f.sev)}`} />
              <span className="truncate">{f.title}</span>
              <span className="ml-auto text-[11px] text-muted">{f.sev}</span>
            </div>
            <div className="text-[11px] text-muted font-mono mt-0.5">{f.evidence}</div>
          </motion.li>
        ))}
      </ul>
    </div>
  );
}

const JOBS = [
  { id: "j-104", kind: "subdomain", target: "example.com", status: "done", t: "12s" },
  { id: "j-105", kind: "port", target: "10.0.4.0/24", status: "running", t: "3m" },
  { id: "j-106", kind: "cve", target: "host:db-01", status: "queued", t: "—" }
];

function JobsCard() {
  return (
    <div className="glass rounded-xl p-4">
      <div className="text-sm font-semibold mb-3">Jobs</div>
      <ul className="text-sm divide-y divide-border/40">
        {JOBS.map((j) => (
          <li key={j.id} className="py-2 flex items-center gap-3">
            <span className="font-mono text-xs">{j.id}</span>
            <span className="text-xs text-muted">{j.kind}</span>
            <span className="text-xs">{j.target}</span>
            <span
              className={`ml-auto text-[11px] px-2 py-0.5 rounded-full ${
                j.status === "done"
                  ? "bg-ok/15 text-ok"
                  : j.status === "running"
                    ? "bg-warn/15 text-warn"
                    : "bg-muted/15 text-muted"
              }`}
            >
              {j.status}
            </span>
            <span className="text-[11px] text-muted w-10 text-right">{j.t}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
