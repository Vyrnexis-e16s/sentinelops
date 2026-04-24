"use client";

import { useCallback, useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Play } from "lucide-react";
import SectionHeader from "@/components/shared/SectionHeader";
import {
  api,
  type ApiError,
  type Paginated,
  type ReconFinding,
  type ReconJob,
  type ReconTarget
} from "@/lib/api";
import { runDeferred } from "@/lib/schedule-deferred";

type JobKind = "subdomain" | "port" | "cve" | "webfuzz";
type TargetKind = "domain" | "host" | "cidr";

function inferTargetKind(value: string): TargetKind {
  const v = value.trim();
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(v)) {
    return "cidr";
  }
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) {
    return "host";
  }
  return "domain";
}

const sevDot = (s: string) =>
  s === "high" || s === "critical"
    ? "bg-danger"
    : s === "medium"
      ? "bg-warn"
      : "bg-ok";

function statusPillClass(status: string) {
  if (status === "done") return "bg-ok/15 text-ok";
  if (status === "running") return "bg-warn/15 text-warn";
  if (status === "failed") return "bg-danger/15 text-danger";
  return "bg-muted/15 text-muted";
}

export default function ReconPage() {
  const [target, setTarget] = useState("");
  const [selectedKind, setSelectedKind] = useState<JobKind>("subdomain");
  const [cpe, setCpe] = useState("");
  const [ports, setPorts] = useState("80,443,8080,8443");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [jobs, setJobs] = useState<ReconJob[]>([]);
  const [findings, setFindings] = useState<ReconFinding[]>([]);
  const [targetById, setTargetById] = useState<Record<string, string>>({});

  const loadLists = useCallback(async () => {
    try {
      const [tgs, jRes, fRes] = await Promise.all([
        api.get<ReconTarget[]>("/api/v1/recon/targets"),
        api.get<Paginated<ReconJob>>("/api/v1/recon/jobs?size=50"),
        api.get<Paginated<ReconFinding>>("/api/v1/recon/findings?size=50")
      ]);
      const map: Record<string, string> = {};
      tgs.forEach((t) => {
        map[t.id] = t.value;
      });
      setTargetById(map);
      setJobs(jRes.items);
      setFindings(fRes.items);
      setError(null);
    } catch (e) {
      const a = e as ApiError;
      if (a.status === 401) {
        setError("Sign in (passkey) and ensure sentinelops_access_token is set to run recon jobs.");
      } else {
        setError(a.detail || "Failed to load recon data. Is the API up?");
      }
    }
  }, []);

  useEffect(() => {
    const t = runDeferred(() => void loadLists());
    return () => clearTimeout(t);
  }, [loadLists]);

  useEffect(() => {
    const needsPoll = jobs.some((j) => j.status === "queued" || j.status === "running");
    if (!needsPoll) return;
    const t = setInterval(() => void loadLists(), 4000);
    return () => clearInterval(t);
  }, [jobs, loadLists]);

  const buildParams = (kind: JobKind, v: string): Record<string, unknown> => {
    if (kind === "port") {
      const parsed = ports
        .split(/[,\s]+/)
        .map((p) => Number.parseInt(p, 10))
        .filter((p) => Number.isInteger(p) && p > 0 && p <= 65535);
      return parsed.length ? { ports: [...new Set(parsed)] } : {};
    }
    if (kind === "cve") {
      return { cpe: cpe.trim() || v };
    }
    return {};
  };

  const validateJob = (kind: JobKind, v: string): string | null => {
    const targetKind = inferTargetKind(v);
    if (kind === "subdomain" && targetKind !== "domain") {
      return "Subdomain enumeration needs a domain such as example.com, not an IP/CIDR.";
    }
    if (kind === "port" && targetKind === "cidr") {
      return "Port scan currently accepts one host/IP at a time. Enter a host or IP, not CIDR.";
    }
    if (kind === "cve") {
      const candidate = (cpe.trim() || v).trim();
      if (!candidate) {
        return "CVE lookup needs either a product:version shortcut (e.g. nginx:1.25.3) or a full CPE 2.3 name.";
      }
    }
    return null;
  };

  const runJob = async (kind: JobKind) => {
    setInfo(null);
    setError(null);
    const v = target.trim();
    if (!v) {
      setError("Enter a target (domain, host, or CIDR).");
      return;
    }
    const validation = validateJob(kind, v);
    if (validation) {
      setError(validation);
      return;
    }
    setBusy(true);
    try {
      const tk = await api.post<ReconTarget>("/api/v1/recon/targets", {
        kind: inferTargetKind(v),
        value: v
      });
      await api.post<ReconJob>("/api/v1/recon/jobs", {
        target_id: tk.id,
        kind,
        params: buildParams(kind, v)
      });
      setInfo(
        `Queued ${kind} job for ${v}. The Docker worker now listens to the recon queue; status will update here.`
      );
      await loadLists();
    } catch (e) {
      const a = e as ApiError;
      if (a.status === 401) {
        setError("Not authenticated. Complete WebAuthn login so the app can call the API.");
      } else {
        setError(a.detail || String(e));
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        eyebrow="Red team"
        title="Recon"
        description="Run subdomain enumeration (DNS brute-force + crt.sh Certificate Transparency), TCP port scan with banner grab, NVD CVE lookup (full CPE or product:version shortcut), and common-path web fuzzing against real hosts. Only scan assets you own or are authorised to assess; configure RECON_TARGET_ALLOWLIST in production."
      />

      {error && (
        <div className="text-sm text-danger border border-danger/40 rounded-md px-3 py-2 bg-danger/5">
          {error}
        </div>
      )}
      {info && (
        <div className="text-sm text-ok border border-ok/40 rounded-md px-3 py-2 bg-ok/5">
          {info}
        </div>
      )}

      <div className="glass rounded-xl p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex-1 min-w-[260px]">
            <label className="text-[11px] text-muted uppercase tracking-wider">Target</label>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={busy}
              className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm font-mono outline-none focus:border-accent/60"
              placeholder="domain, host, or CIDR"
            />
          </div>
          <div className="min-w-[180px]">
            <label className="text-[11px] text-muted uppercase tracking-wider">Job</label>
            <select
              value={selectedKind}
              onChange={(e) => setSelectedKind(e.target.value as JobKind)}
              disabled={busy}
              className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm outline-none focus:border-accent/60"
            >
              <option value="subdomain">Subdomain enum</option>
              <option value="port">Port scan</option>
              <option value="cve">CVE lookup</option>
              <option value="webfuzz">Web fuzz</option>
            </select>
          </div>
          {selectedKind === "port" && (
            <div className="min-w-[220px]">
              <label className="text-[11px] text-muted uppercase tracking-wider">Ports</label>
              <input
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                disabled={busy}
                className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm font-mono outline-none focus:border-accent/60"
                placeholder="80,443,8080"
              />
            </div>
          )}
          {selectedKind === "cve" && (
            <div className="flex-1 min-w-[320px]">
              <label className="text-[11px] text-muted uppercase tracking-wider">
                CPE or product:version
              </label>
              <input
                value={cpe}
                onChange={(e) => setCpe(e.target.value)}
                disabled={busy}
                className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm font-mono outline-none focus:border-accent/60"
                placeholder="nginx:1.25.3  or  cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*"
              />
            </div>
          )}
          <button
            type="button"
            disabled={busy}
            onClick={() => void runJob(selectedKind)}
            className="text-xs px-4 py-2 rounded-md bg-accent/20 text-accent border border-accent/50 hover:bg-accent/30 inline-flex items-center gap-1.5 disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5" />
            {busy ? "Queueing…" : "Run job"}
          </button>
        </div>
        <p className="text-[11px] text-muted mt-3">
          Subdomain → a domain (example.com). Port scan → single host or IP. CVE → full CPE 2.3 or
          shortcut like <span className="font-mono">nginx:1.25.3</span>. Web fuzz → http(s) URL or host.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <FindingsCard findings={findings} />
        <JobsCard jobs={jobs} targetById={targetById} />
      </div>
    </div>
  );
}

function FindingsCard({ findings }: { findings: ReconFinding[] }) {
  return (
    <div className="glass rounded-xl p-4">
      <div className="text-sm font-semibold mb-3">Findings</div>
      {findings.length === 0 ? (
        <p className="text-xs text-muted">No findings yet. Run a job and wait for the worker to finish.</p>
      ) : (
        <ul className="space-y-2 text-sm">
          {findings.map((f, i) => (
            <motion.li
              key={f.id}
              initial={{ opacity: 0, x: -6 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.04 }}
              className="rounded-md border border-border/50 px-3 py-2 hover:border-accent/50"
            >
              <div className="flex items-center gap-2">
                <span className={`h-2 w-2 rounded-full ${sevDot(f.severity)}`} />
                <span className="truncate">{f.title}</span>
                <span className="ml-auto text-[11px] text-muted">{f.severity}</span>
              </div>
              {f.description && (
                <div className="text-[11px] text-muted mt-0.5 line-clamp-2">{f.description}</div>
              )}
            </motion.li>
          ))}
        </ul>
      )}
    </div>
  );
}

function JobsCard({
  jobs,
  targetById
}: {
  jobs: ReconJob[];
  targetById: Record<string, string>;
}) {
  return (
    <div className="glass rounded-xl p-4">
      <div className="text-sm font-semibold mb-3">Jobs</div>
      {jobs.length === 0 ? (
        <p className="text-xs text-muted">No jobs yet. Create one with the buttons above.</p>
      ) : (
        <ul className="text-sm divide-y divide-border/40 max-h-80 overflow-auto">
          {jobs.map((j) => {
            const tv = targetById[j.target_id] || j.target_id.slice(0, 8);
            return (
              <li key={j.id} className="py-2 flex flex-wrap items-center gap-2 text-xs">
                <span className="font-mono">{j.id.slice(0, 8)}</span>
                <span className="text-muted">{j.kind}</span>
                <span className="min-w-0 break-all">{tv}</span>
                <span className={`ml-auto text-[11px] px-2 py-0.5 rounded-full ${statusPillClass(j.status)}`}>
                  {j.status}
                </span>
                {typeof j.result_json?.error === "string" && (
                  <span className="basis-full text-danger/90 break-words">
                    {j.result_json.error}
                  </span>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
