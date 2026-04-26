"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { CheckCircle2, Loader2, Play, RefreshCw, XCircle } from "lucide-react";
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

type JobKind =
  | "subdomain"
  | "port"
  | "cve"
  | "webfuzz"
  | "dns"
  | "httprobe"
  | "http_headers"
  | "tls_cert";
type TargetKind = "domain" | "host" | "cidr";

/** Port scan dropdown: `full` omits the list so the API uses the server default (broad). */
type PortScanPreset = "full" | "web" | "databases" | "remote" | "custom";

const PORT_PRESET_WEB: number[] = [
  80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443, 3001, 8880
];
const PORT_PRESET_DATABASES: number[] = [
  1433, 1434, 1521, 1522, 3050, 3306, 3307, 5000, 5432, 5433, 5500, 5601, 5984, 6379, 7000, 7001, 8000, 11211, 27017, 27018, 27019, 9042, 9200, 9300, 50000
];
const PORT_PRESET_REMOTE: number[] = [22, 23, 135, 139, 445, 2049, 3389, 5800, 5801, 5900, 5985, 5986, 10000];

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

function isTerminal(status: string): boolean {
  return status === "done" || status === "failed";
}

function formatElapsed(startedAt: string | null, finishedAt: string | null): string {
  if (!startedAt) return "";
  const start = Date.parse(startedAt);
  const end = finishedAt ? Date.parse(finishedAt) : Date.now();
  const ms = Math.max(0, end - start);
  if (ms < 1000) return `${ms} ms`;
  const sec = ms / 1000;
  if (sec < 60) return `${sec.toFixed(1)}s`;
  const min = Math.floor(sec / 60);
  const rest = Math.floor(sec % 60);
  return `${min}m ${rest}s`;
}

function summariseResult(job: ReconJob): string {
  const r = job.result_json || {};
  if (typeof r.error === "string" && r.error) return r.error;
  if (job.kind === "subdomain") {
    const count = typeof r.count === "number" ? r.count : Array.isArray(r.hits) ? r.hits.length : 0;
    return `${count} live subdomain${count === 1 ? "" : "s"}`;
  }
  if (job.kind === "port") {
    const open = Array.isArray(r.open) ? r.open.length : 0;
    const tested = typeof r.tested === "number" ? r.tested : 0;
    return `${open} open / ${tested} tested`;
  }
  if (job.kind === "cve") {
    const total = typeof r.total_results === "number" ? r.total_results : 0;
    const shown = Array.isArray(r.vulnerabilities) ? r.vulnerabilities.length : 0;
    return `${shown} CVE${shown === 1 ? "" : "s"} shown (NVD total ${total})`;
  }
  if (job.kind === "webfuzz") {
    const hits = Array.isArray(r.hits) ? r.hits.length : 0;
    return `${hits} interesting path${hits === 1 ? "" : "s"}`;
  }
  if (job.kind === "dns") {
    const rec = (r.records as Record<string, string[]> | undefined) || {};
    const n = Object.values(rec).reduce((a, b) => a + (Array.isArray(b) ? b.length : 0), 0);
    return `${n} DNS record${n === 1 ? "" : "s"}`;
  }
  if (job.kind === "httprobe") {
    const pr = r.probes as unknown[] | undefined;
    return `${Array.isArray(pr) ? pr.length : 0} HTTP probe(s)`;
  }
  if (job.kind === "http_headers") {
    const m = (r.headers_missing as string[] | undefined)?.length;
    if (typeof m === "number") return m ? `${m} security header(s) missing` : "Headers look strong";
    return "Security header check";
  }
  if (job.kind === "tls_cert" && (r as { ok?: boolean }).ok) {
    const d = (r as { days_left?: number }).days_left;
    if (typeof d === "number") return `Cert · ~${d} day(s) to expiry`;
    return "TLS certificate details";
  }
  if (job.kind === "tls_cert") {
    return (r as { error?: string }).error || "TLS check";
  }
  return "completed";
}

export default function ReconPage() {
  const [target, setTarget] = useState("");
  const [selectedKind, setSelectedKind] = useState<JobKind>("subdomain");
  const [cpe, setCpe] = useState("");
  const [portPreset, setPortPreset] = useState<PortScanPreset>("full");
  const [ports, setPorts] = useState("80,443,8080,8443,8081,9443");
  const [tlsPort, setTlsPort] = useState("443");
  /** If true, httprobe and security-headers jobs only use https:// (no cleartext fallback). */
  const [httpsOnly, setHttpsOnly] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [jobs, setJobs] = useState<ReconJob[]>([]);
  const [findings, setFindings] = useState<ReconFinding[]>([]);
  const [targetById, setTargetById] = useState<Record<string, string>>({});
  const [watchJobId, setWatchJobId] = useState<string | null>(null);
  const [elapsedTick, setElapsedTick] = useState(0);

  const loadLists = useCallback(async () => {
    try {
      const jobFindingsUrl = watchJobId
        ? `/api/v1/recon/findings?job_id=${encodeURIComponent(watchJobId)}&size=500`
        : null;
      const [tgs, jRes, fRes, fJobRes] = await Promise.all([
        api.get<ReconTarget[]>("/api/v1/recon/targets"),
        api.get<Paginated<ReconJob>>("/api/v1/recon/jobs?size=50"),
        api.get<Paginated<ReconFinding>>("/api/v1/recon/findings?size=200"),
        jobFindingsUrl
          ? api.get<Paginated<ReconFinding>>(jobFindingsUrl)
          : Promise.resolve({ items: [], page: 1, size: 0, total: 0 })
      ]);
      const map: Record<string, string> = {};
      tgs.forEach((t) => {
        map[t.id] = t.value;
      });
      setTargetById(map);
      setJobs(jRes.items);
      const merged = new Map<string, ReconFinding>();
      fRes.items.forEach((f) => merged.set(f.id, f));
      fJobRes.items.forEach((f) => merged.set(f.id, f));
      setFindings([...merged.values()]);
      setError(null);
    } catch (e) {
      const a = e as ApiError;
      if (a.status === 401) {
        setError("Sign in (passkey) and ensure sentinelops_access_token is set to run recon jobs.");
      } else {
        setError(a.detail || "Failed to load recon data. Is the API up?");
      }
    }
  }, [watchJobId]);

  useEffect(() => {
    const t = runDeferred(() => void loadLists());
    return () => clearTimeout(t);
  }, [loadLists]);

  useEffect(() => {
    const needsPoll = jobs.some((j) => j.status === "queued" || j.status === "running");
    if (!needsPoll) return;
    const t = setInterval(() => void loadLists(), 2000);
    return () => clearInterval(t);
  }, [jobs, loadLists]);

  const watchedJob = useMemo(
    () => (watchJobId ? jobs.find((j) => j.id === watchJobId) ?? null : null),
    [watchJobId, jobs]
  );

  useEffect(() => {
    if (!watchedJob) return;
    if (isTerminal(watchedJob.status)) return;
    const t = setInterval(() => setElapsedTick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [watchedJob]);

  const buildParams = (kind: JobKind, v: string): Record<string, unknown> => {
    if (kind === "port") {
      if (portPreset === "full") {
        return {};
      }
      if (portPreset === "web") {
        return { ports: [...new Set(PORT_PRESET_WEB)] };
      }
      if (portPreset === "databases") {
        return { ports: [...new Set(PORT_PRESET_DATABASES)] };
      }
      if (portPreset === "remote") {
        return { ports: [...new Set(PORT_PRESET_REMOTE)] };
      }
      const parsed = ports
        .split(/[,\s]+/)
        .map((p) => Number.parseInt(p, 10))
        .filter((p) => Number.isInteger(p) && p > 0 && p <= 65535);
      return parsed.length ? { ports: [...new Set(parsed)] } : {};
    }
    if (kind === "cve") {
      return { cpe: cpe.trim() || v };
    }
    if (kind === "tls_cert") {
      const p = Number.parseInt(tlsPort, 10);
      if (Number.isInteger(p) && p > 0 && p <= 65535) {
        return { port: p };
      }
      return { port: 443 };
    }
    if (kind === "httprobe" || kind === "http_headers") {
      return httpsOnly ? { https_only: true } : {};
    }
    return {};
  };

  const validateJob = (kind: JobKind, v: string): string | null => {
    const targetKind = inferTargetKind(v);
    if (kind === "subdomain" && targetKind !== "domain") {
      return "Subdomain enumeration needs a domain such as example.com, not an IP/CIDR.";
    }
    if (kind === "dns" && targetKind === "cidr") {
      return "DNS record lookup does not run on a CIDR. Use a host, domain, or specific IP as a name.";
    }
    if (kind === "port" && targetKind === "cidr") {
      return "Port scan currently accepts one host/IP at a time. Enter a host or IP, not CIDR.";
    }
    if (kind === "httprobe" && targetKind === "cidr") {
      return "HTTP live probe does not work on a CIDR. Use a host, IP, or full URL.";
    }
    if (kind === "http_headers" && targetKind === "cidr") {
      return "Security header check needs a host, IP, or URL — not a CIDR.";
    }
    if (kind === "webfuzz" && targetKind === "cidr") {
      return "Web fuzz needs a host or domain with an HTTP service, not a CIDR range.";
    }
    if (kind === "tls_cert" && targetKind === "cidr") {
      return "TLS certificate grab needs a single host, IP, or https:// URL — not a CIDR.";
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
      const job = await api.post<ReconJob>("/api/v1/recon/jobs", {
        target_id: tk.id,
        kind,
        params: buildParams(kind, v)
      });
      setWatchJobId(job.id);
      setInfo(
        `Queued ${kind} job for ${v}. Worker is running it now — status updates below every 2s.`
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
        description="Recon includes subdomain enum, DNS records, TCP port scan (incl. DB + web profiles), HTTP(S) liveness, security response headers, TLS cert inspection, NVD CVE, and path fuzzing. Only scan assets you are authorised to test; set RECON_TARGET_ALLOWLIST in production."
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
              <optgroup label="Discovery">
                <option value="subdomain">Subdomain enum</option>
                <option value="dns">DNS (A, MX, NS, TXT…)</option>
                <option value="port">Port scan</option>
                <option value="httprobe">HTTP(S) live probe</option>
              </optgroup>
              <optgroup label="Vulnerabilities">
                <option value="cve">CVE lookup (NVD)</option>
              </optgroup>
              <optgroup label="Web &amp; transport">
                <option value="webfuzz">Web path fuzz</option>
                <option value="http_headers">Security headers</option>
                <option value="tls_cert">TLS certificate</option>
              </optgroup>
            </select>
          </div>
          {selectedKind === "port" && (
            <div className="min-w-[200px]">
              <label className="text-[11px] text-muted uppercase tracking-wider">Port profile</label>
              <select
                value={portPreset}
                onChange={(e) => setPortPreset(e.target.value as PortScanPreset)}
                disabled={busy}
                className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm outline-none focus:border-accent/60"
              >
                <option value="full">Full (server list — web, DB, remote…)</option>
                <option value="web">Web &amp; app APIs</option>
                <option value="databases">Databases &amp; caches</option>
                <option value="remote">Remote / admin (SSH, RDP, SMB, …)</option>
                <option value="custom">Custom (comma‑separated)</option>
              </select>
            </div>
          )}
          {selectedKind === "port" && portPreset === "custom" && (
            <div className="min-w-[220px]">
              <label className="text-[11px] text-muted uppercase tracking-wider">Custom ports</label>
              <input
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                disabled={busy}
                className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm font-mono outline-none focus:border-accent/60"
                placeholder="80,443,3306,5432,27017"
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
          {selectedKind === "tls_cert" && (
            <div className="min-w-[100px]">
              <label className="text-[11px] text-muted uppercase tracking-wider">TLS port</label>
              <input
                value={tlsPort}
                onChange={(e) => setTlsPort(e.target.value.replace(/\D/g, "").slice(0, 5))}
                disabled={busy}
                className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm font-mono outline-none focus:border-accent/60"
                placeholder="443"
              />
            </div>
          )}
          {(selectedKind === "httprobe" || selectedKind === "http_headers") && (
            <label className="flex items-center gap-2 self-end text-[11px] text-muted min-w-[200px] pb-0.5 cursor-pointer">
              <input
                type="checkbox"
                checked={httpsOnly}
                onChange={(e) => setHttpsOnly(e.target.checked)}
                disabled={busy}
                className="rounded border-border accent-accent"
              />
              <span>HTTPS only (no cleartext fallback)</span>
            </label>
          )}
          <button
            type="button"
            disabled={busy}
            onClick={() => void runJob(selectedKind)}
            className="text-xs px-4 py-2 rounded-md bg-accent/20 text-accent border border-accent/50 hover:bg-accent/30 inline-flex items-center gap-1.5 disabled:opacity-60 disabled:cursor-not-allowed"
          >
            {busy ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Play className="h-3.5 w-3.5" />
            )}
            {busy ? "Queueing…" : "Run job"}
          </button>
        </div>
        <p className="text-[11px] text-muted mt-3">
          DNS &amp; Subdomain use a resolvable name. Port scan: single host/IP, profiles for full DB
          coverage. HTTP probe and security headers are real HTTPS fetches (TLS verified); check{" "}
          <span className="text-fg/80">HTTPS only</span> to skip any http:// retry.{" "}
          <span className="text-fg/80">TLS cert</span> is a direct TLS handshake. CVE:{" "}
          <span className="font-mono">nginx:1.25.3</span> or full CPE. Web fuzz: http(s) URL or host.
        </p>
      </div>

      {watchedJob && (
        <WatchJobCard
          job={watchedJob}
          target={targetById[watchedJob.target_id]}
          elapsed={formatElapsed(watchedJob.started_at, watchedJob.finished_at)}
          onDismiss={() => setWatchJobId(null)}
          tick={elapsedTick}
        />
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <FindingsCard findings={findings} watchJobId={watchJobId} />
        <JobsCard
          jobs={jobs}
          targetById={targetById}
          onPick={(id) => setWatchJobId(id)}
          onRetry={async (id) => {
            setError(null);
            setInfo(null);
            try {
              const updated = await api.post<ReconJob>(`/api/v1/recon/jobs/${id}/retry`);
              setWatchJobId(updated.id);
              setInfo(`Re-dispatched ${updated.kind} job. Worker is picking it up — status updates below.`);
              await loadLists();
            } catch (e) {
              const a = e as ApiError;
              setError(a.detail || "Failed to retry job. Is the worker up?");
            }
          }}
        />
      </div>
    </div>
  );
}

function WatchJobCard({
  job,
  target,
  elapsed,
  onDismiss,
  tick
}: {
  job: ReconJob;
  target: string | undefined;
  elapsed: string;
  onDismiss: () => void;
  tick: number;
}) {
  void tick; /* ensures re-render on each 1s elapsed update */
  const terminal = isTerminal(job.status);
  const summary = terminal ? summariseResult(job) : null;
  const bar =
    job.status === "queued"
      ? "bg-muted"
      : job.status === "running"
        ? "bg-accent"
        : job.status === "done"
          ? "bg-ok"
          : job.status === "failed"
            ? "bg-danger"
            : "bg-muted";

  return (
    <motion.div
      initial={{ opacity: 0, y: -4 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass rounded-xl p-4 border border-accent/30"
    >
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          {job.status === "done" ? (
            <CheckCircle2 className="h-4 w-4 text-ok" />
          ) : job.status === "failed" ? (
            <XCircle className="h-4 w-4 text-danger" />
          ) : (
            <Loader2 className="h-4 w-4 text-accent animate-spin" />
          )}
          <span className="text-sm font-semibold">
            Latest job · {job.kind}
          </span>
        </div>
        <span className="text-xs text-muted font-mono break-all">
          {target || job.target_id.slice(0, 8)}
        </span>
        <span className={`text-[11px] px-2 py-0.5 rounded-full ${statusPillClass(job.status)}`}>
          {job.status}
        </span>
        <span className="text-[11px] text-muted">
          id {job.id.slice(0, 8)}
          {elapsed ? ` · ${elapsed}` : ""}
        </span>
        <button
          type="button"
          onClick={onDismiss}
          className="ml-auto text-[11px] text-muted hover:text-accent"
        >
          Dismiss
        </button>
      </div>

      <div className="mt-3 h-1.5 w-full rounded-full bg-border/40 overflow-hidden">
        {terminal ? (
          <div className={`${bar} h-full`} style={{ width: "100%" }} />
        ) : (
          <motion.div
            className={`${bar} h-full`}
            initial={{ width: "20%" }}
            animate={{ width: ["20%", "95%", "20%"] }}
            transition={{ duration: 1.8, repeat: Infinity, ease: "easeInOut" }}
          />
        )}
      </div>

      {summary && (
        <div className="mt-3 text-xs text-muted">
          <span className="text-fg">Result:</span> {summary}
        </div>
      )}
      {terminal && job.result_json && (
        <details className="mt-2 text-[11px] text-muted">
          <summary className="cursor-pointer hover:text-accent">Raw result JSON</summary>
          <pre className="mt-2 max-h-64 overflow-auto bg-bg/40 border border-border/40 rounded-md p-2 font-mono text-[11px]">
            {JSON.stringify(job.result_json, null, 2)}
          </pre>
        </details>
      )}
    </motion.div>
  );
}

function FindingsCard({
  findings,
  watchJobId
}: {
  findings: ReconFinding[];
  watchJobId: string | null;
}) {
  const [scope, setScope] = useState<"all" | "watch">(watchJobId ? "watch" : "all");
  useEffect(() => {
    if (!watchJobId) return;
    const t = runDeferred(() => setScope("watch"));
    return () => clearTimeout(t);
  }, [watchJobId]);
  const list =
    scope === "watch" && watchJobId
      ? findings.filter((f) => f.job_id === watchJobId)
      : findings;

  return (
    <div className="glass rounded-xl p-4">
      <div className="flex items-center gap-2 mb-3">
        <div className="text-sm font-semibold">Findings</div>
        {watchJobId && (
          <div className="ml-auto inline-flex rounded-md border border-border/60 overflow-hidden text-[11px]">
            <button
              type="button"
              onClick={() => setScope("watch")}
              className={`px-2 py-0.5 ${scope === "watch" ? "bg-accent/15 text-accent" : "text-muted hover:text-fg"}`}
            >
              Latest job
            </button>
            <button
              type="button"
              onClick={() => setScope("all")}
              className={`px-2 py-0.5 ${scope === "all" ? "bg-accent/15 text-accent" : "text-muted hover:text-fg"}`}
            >
              All
            </button>
          </div>
        )}
      </div>
      {list.length === 0 ? (
        <p className="text-xs text-muted">
          {scope === "watch"
            ? "No findings for this job yet. If the job is still running, results will appear here."
            : "No findings yet. Run a job and wait for the worker to finish."}
        </p>
      ) : (
        <ul className="space-y-2 text-sm max-h-80 overflow-auto pr-1">
          {list.map((f, i) => (
            <motion.li
              key={f.id}
              initial={{ opacity: 0, x: -6 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: Math.min(i, 12) * 0.02 }}
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
  targetById,
  onPick,
  onRetry
}: {
  jobs: ReconJob[];
  targetById: Record<string, string>;
  onPick: (id: string) => void;
  onRetry: (id: string) => Promise<void>;
}) {
  const [retryingId, setRetryingId] = useState<string | null>(null);
  const handleRetry = async (id: string) => {
    setRetryingId(id);
    try {
      await onRetry(id);
    } finally {
      setRetryingId(null);
    }
  };

  return (
    <div className="glass rounded-xl p-4">
      <div className="text-sm font-semibold mb-3">Jobs</div>
      {jobs.length === 0 ? (
        <p className="text-xs text-muted">No jobs yet. Fill the target above and press Run job.</p>
      ) : (
        <ul className="text-sm divide-y divide-border/40 max-h-80 overflow-auto">
          {jobs.map((j) => {
            const tv = targetById[j.target_id] || j.target_id.slice(0, 8);
            const active = j.status === "queued" || j.status === "running";
            // A queued job that hasn't started after a few seconds is almost
            // always orphaned (worker/broker recreate, lost message). Offer a
            // retry button for those, and for any job that ended in failure.
            const showRetry =
              j.status === "failed" ||
              (j.status === "queued" && !j.started_at);
            return (
              <li
                key={j.id}
                className="py-2 flex flex-wrap items-center gap-2 text-xs cursor-pointer hover:bg-accent/5 px-1 rounded"
                onClick={() => onPick(j.id)}
              >
                {active ? (
                  <span className="relative inline-flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-warn opacity-75" />
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-warn" />
                  </span>
                ) : (
                  <span
                    className={`inline-block h-2 w-2 rounded-full ${
                      j.status === "done"
                        ? "bg-ok"
                        : j.status === "failed"
                          ? "bg-danger"
                          : "bg-muted"
                    }`}
                  />
                )}
                <span className="font-mono">{j.id.slice(0, 8)}</span>
                <span className="text-muted">{j.kind}</span>
                <span className="min-w-0 break-all">{tv}</span>
                <span className={`ml-auto text-[11px] px-2 py-0.5 rounded-full ${statusPillClass(j.status)}`}>
                  {j.status}
                </span>
                {showRetry && (
                  <button
                    type="button"
                    disabled={retryingId === j.id}
                    onClick={(e) => {
                      e.stopPropagation();
                      void handleRetry(j.id);
                    }}
                    title={
                      j.status === "queued"
                        ? "Stuck queued? Re-dispatch the job to the worker."
                        : "Retry this failed job."
                    }
                    className="text-[11px] px-2 py-0.5 rounded-md border border-accent/40 text-accent hover:bg-accent/10 inline-flex items-center gap-1 disabled:opacity-60 disabled:cursor-not-allowed"
                  >
                    {retryingId === j.id ? (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    ) : (
                      <RefreshCw className="h-3 w-3" />
                    )}
                    Retry
                  </button>
                )}
                {isTerminal(j.status) && (
                  <span className="basis-full text-[11px] text-muted pl-4">
                    {summariseResult(j)}
                  </span>
                )}
                {typeof j.result_json?.error === "string" && (
                  <span className="basis-full text-danger/90 break-words pl-4">
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
