"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  Calendar,
  CheckCircle2,
  Download,
  GitCompareArrows,
  Loader2,
  Network,
  Play,
  RefreshCw,
  Search,
  XCircle
} from "lucide-react";
import SectionHeader from "@/components/shared/SectionHeader";
import {
  api,
  type ApiError,
  type Paginated,
  type ReconDiffResult,
  type ReconFinding,
  type ReconGraphResult,
  type ReconJob,
  type ReconSchedule,
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
  | "tls_cert"
  | "ct"
  | "wellknown"
  | "fingerprint"
  | "ptr"
  | "takeover"
  | "axfr"
  | "robots_sitemap"
  | "js_endpoints"
  | "cookie_audit"
  | "tls_audit"
  | "wayback";
type TargetKind = "domain" | "host" | "cidr";

const KIND_HINTS: Record<JobKind, string> = {
  subdomain:
    "Brute-force common subdomain names against the apex DNS — surfaces dev/staging/admin hosts. Needs a domain (example.com).",
  port:
    "TCP connect scan with optional concurrency/timeout. Pick a profile (web/db/remote/full) or paste custom ports. Use a host or IP.",
  cve:
    "NVD CVE lookup by CPE. Either a full cpe:2.3:… string or shorthand like nginx:1.25.3. Tip: run a fingerprint job first.",
  webfuzz:
    "Path fuzz against a live HTTP service (200/401/403/etc). Feed it disallow paths from robots_sitemap or paths from js_endpoints.",
  dns:
    "Resolve A/AAAA/MX/NS/TXT/CNAME for the host. Quick reconnaissance baseline; pairs well with axfr.",
  httprobe:
    "Reach out to http(s)://target/ and record server, title, response size, request/response bytes and request duration (IDS-friendly).",
  http_headers:
    "Score response security headers (HSTS, CSP, X-Frame-Options, COOP, …). Use https_only to skip cleartext fallback.",
  tls_cert:
    "Single TLS handshake — pulls the leaf cert (CN/SAN, validity, days_left). Cheap; pairs with the deeper tls_audit.",
  ct:
    "Crowd-sourced subdomain hint via Certificate Transparency (crt.sh). Catches names that don't show up in DNS brute-force.",
  wellknown:
    "Probe /.well-known/ files (security.txt, openid-configuration, robots.txt, …). Useful for stack inference.",
  fingerprint:
    "Single GET against a chosen path; parses Server / X-Powered-By / common framework hints into CPE candidates.",
  ptr:
    "Reverse DNS for a single IP. Useful after a subdomain resolves to an unknown IP, to identify the hosting provider.",
  takeover:
    "Follow each subdomain's CNAME chain and match dangling cloud tenants (GitHub Pages, Heroku, S3, …). High-impact bug-class.",
  axfr:
    "Attempt a DNS zone transfer against every authoritative NS. Refused = expected. Successful = leaks the entire internal zone.",
  robots_sitemap:
    "Fetch robots.txt + sitemap.xml — emits Disallow paths and sitemap URLs as a seed list for webfuzz.",
  js_endpoints:
    "Fetch the homepage, walk <script src=> bundles, regex out /api/*, /v1/*, fetch(), axios() endpoints.",
  cookie_audit:
    "Parse every Set-Cookie in the response chain — flags missing Secure / HttpOnly / SameSite, bad __Host- usage, etc.",
  tls_audit:
    "Negotiates TLS 1.0/1.1/1.2/1.3 individually, records the cipher, validates the chain, checks SAN match — outputs a grade.",
  wayback:
    "Pull historical URLs for the host from web.archive.org/CDX. Emits unique paths that can seed webfuzz."
};

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

function summariseResult(job: ReconJob, jobFindings?: ReconFinding[]): string {
  const r = job.result_json || {};
  if (typeof r.error === "string" && r.error) return r.error;
  // Live findings count for this job — used as a fallback for "completed" jobs
  // whose `result_json` was overwritten by an old rescue path. The findings
  // table is the source of truth; result_json is only a denormalized summary.
  const liveCount = jobFindings ? jobFindings.length : undefined;
  if (job.kind === "subdomain") {
    let count: number;
    if (typeof r.count === "number") count = r.count;
    else if (Array.isArray(r.hits)) count = r.hits.length;
    else if (job.status === "done" && typeof liveCount === "number") count = liveCount;
    else count = 0;
    return `${count} live subdomain${count === 1 ? "" : "s"}`;
  }
  if (job.kind === "port") {
    let open: number;
    if (Array.isArray(r.open)) open = r.open.length;
    else if (job.status === "done" && typeof liveCount === "number") open = liveCount;
    else open = 0;
    const tested = typeof r.tested === "number" ? r.tested : 0;
    return tested ? `${open} open / ${tested} tested` : `${open} open port${open === 1 ? "" : "s"}`;
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
  if (job.kind === "ct") {
    const n = (r as { unique_names?: number; returned?: number }).unique_names;
    const ret = (r as { returned?: number }).returned;
    if (typeof n === "number") return `${n} unique name(s) in CT (${ret ?? "?"} from crt.sh)`;
    if (typeof ret === "number") return `crt.sh returned ${ret} row(s)`;
    return "Certificate transparency search";
  }
  if (job.kind === "wellknown") {
    const n = (r as { probed?: number }).probed;
    if (typeof n === "number") return `${n} well-known path(s) probed`;
    return "Well-known file probe";
  }
  if (job.kind === "fingerprint") {
    const sigs = (r as { signals?: string[] }).signals;
    if (Array.isArray(sigs) && sigs.length) return `Signals: ${sigs.join(", ")}`;
    return (r as { ok?: boolean }).ok
      ? "HTTP stack hints recorded"
      : (r as { error?: string }).error || "Fingerprint";
  }
  if (job.kind === "ptr") {
    if ((r as { ok?: boolean }).ok && (r as { ptr?: string }).ptr) {
      return `PTR: ${(r as { ptr: string }).ptr}`;
    }
    return (r as { error?: string }).error || "Reverse DNS";
  }
  if (job.kind === "takeover") {
    const vuln = ((r as { vulnerable?: unknown[] }).vulnerable || []).length;
    const tested = ((r as { results?: unknown[] }).results || []).length;
    if (vuln > 0) return `${vuln} likely takeover${vuln === 1 ? "" : "s"} (of ${tested} candidates)`;
    return `${tested} candidate${tested === 1 ? "" : "s"} checked, no takeover marker`;
  }
  if (job.kind === "axfr") {
    if ((r as { any_leak?: boolean }).any_leak) return "AXFR LEAKS records — fix NS ACLs immediately";
    const ns = ((r as { nameservers?: string[] }).nameservers || []).length;
    return ns ? `AXFR refused on ${ns} NS (expected)` : "no NS records";
  }
  if (job.kind === "robots_sitemap") {
    const dis = ((r as { disallow?: string[] }).disallow || []).length;
    const sm = ((r as { sitemap_urls?: string[] }).sitemap_urls || []).length;
    return `${dis} disallow + ${sm} sitemap URL${sm === 1 ? "" : "s"}`;
  }
  if (job.kind === "js_endpoints") {
    const paths = ((r as { paths?: string[] }).paths || []).length;
    const scripts = ((r as { scripts_seen?: string[] }).scripts_seen || []).length;
    return `${paths} unique path${paths === 1 ? "" : "s"} from ${scripts} JS bundle${scripts === 1 ? "" : "s"}`;
  }
  if (job.kind === "cookie_audit") {
    const summary = (r as { summary?: { total?: number; with_issues?: number; high?: number } }).summary || {};
    if (typeof summary.with_issues === "number" && summary.total) {
      return `${summary.with_issues}/${summary.total} cookie${summary.total === 1 ? "" : "s"} with issues${summary.high ? ` (${summary.high} high)` : ""}`;
    }
    return (r as { error?: string }).error || "no cookies set";
  }
  if (job.kind === "tls_audit") {
    if ((r as { ok?: boolean }).ok) {
      const grade = (r as { grade?: string }).grade || "?";
      const issues = ((r as { issues?: string[] }).issues || []).length;
      return `Grade ${grade}${issues ? ` · ${issues} issue${issues === 1 ? "" : "s"}` : ""}`;
    }
    return (r as { error?: string }).error || "TLS audit error";
  }
  if (job.kind === "wayback") {
    const n = (r as { count?: number }).count;
    if (typeof n === "number") return `${n} unique historical URL${n === 1 ? "" : "s"}`;
    return (r as { error?: string }).error || "Wayback query";
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
  /** Port scan — optional worker tuning (empty = server default). */
  const [portConcurrency, setPortConcurrency] = useState("");
  const [portTimeoutSec, setPortTimeoutSec] = useState("");
  /** HTTP stack fingerprint path (GET). */
  const [fpPath, setFpPath] = useState("/");
  /** CT (crt.sh) max unique names to persist. */
  const [ctMaxNames, setCtMaxNames] = useState("150");
  /** Wayback CDX hard cap. */
  const [waybackLimit, setWaybackLimit] = useState("200");
  const [waybackOnly2xx, setWaybackOnly2xx] = useState(false);
  /** Robots/sitemap path cap. */
  const [robotsMaxPaths, setRobotsMaxPaths] = useState("250");
  /** JS endpoint extractor — script cap. */
  const [jsMaxScripts, setJsMaxScripts] = useState("8");
  /** Takeover candidate names — empty = pull from latest subdomain job. */
  const [takeoverNames, setTakeoverNames] = useState("");
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
      let base: Record<string, unknown> = {};
      if (portPreset === "full") {
        base = {};
      } else if (portPreset === "web") {
        base = { ports: [...new Set(PORT_PRESET_WEB)] };
      } else if (portPreset === "databases") {
        base = { ports: [...new Set(PORT_PRESET_DATABASES)] };
      } else if (portPreset === "remote") {
        base = { ports: [...new Set(PORT_PRESET_REMOTE)] };
      } else {
        const parsed = ports
          .split(/[,\s]+/)
          .map((p) => Number.parseInt(p, 10))
          .filter((p) => Number.isInteger(p) && p > 0 && p <= 65535);
        base = parsed.length ? { ports: [...new Set(parsed)] } : {};
      }
      const c = portConcurrency.trim();
      if (c && /^\d+$/.test(c)) {
        const n = Number.parseInt(c, 10);
        if (n >= 1 && n <= 200) base = { ...base, concurrency: n };
      }
      const t = portTimeoutSec.trim();
      if (t && /^\d*\.?\d+$/.test(t)) {
        const x = Number.parseFloat(t);
        if (x >= 0.25 && x <= 120) base = { ...base, per_port_timeout: x };
      }
      return base;
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
    if (kind === "fingerprint") {
      const p = fpPath.trim() || "/";
      return { path: p.startsWith("/") ? p : `/${p}` };
    }
    if (kind === "ct") {
      const m = Number.parseInt(ctMaxNames, 10);
      return { max_names: Number.isInteger(m) && m > 0 ? Math.min(500, m) : 150 };
    }
    if (kind === "wellknown" || kind === "ptr") {
      return {};
    }
    if (kind === "tls_audit") {
      const p = Number.parseInt(tlsPort, 10);
      return { port: Number.isInteger(p) && p > 0 && p <= 65535 ? p : 443 };
    }
    if (kind === "wayback") {
      const out: Record<string, unknown> = {};
      const n = Number.parseInt(waybackLimit, 10);
      if (Number.isInteger(n) && n > 0) out.limit = Math.min(5000, n);
      if (waybackOnly2xx) out.only_2xx = true;
      return out;
    }
    if (kind === "robots_sitemap") {
      const n = Number.parseInt(robotsMaxPaths, 10);
      return Number.isInteger(n) && n > 0 ? { max_paths: Math.min(2000, n) } : {};
    }
    if (kind === "js_endpoints") {
      const n = Number.parseInt(jsMaxScripts, 10);
      return Number.isInteger(n) && n > 0 ? { max_scripts: Math.min(32, n) } : {};
    }
    if (kind === "cookie_audit") {
      return httpsOnly ? { https_only: true } : {};
    }
    if (kind === "takeover") {
      const names = takeoverNames
        .split(/[\s,]+/)
        .map((n) => n.trim())
        .filter(Boolean);
      return names.length ? { names } : {};
    }
    if (kind === "axfr") {
      return {};
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
    if (kind === "ptr") {
      if (targetKind === "cidr") {
        return "Reverse DNS (PTR) needs a single IP address, not a CIDR.";
      }
      const t = v.trim();
      const v4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(t);
      const v6 = t.includes(":") && !t.includes("://");
      if (!v4 && !v6) {
        return "PTR needs a numeric IPv4 or IPv6 (resolve a hostname to an IP first if needed).";
      }
    }
    if (kind === "fingerprint" && targetKind === "cidr") {
      return "HTTP stack fingerprint needs one host, IP, or URL — not a CIDR.";
    }
    if (kind === "ct" && targetKind === "cidr") {
      return "Certificate transparency search does not use CIDR — use a domain or IP.";
    }
    if (kind === "wellknown" && targetKind === "cidr") {
      return "Well-known file probe needs a host, domain, or http(s) URL — not a CIDR.";
    }
    if (kind === "axfr" && targetKind !== "domain") {
      return "AXFR runs against a domain's authoritative NS — pass a domain like example.com, not an IP/CIDR.";
    }
    if ((kind === "robots_sitemap" || kind === "js_endpoints" || kind === "cookie_audit" || kind === "wayback") && targetKind === "cidr") {
      return "This kind needs a host or domain (with HTTP service), not a CIDR.";
    }
    if (kind === "tls_audit" && targetKind === "cidr") {
      return "TLS deep audit needs a single host, IP, or https:// URL — not a CIDR.";
    }
    if (kind === "takeover") {
      const namesRaw = takeoverNames.trim();
      if (targetKind !== "domain" && !namesRaw) {
        return "Takeover detection needs either a domain (so we can reuse the last subdomain job) or an explicit list of names in 'Names'.";
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
        description="Recon: CT (crt.sh), well-known files, HTTP stack hints, reverse DNS, plus port scan (with optional concurrency/timeout), subdomains, DNS, HTTP(S) probes, security headers, TLS, NVD CVE, and path fuzz. Only scan assets you are authorised to test; set RECON_TARGET_ALLOWLIST in production."
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
                <option value="ct">Certificate transparency (crt.sh)</option>
                <option value="wayback">Wayback Machine (historical URLs)</option>
              </optgroup>
              <optgroup label="Vulnerabilities">
                <option value="cve">CVE lookup (NVD)</option>
                <option value="takeover">Subdomain takeover</option>
                <option value="axfr">DNS zone transfer (AXFR)</option>
              </optgroup>
              <optgroup label="Web &amp; transport">
                <option value="webfuzz">Web path fuzz</option>
                <option value="http_headers">Security headers</option>
                <option value="cookie_audit">Cookie / Set-Cookie audit</option>
                <option value="tls_cert">TLS certificate (quick)</option>
                <option value="tls_audit">TLS deep audit (cipher / chain / SAN)</option>
                <option value="fingerprint">HTTP stack fingerprint</option>
                <option value="wellknown">Well-known (security.txt, robots…)</option>
                <option value="robots_sitemap">robots.txt + sitemap.xml</option>
                <option value="js_endpoints">JS endpoint extractor</option>
              </optgroup>
              <optgroup label="DNS intel">
                <option value="ptr">Reverse DNS (PTR)</option>
              </optgroup>
            </select>
            <p className="mt-1 text-[11px] text-muted leading-snug">{KIND_HINTS[selectedKind]}</p>
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
          {selectedKind === "port" && (
            <>
              <div className="min-w-[90px]">
                <label className="text-[11px] text-muted uppercase tracking-wider">Concurrency</label>
                <input
                  value={portConcurrency}
                  onChange={(e) => setPortConcurrency(e.target.value.replace(/\D/g, "").slice(0, 3))}
                  disabled={busy}
                  className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm font-mono outline-none focus:border-accent/60"
                  placeholder="def"
                  title="Optional 1–200 parallel connects (default: server setting)"
                />
              </div>
              <div className="min-w-[90px]">
                <label className="text-[11px] text-muted uppercase tracking-wider">Timeout s</label>
                <input
                  value={portTimeoutSec}
                  onChange={(e) => {
                    const x = e.target.value.replace(/[^\d.]/g, "");
                    setPortTimeoutSec(x.slice(0, 6));
                  }}
                  disabled={busy}
                  className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm font-mono outline-none focus:border-accent/60"
                  placeholder="def"
                  title="Per-port connect timeout, 0.25–120s (default: RECON_TIMEOUT_SECONDS)"
                />
              </div>
            </>
          )}
          {selectedKind === "fingerprint" && (
            <div className="min-w-[160px]">
              <label className="text-[11px] text-muted uppercase tracking-wider">GET path</label>
              <input
                value={fpPath}
                onChange={(e) => setFpPath(e.target.value)}
                disabled={busy}
                className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm font-mono outline-none focus:border-accent/60"
                placeholder="/"
              />
            </div>
          )}
          {selectedKind === "ct" && (
            <div className="min-w-[100px]">
              <label className="text-[11px] text-muted uppercase tracking-wider">Max names</label>
              <input
                value={ctMaxNames}
                onChange={(e) => setCtMaxNames(e.target.value.replace(/\D/g, "").slice(0, 3))}
                disabled={busy}
                className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm font-mono outline-none focus:border-accent/60"
                placeholder="150"
                title="Max unique cert names to store (10–500)"
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
          {(selectedKind === "httprobe" || selectedKind === "http_headers" || selectedKind === "cookie_audit") && (
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
          {selectedKind === "tls_audit" && (
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
          {selectedKind === "wayback" && (
            <>
              <div className="min-w-[100px]">
                <label className="text-[11px] text-muted uppercase tracking-wider">Limit</label>
                <input
                  value={waybackLimit}
                  onChange={(e) => setWaybackLimit(e.target.value.replace(/\D/g, "").slice(0, 4))}
                  disabled={busy}
                  className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm font-mono outline-none focus:border-accent/60"
                  placeholder="200"
                  title="Max unique URLs to keep (10 – 5000)"
                />
              </div>
              <label className="flex items-center gap-2 self-end text-[11px] text-muted pb-0.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={waybackOnly2xx}
                  onChange={(e) => setWaybackOnly2xx(e.target.checked)}
                  disabled={busy}
                  className="rounded border-border accent-accent"
                />
                <span>Only 2xx historical statuses</span>
              </label>
            </>
          )}
          {selectedKind === "robots_sitemap" && (
            <div className="min-w-[110px]">
              <label className="text-[11px] text-muted uppercase tracking-wider">Max paths</label>
              <input
                value={robotsMaxPaths}
                onChange={(e) => setRobotsMaxPaths(e.target.value.replace(/\D/g, "").slice(0, 4))}
                disabled={busy}
                className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm font-mono outline-none focus:border-accent/60"
                placeholder="250"
                title="Cap total paths kept (10 – 2000)"
              />
            </div>
          )}
          {selectedKind === "js_endpoints" && (
            <div className="min-w-[110px]">
              <label className="text-[11px] text-muted uppercase tracking-wider">Max scripts</label>
              <input
                value={jsMaxScripts}
                onChange={(e) => setJsMaxScripts(e.target.value.replace(/\D/g, "").slice(0, 3))}
                disabled={busy}
                className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm font-mono outline-none focus:border-accent/60"
                placeholder="8"
                title="How many <script src> bundles to fetch (1 – 32)"
              />
            </div>
          )}
          {selectedKind === "takeover" && (
            <div className="flex-1 min-w-[280px]">
              <label className="text-[11px] text-muted uppercase tracking-wider">
                Names (optional — empty reuses latest subdomain job)
              </label>
              <input
                value={takeoverNames}
                onChange={(e) => setTakeoverNames(e.target.value)}
                disabled={busy}
                className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm font-mono outline-none focus:border-accent/60"
                placeholder="staging.example.com, dev.example.com"
              />
            </div>
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
          Pick a job from the dropdown — the hint below it explains exactly what each one does.{" "}
          <span className="text-fg/80">HTTPS only</span> skips http:// fallback for httprobe/headers/cookie audit.
          New: <span className="text-fg/80">takeover</span> reuses your last subdomain job by default,{" "}
          <span className="text-fg/80">robots_sitemap</span> + <span className="text-fg/80">js_endpoints</span> +{" "}
          <span className="text-fg/80">wayback</span> all emit paths you can feed straight into webfuzz.
        </p>
      </div>

      {watchedJob && (
        <WatchJobCard
          job={watchedJob}
          target={targetById[watchedJob.target_id]}
          elapsed={formatElapsed(watchedJob.started_at, watchedJob.finished_at)}
          onDismiss={() => setWatchJobId(null)}
          tick={elapsedTick}
          jobFindings={findings.filter((f) => f.job_id === watchedJob.id)}
        />
      )}

      <ToolboxCard
        targets={Object.entries(targetById).map(([id, value]) => ({ id, value }))}
        currentTargetValue={target}
        onCpeFill={(c) => {
          setCpe(c);
          setSelectedKind("cve");
          setInfo(`Loaded CPE '${c}' into the CVE form. Click Run job to query NVD.`);
        }}
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <FindingsCard
          findings={findings}
          watchJobId={watchJobId}
          onCpeFill={(c) => {
            setCpe(c);
            setSelectedKind("cve");
            setInfo(`Loaded CPE '${c}' into the CVE form. Click Run job to query NVD.`);
          }}
        />
        <JobsCard
          jobs={jobs}
          targetById={targetById}
          findings={findings}
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
  tick,
  jobFindings
}: {
  job: ReconJob;
  target: string | undefined;
  elapsed: string;
  onDismiss: () => void;
  tick: number;
  jobFindings: ReconFinding[];
}) {
  void tick; /* ensures re-render on each 1s elapsed update */
  const terminal = isTerminal(job.status);
  const summary = terminal ? summariseResult(job, jobFindings) : null;
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

function _cpeFromFinding(f: ReconFinding): string | null {
  // The fingerprint service stashes signals like "nginx/1.25.3" into evidence.signals
  // and stack_fingerprint also writes evidence.tech = [{name, version}]. We try
  // both shapes here so this works for any future fingerprint enhancement.
  const ev = (f.evidence_json || {}) as Record<string, unknown>;
  const tech = ev.tech as Array<{ name?: string; version?: string }> | undefined;
  if (Array.isArray(tech)) {
    const hit = tech.find((t) => t && t.name && t.version);
    if (hit && hit.name && hit.version) {
      return `${hit.name.toLowerCase()}:${hit.version}`;
    }
  }
  const signals = ev.signals as string[] | undefined;
  if (Array.isArray(signals)) {
    for (const s of signals) {
      const m = /^([a-zA-Z0-9_+.\-]+)\/([0-9][\w.\-]*)$/.exec((s || "").trim());
      if (m) return `${m[1].toLowerCase()}:${m[2]}`;
    }
  }
  // Try parsing the title for a "<product>/<ver>" hint as a last resort
  const m = /([a-zA-Z][\w+.\-]+)\/([0-9][\w.\-]*)/.exec(f.title || "");
  if (m) return `${m[1].toLowerCase()}:${m[2]}`;
  return null;
}

function FindingsCard({
  findings,
  watchJobId,
  onCpeFill
}: {
  findings: ReconFinding[];
  watchJobId: string | null;
  onCpeFill?: (cpe: string) => void;
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
          {list.map((f, i) => {
            const cpe = onCpeFill ? _cpeFromFinding(f) : null;
            return (
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
                {cpe && onCpeFill && (
                  <button
                    type="button"
                    onClick={() => onCpeFill(cpe)}
                    className="mt-1 text-[11px] inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-accent/40 text-accent hover:bg-accent/15"
                    title={`Run a CVE lookup for ${cpe}`}
                  >
                    <Search className="h-3 w-3" />
                    Lookup CVEs ({cpe})
                  </button>
                )}
              </motion.li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function JobsCard({
  jobs,
  targetById,
  findings,
  onPick,
  onRetry
}: {
  jobs: ReconJob[];
  targetById: Record<string, string>;
  findings: ReconFinding[];
  onPick: (id: string) => void;
  onRetry: (id: string) => Promise<void>;
}) {
  const findingsByJob = useMemo(() => {
    const m = new Map<string, ReconFinding[]>();
    findings.forEach((f) => {
      const arr = m.get(f.job_id);
      if (arr) arr.push(f);
      else m.set(f.job_id, [f]);
    });
    return m;
  }, [findings]);
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
                    {summariseResult(j, findingsByJob.get(j.id))}
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

// --- Toolbox: Export / Diff / Schedule / Asset graph ----------------------- //

const SCHEDULE_KINDS: { value: JobKind; label: string }[] = [
  { value: "subdomain", label: "Subdomain enum" },
  { value: "httprobe", label: "HTTP(S) live probe" },
  { value: "http_headers", label: "Security headers" },
  { value: "tls_audit", label: "TLS deep audit" },
  { value: "wayback", label: "Wayback URLs" },
  { value: "robots_sitemap", label: "robots.txt + sitemap" },
  { value: "js_endpoints", label: "JS endpoints" },
  { value: "takeover", label: "Subdomain takeover" }
];

function ToolboxCard({
  targets,
  currentTargetValue,
  onCpeFill
}: {
  targets: { id: string; value: string }[];
  currentTargetValue: string;
  onCpeFill?: (cpe: string) => void;
}) {
  const [tab, setTab] = useState<"export" | "diff" | "schedule" | "graph">("export");
  void currentTargetValue;
  void onCpeFill;
  return (
    <div className="glass rounded-xl p-4">
      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <div className="text-sm font-semibold">Recon toolbox</div>
        <div className="ml-auto inline-flex rounded-md border border-border/60 overflow-hidden text-[11px]">
          <button
            type="button"
            onClick={() => setTab("export")}
            className={`px-2 py-0.5 inline-flex items-center gap-1 ${tab === "export" ? "bg-accent/15 text-accent" : "text-muted hover:text-fg"}`}
          >
            <Download className="h-3 w-3" /> Export
          </button>
          <button
            type="button"
            onClick={() => setTab("diff")}
            className={`px-2 py-0.5 inline-flex items-center gap-1 ${tab === "diff" ? "bg-accent/15 text-accent" : "text-muted hover:text-fg"}`}
          >
            <GitCompareArrows className="h-3 w-3" /> Diff runs
          </button>
          <button
            type="button"
            onClick={() => setTab("schedule")}
            className={`px-2 py-0.5 inline-flex items-center gap-1 ${tab === "schedule" ? "bg-accent/15 text-accent" : "text-muted hover:text-fg"}`}
          >
            <Calendar className="h-3 w-3" /> Schedules
          </button>
          <button
            type="button"
            onClick={() => setTab("graph")}
            className={`px-2 py-0.5 inline-flex items-center gap-1 ${tab === "graph" ? "bg-accent/15 text-accent" : "text-muted hover:text-fg"}`}
          >
            <Network className="h-3 w-3" /> Asset graph
          </button>
        </div>
      </div>
      {tab === "export" && <ExportPanel targets={targets} />}
      {tab === "diff" && <DiffPanel targets={targets} />}
      {tab === "schedule" && <SchedulePanel targets={targets} />}
      {tab === "graph" && <GraphPanel targets={targets} />}
    </div>
  );
}

function ExportPanel({ targets }: { targets: { id: string; value: string }[] }) {
  const [targetId, setTargetId] = useState<string>("");
  const [severity, setSeverity] = useState<string>("");
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const trigger = async (fmt: "json" | "csv" | "burp" | "nessus") => {
    setBusy(fmt);
    setErr(null);
    try {
      const url = new URL("/api/v1/recon/export", window.location.origin);
      url.searchParams.set("fmt", fmt);
      if (targetId) url.searchParams.set("target_id", targetId);
      if (severity) url.searchParams.set("severity", severity);
      const token = (await import("@/lib/auth")).getAccessToken();
      const res = await fetch(url.toString(), {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        credentials: "include"
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const dl = document.createElement("a");
      dl.href = URL.createObjectURL(blob);
      dl.download =
        fmt === "csv"
          ? "sentinelops-findings.csv"
          : fmt === "burp"
            ? "sentinelops-burp-scope.json"
            : fmt === "nessus"
              ? "sentinelops-findings.nessus"
              : "sentinelops-findings.json";
      document.body.appendChild(dl);
      dl.click();
      dl.remove();
      URL.revokeObjectURL(dl.href);
    } catch (e) {
      setErr(`Export failed: ${(e as Error).message}`);
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="space-y-2 text-xs">
      <div className="flex flex-wrap items-end gap-2">
        <div className="min-w-[220px] flex-1">
          <label className="text-[11px] text-muted uppercase tracking-wider">Target (optional)</label>
          <select
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
            className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-1.5 text-sm outline-none"
          >
            <option value="">All my targets</option>
            {targets.map((t) => (
              <option key={t.id} value={t.id}>{t.value}</option>
            ))}
          </select>
        </div>
        <div className="min-w-[140px]">
          <label className="text-[11px] text-muted uppercase tracking-wider">Severity</label>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-1.5 text-sm outline-none"
          >
            <option value="">Any</option>
            <option value="info">info</option>
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
            <option value="critical">critical</option>
          </select>
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        {(["json", "csv", "burp", "nessus"] as const).map((f) => (
          <button
            key={f}
            type="button"
            disabled={busy !== null}
            onClick={() => void trigger(f)}
            className="px-3 py-1.5 rounded-md bg-accent/15 text-accent border border-accent/40 hover:bg-accent/25 inline-flex items-center gap-1.5 disabled:opacity-60"
          >
            {busy === f ? <Loader2 className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
            {f === "burp" ? "Burp Scope JSON" : f === "nessus" ? "Nessus XML" : f.toUpperCase()}
          </button>
        ))}
      </div>
      {err && <div className="text-danger text-[11px]">{err}</div>}
      <p className="text-[11px] text-muted leading-snug">
        JSON / CSV are flat finding lists. <span className="text-fg/80">Burp Scope JSON</span> imports
        directly via Project options → Target → Scope → Load. <span className="text-fg/80">Nessus XML</span> is
        a NessusClientData_v2 stub that DefectDojo / Faraday / Nexpose accept.
      </p>
    </div>
  );
}

function DiffPanel({ targets }: { targets: { id: string; value: string }[] }) {
  const [pickedTargetId, setTargetId] = useState<string>("");
  const targetId = pickedTargetId || targets[0]?.id || "";
  const [kind, setKind] = useState<string>("subdomain");
  const [result, setResult] = useState<ReconDiffResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    if (!targetId) {
      setErr("Pick a target.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const r = await api.get<ReconDiffResult>(
        `/api/v1/recon/diff?target_id=${encodeURIComponent(targetId)}&kind=${encodeURIComponent(kind)}`
      );
      setResult(r);
    } catch (e) {
      const a = e as ApiError;
      setErr(a.detail || "Failed to compute diff. Need at least one completed job of this kind.");
      setResult(null);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="space-y-2 text-xs">
      <div className="flex flex-wrap items-end gap-2">
        <div className="min-w-[220px] flex-1">
          <label className="text-[11px] text-muted uppercase tracking-wider">Target</label>
          <select
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
            className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-1.5 text-sm outline-none"
          >
            {targets.map((t) => (
              <option key={t.id} value={t.id}>{t.value}</option>
            ))}
          </select>
        </div>
        <div className="min-w-[180px]">
          <label className="text-[11px] text-muted uppercase tracking-wider">Job kind</label>
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value)}
            className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-1.5 text-sm outline-none"
          >
            <option value="subdomain">subdomain</option>
            <option value="wayback">wayback</option>
            <option value="robots_sitemap">robots_sitemap</option>
            <option value="js_endpoints">js_endpoints</option>
          </select>
        </div>
        <button
          type="button"
          onClick={() => void run()}
          disabled={busy}
          className="px-3 py-1.5 rounded-md bg-accent/15 text-accent border border-accent/40 hover:bg-accent/25 inline-flex items-center gap-1.5 disabled:opacity-60"
        >
          {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <GitCompareArrows className="h-3 w-3" />}
          Compute diff
        </button>
      </div>
      {err && <div className="text-danger text-[11px]">{err}</div>}
      {result && (
        <div className="text-[11px] space-y-1">
          <div className="text-muted">
            <span className="text-ok">{result.new_count} new</span> ·{" "}
            <span className="text-danger">{result.removed_count} removed</span> ·{" "}
            <span>{result.stable_count} stable</span> ·{" "}
            base <span className="font-mono">{result.base_job_id?.slice(0, 8) || "—"}</span>{" "}
            head <span className="font-mono">{result.head_job_id.slice(0, 8)}</span>
          </div>
          <ul className="max-h-56 overflow-auto pr-1 space-y-0.5">
            {result.entries
              .filter((e) => e.state !== "stable")
              .map((e) => (
                <li
                  key={`${e.state}:${e.name}`}
                  className={`font-mono ${e.state === "new" ? "text-ok" : "text-danger"}`}
                >
                  {e.state === "new" ? "+ " : "- "}
                  {e.name}
                </li>
              ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function SchedulePanel({ targets }: { targets: { id: string; value: string }[] }) {
  const [items, setItems] = useState<ReconSchedule[]>([]);
  const [pickedTargetId, setTargetId] = useState<string>("");
  const targetId = pickedTargetId || targets[0]?.id || "";
  const [kind, setKind] = useState<JobKind>("subdomain");
  const [intervalMin, setIntervalMin] = useState<string>("60");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const reload = useCallback(async () => {
    try {
      const r = await api.get<ReconSchedule[]>("/api/v1/recon/schedules");
      setItems(r);
      setErr(null);
    } catch (e) {
      setErr((e as ApiError).detail || "Failed to load schedules.");
    }
  }, []);
  useEffect(() => {
    const t = runDeferred(() => void reload());
    return () => clearTimeout(t);
  }, [reload]);
  const create = async () => {
    if (!targetId) {
      setErr("Pick a target.");
      return;
    }
    const min = Number.parseInt(intervalMin, 10);
    if (!Number.isInteger(min) || min < 5 || min > 10080) {
      setErr("Interval must be 5–10080 minutes (5 minutes to 7 days).");
      return;
    }
    setBusy(true);
    try {
      await api.post<ReconSchedule>("/api/v1/recon/schedules", {
        target_id: targetId,
        kind,
        interval_minutes: min,
        enabled: true,
        params: {}
      });
      setErr(null);
      await reload();
    } catch (e) {
      setErr((e as ApiError).detail || "Failed to create schedule.");
    } finally {
      setBusy(false);
    }
  };
  const toggle = async (id: string, enabled: boolean) => {
    try {
      await api.patch<ReconSchedule>(`/api/v1/recon/schedules/${id}`, { enabled });
      await reload();
    } catch (e) {
      setErr((e as ApiError).detail || "Failed to update schedule.");
    }
  };
  const remove = async (id: string) => {
    try {
      await api.del<{ ok: boolean }>(`/api/v1/recon/schedules/${id}`);
      await reload();
    } catch (e) {
      setErr((e as ApiError).detail || "Failed to delete schedule.");
    }
  };
  return (
    <div className="space-y-2 text-xs">
      <div className="flex flex-wrap items-end gap-2">
        <div className="min-w-[220px] flex-1">
          <label className="text-[11px] text-muted uppercase tracking-wider">Target</label>
          <select
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
            className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-1.5 text-sm outline-none"
          >
            {targets.map((t) => (
              <option key={t.id} value={t.id}>{t.value}</option>
            ))}
          </select>
        </div>
        <div className="min-w-[180px]">
          <label className="text-[11px] text-muted uppercase tracking-wider">Job kind</label>
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value as JobKind)}
            className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-1.5 text-sm outline-none"
          >
            {SCHEDULE_KINDS.map((k) => (
              <option key={k.value} value={k.value}>{k.label}</option>
            ))}
          </select>
        </div>
        <div className="min-w-[100px]">
          <label className="text-[11px] text-muted uppercase tracking-wider">Every (min)</label>
          <input
            value={intervalMin}
            onChange={(e) => setIntervalMin(e.target.value.replace(/\D/g, "").slice(0, 5))}
            className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-1.5 text-sm font-mono outline-none"
            placeholder="60"
            title="5 minutes – 7 days (10080)"
          />
        </div>
        <button
          type="button"
          disabled={busy}
          onClick={() => void create()}
          className="px-3 py-1.5 rounded-md bg-accent/15 text-accent border border-accent/40 hover:bg-accent/25 inline-flex items-center gap-1.5 disabled:opacity-60"
        >
          {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <Calendar className="h-3 w-3" />}
          Add schedule
        </button>
      </div>
      {err && <div className="text-danger text-[11px]">{err}</div>}
      {items.length === 0 ? (
        <p className="text-[11px] text-muted">
          No recurring scans yet. Add one above — Celery beat will dispatch it every <span className="text-fg/80">interval</span> minutes.
        </p>
      ) : (
        <ul className="space-y-1 max-h-56 overflow-auto pr-1">
          {items.map((s) => {
            const target = targets.find((t) => t.id === s.target_id);
            return (
              <li key={s.id} className="rounded-md border border-border/50 px-2 py-1 flex items-center gap-2 flex-wrap">
                <span className={`h-2 w-2 rounded-full ${s.enabled ? "bg-ok" : "bg-muted"}`} />
                <span className="font-mono text-[11px]">{target?.value || s.target_id.slice(0, 8)}</span>
                <span className="text-[11px]">{s.kind}</span>
                <span className="text-[11px] text-muted">every {s.interval_minutes}m</span>
                {s.last_run_at && (
                  <span className="text-[11px] text-muted">last {new Date(s.last_run_at).toLocaleString()}</span>
                )}
                <div className="ml-auto inline-flex gap-1">
                  <button
                    type="button"
                    onClick={() => void toggle(s.id, !s.enabled)}
                    className="text-[11px] px-2 py-0.5 rounded-md border border-border/60 hover:border-accent/60"
                  >
                    {s.enabled ? "Pause" : "Resume"}
                  </button>
                  <button
                    type="button"
                    onClick={() => void remove(s.id)}
                    className="text-[11px] px-2 py-0.5 rounded-md border border-danger/40 text-danger hover:bg-danger/10"
                  >
                    Delete
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function GraphPanel({ targets }: { targets: { id: string; value: string }[] }) {
  const [pickedTargetId, setTargetId] = useState<string>("");
  const targetId = pickedTargetId || targets[0]?.id || "";
  const [data, setData] = useState<ReconGraphResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    if (!targetId) {
      setErr("Pick a target.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const r = await api.get<ReconGraphResult>(
        `/api/v1/recon/graph?target_id=${encodeURIComponent(targetId)}`
      );
      setData(r);
    } catch (e) {
      setErr((e as ApiError).detail || "Failed to fetch asset graph.");
      setData(null);
    } finally {
      setBusy(false);
    }
  };
  const counts = useMemo(() => {
    if (!data) return null;
    const c: Record<string, number> = {};
    data.nodes.forEach((n) => {
      c[n.type] = (c[n.type] || 0) + 1;
    });
    return c;
  }, [data]);
  return (
    <div className="space-y-2 text-xs">
      <div className="flex flex-wrap items-end gap-2">
        <div className="min-w-[220px] flex-1">
          <label className="text-[11px] text-muted uppercase tracking-wider">Target</label>
          <select
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
            className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-1.5 text-sm outline-none"
          >
            {targets.map((t) => (
              <option key={t.id} value={t.id}>{t.value}</option>
            ))}
          </select>
        </div>
        <button
          type="button"
          disabled={busy}
          onClick={() => void run()}
          className="px-3 py-1.5 rounded-md bg-accent/15 text-accent border border-accent/40 hover:bg-accent/25 inline-flex items-center gap-1.5 disabled:opacity-60"
        >
          {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <Network className="h-3 w-3" />}
          Build graph
        </button>
      </div>
      {err && <div className="text-danger text-[11px]">{err}</div>}
      {data && counts && (
        <div className="space-y-1">
          <div className="text-[11px] text-muted">
            {data.nodes.length} nodes · {data.edges.length} edges ·{" "}
            {Object.entries(counts)
              .map(([k, v]) => `${k}:${v}`)
              .join(" · ")}
          </div>
          <details className="text-[11px]">
            <summary className="cursor-pointer hover:text-accent">Edges</summary>
            <ul className="mt-1 max-h-40 overflow-auto pr-1 space-y-0.5">
              {data.edges.slice(0, 200).map((e, i) => (
                <li key={i} className="font-mono">
                  <span className="text-muted">{e.source}</span>
                  <span className="text-accent"> {"-["}{e.relation}{"]->"} </span>
                  <span>{e.target}</span>
                </li>
              ))}
              {data.edges.length > 200 && (
                <li className="text-muted">… and {data.edges.length - 200} more</li>
              )}
            </ul>
          </details>
          <details className="text-[11px]">
            <summary className="cursor-pointer hover:text-accent">Raw JSON</summary>
            <pre className="mt-1 max-h-48 overflow-auto bg-bg/40 border border-border/40 rounded-md p-2 font-mono text-[11px]">
              {JSON.stringify(data, null, 2)}
            </pre>
          </details>
        </div>
      )}
      <p className="text-[11px] text-muted leading-snug">
        Builds a node/edge view from your most-recent done jobs:{" "}
        <span className="font-mono">target → subdomain → ip → service</span>, plus{" "}
        <span className="font-mono">target → cve</span> for NVD findings and{" "}
        <span className="font-mono">target → takeover</span> for any vulnerable subdomain matches.
      </p>
    </div>
  );
}
