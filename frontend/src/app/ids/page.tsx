"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Radar, RefreshCcw, Sparkles } from "lucide-react";
import SectionHeader from "@/components/shared/SectionHeader";
import {
  api,
  type ApiError,
  type IdsInferenceResult,
  type IdsModelInfo,
  type Inference,
  type Paginated,
  type ReconJob,
  type ReconTarget
} from "@/lib/api";
import { runDeferred } from "@/lib/schedule-deferred";

const DEFAULT_FEATURES = `{
  "duration": 0,
  "protocol_type": "tcp",
  "service": "http",
  "flag": "SF",
  "src_bytes": 28000,
  "dst_bytes": 1200,
  "serror_rate": 0.93,
  "srv_serror_rate": 0.91
}`;

const HTTP_LOG_TEMPLATE_HINT = `{
  "url": "https://<your-host>/login",
  "method": "POST",
  "status_code": 200,
  "request_bytes": 850,
  "response_bytes": 4200,
  "duration": 0.12
}`;

type ReconHttpProbe = {
  url?: string;
  method?: string;
  status?: number;
  request_bytes?: number;
  response_bytes?: number;
  duration_seconds?: number;
  error?: string;
};

function formatTs(iso: string) {
  try {
    return new Date(iso).toLocaleTimeString(undefined, { hour12: false });
  } catch {
    return iso;
  }
}

function jobIsHttpProbe(j: ReconJob): boolean {
  return j.kind === "httprobe" && j.status === "done";
}

function extractProbes(job: ReconJob): ReconHttpProbe[] {
  const raw = (job.result_json as { probes?: ReconHttpProbe[] } | undefined)?.probes;
  return Array.isArray(raw) ? raw : [];
}

function probeToFlowJson(probe: ReconHttpProbe): string {
  const body = {
    url: probe.url ?? "",
    method: (probe.method || "GET").toUpperCase(),
    status_code: probe.status ?? 200,
    request_bytes: typeof probe.request_bytes === "number" ? probe.request_bytes : 250,
    response_bytes: typeof probe.response_bytes === "number" ? probe.response_bytes : 0,
    duration: typeof probe.duration_seconds === "number" ? probe.duration_seconds : 0
  };
  return JSON.stringify(body, null, 2);
}

export default function IdsPage() {
  const [features, setFeatures] = useState(DEFAULT_FEATURES);
  const [result, setResult] = useState<IdsInferenceResult | null>(null);
  const [modelInfo, setModelInfo] = useState<IdsModelInfo | null>(null);
  const [recent, setRecent] = useState<Inference[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [reconJobs, setReconJobs] = useState<ReconJob[]>([]);
  const [reconTargets, setReconTargets] = useState<ReconTarget[]>([]);
  const [reconJobId, setReconJobId] = useState<string>("");
  const [reconProbeIdx, setReconProbeIdx] = useState<number>(0);
  const [reconLoading, setReconLoading] = useState(false);

  const loadModelAndHistory = useCallback(async () => {
    try {
      const [m, list] = await Promise.all([
        api.get<IdsModelInfo>("/api/v1/ids/model/info"),
        api.get<Inference[]>("/api/v1/ids/inferences?limit=12")
      ]);
      setModelInfo(m);
      setRecent(list);
      setError(null);
    } catch (e) {
      const a = e as ApiError;
      if (a.status === 401) {
        setError("Sign in so the app can call the IDS API.");
      } else {
        setError(a.detail || "Could not load model info or history.");
      }
    }
  }, []);

  const loadReconHttpProbes = useCallback(async () => {
    setReconLoading(true);
    try {
      const [jobsResp, targets] = await Promise.all([
        api.get<Paginated<ReconJob>>("/api/v1/recon/jobs?size=200&page=1"),
        api.get<ReconTarget[]>("/api/v1/recon/targets")
      ]);
      const probes = jobsResp.items.filter(jobIsHttpProbe).filter((j) => extractProbes(j).length > 0);
      setReconJobs(probes);
      setReconTargets(targets);
      if (probes.length > 0) {
        setReconJobId((prev) => (prev && probes.some((j) => j.id === prev) ? prev : probes[0].id));
      } else {
        setReconJobId("");
      }
      setReconProbeIdx(0);
    } catch (e) {
      const a = e as ApiError;
      if (a.status === 401) {
        setError("Sign in so the app can read recon jobs.");
      }
    } finally {
      setReconLoading(false);
    }
  }, []);

  useEffect(() => {
    const t = runDeferred(() => void loadModelAndHistory());
    return () => clearTimeout(t);
  }, [loadModelAndHistory]);

  useEffect(() => {
    const t = runDeferred(() => void loadReconHttpProbes());
    return () => clearTimeout(t);
  }, [loadReconHttpProbes]);

  const targetByIdValue = useMemo(() => {
    const m = new Map<string, string>();
    for (const t of reconTargets) m.set(t.id, t.value);
    return m;
  }, [reconTargets]);

  const selectedJob = useMemo(
    () => reconJobs.find((j) => j.id === reconJobId) ?? null,
    [reconJobs, reconJobId]
  );

  const selectedJobProbes = useMemo(
    () => (selectedJob ? extractProbes(selectedJob) : []),
    [selectedJob]
  );

  const useReconProbe = useCallback(() => {
    if (!selectedJob || selectedJobProbes.length === 0) return;
    const probe = selectedJobProbes[Math.min(reconProbeIdx, selectedJobProbes.length - 1)];
    if (!probe) return;
    if (probe.error) {
      setError(`That probe failed (${probe.error}). Pick a different one.`);
      return;
    }
    setError(null);
    setInfo(null);
    setFeatures(probeToFlowJson(probe));
  }, [selectedJob, selectedJobProbes, reconProbeIdx]);

  async function runInference() {
    setError(null);
    setInfo(null);
    setBusy(true);
    setResult(null);
    try {
      const parsed = JSON.parse(features) as Record<string, unknown> | Array<Record<string, unknown>>;
      if (Array.isArray(parsed)) {
        const flows = parsed.map(toFeatureRecord);
        const out = await api.post<IdsInferenceResult[]>("/api/v1/ids/infer/bulk", {
          flows
        });
        setResult(out.at(-1) ?? null);
        setInfo(`Stored ${out.length} flow inference(s).`);
        await loadModelAndHistory();
        return;
      }
      const featuresRecord = toFeatureRecord(parsed);
      const out = await api.post<IdsInferenceResult>("/api/v1/ids/infer", {
        features: featuresRecord,
        explain: true
      });
      setResult(out);
      setInfo("Flow inference stored and audited.");
      await loadModelAndHistory();
    } catch (e) {
      const a = e as ApiError;
      if (a.status === 401) {
        setError("Not authenticated.");
      } else if (a.status === 503) {
        setError(
          a.detail || "IDS model missing. Run `python ml/scripts/train_ids.py` and ensure `ml/artifacts` is available to the API."
        );
      } else {
        setError(a.detail || "Invalid JSON or inference failed.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <SectionHeader
        eyebrow="Detection · ML"
        title="Network IDS"
        description="NSL-KDD-style flow inference. Paste one JSON flow or an array of flows from NetFlow, Zeek, Suricata, proxy logs, or HTTP access logs — or pull a real probe from your recon jobs below. The model returns benign/attack with a probability and (when available) a class."
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

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="glass rounded-xl p-4 lg:col-span-2">
          <div className="text-sm font-semibold flex items-center gap-2 mb-3">
            <Radar className="h-4 w-4 text-accent" /> Flow inference
          </div>
          <textarea
            value={features}
            onChange={(e) => setFeatures(e.target.value)}
            spellCheck={false}
            disabled={busy}
            className="w-full h-56 bg-bg/60 border border-border/60 rounded-md p-3 font-mono text-xs outline-none focus:border-accent/60"
          />

          <div className="mt-3 rounded-md border border-border/60 bg-bg/40 p-3">
            <div className="text-[11px] uppercase tracking-wider text-muted mb-2 flex items-center gap-2">
              <span>Pull from real recon HTTP probe</span>
              <button
                type="button"
                onClick={() => void loadReconHttpProbes()}
                disabled={reconLoading}
                className="text-[10px] inline-flex items-center gap-1 text-muted hover:text-fg disabled:opacity-50"
                aria-label="Refresh recon jobs"
              >
                <RefreshCcw className="h-3 w-3" />
                {reconLoading ? "Loading…" : "Refresh"}
              </button>
            </div>
            {reconJobs.length === 0 ? (
              <p className="text-xs text-muted">
                No completed httprobe jobs yet. Run an httprobe in the Recon tab against a real target — it will appear here automatically and you can replay it through the IDS model.
              </p>
            ) : (
              <div className="flex items-center gap-2 flex-wrap">
                <select
                  value={reconJobId}
                  onChange={(e) => {
                    setReconJobId(e.target.value);
                    setReconProbeIdx(0);
                  }}
                  className="text-xs bg-bg/60 border border-border/60 rounded-md px-2 py-1.5 outline-none focus:border-accent/60"
                  disabled={busy}
                >
                  {reconJobs.map((j) => {
                    const target = targetByIdValue.get(j.target_id) ?? "(unknown target)";
                    const ts = j.finished_at ?? j.started_at ?? "";
                    return (
                      <option key={j.id} value={j.id}>
                        {target} · {extractProbes(j).length} probe(s)
                        {ts ? ` · ${formatTs(ts)}` : ""}
                      </option>
                    );
                  })}
                </select>
                {selectedJobProbes.length > 1 && (
                  <select
                    value={reconProbeIdx}
                    onChange={(e) => setReconProbeIdx(Number(e.target.value))}
                    className="text-xs bg-bg/60 border border-border/60 rounded-md px-2 py-1.5 outline-none focus:border-accent/60"
                    disabled={busy}
                  >
                    {selectedJobProbes.map((p, idx) => (
                      <option key={idx} value={idx}>
                        {p.error ? "× " : ""}
                        {(p.method || "GET").toUpperCase()} {p.url ?? "(no url)"} · {p.status ?? "—"}
                      </option>
                    ))}
                  </select>
                )}
                <button
                  type="button"
                  onClick={useReconProbe}
                  disabled={busy || !selectedJob || selectedJobProbes.length === 0}
                  className="text-xs px-3 py-1.5 rounded-md border border-accent/40 text-accent hover:bg-accent/10 disabled:opacity-50"
                >
                  Use this probe
                </button>
              </div>
            )}
            <details className="mt-2 text-[11px] text-muted">
              <summary className="cursor-pointer">HTTP-log template (manual entry)</summary>
              <pre className="mt-2 font-mono text-[11px] bg-bg/60 border border-border/40 rounded p-2 overflow-x-auto">
{HTTP_LOG_TEMPLATE_HINT}
              </pre>
              <button
                type="button"
                onClick={() => setFeatures(HTTP_LOG_TEMPLATE_HINT)}
                disabled={busy}
                className="mt-2 text-[11px] px-2 py-1 rounded border border-border/60 hover:border-accent/60 disabled:opacity-50"
              >
                Load template into editor
              </button>
            </details>
          </div>

          <div className="mt-3 flex items-center gap-3 flex-wrap">
            <button
              type="button"
              onClick={() => void runInference()}
              disabled={busy}
              className="text-xs px-3 py-1.5 rounded-md bg-accent/15 text-accent border border-accent/40 hover:bg-accent/25 inline-flex items-center gap-1.5 disabled:opacity-50"
            >
              <Sparkles className="h-3.5 w-3.5" />
              {busy ? "Inferring…" : "Run inference"}
            </button>
            {result && (
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="text-xs flex items-center gap-3 flex-wrap"
              >
                <span className="text-muted">prediction</span>
                <span
                  className={
                    result.label === "attack" ? "text-danger" : "text-ok"
                  }
                >
                  {result.prediction}
                </span>
                <span className="text-muted">prob</span>
                <span className="font-mono">{result.probability.toFixed(2)}</span>
                {result.attack_class && (
                  <>
                    <span className="text-muted">class</span>
                    <span className="font-mono">{result.attack_class}</span>
                  </>
                )}
              </motion.div>
            )}
          </div>
        </div>

        <div className="glass rounded-xl p-4">
          <div className="text-sm font-semibold mb-3">Model</div>
          {modelInfo ? (
            <dl className="text-xs grid grid-cols-2 gap-y-2">
              <dt className="text-muted">Artifact</dt>
              <dd>{modelInfo.artifact_present ? "present" : "missing"}</dd>
              <dt className="text-muted">Algorithm</dt>
              <dd>RandomForest (see ml)</dd>
              <dt className="text-muted">Features</dt>
              <dd>{modelInfo.feature_count}</dd>
              <dt className="text-muted">Classes</dt>
              <dd>{modelInfo.classes.length}</dd>
              <dt className="text-muted">Accuracy</dt>
              <dd className="text-ok">
                {modelInfo.accuracy != null ? modelInfo.accuracy.toFixed(3) : "—"}
              </dd>
              {modelInfo.notes && (
                <>
                  <dt className="text-muted col-span-2">Notes</dt>
                  <dd className="col-span-2 text-muted leading-snug">
                    {modelInfo.notes}
                  </dd>
                </>
              )}
            </dl>
          ) : (
            <p className="text-xs text-muted">Loading model metadata…</p>
          )}
          {modelInfo?.feature_list?.length ? (
            <details className="mt-4 text-xs">
              <summary className="cursor-pointer text-muted">Accepted canonical features</summary>
              <div className="mt-2 max-h-36 overflow-auto font-mono text-[11px] text-muted">
                {modelInfo.feature_list.join(", ")}
              </div>
              <p className="mt-2 text-[11px] text-muted">
                Common aliases accepted by the API include protocol/proto, service/app, bytes/request_bytes,
                response_bytes, url, method, and status_code.
              </p>
            </details>
          ) : null}
        </div>
      </div>

      <div className="glass rounded-xl p-4">
        <div className="text-sm font-semibold mb-3">Recent inferences</div>
        {recent.length === 0 ? (
          <p className="text-xs text-muted">No stored inferences yet. Run one above.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm min-w-[520px]">
              <thead className="text-[11px] uppercase tracking-wider text-muted">
                <tr>
                  <th className="text-left pb-2">Time</th>
                  <th className="text-left pb-2">Prediction</th>
                  <th className="text-left pb-2">Prob</th>
                  <th className="text-left pb-2">Label</th>
                  <th className="text-left pb-2">Class</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((r) => (
                  <tr key={r.id} className="border-t border-border/40">
                    <td className="py-2 font-mono text-xs">
                      {formatTs(r.timestamp)}
                    </td>
                    <td className="py-2">{r.prediction}</td>
                    <td className="py-2 font-mono text-xs">
                      {r.probability.toFixed(2)}
                    </td>
                    <td className="py-2">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[11px] ${
                          r.label === "attack"
                            ? "bg-danger/15 text-danger"
                            : "bg-ok/15 text-ok"
                        }`}
                      >
                        {r.label}
                      </span>
                    </td>
                    <td className="py-2 text-muted">
                      {r.attack_class ?? "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function toFeatureRecord(obj: Record<string, unknown>): Record<string, number | string> {
  const featuresRecord: Record<string, number | string> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === "number" || typeof v === "string") {
      featuresRecord[k] = v;
    } else if (typeof v === "boolean") {
      featuresRecord[k] = v ? 1 : 0;
    } else if (v != null) {
      featuresRecord[k] = JSON.stringify(v);
    }
  }
  return featuresRecord;
}
