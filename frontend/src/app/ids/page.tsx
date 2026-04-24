"use client";

import { useCallback, useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Radar, Sparkles } from "lucide-react";
import SectionHeader from "@/components/shared/SectionHeader";
import {
  api,
  type ApiError,
  type IdsInferenceResult,
  type IdsModelInfo,
  type Inference
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

function formatTs(iso: string) {
  try {
    return new Date(iso).toLocaleTimeString(undefined, { hour12: false });
  } catch {
    return iso;
  }
}

export default function IdsPage() {
  const [features, setFeatures] = useState(DEFAULT_FEATURES);
  const [result, setResult] = useState<IdsInferenceResult | null>(null);
  const [modelInfo, setModelInfo] = useState<IdsModelInfo | null>(null);
  const [recent, setRecent] = useState<Inference[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

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

  useEffect(() => {
    const t = runDeferred(() => void loadModelAndHistory());
    return () => clearTimeout(t);
  }, [loadModelAndHistory]);

  async function runInference() {
    setError(null);
    setInfo(null);
    setBusy(true);
    setResult(null);
    try {
      const obj = JSON.parse(features) as Record<string, unknown>;
      const featuresRecord: Record<string, number | string> = {};
      for (const [k, v] of Object.entries(obj)) {
        if (typeof v === "number" || typeof v === "string") {
          featuresRecord[k] = v;
        } else if (typeof v === "boolean") {
          featuresRecord[k] = v ? 1 : 0;
        } else {
          featuresRecord[k] = String(v);
        }
      }
      const out = await api.post<IdsInferenceResult>("/api/v1/ids/infer", {
        features: featuresRecord,
        explain: false
      });
      setResult(out);
      setInfo("Inference stored. Recent table refreshes on load; expand history after run.");
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
        description="RandomForest on NSL-KDD features. Paste a JSON object of feature names → values; inference runs on the real API and is persisted."
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
            <Radar className="h-4 w-4 text-accent" /> Inference playground
          </div>
          <textarea
            value={features}
            onChange={(e) => setFeatures(e.target.value)}
            spellCheck={false}
            disabled={busy}
            className="w-full h-56 bg-bg/60 border border-border/60 rounded-md p-3 font-mono text-xs outline-none focus:border-accent/60"
          />
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
