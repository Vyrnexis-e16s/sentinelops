"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { Radar, Sparkles } from "lucide-react";
import SectionHeader from "@/components/shared/SectionHeader";

const SAMPLE_FEATURES = `{
  "duration": 0,
  "protocol_type": "tcp",
  "service": "http",
  "flag": "SF",
  "src_bytes": 28000,
  "dst_bytes": 1200,
  "serror_rate": 0.93,
  "srv_serror_rate": 0.91
}`;

const RECENT = [
  { ts: "12:04:18", pred: "neptune", prob: 0.94, label: "attack", cls: "dos" },
  { ts: "12:04:11", pred: "normal", prob: 0.99, label: "benign", cls: null },
  { ts: "12:04:03", pred: "satan", prob: 0.71, label: "attack", cls: "probe" },
  { ts: "12:03:58", pred: "normal", prob: 0.97, label: "benign", cls: null },
  { ts: "12:03:42", pred: "smurf", prob: 0.83, label: "attack", cls: "dos" }
];

export default function IdsPage() {
  const [features, setFeatures] = useState(SAMPLE_FEATURES);
  const [result, setResult] = useState<null | { pred: string; prob: number; label: string }>(null);
  const [busy, setBusy] = useState(false);

  async function runDemo() {
    setBusy(true);
    // Local demo logic: just look at serror_rate. Wire to /api/v1/ids/infer when backend is up.
    try {
      const parsed = JSON.parse(features);
      const isAttack = (parsed.serror_rate ?? 0) > 0.5 || (parsed.src_bytes ?? 0) > 10000;
      await new Promise((r) => setTimeout(r, 350));
      setResult({
        pred: isAttack ? "neptune" : "normal",
        prob: isAttack ? 0.91 : 0.97,
        label: isAttack ? "attack" : "benign"
      });
    } catch {
      setResult({ pred: "error", prob: 0, label: "error" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <SectionHeader
        eyebrow="Detection · ML"
        title="Network IDS"
        description="RandomForest classifier on NSL-KDD features. Paste a flow, get a verdict."
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="glass rounded-xl p-4 lg:col-span-2">
          <div className="text-sm font-semibold flex items-center gap-2 mb-3">
            <Radar className="h-4 w-4 text-accent" /> Inference playground
          </div>
          <textarea
            value={features}
            onChange={(e) => setFeatures(e.target.value)}
            spellCheck={false}
            className="w-full h-56 bg-bg/60 border border-border/60 rounded-md p-3 font-mono text-xs outline-none focus:border-accent/60"
          />
          <div className="mt-3 flex items-center gap-3">
            <button
              onClick={runDemo}
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
                className="text-xs flex items-center gap-3"
              >
                <span className="text-muted">prediction</span>
                <span className={result.label === "attack" ? "text-danger" : "text-ok"}>
                  {result.pred}
                </span>
                <span className="text-muted">prob</span>
                <span className="font-mono">{result.prob.toFixed(2)}</span>
              </motion.div>
            )}
          </div>
        </div>

        <div className="glass rounded-xl p-4">
          <div className="text-sm font-semibold mb-3">Model</div>
          <dl className="text-xs grid grid-cols-2 gap-y-2">
            <dt className="text-muted">Algorithm</dt>
            <dd>RandomForest (120 trees)</dd>
            <dt className="text-muted">Dataset</dt>
            <dd>NSL-KDD</dd>
            <dt className="text-muted">Features</dt>
            <dd>41</dd>
            <dt className="text-muted">Classes</dt>
            <dd>5</dd>
            <dt className="text-muted">Accuracy</dt>
            <dd className="text-ok">0.998 (real) / 0.80 (synth)</dd>
          </dl>
        </div>
      </div>

      <div className="glass rounded-xl p-4">
        <div className="text-sm font-semibold mb-3">Recent inferences</div>
        <table className="w-full text-sm">
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
            {RECENT.map((r, i) => (
              <tr key={i} className="border-t border-border/40">
                <td className="py-2 font-mono text-xs">{r.ts}</td>
                <td className="py-2">{r.pred}</td>
                <td className="py-2 font-mono text-xs">{r.prob.toFixed(2)}</td>
                <td className="py-2">
                  <span
                    className={`px-2 py-0.5 rounded-full text-[11px] ${
                      r.label === "attack" ? "bg-danger/15 text-danger" : "bg-ok/15 text-ok"
                    }`}
                  >
                    {r.label}
                  </span>
                </td>
                <td className="py-2 text-muted">{r.cls ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
