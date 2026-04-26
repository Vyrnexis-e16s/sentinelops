"use client";

import { useCallback, useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Brain, Loader2, Network, Plus, Save, Sparkles, Trash2 } from "lucide-react";
import SectionHeader from "@/components/shared/SectionHeader";
import {
  api,
  type ApiError,
  type Alert,
  type Inference,
  type LlmSummarizeResult,
  type Paginated,
  type ReconFinding,
  type VaptBrief,
  type VaptSurface
} from "@/lib/api";
import { runDeferred } from "@/lib/schedule-deferred";

export default function VaptPage() {
  const [surface, setSurface] = useState<VaptSurface | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [ctx, setCtx] = useState("");
  const [out, setOut] = useState<string | null>(null);
  const [llmModel, setLlmModel] = useState<string | null>(null);
  const [briefs, setBriefs] = useState<VaptBrief[]>([]);
  const [saving, setSaving] = useState(false);
  const [title, setTitle] = useState("Executive summary");
  const [busy, setBusy] = useState({ load: true, gen: false, del: null as string | null });

  const load = useCallback(async () => {
    setErr(null);
    setBusy((b) => ({ ...b, load: true }));
    try {
      const [s, b] = await Promise.all([
        api.get<VaptSurface>("/api/v1/vapt/surface"),
        api.get<Paginated<VaptBrief>>("/api/v1/vapt/briefs?size=30")
      ]);
      setSurface(s);
      setBriefs(b.items);
    } catch (e) {
      const a = e as ApiError;
      if (a.status === 401) {
        setErr("Sign in to use the VAPT command view.");
      } else {
        setErr(a.detail || "Failed to load VAPT data.");
      }
    } finally {
      setBusy((b) => ({ ...b, load: false }));
    }
  }, []);

  useEffect(() => {
    const t = runDeferred(() => void load());
    return () => clearTimeout(t);
  }, [load]);

  const assembleContext = useCallback(async () => {
    setErr(null);
    setBusy((b) => ({ ...b, load: true }));
    try {
      const [s, f, a, i] = await Promise.all([
        api.get<VaptSurface>("/api/v1/vapt/surface"),
        api.get<Paginated<ReconFinding>>("/api/v1/recon/findings?size=40"),
        api.get<Paginated<Alert>>("/api/v1/siem/alerts?size=15"),
        api.get<Inference[]>("/api/v1/ids/inferences?limit=25")
      ]);
      setSurface(s);
      const block = {
        vapt_surface: s,
        recon_findings_excerpt: f.items.map((x) => ({
          severity: x.severity,
          title: x.title,
          description: (x.description || "").slice(0, 500)
        })),
        siem_alerts_excerpt: a.items.map((x) => ({
          rule: x.rule_name,
          score: x.score,
          status: x.status
        })),
        ids_inferences_excerpt: i.map((x) => ({
          label: x.label,
          prediction: x.prediction,
          probability: x.probability
        }))
      };
      setCtx(JSON.stringify(block, null, 2));
    } catch (e) {
      const a = e as ApiError;
      setErr(a.detail || "Could not assemble context from the API.");
    } finally {
      setBusy((b) => ({ ...b, load: false }));
    }
  }, []);

  const generate = async () => {
    if (!ctx.trim()) {
      setErr("Paste or assemble context first.");
      return;
    }
    setErr(null);
    setOut(null);
    setLlmModel(null);
    setBusy((b) => ({ ...b, gen: true }));
    try {
      const r = await api.post<LlmSummarizeResult>("/api/v1/vapt/llm/summarize", {
        context: ctx
      });
      setOut(r.summary);
      setLlmModel(r.model);
    } catch (e) {
      const a = e as ApiError;
      if (a.status === 503) {
        setErr(
          `${a.detail} Configure OPENAI_API_KEY and optionally SENTINELOPS_LLM_BASE_URL (for Ollama/vLLM) on the API.`
        );
      } else {
        setErr(a.detail || "LLM call failed.");
      }
    } finally {
      setBusy((b) => ({ ...b, gen: false }));
    }
  };

  const saveBrief = async () => {
    if (!out?.trim()) return;
    setSaving(true);
    setErr(null);
    try {
      const row = await api.post<VaptBrief>("/api/v1/vapt/briefs", { title, body: out });
      setBriefs((prev) => [row, ...prev]);
    } catch (e) {
      const a = e as ApiError;
      setErr(a.detail || "Save failed — run `alembic upgrade head` if the table is missing.");
    } finally {
      setSaving(false);
    }
  };

  const remove = async (id: string) => {
    setBusy((b) => ({ ...b, del: id }));
    setErr(null);
    try {
      await api.del(`/api/v1/vapt/briefs/${id}`);
      setBriefs((prev) => prev.filter((b) => b.id !== id));
    } catch (e) {
      const a = e as ApiError;
      setErr(a.detail || "Delete failed.");
    } finally {
      setBusy((b) => ({ ...b, del: null }));
    }
  };

  return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-amber-500/25 bg-gradient-to-br from-amber-950/25 via-bg to-violet-950/20 p-[1px] shadow-[0_0_40px_-12px_rgba(245,158,11,0.35)]">
        <div className="rounded-2xl bg-bg/90 backdrop-blur-sm px-4 py-5 md:px-6">
          <div className="flex flex-wrap items-start gap-3">
            <div className="h-10 w-10 rounded-lg bg-amber-500/15 border border-amber-500/40 grid place-items-center shrink-0">
              <Network className="h-5 w-5 text-amber-400" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-[10px] uppercase tracking-[0.2em] text-amber-400/90 font-mono">
                VAPT · live fabric
              </p>
              <h1 className="text-lg md:text-xl font-semibold text-text mt-0.5">
                Unified surface &amp; triage
              </h1>
              <p className="text-sm text-muted mt-1 max-w-3xl">
                Metrics and assembled context are read from your running SentinelOps services (Postgres
                + workers). The optional triage call uses your configured OpenAI-compatible endpoint —
                it never returns canned copy when the key is missing (you get a 503 with setup text).
                Saved briefs are stored in <span className="font-mono">vapt_briefs</span> per user.
              </p>
            </div>
          </div>
        </div>
      </div>

      <SectionHeader
        eyebrow="Operations"
        title="Attack-surface &amp; intelligence"
        description="Roll-up of SIEM, your recon jobs, deployment IDS, vault, and investigations. Distinct from the main dashboard: purpose-built for assessment workflows."
      />

      {err && (
        <div className="text-sm text-danger border border-danger/40 rounded-md px-3 py-2 bg-danger/5">
          {err}
        </div>
      )}

      {busy.load && !surface && (
        <div className="flex items-center gap-2 text-sm text-muted">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading live surface…
        </div>
      )}

      {surface && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2"
        >
          {(
            [
              ["SIEM new", surface.siem_alerts_new],
              ["SIEM ack", surface.siem_alerts_ack],
              ["Events 24h", surface.siem_events_24h],
              ["Recon Q", surface.recon_jobs_queued],
              ["Recon run", surface.recon_jobs_running],
              ["Recon findings", surface.recon_findings_total],
              ["IDS 24h", surface.ids_inferences_24h],
              ["IDS attacks 24h", surface.ids_attacks_24h],
              ["Vault files", surface.vault_files],
              ["Cases open", surface.investigations_open]
            ] as const
          ).map(([k, v]) => (
            <div
              key={k}
              className="rounded-lg border border-border/50 bg-panel/50 px-3 py-2 font-mono text-xs"
            >
              <div className="text-muted text-[10px] uppercase tracking-wide">{k}</div>
              <div className="text-lg text-fg font-semibold tabular-nums">{v}</div>
            </div>
          ))}
        </motion.div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="glass rounded-xl p-4 border border-violet-500/20">
          <div className="flex items-center gap-2 mb-3 text-violet-300/90">
            <Sparkles className="h-4 w-4" />
            <span className="text-sm font-medium">Triage context (editable JSON / text)</span>
          </div>
          <div className="flex flex-wrap gap-2 mb-2">
            <button
              type="button"
              onClick={() => void assembleContext()}
              disabled={busy.load}
              className="text-xs px-3 py-1.5 rounded-md border border-amber-500/40 text-amber-200 hover:bg-amber-500/10"
            >
              Assemble from live API
            </button>
            <span className="text-[11px] text-muted self-center">
              Pulls surface + recon + SIEM + IDS — you may edit before LLM.
            </span>
          </div>
          <textarea
            value={ctx}
            onChange={(e) => setCtx(e.target.value)}
            rows={12}
            className="w-full text-xs font-mono bg-bg/50 border border-border/60 rounded-md p-2 outline-none focus:border-violet-500/50"
            spellCheck={false}
          />
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => void generate()}
              disabled={busy.gen}
              className="inline-flex items-center gap-2 text-sm px-4 py-2 rounded-md bg-violet-600/20 text-violet-200 border border-violet-500/50 hover:bg-violet-600/30 disabled:opacity-50"
            >
              {busy.gen ? <Loader2 className="h-4 w-4 animate-spin" /> : <Brain className="h-4 w-4" />}
              Generate triage (LLM)
            </button>
            {llmModel && <span className="text-[11px] text-muted font-mono">Model: {llmModel}</span>}
          </div>
        </div>

        <div className="glass rounded-xl p-4 border border-emerald-500/15">
          <div className="flex items-center gap-2 mb-3 text-emerald-200/80">
            <Plus className="h-4 w-4" />
            <span className="text-sm font-medium">Output &amp; memory</span>
          </div>
          <pre className="whitespace-pre-wrap text-xs text-text/90 font-mono min-h-[12rem] max-h-[20rem] overflow-auto bg-bg/40 rounded-md p-3 border border-border/40">
            {out || "Generated summary appears here. Requires OPENAI_API_KEY on the API."}
          </pre>
          <div className="mt-3 flex flex-wrap items-end gap-2">
            <div className="flex-1 min-w-[120px]">
              <label className="text-[10px] text-muted">Save title</label>
              <input
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="mt-0.5 w-full text-sm bg-panel/50 border border-border/60 rounded px-2 py-1"
              />
            </div>
            <button
              type="button"
              onClick={() => void saveBrief()}
              disabled={saving || !out}
              className="inline-flex items-center gap-1.5 text-xs px-3 py-2 rounded-md border border-ok/40 text-ok hover:bg-ok/10 disabled:opacity-50"
            >
              {saving ? <Loader2 className="h-3 w-3 animate-spin" /> : <Save className="h-3 w-3" />}
              Save to briefs
            </button>
          </div>
        </div>
      </div>

      <div className="glass rounded-xl p-4 border border-border/50">
        <h3 className="text-sm font-medium mb-2">Saved briefs (Postgres · per user)</h3>
        {briefs.length === 0 ? (
          <p className="text-sm text-muted">None yet. Generate and save, or run migrations if needed.</p>
        ) : (
          <ul className="space-y-2">
            {briefs.map((b) => (
              <li
                key={b.id}
                className="flex gap-2 items-start border border-border/40 rounded-md p-2 bg-panel/30"
              >
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-fg">{b.title}</div>
                  <div className="text-[10px] text-muted font-mono">{b.created_at}</div>
                  <p className="text-xs text-muted mt-1 line-clamp-3 whitespace-pre-wrap">{b.body}</p>
                </div>
                <button
                  type="button"
                  title="Delete"
                  disabled={busy.del === b.id}
                  onClick={() => void remove(b.id)}
                  className="p-1.5 rounded border border-border/50 text-muted hover:text-danger"
                >
                  {busy.del === b.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
