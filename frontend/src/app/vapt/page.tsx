"use client";

import { useCallback, useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  Brain,
  ClipboardCopy,
  Loader2,
  Network,
  Plus,
  Save,
  Sparkles,
  Trash2
} from "lucide-react";
import SectionHeader from "@/components/shared/SectionHeader";
import {
  RECON_KINDS,
  api,
  type ApiError,
  type Alert,
  type Inference,
  type LlmSummarizeResult,
  type MitreFoundationOut,
  type Paginated,
  type ReconFinding,
  type VaptAnalystFeedback,
  type VaptBrief,
  type VaptCypherExport,
  type VaptGraphEdge,
  type VaptOrchestrateResult,
  type VaptSurface,
  type VaptTtpMemory
} from "@/lib/api";
import { getApiErrorMessage, isUnauthorized, redirectToReauth } from "@/lib/api-auth";
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
  const [injectMitre, setInjectMitre] = useState(false);
  const [useLlmCascade, setUseLlmCascade] = useState(true);
  const [mitre, setMitre] = useState<MitreFoundationOut | null>(null);
  const [ttpRows, setTtpRows] = useState<VaptTtpMemory[]>([]);
  const [ttpTid, setTtpTid] = useState("T1190");
  const [ttpName, setTtpName] = useState("");
  const [ttpBody, setTtpBody] = useState("");
  const [ttpBusy, setTtpBusy] = useState(false);
  const [edges, setEdges] = useState<VaptGraphEdge[]>([]);
  const [eFrom, setEFrom] = useState("T1190");
  const [eTo, setETo] = useState("T1003");
  const [eRel, setERel] = useState("leads_to");
  const [eNote, setENote] = useState("");
  const [eBusy, setEBusy] = useState(false);
  const [cypher, setCypher] = useState<VaptCypherExport | null>(null);
  const [orchTarget, setOrchTarget] = useState("example.com");
  const [orchKinds, setOrchKinds] = useState<Set<string>>(
    () => new Set(["subdomain", "dns", "httprobe"])
  );
  const [orchBusy, setOrchBusy] = useState(false);
  const [orchOut, setOrchOut] = useState<VaptOrchestrateResult | null>(null);
  const [feedback, setFeedback] = useState<VaptAnalystFeedback[]>([]);
  const [fbBody, setFbBody] = useState("");
  const [fbType, setFbType] = useState<"ttp" | "edge" | "brief" | "other">("other");
  const [fbKey, setFbKey] = useState("");
  const [fbBusy, setFbBusy] = useState(false);
  const [busy, setBusy] = useState({ load: true, gen: false, del: null as string | null });

  const load = useCallback(async () => {
    setErr(null);
    setBusy((b) => ({ ...b, load: true }));
    try {
      const [s, b, ttp, ge, fb, m] = await Promise.all([
        api.get<VaptSurface>("/api/v1/vapt/surface"),
        api.get<Paginated<VaptBrief>>("/api/v1/vapt/briefs?size=30"),
        api.get<Paginated<VaptTtpMemory>>("/api/v1/vapt/ttp?size=50"),
        api.get<Paginated<VaptGraphEdge>>("/api/v1/vapt/graph/edges?size=100"),
        api.get<Paginated<VaptAnalystFeedback>>("/api/v1/vapt/feedback?size=30"),
        api.get<MitreFoundationOut>("/api/v1/vapt/mitre/foundation")
      ]);
      setSurface(s);
      setBriefs(b.items);
      setTtpRows(ttp.items);
      setEdges(ge.items);
      setFeedback(fb.items);
      setMitre(m);
    } catch (e) {
      if (isUnauthorized(e)) {
        redirectToReauth();
        return;
      }
      setErr(getApiErrorMessage(e, "Failed to load VAPT data."));
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
        api.get<Paginated<ReconFinding>>("/api/v1/recon/findings?size=120"),
        api.get<Paginated<Alert>>("/api/v1/siem/alerts?size=15"),
        api.get<Inference[]>("/api/v1/ids/inferences?limit=25")
      ]);
      setSurface(s);
      const seen = new Set<string>();
      const reconDedup: { severity: string; title: string; description: string }[] = [];
      for (const x of f.items) {
        // Dedupe by title so repeated port/webfuzz rows across jobs don’t fill the excerpt.
        const key = x.title;
        if (seen.has(key)) continue;
        seen.add(key);
        reconDedup.push({
          severity: x.severity,
          title: x.title,
          description: (x.description || "").slice(0, 500)
        });
        if (reconDedup.length >= 40) break;
      }
      const block = {
        vapt_surface: s,
        recon_findings_excerpt: reconDedup,
        siem_alerts_excerpt: a.items.map((x) => ({
          rule: x.rule_name,
          score: x.score,
          status: x.status
        })),
        ids_inferences_excerpt: (() => {
          const s = new Set<string>();
          const out: { label: string; prediction: string; probability: number }[] = [];
          for (const x of i) {
            const k = `${x.label}\t${x.prediction}\t${x.probability}`;
            if (s.has(k)) continue;
            s.add(k);
            out.push({
              label: x.label,
              prediction: x.prediction,
              probability: x.probability
            });
            if (out.length >= 15) break;
          }
          return out;
        })()
      };
      setCtx(JSON.stringify(block, null, 2));
    } catch (e) {
      if (isUnauthorized(e)) {
        redirectToReauth();
        return;
      }
      setErr(getApiErrorMessage(e, "Could not assemble context from the API."));
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
        context: ctx,
        inject_mitre_context: injectMitre,
        use_cascade: useLlmCascade
      });
      setOut(r.summary);
      setLlmModel(r.model);
    } catch (e) {
      if (isUnauthorized(e)) {
        redirectToReauth();
        return;
      }
      const a = e as ApiError;
      if (a.status === 503) {
        setErr(
          `${a.detail} For cloud: OPENAI_API_KEY. For Ollama: run ./scripts/sentinelops-dev.sh --setup-llm (or scripts/setup-local-llm.ps1), merge .env.llm.local.generated, set SENTINELOPS_LLM_OLLAMA=1, restart the API.`
        );
      } else if (a.status === 502) {
        setErr(
          a.detail ||
            "LLM endpoint error (check Ollama is running, base URL, and models are pulled)."
        );
      } else {
        setErr(getApiErrorMessage(e, "LLM call failed."));
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
      if (isUnauthorized(e)) {
        redirectToReauth();
        return;
      }
      setErr(getApiErrorMessage(e, "Save failed — run `alembic upgrade head` if the table is missing."));
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
      if (isUnauthorized(e)) {
        redirectToReauth();
        return;
      }
      setErr(getApiErrorMessage(e, "Delete failed."));
    } finally {
      setBusy((b) => ({ ...b, del: null }));
    }
  };

  const saveTtp = async () => {
    if (!ttpTid.trim()) return;
    setTtpBusy(true);
    setErr(null);
    try {
      const row = await api.put<VaptTtpMemory>("/api/v1/vapt/ttp", {
        technique_id: ttpTid.trim(),
        name: ttpName,
        body: ttpBody,
        narrative: {}
      });
      setTtpRows((prev) => {
        const rest = prev.filter((x) => x.technique_id !== row.technique_id);
        return [row, ...rest];
      });
    } catch (e) {
      if (isUnauthorized(e)) {
        redirectToReauth();
        return;
      }
      setErr(getApiErrorMessage(e, "TTP save failed — run DB migrations if the table is missing."));
    } finally {
      setTtpBusy(false);
    }
  };

  const delTtp = async (id: string) => {
    setErr(null);
    try {
      await api.del(`/api/v1/vapt/ttp/${id}`);
      setTtpRows((prev) => prev.filter((x) => x.id !== id));
    } catch (e) {
      if (isUnauthorized(e)) {
        redirectToReauth();
        return;
      }
      setErr(getApiErrorMessage(e, "Delete TTP failed."));
    }
  };

  const addEdge = async () => {
    setEBusy(true);
    setErr(null);
    try {
      const row = await api.post<VaptGraphEdge>("/api/v1/vapt/graph/edges", {
        from_technique_id: eFrom.trim(),
        to_technique_id: eTo.trim(),
        relation: eRel,
        note: eNote
      });
      setEdges((prev) => [row, ...prev]);
    } catch (e) {
      if (isUnauthorized(e)) {
        redirectToReauth();
        return;
      }
      setErr(getApiErrorMessage(e, "Add edge failed."));
    } finally {
      setEBusy(false);
    }
  };

  const delEdge = async (id: string) => {
    setErr(null);
    try {
      await api.del(`/api/v1/vapt/graph/edges/${id}`);
      setEdges((prev) => prev.filter((x) => x.id !== id));
    } catch (e) {
      if (isUnauthorized(e)) {
        redirectToReauth();
        return;
      }
      setErr(getApiErrorMessage(e, "Delete edge failed."));
    }
  };

  const loadCypher = async () => {
    setErr(null);
    try {
      const c = await api.get<VaptCypherExport>("/api/v1/vapt/graph/cypher");
      setCypher(c);
    } catch (e) {
      if (isUnauthorized(e)) {
        redirectToReauth();
        return;
      }
      setErr(getApiErrorMessage(e, "Cypher export failed."));
    }
  };

  const copyCypher = async () => {
    if (!cypher?.cypher) return;
    await navigator.clipboard.writeText(cypher.cypher);
  };

  const runOrchestrate = async () => {
    if (!orchTarget.trim() || orchKinds.size === 0) {
      setErr("Set an allowlisted target and at least one recon kind.");
      return;
    }
    setOrchBusy(true);
    setOrchOut(null);
    setErr(null);
    try {
      const r = await api.post<VaptOrchestrateResult>("/api/v1/vapt/recon/orchestrate", {
        target: orchTarget.trim(),
        kinds: Array.from(orchKinds),
        default_params: {}
      });
      setOrchOut(r);
    } catch (e) {
      if (isUnauthorized(e)) {
        redirectToReauth();
        return;
      }
      setErr(getApiErrorMessage(e, "Orchestrate failed (allowlist / worker / queue)."));
    } finally {
      setOrchBusy(false);
    }
  };

  const saveFeedback = async () => {
    if (!fbBody.trim()) return;
    setFbBusy(true);
    setErr(null);
    try {
      const row = await api.post<VaptAnalystFeedback>("/api/v1/vapt/feedback", {
        ref_type: fbType,
        ref_key: fbKey,
        body: fbBody
      });
      setFeedback((prev) => [row, ...prev]);
      setFbBody("");
    } catch (e) {
      if (isUnauthorized(e)) {
        redirectToReauth();
        return;
      }
      setErr(getApiErrorMessage(e, "Feedback save failed."));
    } finally {
      setFbBusy(false);
    }
  };

  const delFeedback = async (id: string) => {
    setErr(null);
    try {
      await api.del(`/api/v1/vapt/feedback/${id}`);
      setFeedback((prev) => prev.filter((x) => x.id !== id));
    } catch (e) {
      if (isUnauthorized(e)) {
        redirectToReauth();
        return;
      }
      setErr(getApiErrorMessage(e, "Delete feedback failed."));
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
                Metrics and assembled context are read from your running stack (Postgres + workers). TTP
                memory and graph edges are analyst-curated (not self-training). Cypher is an optional export;
                batch recon enqueues the same job types as <span className="font-mono">/recon/jobs</span>.
                The LLM path uses your OpenAI-compatible endpoint; without a key you get 503, not fake text.
                Run <span className="font-mono">alembic upgrade head</span> for new VAPT tables after pull.
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
          <div className="mt-3 flex flex-col sm:flex-row sm:flex-wrap sm:items-center gap-2">
            <label className="inline-flex items-center gap-2 text-[11px] text-muted">
              <input
                type="checkbox"
                checked={injectMitre}
                onChange={(e) => setInjectMitre(e.target.checked)}
                className="rounded border-border"
              />
              Append curated MITRE reference to the system prompt (no live ATT&amp;CK API).
            </label>
            <label className="inline-flex items-center gap-2 text-[11px] text-muted">
              <input
                type="checkbox"
                checked={useLlmCascade}
                onChange={(e) => setUseLlmCascade(e.target.checked)}
                className="rounded border-border"
              />
              Two-step (draft+refine) when the API has SENTINELOPS_LLM_DRAFT_MODEL set.
            </label>
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
            {out ||
              "Generated summary appears here. Configure cloud API key, or Ollama + .env (see scripts/sentinelops-dev --setup-llm)."}
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

      <SectionHeader
        eyebrow="TTP & graph"
        title="Analyst memory &amp; export"
        description="Notes keyed by MITRE technique id, optional edges, and a paste-ready Cypher script. This is not autonomous red-teaming — it is structured note-taking in Postgres."
      />

      {mitre && (
        <div className="text-[11px] text-muted font-mono max-w-4xl">
          MITRE foundation bundle loaded: {mitre.items.length} entries (read-only, bundled JSON).
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="glass rounded-xl p-4 border border-amber-500/15">
          <h3 className="text-sm font-medium text-amber-200/90 mb-2">TTP memory (upsert by technique id)</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-2">
            <div>
              <label className="text-[10px] text-muted">Technique id</label>
              <input
                value={ttpTid}
                onChange={(e) => setTtpTid(e.target.value)}
                className="mt-0.5 w-full text-sm font-mono bg-panel/50 border border-border/60 rounded px-2 py-1"
              />
            </div>
            <div>
              <label className="text-[10px] text-muted">Display name (optional)</label>
              <input
                value={ttpName}
                onChange={(e) => setTtpName(e.target.value)}
                className="mt-0.5 w-full text-sm bg-panel/50 border border-border/60 rounded px-2 py-1"
              />
            </div>
          </div>
          <label className="text-[10px] text-muted">Notes / narrative</label>
          <textarea
            value={ttpBody}
            onChange={(e) => setTtpBody(e.target.value)}
            rows={4}
            className="mt-0.5 w-full text-xs font-mono bg-bg/50 border border-border/60 rounded-md p-2"
          />
          <button
            type="button"
            onClick={() => void saveTtp()}
            disabled={ttpBusy}
            className="mt-2 text-xs px-3 py-1.5 rounded-md border border-amber-500/40 text-amber-100 hover:bg-amber-500/10"
          >
            {ttpBusy ? <Loader2 className="h-3 w-3 inline animate-spin" /> : null} Save TTP memory
          </button>
          <ul className="mt-3 space-y-2 max-h-48 overflow-auto">
            {ttpRows.map((r) => (
              <li key={r.id} className="text-xs border border-border/40 rounded p-2 bg-panel/30">
                <div className="flex justify-between gap-2">
                  <span className="font-mono text-amber-200/80">{r.technique_id}</span>
                  <button
                    type="button"
                    onClick={() => void delTtp(r.id)}
                    className="text-[10px] text-muted hover:text-danger"
                  >
                    Delete
                  </button>
                </div>
                {r.name ? <div className="text-muted text-[10px]">{r.name}</div> : null}
                <p className="text-[11px] text-text/80 mt-1 line-clamp-3 whitespace-pre-wrap">{r.body}</p>
              </li>
            ))}
          </ul>
        </div>

        <div className="glass rounded-xl p-4 border border-sky-500/15">
          <h3 className="text-sm font-medium text-sky-200/90 mb-2">Graph edge (TTP → TTP)</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <div>
              <label className="text-[10px] text-muted">From</label>
              <input
                value={eFrom}
                onChange={(e) => setEFrom(e.target.value)}
                className="mt-0.5 w-full text-sm font-mono bg-panel/50 border border-border/60 rounded px-2 py-1"
              />
            </div>
            <div>
              <label className="text-[10px] text-muted">To</label>
              <input
                value={eTo}
                onChange={(e) => setETo(e.target.value)}
                className="mt-0.5 w-full text-sm font-mono bg-panel/50 border border-border/60 rounded px-2 py-1"
              />
            </div>
            <div>
              <label className="text-[10px] text-muted">Relation</label>
              <input
                value={eRel}
                onChange={(e) => setERel(e.target.value)}
                className="mt-0.5 w-full text-sm bg-panel/50 border border-border/60 rounded px-2 py-1"
              />
            </div>
            <div>
              <label className="text-[10px] text-muted">Note</label>
              <input
                value={eNote}
                onChange={(e) => setENote(e.target.value)}
                className="mt-0.5 w-full text-sm bg-panel/50 border border-border/60 rounded px-2 py-1"
              />
            </div>
          </div>
          <button
            type="button"
            onClick={() => void addEdge()}
            disabled={eBusy}
            className="mt-2 text-xs px-3 py-1.5 rounded-md border border-sky-500/40 text-sky-100 hover:bg-sky-500/10"
          >
            {eBusy ? <Loader2 className="h-3 w-3 inline animate-spin" /> : null} Add edge
          </button>
          <ul className="mt-2 space-y-1 max-h-40 overflow-auto text-[11px] font-mono">
            {edges.map((e) => (
              <li key={e.id} className="flex justify-between gap-2 border border-border/30 rounded px-2 py-1">
                <span>
                  {e.from_technique_id} → {e.to_technique_id} ({e.relation})
                </span>
                <button type="button" onClick={() => void delEdge(e.id)} className="text-muted hover:text-danger">
                  ×
                </button>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="glass rounded-xl p-4 border border-rose-500/15">
          <h3 className="text-sm font-medium text-rose-200/90 mb-2">Cypher export (Neo4j — optional)</h3>
          <p className="text-xs text-muted mb-2">
            Builds MERGE statements from your TTP rows and edges. Nothing runs against Neo4j from the API.
          </p>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => void loadCypher()}
              className="text-xs px-3 py-1.5 rounded-md border border-rose-500/40 text-rose-100 hover:bg-rose-500/10"
            >
              Build Cypher
            </button>
            {cypher ? (
              <button
                type="button"
                onClick={() => void copyCypher()}
                className="text-xs inline-flex items-center gap-1 px-3 py-1.5 rounded-md border border-border/50"
              >
                <ClipboardCopy className="h-3 w-3" /> Copy
              </button>
            ) : null}
            {cypher ? (
              <span className="text-[11px] text-muted self-center">
                nodes {cypher.node_count} · edges {cypher.edge_count}
              </span>
            ) : null}
          </div>
          {cypher ? (
            <pre className="mt-2 text-[10px] font-mono whitespace-pre-wrap max-h-40 overflow-auto bg-bg/40 p-2 rounded border border-border/40">
              {cypher.cypher}
            </pre>
          ) : null}
        </div>

        <div className="glass rounded-xl p-4 border border-cyan-500/15">
          <h3 className="text-sm font-medium text-cyan-200/90 mb-2">Recon batch (allowlisted target)</h3>
          <p className="text-xs text-muted mb-2">
            Enqueues the selected kinds — same Celery workers as the Recon page. Use a value allowed by
            RECON_TARGET_ALLOWLIST.
          </p>
          <input
            value={orchTarget}
            onChange={(e) => setOrchTarget(e.target.value)}
            className="w-full text-sm font-mono bg-panel/50 border border-border/60 rounded px-2 py-1 mb-2"
            placeholder="e.g. example.com"
          />
          <div className="flex flex-wrap gap-2 mb-2">
            {RECON_KINDS.map((k) => (
              <label key={k} className="text-[10px] font-mono flex items-center gap-1.5 text-muted">
                <input
                  type="checkbox"
                  checked={orchKinds.has(k)}
                  onChange={() => {
                    setOrchKinds((prev) => {
                      const n = new Set(prev);
                      if (n.has(k)) n.delete(k);
                      else n.add(k);
                      return n;
                    });
                  }}
                />
                {k}
              </label>
            ))}
          </div>
          <button
            type="button"
            onClick={() => void runOrchestrate()}
            disabled={orchBusy}
            className="text-xs px-3 py-1.5 rounded-md border border-cyan-500/40 text-cyan-100 hover:bg-cyan-500/10"
          >
            {orchBusy ? <Loader2 className="h-3 w-3 inline animate-spin" /> : null} Enqueue jobs
          </button>
          {orchOut ? (
            <pre className="mt-2 text-[10px] font-mono bg-bg/40 p-2 rounded border border-border/40 max-h-32 overflow-auto">
              {JSON.stringify(orchOut, null, 2)}
            </pre>
          ) : null}
        </div>
      </div>

      <div className="glass rounded-xl p-4 border border-border/50">
        <h3 className="text-sm font-medium mb-2">Analyst feedback (internal notes)</h3>
        <div className="flex flex-wrap gap-2 mb-2">
          <select
            value={fbType}
            onChange={(e) => setFbType(e.target.value as typeof fbType)}
            className="text-xs bg-panel/50 border border-border/60 rounded px-2 py-1"
          >
            <option value="ttp">ttp</option>
            <option value="edge">edge</option>
            <option value="brief">brief</option>
            <option value="other">other</option>
          </select>
          <input
            value={fbKey}
            onChange={(e) => setFbKey(e.target.value)}
            placeholder="ref id (optional)"
            className="text-xs font-mono flex-1 min-w-[8rem] bg-panel/50 border border-border/60 rounded px-2 py-1"
          />
        </div>
        <textarea
          value={fbBody}
          onChange={(e) => setFbBody(e.target.value)}
          rows={2}
          className="w-full text-xs bg-bg/50 border border-border/60 rounded-md p-2"
          placeholder="Short comment…"
        />
        <button
          type="button"
          onClick={() => void saveFeedback()}
          disabled={fbBusy}
          className="mt-2 text-xs px-3 py-1.5 rounded-md border border-border/50"
        >
          {fbBusy ? <Loader2 className="h-3 w-3 inline animate-spin" /> : null} Save feedback
        </button>
        <ul className="mt-2 space-y-1 text-xs">
          {feedback.map((f) => (
            <li key={f.id} className="flex justify-between gap-2 border border-border/30 rounded px-2 py-1">
              <span className="min-w-0">
                <span className="font-mono text-[10px] text-muted">
                  {f.ref_type} {f.ref_key}
                </span>{" "}
                {f.body}
              </span>
              <button
                type="button"
                onClick={() => void delFeedback(f.id)}
                className="text-muted hover:text-danger shrink-0"
              >
                ×
              </button>
            </li>
          ))}
        </ul>
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
