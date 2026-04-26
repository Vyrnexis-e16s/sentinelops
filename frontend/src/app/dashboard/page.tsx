"use client";

import { useCallback, useEffect, useState } from "react";
import type { ElementType } from "react";
import dynamic from "next/dynamic";
import { motion } from "framer-motion";
import { Activity, Crosshair, Lock, Radar, Shield } from "lucide-react";
import StatCard from "@/components/shared/StatCard";
import SectionHeader from "@/components/shared/SectionHeader";
import { LiveAlertsPanel } from "@/components/dashboard/LiveAlertsPanel";
import {
  api,
  type ApiError,
  type Inference,
  type Paginated,
  type PlatformStatus,
  type ReconJob,
  type VaultObject
} from "@/lib/api";
import { runDeferred } from "@/lib/schedule-deferred";

const Globe = dynamic(() => import("@/components/three/Globe"), { ssr: false });

type DashStats = {
  openAlerts: number | null;
  reconActive: number | null;
  idsAttackPct: number | null;
  idsError: "none" | "unavailable" | "auth";
  vaultCount: number | null;
  auth: boolean;
  platform: PlatformStatus | null;
};

export default function DashboardPage() {
  const [stats, setStats] = useState<DashStats>({
    openAlerts: null,
    reconActive: null,
    idsAttackPct: null,
    idsError: "none",
    vaultCount: null,
    auth: false,
    platform: null
  });

  const loadStats = useCallback(async () => {
    try {
      const [nNew, nAck, jobsP, vaultFiles, platform] = await Promise.all([
        api.get<Paginated<{ id: string }>>("/api/v1/siem/alerts?status=new&size=1&page=1"),
        api.get<Paginated<{ id: string }>>("/api/v1/siem/alerts?status=ack&size=1&page=1"),
        api.get<Paginated<ReconJob>>("/api/v1/recon/jobs?size=200&page=1"),
        api.get<VaultObject[]>("/api/v1/vault/files"),
        api.get<PlatformStatus>("/api/v1/platform/status").catch(() => null)
      ]);
      const open = nNew.total + nAck.total;
      const reconActive = jobsP.items.filter(
        (j) => j.status === "running" || j.status === "queued"
      ).length;
      let idsAttackPct: number | null = null;
      let idsError: DashStats["idsError"] = "none";
      try {
        const inf = await api.get<Inference[]>("/api/v1/ids/inferences?limit=200");
        const attacks = inf.filter((x) => x.label === "attack").length;
        idsAttackPct =
          inf.length > 0 ? Math.round((attacks / inf.length) * 1000) / 10 : 0;
      } catch (ie) {
        const a = ie as ApiError;
        if (a.status === 503) idsError = "unavailable";
        else if (a.status === 401) idsError = "auth";
        else throw ie;
      }
      setStats({
        openAlerts: open,
        reconActive,
        idsAttackPct,
        idsError,
        vaultCount: vaultFiles.length,
        auth: true,
        platform
      });
    } catch (e) {
      const a = e as ApiError;
      if (a.status === 401) {
        setStats({
          openAlerts: null,
          reconActive: null,
          idsAttackPct: null,
          idsError: "auth",
          vaultCount: null,
          auth: false,
          platform: null
        });
      }
    }
  }, []);

  useEffect(() => {
    const t0 = runDeferred(() => void loadStats());
    const t = setInterval(() => {
      void loadStats();
    }, 30000);
    return () => {
      clearTimeout(t0);
      clearInterval(t);
    };
  }, [loadStats]);

  const fmt = (n: number | null, suffix = "") =>
    n === null ? "—" : `${n}${suffix}`;
  const deltaAuth = stats.auth ? "From API" : "Sign in for live counts";
  const idsValue =
    !stats.auth || stats.idsError === "auth"
      ? "—"
      : stats.idsError === "unavailable" || stats.idsAttackPct === null
        ? "N/A"
        : `${stats.idsAttackPct}%`;
  const idsDelta =
    !stats.auth
      ? "Sign in for live counts"
      : stats.idsError === "unavailable"
        ? "Model not loaded (train IDS)"
        : deltaAuth;

  return (
    <div className="space-y-6">
      <SectionHeader
        eyebrow="Operations"
        title="Single-pane overview"
        description="Stat cards pull from SIEM alerts, recon jobs, IDS inferences, and vault file list when you are signed in. Recent alerts use the API and WebSocket when a JWT is in localStorage."
      />
      {stats.auth && stats.platform && (
        <p className="text-[11px] text-muted">
          <span className="text-fg/80">Platform:</span> DB {stats.platform.database} · Redis{" "}
          {stats.platform.redis} · IDS model {stats.platform.ids_model} · API modules{" "}
          {stats.platform.modules?.length ?? 0} loaded
        </p>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard
          label="Open alerts (new + ack)"
          value={fmt(stats.openAlerts)}
          delta={deltaAuth}
          tone="warn"
        />
        <StatCard
          label="Recon queued / running"
          value={fmt(stats.reconActive)}
          delta={deltaAuth}
          tone="neutral"
        />
        <StatCard
          label="IDS attack rate (recent)"
          value={idsValue}
          delta={idsDelta}
          tone="good"
        />
        <StatCard
          label="Vault objects"
          value={fmt(stats.vaultCount)}
          delta={deltaAuth}
          tone="neutral"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="glass rounded-xl p-4 lg:col-span-2"
        >
          <div className="flex items-center justify-between mb-2">
            <div className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-accent" /> Threat origins (24h)
            </div>
            <div className="text-[11px] text-muted">3D view · not mapped from event geo-IP (decorative)</div>
          </div>
          <Globe height={320} />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <LiveAlertsPanel />
        </motion.div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        <ModuleTile icon={Shield} title="SIEM" body="Ingest. Detect. Triage." href="/siem" />
        <ModuleTile icon={Crosshair} title="Recon" body="Find what's exposed." href="/recon" />
        <ModuleTile icon={Radar} title="IDS" body="ML-classified flows." href="/ids" />
        <ModuleTile icon={Lock} title="Vault" body="Zero-trust files." href="/vault" />
      </div>
    </div>
  );
}

function ModuleTile({
  icon: Icon,
  title,
  body,
  href
}: {
  icon: ElementType;
  title: string;
  body: string;
  href: string;
}) {
  return (
    <motion.a
      whileHover={{ y: -2 }}
      transition={{ type: "spring", stiffness: 320, damping: 24 }}
      href={href}
      className="glass rounded-xl p-4 block group"
    >
      <Icon className="h-5 w-5 text-accent group-hover:text-accent2 transition-colors" />
      <div className="mt-3 font-semibold">{title}</div>
      <div className="text-xs text-muted">{body}</div>
    </motion.a>
  );
}
