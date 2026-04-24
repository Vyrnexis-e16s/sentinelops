"use client";

import dynamic from "next/dynamic";
import { motion } from "framer-motion";
import { Activity, Crosshair, Lock, Radar, Shield } from "lucide-react";
import StatCard from "@/components/shared/StatCard";
import SectionHeader from "@/components/shared/SectionHeader";
import { LiveAlertsPanel } from "@/components/dashboard/LiveAlertsPanel";

const Globe = dynamic(() => import("@/components/three/Globe"), { ssr: false });

export default function DashboardPage() {
  return (
    <div className="space-y-6">
        <SectionHeader
        eyebrow="Operations"
        title="Single-pane overview"
        description="Live posture across SIEM, Recon, IDS, and Vault. Stat cards are demo figures; the alert column uses the API when you are authenticated, and WebSocket when a JWT is in localStorage."
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Open alerts" value={37} delta="+4 in last hour" tone="warn" />
        <StatCard label="Active recon jobs" value={3} delta="2 queued" tone="neutral" />
        <StatCard label="IDS attack rate" value="6.2%" delta="-0.4% today" tone="good" />
        <StatCard label="Vault objects" value={128} delta="+2 today" tone="neutral" />
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
            <div className="text-[11px] text-muted">live · sample data</div>
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
  icon: React.ElementType;
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
