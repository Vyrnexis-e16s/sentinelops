"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/cn";

export default function StatCard({
  label,
  value,
  delta,
  tone = "neutral"
}: {
  label: string;
  value: string | number;
  delta?: string;
  tone?: "neutral" | "good" | "warn" | "bad";
}) {
  const toneColor =
    tone === "good"
      ? "text-ok"
      : tone === "warn"
        ? "text-warn"
        : tone === "bad"
          ? "text-danger"
          : "text-accent";
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ type: "spring", stiffness: 240, damping: 28 }}
      className="glass rounded-xl p-4"
    >
      <div className="text-[11px] uppercase tracking-wider text-muted">{label}</div>
      <div className={cn("mt-1 text-2xl font-semibold", toneColor)}>{value}</div>
      {delta && <div className="mt-1 text-xs text-muted">{delta}</div>}
    </motion.div>
  );
}
