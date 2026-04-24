"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Bell, Search } from "lucide-react";
import { api, type Alert, type Paginated } from "@/lib/api";
import { runDeferred } from "@/lib/schedule-deferred";
import { PALETTE_OPEN_EVENT } from "@/components/shared/CommandPalette";
import ThemeSwitch from "./ThemeSwitch";

const POLL_MS = 30000;

export default function Topbar() {
  const [newCount, setNewCount] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    const pull = async () => {
      try {
        const res = await api.get<Paginated<Alert>>(
          "/api/v1/siem/alerts?size=50&status=new"
        );
        if (!cancelled) setNewCount(res.total);
      } catch {
        if (!cancelled) setNewCount(null);
      }
    };
    const kick = runDeferred(() => {
      void pull();
    });
    const t = setInterval(() => void pull(), POLL_MS);
    return () => {
      cancelled = true;
      clearTimeout(kick);
      clearInterval(t);
    };
  }, []);

  const openPalette = () => {
    if (typeof window === "undefined") return;
    window.dispatchEvent(new CustomEvent(PALETTE_OPEN_EVENT));
  };

  return (
    <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-border/60 bg-bg/70 backdrop-blur-md px-4 py-2">
      <div className="md:hidden font-semibold">SentinelOps</div>
      <div className="ml-auto flex items-center gap-2">
        <button
          type="button"
          onClick={openPalette}
          className="hidden sm:flex items-center gap-2 text-xs text-muted px-3 py-1.5 rounded-md border border-border/60 hover:border-accent/60 hover:text-text"
          aria-label="Open command palette"
        >
          <Search className="h-3.5 w-3.5" />
          <span>Search alerts, hosts, CVEs…</span>
          <kbd className="ml-3 px-1.5 py-0.5 rounded bg-panel/80 text-[10px] border border-border/80">
            ⌘K
          </kbd>
        </button>
        <Link
          href="/siem?status=new"
          className="relative grid place-items-center h-8 w-8 rounded-md border border-border/60 hover:border-accent/60"
          aria-label={
            newCount && newCount > 0
              ? `Notifications: ${newCount} new alerts`
              : "Notifications"
          }
          title={
            newCount && newCount > 0
              ? `${newCount} new alerts — open SIEM`
              : "Open SIEM"
          }
        >
          <Bell className="h-4 w-4" />
          {newCount !== null && newCount > 0 && (
            <span className="absolute -top-1 -right-1 min-w-[16px] h-4 px-1 rounded-full bg-warn text-[9px] font-mono font-semibold text-bg grid place-items-center">
              {newCount > 99 ? "99+" : newCount}
            </span>
          )}
        </Link>
        <ThemeSwitch />
      </div>
    </header>
  );
}
