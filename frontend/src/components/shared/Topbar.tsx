"use client";

import { Bell, Search } from "lucide-react";
import ThemeSwitch from "./ThemeSwitch";

export default function Topbar() {
  return (
    <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-border/60 bg-bg/70 backdrop-blur-md px-4 py-2">
      <div className="md:hidden font-semibold">SentinelOps</div>
      <div className="ml-auto flex items-center gap-2">
        <div className="hidden sm:flex items-center gap-2 text-xs text-muted px-3 py-1.5 rounded-md border border-border/60">
          <Search className="h-3.5 w-3.5" />
          <span>Search alerts, hosts, CVEs…</span>
          <kbd className="ml-3 px-1.5 py-0.5 rounded bg-panel/80 text-[10px] border border-border/80">⌘K</kbd>
        </div>
        <button
          className="grid place-items-center h-8 w-8 rounded-md border border-border/60 hover:border-accent/60"
          aria-label="Notifications"
        >
          <Bell className="h-4 w-4" />
        </button>
        <ThemeSwitch />
      </div>
    </header>
  );
}
