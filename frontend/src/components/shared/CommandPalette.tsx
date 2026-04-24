"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Command } from "cmdk";
import {
  Crosshair,
  LayoutDashboard,
  Lock,
  Radar,
  Search,
  Shield
} from "lucide-react";
import { cn } from "@/lib/cn";

const routes = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard, kw: "home overview" },
  { href: "/siem", label: "SIEM", icon: Shield, kw: "alerts rules blue" },
  { href: "/recon", label: "Recon", icon: Crosshair, kw: "scan ports" },
  { href: "/ids", label: "IDS", icon: Radar, kw: "ml network" },
  { href: "/vault", label: "Vault", icon: Lock, kw: "files encryption" }
];

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const router = useRouter();

  const down = useCallback((e: KeyboardEvent) => {
    if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      setOpen((o) => !o);
    }
  }, []);
  useEffect(() => {
    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, [down]);

  return (
    <>
      {open && (
        <div
          className="fixed inset-0 z-[200] grid place-items-center p-4 bg-bg/60 backdrop-blur-sm"
          role="button"
          tabIndex={0}
          onClick={() => setOpen(false)}
          onKeyDown={(e) => e.key === "Escape" && setOpen(false)}
        >
          <div
            className="w-full max-w-lg glass rounded-xl border border-border/70 shadow-2xl overflow-hidden"
            onClick={(e) => e.stopPropagation()}
            role="presentation"
          >
            <Command
              className="text-sm"
              label="Command menu"
            >
              <div className="flex items-center gap-2 border-b border-border/60 px-3 py-2">
                <Search className="h-4 w-4 text-muted shrink-0" />
                <Command.Input
                  placeholder="Jump to module…"
                  className="w-full bg-transparent outline-none text-text placeholder:text-muted"
                />
              </div>
              <Command.List className="max-h-72 overflow-auto p-1">
                <Command.Empty className="px-3 py-6 text-center text-xs text-muted">
                  No matches. Try <span className="font-mono">SIEM</span> or{" "}
                  <span className="font-mono">recon</span>.
                </Command.Empty>
                {routes.map(({ href, label, icon: Icon, kw }) => (
                  <Command.Item
                    key={href}
                    value={`${label} ${kw}`}
                    onSelect={() => {
                      setOpen(false);
                      router.push(href);
                    }}
                    className={cn(
                      "flex cursor-pointer items-center gap-2 rounded-md px-2 py-2",
                      "data-[selected=true]:bg-panel/80 aria-selected:bg-panel/80"
                    )}
                  >
                    <Icon className="h-4 w-4 text-accent" />
                    <span>{label}</span>
                    <span className="ml-auto text-[10px] text-muted font-mono">{href}</span>
                  </Command.Item>
                ))}
              </Command.List>
            </Command>
            <div className="px-3 py-1.5 text-[10px] text-muted border-t border-border/50 text-center">
              ⌘K / Ctrl+K to toggle
            </div>
          </div>
        </div>
      )}
    </>
  );
}
