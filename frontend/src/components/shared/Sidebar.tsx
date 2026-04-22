"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, Crosshair, Lock, Radar, Shield } from "lucide-react";
import { cn } from "@/lib/cn";

const NAV = [
  { href: "/dashboard", label: "Dashboard", icon: Activity },
  { href: "/siem", label: "SIEM", icon: Shield },
  { href: "/recon", label: "Recon", icon: Crosshair },
  { href: "/ids", label: "IDS", icon: Radar },
  { href: "/vault", label: "Vault", icon: Lock }
];

export default function Sidebar() {
  const path = usePathname();
  return (
    <aside className="hidden md:flex md:w-60 shrink-0 flex-col gap-1 px-3 py-4 border-r border-border/60">
      <div className="flex items-center gap-2 px-2 pb-4">
        <div className="h-8 w-8 rounded-md bg-gradient-to-br from-accent to-accent2 shadow-glow grid place-items-center font-bold text-bg">
          S
        </div>
        <div className="font-semibold tracking-tight">SentinelOps</div>
      </div>
      {NAV.map(({ href, label, icon: Icon }) => {
        const active = path?.startsWith(href);
        return (
          <Link
            key={href}
            href={href}
            className={cn(
              "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors",
              active
                ? "bg-accent/10 text-accent"
                : "text-text/80 hover:text-text hover:bg-panel/60"
            )}
          >
            <Icon className="h-4 w-4" />
            {label}
          </Link>
        );
      })}
      <div className="mt-auto px-3 py-2 text-[11px] text-muted leading-relaxed">
        v1.0.0 · {new Date().getFullYear()}
        <br />
        Single-pane SOC. Use responsibly.
      </div>
    </aside>
  );
}
