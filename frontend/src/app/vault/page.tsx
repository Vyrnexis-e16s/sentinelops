"use client";

import { motion } from "framer-motion";
import { Download, FileLock2, Share2, Upload, Trash2 } from "lucide-react";
import SectionHeader from "@/components/shared/SectionHeader";

const FILES = [
  { id: "v-204", name: "ir-runbook.md", size: "1.2 KB", at: "2026-04-22 09:11", mime: "text/markdown" },
  { id: "v-205", name: "passkeys-policy.pdf", size: "84.7 KB", at: "2026-04-21 14:48", mime: "application/pdf" },
  { id: "v-206", name: "engagement-rules.docx", size: "23.0 KB", at: "2026-04-19 16:02", mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
  { id: "v-207", name: "kek-rotation-2026q2.txt", size: "412 B", at: "2026-04-18 11:40", mime: "text/plain" }
];

const AUDIT = [
  { ts: "12:04:18", actor: "analyst@…", action: "vault.upload", obj: "ir-runbook.md" },
  { ts: "11:42:01", actor: "analyst@…", action: "vault.share", obj: "engagement-rules.docx" },
  { ts: "10:21:55", actor: "analyst@…", action: "vault.download", obj: "passkeys-policy.pdf" }
];

export default function VaultPage() {
  return (
    <div className="space-y-6">
      <SectionHeader
        eyebrow="Zero-trust"
        title="Vault"
        description="Passkey-gated, AES-256-GCM envelope encryption. Every action is hash-chained into the audit log."
        right={
          <button className="text-xs px-3 py-1.5 rounded-md bg-accent/15 text-accent border border-accent/40 hover:bg-accent/25 inline-flex items-center gap-1">
            <Upload className="h-3.5 w-3.5" /> Upload
          </button>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="glass rounded-xl p-4 lg:col-span-2">
          <div className="text-sm font-semibold flex items-center gap-2 mb-3">
            <FileLock2 className="h-4 w-4 text-accent" /> Files
          </div>
          <ul className="text-sm divide-y divide-border/40">
            {FILES.map((f, i) => (
              <motion.li
                key={f.id}
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.04 }}
                className="py-2 flex items-center gap-3"
              >
                <div className="font-mono text-xs text-muted w-12">{f.id}</div>
                <div className="flex-1 min-w-0">
                  <div className="truncate">{f.name}</div>
                  <div className="text-[11px] text-muted">
                    {f.size} · {f.mime} · {f.at}
                  </div>
                </div>
                <button className="p-1.5 rounded-md hover:bg-panel/60" aria-label="Share">
                  <Share2 className="h-4 w-4 text-muted hover:text-accent" />
                </button>
                <button className="p-1.5 rounded-md hover:bg-panel/60" aria-label="Download">
                  <Download className="h-4 w-4 text-muted hover:text-accent" />
                </button>
                <button className="p-1.5 rounded-md hover:bg-panel/60" aria-label="Delete">
                  <Trash2 className="h-4 w-4 text-muted hover:text-danger" />
                </button>
              </motion.li>
            ))}
          </ul>
        </div>

        <div className="glass rounded-xl p-4">
          <div className="text-sm font-semibold mb-3">Audit chain</div>
          <ul className="text-xs space-y-2">
            {AUDIT.map((e, i) => (
              <li key={i} className="flex items-start gap-2">
                <span className="font-mono text-muted">{e.ts}</span>
                <div className="min-w-0">
                  <div>
                    <span className="text-muted">{e.actor}</span> · <span className="font-mono">{e.action}</span>
                  </div>
                  <div className="text-muted truncate">{e.obj}</div>
                </div>
              </li>
            ))}
          </ul>
          <div className="mt-3 text-[11px] text-muted">
            chain head:{" "}
            <span className="font-mono text-accent">7b9c…1a4f</span>
          </div>
        </div>
      </div>
    </div>
  );
}
