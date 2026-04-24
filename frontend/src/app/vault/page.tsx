"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { Download, FileLock2, Share2, Upload, Trash2 } from "lucide-react";
import SectionHeader from "@/components/shared/SectionHeader";
import {
  api,
  type ApiError,
  type VaultAuditEntry,
  type VaultObject,
  vaultDownloadBlob,
  vaultUpload
} from "@/lib/api";
import { runDeferred } from "@/lib/schedule-deferred";

function formatBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function formatTs(iso: string) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export default function VaultPage() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<VaultObject[]>([]);
  const [audit, setAudit] = useState<VaultAuditEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [f, a] = await Promise.all([
        api.get<VaultObject[]>("/api/v1/vault/files"),
        api.get<VaultAuditEntry[]>("/api/v1/vault/audit?limit=20")
      ]);
      setFiles(f);
      setAudit(a);
      setError(null);
    } catch (e) {
      const a = e as ApiError;
      if (a.status === 401) {
        setError("Sign in to use the Vault (passkey + JWT).");
      } else {
        setError(a.detail || "Failed to load vault data.");
      }
    }
  }, []);

  useEffect(() => {
    const t = runDeferred(() => void load());
    return () => clearTimeout(t);
  }, [load]);

  const onPickFiles = (e: React.ChangeEvent<HTMLInputElement>) => {
    const list = e.target.files;
    if (!list?.length) return;
    setBusy(true);
    setError(null);
    setInfo(null);
    void (async () => {
      try {
        for (let i = 0; i < list.length; i++) {
          await vaultUpload(list[i]!);
        }
        setInfo(`Uploaded ${list.length} file(s).`);
        await load();
      } catch (err) {
        const a = err as ApiError;
        setError(a.detail || "Upload failed.");
      } finally {
        e.target.value = "";
        setBusy(false);
      }
    })();
  };

  const onDownload = async (o: VaultObject) => {
    setError(null);
    try {
      const blob = await vaultDownloadBlob(o.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = o.name;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      const a = e as ApiError;
      setError(a.detail || "Download failed.");
    }
  };

  const onDelete = async (o: VaultObject) => {
    if (!window.confirm(`Delete “${o.name}”?`)) return;
    setError(null);
    try {
      await api.del<unknown>(`/api/v1/vault/files/${o.id}`);
      await load();
    } catch (e) {
      const a = e as ApiError;
      setError(a.detail || "Delete failed.");
    }
  };

  const onShare = async (o: VaultObject) => {
    const raw = window.prompt("Grant read access to user ID (UUID) of the grantee:");
    if (!raw) return;
    setError(null);
    try {
      await api.post(`/api/v1/vault/files/${o.id}/share`, {
        grantee_id: raw.trim(),
        permissions: "read"
      });
      setInfo("Share created.");
      await load();
    } catch (e) {
      const a = e as ApiError;
      setError(a.detail || "Share failed. Use a valid user UUID from your org.");
    }
  };

  return (
    <div className="space-y-6">
      <input
        ref={inputRef}
        type="file"
        className="hidden"
        onChange={onPickFiles}
        multiple
        disabled={busy}
      />
      <SectionHeader
        eyebrow="Zero-trust"
        title="Vault"
        description="Encrypted file storage: list, upload, download, delete, and optional share. Data comes from the API; audit log shows vault entries with chain hashes."
        right={
          <button
            type="button"
            disabled={busy}
            onClick={() => inputRef.current?.click()}
            className="text-xs px-3 py-1.5 rounded-md bg-accent/15 text-accent border border-accent/40 hover:bg-accent/25 inline-flex items-center gap-1 disabled:opacity-50"
          >
            <Upload className="h-3.5 w-3.5" /> Upload
          </button>
        }
      />

      {error && (
        <div className="text-sm text-danger border border-danger/40 rounded-md px-3 py-2 bg-danger/5">
          {error}
        </div>
      )}
      {info && (
        <div className="text-sm text-ok border border-ok/40 rounded-md px-3 py-2 bg-ok/5">
          {info}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="glass rounded-xl p-4 lg:col-span-2">
          <div className="text-sm font-semibold flex items-center gap-2 mb-3">
            <FileLock2 className="h-4 w-4 text-accent" /> Files
          </div>
          {files.length === 0 ? (
            <p className="text-xs text-muted">No files yet. Click Upload to add encrypted objects.</p>
          ) : (
            <ul className="text-sm divide-y divide-border/40 max-h-[32rem] overflow-y-auto">
              {files.map((f, i) => (
                <motion.li
                  key={f.id}
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.03 }}
                  className="py-2 flex items-center gap-2 sm:gap-3 flex-wrap"
                >
                  <div className="font-mono text-xs text-muted w-20 shrink-0">
                    {f.id.slice(0, 8)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="truncate">{f.name}</div>
                    <div className="text-[11px] text-muted">
                      {formatBytes(f.size)} · {f.mime_type} · {formatTs(f.created_at)}
                    </div>
                  </div>
                  <button
                    type="button"
                    className="p-1.5 rounded-md hover:bg-panel/60"
                    aria-label="Share"
                    onClick={() => void onShare(f)}
                  >
                    <Share2 className="h-4 w-4 text-muted hover:text-accent" />
                  </button>
                  <button
                    type="button"
                    className="p-1.5 rounded-md hover:bg-panel/60"
                    aria-label="Download"
                    onClick={() => void onDownload(f)}
                  >
                    <Download className="h-4 w-4 text-muted hover:text-accent" />
                  </button>
                  <button
                    type="button"
                    className="p-1.5 rounded-md hover:bg-panel/60"
                    aria-label="Delete"
                    onClick={() => void onDelete(f)}
                  >
                    <Trash2 className="h-4 w-4 text-muted hover:text-danger" />
                  </button>
                </motion.li>
              ))}
            </ul>
          )}
        </div>

        <div className="glass rounded-xl p-4">
          <div className="text-sm font-semibold mb-3">Audit chain (vault)</div>
          {audit.length === 0 ? (
            <p className="text-xs text-muted">No audit rows yet, or you are not authenticated.</p>
          ) : (
            <ul className="text-xs space-y-2 max-h-80 overflow-y-auto">
              {audit.map((e) => (
                <li key={e.id} className="flex items-start gap-2">
                  <span className="font-mono text-muted shrink-0">
                    {formatTs(e.timestamp)}
                  </span>
                  <div className="min-w-0">
                    <div>
                      <span className="font-mono">{e.action}</span>{" "}
                      <span className="text-muted">{e.resource_type}</span>
                    </div>
                    {e.metadata && Object.keys(e.metadata).length > 0 && (
                      <div className="text-muted truncate text-[10px]">
                        {JSON.stringify(e.metadata).slice(0, 80)}
                        …
                      </div>
                    )}
                    <div className="font-mono text-[10px] text-muted break-all">
                      hash: {e.entry_hash.slice(0, 20)}…
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
