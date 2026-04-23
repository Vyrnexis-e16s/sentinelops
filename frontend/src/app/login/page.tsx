"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { Fingerprint, Shield } from "lucide-react";

export default function LoginPage() {
  const [email, setEmail] = useState("analyst@sentinelops.local");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function startPasskey() {
    setBusy(true);
    setMsg(null);
    try {
      // Real flow:
      //   1) POST /api/v1/auth/webauthn/login/begin {email} -> options
      //   2) navigator.credentials.get({publicKey: options})
      //   3) POST /api/v1/auth/webauthn/login/finish -> { token }
      // We stub it here so the page compiles without a backend running.
      await new Promise((r) => setTimeout(r, 600));
      setMsg("Passkey prompt would open here. Wire NEXT_PUBLIC_API_URL and try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-[70vh] grid place-items-center">
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass rounded-2xl p-8 w-full max-w-md"
      >
        <div className="flex items-center gap-3 mb-6">
          <Shield className="h-6 w-6 text-accent" />
          <div>
            <div className="font-semibold">Sign in to SentinelOps</div>
            <div className="text-xs text-muted">Passwordless · WebAuthn</div>
          </div>
        </div>
        <label className="text-[11px] text-muted uppercase tracking-wider">Email</label>
        <input
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          type="email"
          autoComplete="email"
          className="mt-1 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm outline-none focus:border-accent/60"
        />
        <button
          onClick={startPasskey}
          disabled={busy}
          className="mt-4 w-full text-sm py-2.5 rounded-md bg-accent text-bg font-medium inline-flex items-center justify-center gap-2 hover:opacity-90 disabled:opacity-60"
        >
          <Fingerprint className="h-4 w-4" />
          {busy ? "Waiting for passkey…" : "Continue with passkey"}
        </button>
        {msg && (
          <div className="mt-3 text-xs text-muted text-center">{msg}</div>
        )}
        <div className="mt-6 text-[11px] text-muted text-center">
          New here? Your first sign-in registers a passkey on this device.
        </div>
      </motion.div>
    </div>
  );
}
