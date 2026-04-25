"use client";

import { useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { motion } from "framer-motion";
import {
  Fingerprint,
  KeyRound,
  Lock,
  ShieldCheck,
  UserPlus
} from "lucide-react";

import { api, type ApiError } from "@/lib/api";
import { setAccessToken } from "@/lib/auth";
import {
  decodeAuthenticationOptions,
  decodeRegistrationOptions,
  encodeAuthenticationCredential,
  encodeRegistrationCredential
} from "@/lib/webauthn";

type Method = "passkey" | "password";
type Mode = "login" | "register";

interface LoginBeginRes {
  options: PublicKeyCredentialRequestOptionsJSON;
  challenge_id: string;
}
interface RegisterBeginRes {
  user_id: string;
  options: PublicKeyCredentialCreationOptionsJSON;
  challenge_id: string;
}
interface TokenRes {
  access_token: string;
  token_type: string;
  expires_in: number;
}

// Subset of the JSON the backend serialises via py_webauthn — only the fields
// we touch in the helpers are typed strictly; everything else is forwarded.
type PublicKeyCredentialRequestOptionsJSON = {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: { id: string; type: string; transports?: string[] }[];
  userVerification?: UserVerificationRequirement;
};

type PublicKeyCredentialCreationOptionsJSON = {
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: { id: string; type: string; transports?: string[] }[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
};

function errMsg(e: unknown): string {
  if (e && typeof e === "object" && "detail" in e) {
    return String((e as ApiError).detail || "Request failed");
  }
  if (e instanceof Error) return e.message;
  return "Unknown error";
}

export default function LoginPage() {
  const router = useRouter();
  const search = useSearchParams();
  const next = search.get("next") || "/dashboard";

  const [method, setMethod] = useState<Method>("passkey");
  const [mode, setMode] = useState<Mode>("login");
  const [email, setEmail] = useState("analyst@sentinelops.local");
  const [displayName, setDisplayName] = useState("Security Analyst");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  const passkeySupported = useMemo(() => {
    if (typeof window === "undefined") return true;
    return (
      window.isSecureContext &&
      typeof window.PublicKeyCredential !== "undefined" &&
      !!navigator.credentials
    );
  }, []);

  function clearStatus() {
    setErr(null);
    setInfo(null);
  }
  function switchMode(m: Mode) {
    setMode(m);
    clearStatus();
  }
  function switchMethod(m: Method) {
    setMethod(m);
    clearStatus();
  }

  async function onTokenIssued(token: string, msg: string) {
    setAccessToken(token);
    setInfo(msg);
    router.replace(next);
    router.refresh();
  }

  async function passkeyLogin() {
    setBusy(true);
    clearStatus();
    try {
      const begin = await api.post<LoginBeginRes>(
        "/api/v1/auth/webauthn/login/begin",
        { email }
      );
      const publicKey = decodeAuthenticationOptions(begin.options);
      const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
      if (!cred) throw new Error("No credential returned by the authenticator");
      const finish = await api.post<TokenRes>("/api/v1/auth/webauthn/login/finish", {
        challenge_id: begin.challenge_id,
        credential: encodeAuthenticationCredential(cred)
      });
      await onTokenIssued(finish.access_token, "Signed in. Redirecting…");
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  async function passkeyRegister() {
    setBusy(true);
    clearStatus();
    try {
      const begin = await api.post<RegisterBeginRes>(
        "/api/v1/auth/webauthn/register/begin",
        { email, display_name: displayName }
      );
      const publicKey = decodeRegistrationOptions(begin.options);
      const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
      if (!cred) throw new Error("No credential returned by the authenticator");
      const finish = await api.post<TokenRes>(
        "/api/v1/auth/webauthn/register/finish",
        {
          challenge_id: begin.challenge_id,
          credential: encodeRegistrationCredential(cred),
          nickname: displayName || null
        }
      );
      await onTokenIssued(finish.access_token, "Passkey registered. Redirecting…");
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  async function passwordLogin() {
    setBusy(true);
    clearStatus();
    try {
      const res = await api.post<TokenRes>("/api/v1/auth/password/login", {
        email,
        password
      });
      await onTokenIssued(res.access_token, "Signed in. Redirecting…");
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  async function passwordRegister() {
    setBusy(true);
    clearStatus();
    try {
      const res = await api.post<TokenRes>("/api/v1/auth/password/register", {
        email,
        password,
        display_name: displayName
      });
      await onTokenIssued(res.access_token, "Account created. Redirecting…");
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  const submit =
    method === "passkey"
      ? mode === "login"
        ? passkeyLogin
        : passkeyRegister
      : mode === "login"
        ? passwordLogin
        : passwordRegister;

  const requiresPassword = method === "password";
  const requiresDisplayName = mode === "register";
  const submitDisabled =
    busy ||
    !email ||
    (method === "passkey" && !passkeySupported) ||
    (requiresPassword && password.length < (mode === "register" ? 8 : 1)) ||
    (requiresDisplayName && !displayName.trim());

  return (
    <div className="min-h-[70vh] grid place-items-center">
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass rounded-2xl p-8 w-full max-w-md"
      >
        <div className="flex items-center gap-3 mb-6">
          <ShieldCheck className="h-6 w-6 text-accent" />
          <div>
            <div className="font-semibold">Sign in to SentinelOps</div>
            <div className="text-xs text-muted">
              {method === "passkey" ? "Passwordless · WebAuthn" : "Email · Password"}
            </div>
          </div>
        </div>

        {/* Method (passkey vs password) */}
        <div className="grid grid-cols-2 gap-1 mb-3 p-1 rounded-md bg-panel/60 border border-border/60">
          <button
            type="button"
            onClick={() => switchMethod("passkey")}
            className={`text-xs py-1.5 rounded-sm inline-flex items-center justify-center gap-1.5 ${
              method === "passkey" ? "bg-bg/80 text-text" : "text-muted hover:text-text"
            }`}
          >
            <KeyRound className="h-3.5 w-3.5" /> Passkey
          </button>
          <button
            type="button"
            onClick={() => switchMethod("password")}
            className={`text-xs py-1.5 rounded-sm inline-flex items-center justify-center gap-1.5 ${
              method === "password" ? "bg-bg/80 text-text" : "text-muted hover:text-text"
            }`}
          >
            <Lock className="h-3.5 w-3.5" /> Password
          </button>
        </div>

        {/* Mode (sign-in vs register) */}
        <div className="grid grid-cols-2 gap-1 mb-4 p-1 rounded-md bg-panel/60 border border-border/60">
          <button
            type="button"
            onClick={() => switchMode("login")}
            className={`text-xs py-1.5 rounded-sm ${
              mode === "login" ? "bg-bg/80 text-text" : "text-muted hover:text-text"
            }`}
          >
            Sign in
          </button>
          <button
            type="button"
            onClick={() => switchMode("register")}
            className={`text-xs py-1.5 rounded-sm ${
              mode === "register" ? "bg-bg/80 text-text" : "text-muted hover:text-text"
            }`}
          >
            {method === "passkey" ? "Register passkey" : "Create account"}
          </button>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!submitDisabled) void submit();
          }}
        >
          <label className="text-[11px] text-muted uppercase tracking-wider">Email</label>
          <input
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            type="email"
            autoComplete="email"
            spellCheck={false}
            className="mt-1 mb-3 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm outline-none focus:border-accent/60"
          />

          {requiresPassword && (
            <>
              <label className="text-[11px] text-muted uppercase tracking-wider">
                Password
              </label>
              <input
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                type="password"
                autoComplete={mode === "login" ? "current-password" : "new-password"}
                minLength={mode === "register" ? 8 : 1}
                className="mt-1 mb-3 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm outline-none focus:border-accent/60"
                placeholder={
                  mode === "register" ? "At least 8 characters" : "Your password"
                }
              />
            </>
          )}

          {requiresDisplayName && (
            <>
              <label className="text-[11px] text-muted uppercase tracking-wider">
                Display name
              </label>
              <input
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                type="text"
                autoComplete="name"
                className="mt-1 mb-3 w-full bg-panel/60 border border-border/60 rounded-md px-3 py-2 text-sm outline-none focus:border-accent/60"
              />
            </>
          )}

          <button
            type="submit"
            disabled={submitDisabled}
            className="mt-2 w-full text-sm py-2.5 rounded-md bg-accent text-bg font-medium inline-flex items-center justify-center gap-2 hover:opacity-90 disabled:opacity-60"
          >
            {method === "passkey" ? (
              mode === "login" ? (
                <Fingerprint className="h-4 w-4" />
              ) : (
                <UserPlus className="h-4 w-4" />
              )
            ) : mode === "login" ? (
              <Lock className="h-4 w-4" />
            ) : (
              <UserPlus className="h-4 w-4" />
            )}
            {busy
              ? method === "passkey"
                ? mode === "login"
                  ? "Waiting for passkey…"
                  : "Creating passkey…"
                : mode === "login"
                  ? "Signing in…"
                  : "Creating account…"
              : method === "passkey"
                ? mode === "login"
                  ? "Continue with passkey"
                  : "Register a passkey"
                : mode === "login"
                  ? "Sign in with password"
                  : "Create account"}
          </button>
        </form>

        {method === "passkey" && !passkeySupported && (
          <div className="mt-3 text-xs text-warn text-center">
            WebAuthn requires a secure context. Open this app via{" "}
            <code>http://localhost:3000</code> or HTTPS, or use the{" "}
            <button
              type="button"
              onClick={() => switchMethod("password")}
              className="underline hover:text-text"
            >
              Password
            </button>{" "}
            tab.
          </div>
        )}
        {err && (
          <div className="mt-3 text-xs text-bad text-center break-words">
            {err}
          </div>
        )}
        {info && !err && (
          <div className="mt-3 text-xs text-muted text-center">{info}</div>
        )}

        <div className="mt-6 text-[11px] text-muted text-center leading-5">
          {mode === "login" ? (
            <>
              First time on this device? Switch to{" "}
              <button
                type="button"
                onClick={() => switchMode("register")}
                className="underline hover:text-text"
              >
                {method === "passkey" ? "Register passkey" : "Create account"}
              </button>
              .
            </>
          ) : (
            <>
              Already have an account? Switch to{" "}
              <button
                type="button"
                onClick={() => switchMode("login")}
                className="underline hover:text-text"
              >
                Sign in
              </button>
              .
            </>
          )}
        </div>
      </motion.div>
    </div>
  );
}
