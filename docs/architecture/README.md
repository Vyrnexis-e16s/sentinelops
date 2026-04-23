# Architecture

A fuller walkthrough of how SentinelOps fits together. If you just want to get it running, the top-level README has you covered.

## Guiding principles

1. **Module isolation.** The four capability areas (SIEM, Recon, IDS, Vault) live under `backend/app/modules/` and `frontend/src/components/<module>/`. Cross-module imports are banned by our lint config; everything crosses through shared `core` or `services` layers.
2. **One shell, many faces.** The frontend is one Next.js app with two themes. We don't ship a "red team UI" and a "blue team UI" — the same analyst works both sides of the house.
3. **Zero-trust internally.** Every API call is authenticated; the frontend never proxies unauthenticated requests. WebAuthn replaces passwords entirely; JWTs are short-lived (1 hour) and rotated on session activity.
4. **Batteries included, but removable.** You can delete a module directory and the rest keeps compiling.

## Backend layout

```
backend/app/
├── main.py                 # FastAPI entrypoint, router registration
├── core/
│   ├── config.py           # Pydantic Settings from env
│   ├── db.py               # Async SQLAlchemy session factory
│   ├── security.py         # JWT encode/decode, password-less auth helpers
│   ├── crypto.py           # AES-GCM, HKDF, HMAC helpers used by Vault + audit log
│   └── logging.py          # Structlog + Sentry bootstrap
├── models/                 # Declarative SQLAlchemy models (shared)
├── schemas/                # Pydantic request/response schemas (shared)
├── services/
│   ├── auth.py             # Login, WebAuthn challenge/verify
│   ├── audit.py            # Append-only log with SHA-256 hash chain
│   └── events.py           # Redis pub/sub fan-out
├── workers/
│   ├── celery_app.py       # Celery instance
│   └── tasks.py            # Long-running jobs (recon scans, log ingests)
├── modules/
│   ├── siem/               # Event ingest, anomaly scoring, ATT&CK mapping
│   ├── recon/              # Subdomain, port scan, CVE lookup, web fuzz
│   ├── ids/                # Flow inference against the ML artifact
│   └── vault/              # File encryption, WebAuthn gate, audit
└── tests/                  # Pytest suite
```

Every module exposes `router.py` (FastAPI APIRouter), `service.py` (business logic), `models.py` (module-scoped DB tables), `schemas.py` (module-scoped pydantic), and `tests/`.

## Frontend layout

```
frontend/src/
├── app/                    # Next.js App Router
│   ├── layout.tsx          # Root layout, theme provider, auth guard
│   ├── page.tsx            # Redirects to /dashboard
│   ├── login/              # WebAuthn registration + auth
│   ├── dashboard/          # Unified SOC overview
│   ├── siem/               # Events, rules, alerts
│   ├── recon/              # Targets, jobs, findings
│   ├── ids/                # Inference playground
│   └── vault/              # File manager, audit viewer
├── components/
│   ├── ui/                 # shadcn/ui primitives
│   ├── three/              # Three.js scenes (lazy-loaded)
│   ├── aurora/              # WebGL fragment shaders
│   ├── shared/             # Cross-module components (StatCard, AlertTable)
│   └── {siem,recon,ids,vault}/  # Module-scoped components
├── lib/
│   ├── api.ts              # Typed fetch client
│   ├── auth.ts             # WebAuthn helpers
│   ├── theme.ts            # Theme variables + switcher
│   └── ws.ts               # WebSocket client
├── hooks/                  # React hooks (useAuth, useTheme, useEvents)
└── styles/                 # Global CSS, theme variables
```

## Data model (summary)

A single logical schema under the `sentinelops` database. Each module gets a table namespace:

- `core_*` — users, sessions, webauthn_credentials, audit_log
- `siem_*` — events, rules, alerts, attack_mappings
- `recon_*` — targets, jobs, findings, cve_cache
- `ids_*` — inferences, feedback (analyst-labelled corrections for retraining)
- `vault_*` — objects, keys (wrapped), access_grants

Full DDL lives in Alembic migrations under `backend/migrations/versions/`.

## Auth flow

1. First visit — user registers a passkey. The frontend calls `/api/v1/auth/webauthn/register/begin`, gets a challenge, prompts the browser (`navigator.credentials.create`), posts the attestation to `/register/finish`.
2. Subsequent visits — `/auth/webauthn/login/begin` returns a challenge + allow-list of credential IDs for the email. Browser signs it (`navigator.credentials.get`). Backend verifies and issues a JWT.
3. JWT is stored in an `HttpOnly; Secure; SameSite=Strict` cookie (not localStorage).
4. All protected API routes depend on `Depends(current_user)`, which verifies the JWT and hydrates the user + org context.

JWTs are short-lived (60 min default). Long-lived auth is re-authentication via passkey — no refresh tokens, to keep the threat model simple.

## Vault crypto

- Root `VAULT_MASTER_KEY` (64-char hex) lives in the environment. In a real deployment, wrap this via KMS/HSM.
- Per-user KEK: `HKDF-Expand(VAULT_MASTER_KEY, user_id, "sentinelops-kek-v1")`.
- Per-object DEK: random 32 bytes, generated on upload.
- File: AES-256-GCM with random 12-byte nonce, stored as `nonce || ciphertext || tag` on disk.
- DEK wrapped with KEK via AES-GCM; wrapped DEK stored in `vault_keys` table.
- Audit log entry hashed with SHA-256 over `(prev_hash || timestamp || actor || event || resource_id)`. Tampering breaks the chain.

## Observability

- Structured logs via structlog, JSON in prod.
- Optional Sentry DSN via env.
- Prometheus metrics at `/metrics` (enabled when `APP_ENV=production`).
- Request IDs propagated from frontend through backend for trace correlation.

## Why these choices

**FastAPI over Django.** Async support is first-class, OpenAPI comes for free, the type-driven approach meshes well with Pydantic. Django's admin is tempting but we don't need it.

**Next.js over Vite + Express.** App Router + server components give us SSR for the dashboard (good for SEO on the public demo) and we can co-locate API routes for WebAuthn origin matching.

**scikit-learn over PyTorch for IDS.** NSL-KDD is tabular; trees outperform MLPs here and the model fits in 5MB. Keeps the Docker image small.

**Celery over RQ / arq.** Celery's ecosystem (flower, beat, chord primitives) is still the best-documented.

**Postgres over Elasticsearch for SIEM.** This is a teaching project. For real event volumes you'd stream through Kafka into ClickHouse or OpenSearch; pretending otherwise would make the demo misleading.
