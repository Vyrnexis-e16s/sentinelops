# SentinelOps

A unified security operations platform that folds four very different security disciplines into a single workspace. I built this because every job description I look at wants "full-stack security engineer who also knows ML" and that's really four skill trees at once — so instead of four tiny repos, I made one honest attempt at the whole thing.

It is not a replacement for Splunk, Nessus, Suricata, or a real KMS. It is a portfolio-grade prototype that demonstrates how those capabilities fit together architecturally and how they'd present to an analyst on one screen.

## What's in it

**Blue Team SIEM.** Ingest JSON and syslog events, parse them, score them for anomaly with a simple IQR + z-score detector, and map the survivors to MITRE ATT&CK techniques so an analyst can triage by tactic instead of by log line.

**Red Team Recon.** Subdomain enumeration against a resolver, async TCP port scan with service-banner grabs, NVD CVE lookup by CPE string, and a web-path fuzzer with a curated wordlist. Built to be used against targets you own or have written authorisation to test.

**Network IDS with ML.** A RandomForest classifier trained on NSL-KDD, exposed behind a FastAPI inference endpoint. The training pipeline is committed — you can rerun it from scratch — and a pre-fit model artifact ships with the repo so the UI works the moment you run `docker compose up`.

**Zero-Trust Vault.** WebAuthn/passkey authentication (no passwords), envelope encryption with per-user KEKs derived via HKDF, AES-256-GCM for file content, and an append-only audit log hash-chained so tampering is detectable.

## Architecture at a glance

```
┌─────────────────────────── Next.js 14 (App Router) ───────────────────────────┐
│  Dashboard  │    SIEM    │   Recon   │    IDS    │   Vault   │  Theme Toggle │
│             │            │           │           │           │ Tactical │ Aurora │
└────────┬──────────────┬──────────────┬──────────────┬──────────────┬─────────┘
         │              │              │              │              │
         │              │              │              │              │ REST + WS
         ▼              ▼              ▼              ▼              ▼
┌───────────────────────── FastAPI (Python 3.11) ─────────────────────────────┐
│  /api/v1/siem  │  /api/v1/recon  │  /api/v1/ids  │  /api/v1/vault  │  auth │
└────────┬──────────────┬──────────────┬──────────────┬──────────────┬────────┘
         │              │              │              │              │
         ▼              ▼              ▼              ▼              ▼
   Postgres        Celery workers     scikit-learn   AES-GCM +     JWT +
   (events,        (recon jobs,       model artifact HKDF          WebAuthn
    alerts,         long scans)        (ml/artifacts)
    audit)
         └──────────────┬──────────────┘
                        ▼
                      Redis
              (broker + cache + pub/sub)
```

The four modules share auth, the event bus, the audit log, and the UI shell. Everything else is isolated — you can delete a module directory and the rest keeps running.

## Running it

You need Docker and Docker Compose. That's it.

```bash
git clone https://github.com/Vyrnexis-e16s/sentinelops.git
cd sentinelops
cp .env.example .env
make up
```

Then:

- UI at http://localhost:3000
- API docs at http://localhost:8000/docs
- Default dev user: `analyst@sentinelops.local` / passkey registered on first visit

`make seed` loads a few weeks of fake SIEM events and a handful of known-bad CVEs so the dashboard isn't empty.

### Automated setup (Windows & Linux)

Use the scripts in [`scripts/`](scripts/) to create Python **venv**s (`backend/.venv`, `ml/.venv`), install **requirements.txt**, install **Node** dependencies, run **TypeScript** + **ESLint** checks, optionally start **Docker** Compose, and log everything under `logs/`.

- **Windows (PowerShell):** `.\scripts\sentinelops-dev.ps1` — see [`scripts/README.md`](scripts/README.md) for `-Mode` and `-TryUpgradePython`.
- **Linux / Ubuntu / WSL:** `chmod +x scripts/sentinelops-dev.sh && ./scripts/sentinelops-dev.sh` — the default `MODE=full` needs Docker running; `MODE=local` only prepares venvs/Node without compose. `SENTINELOPS_APT_INSTALL=1` on Ubuntu installs Python 3.12 + venv via apt (requires sudo).

## Portfolio proof (screenshots)

Add PNGs under [`docs/screenshots/`](docs/screenshots/) and reference them here. Suggested shots — capture **after** `make up` and `make seed`, signed in (or with a dev JWT) so the API-backed panels are populated.

| # | Suggested filename | **Exactly where to capture (URL + what to show)** |
|---|-------------------|-----------------------------------------------|
| 1 | `01-dashboard.png` | `http://localhost:3000/dashboard` — full page: stat cards, globe, **Recent alerts** (REST and/or live WS if a JWT is in `localStorage` key `sentinelops_access_token`), module tiles. |
| 2 | `02-siem.png` | `http://localhost:3000/siem` — table of alerts and rules list (or disconnect banner + fallback if unauthenticated). |
| 3 | `03-recon.png` | `http://localhost:3000/recon` — target list and job state after a scan. |
| 4 | `04-ids.png` | `http://localhost:3000/ids` — inference / feature strip. |
| 5 | `05-vault.png` | `http://localhost:3000/vault` — encrypted object list. |
| 6 | `06-api-docs.png` | `http://localhost:8000/docs` — Swagger with SIEM, Sigma, STIX, IDS drift endpoints visible. |
| 7 | `07-metrics.png` | `http://localhost:8000/metrics` — Prometheus text export (if `EXPOSE_PROMETHEUS=true`). |
| 8 | `08-command-palette.png` | `http://localhost:3000/dashboard` with **⌘K / Ctrl+K** — command palette open. |
| 9 | `09-themes.png` | Any page with the theme control used to show **Tactical** vs **Quantum Aurora**. |

**How to get a JWT for real UI data:** use **Authorize** in Swagger on `http://localhost:8000/docs` after registering a passkey, or run WebAuthn from the app and copy the token into `localStorage` as `sentinelops_access_token` (or set `NEXT_PUBLIC_DEV_TOKEN` in `.env.local` for local only).

Placeholder image slots (replace with your files):

![Dashboard](docs/screenshots/01-dashboard.png)

![SIEM](docs/screenshots/02-siem.png)

![API docs](docs/screenshots/06-api-docs.png)

## Developing without Docker

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend
cd frontend
pnpm install
pnpm dev

# ML (retrain)
cd ml
pip install -r requirements.txt
python scripts/train_ids.py
```

## Two UI variants

The frontend ships with two themes that swap at runtime. Both use the same component primitives — the only difference is CSS variables and which background layer mounts.

- **Tactical Night** — graphite base, neon teal and amber accents, glass panels, JetBrains Mono for data. Includes a Three.js 3D globe of threat origins and a subtle scanline overlay. Feels like a NOC at 2am.
- **Quantum Aurora** — midnight-blue-to-violet gradient, aurora WebGL particle field, rounded cards with gradient borders, spring-physics hover states. Feels like a premium product.

Theme choice persists per-user. The shader-heavy components (`<Globe />`, `<AuroraCanvas />`) are lazy-loaded so the initial paint stays fast.

## Testing

```bash
make test          # runs backend pytest + frontend vitest + ml pytest
make test-e2e      # Playwright smoke tests against a docker-compose stack
make lint          # ruff + black --check + mypy + eslint + tsc --noEmit
```

CI runs the same commands on every push and on pull requests into `main`.

## What I'd do next

This repo is a **portfolio** piece: it shows the architecture, not a full commercial SOC. A detailed backlog — production gaps, research ideas, and **what is already stubbed in config or code** — is in [`docs/ROADMAP.md`](docs/ROADMAP.md).

**Shipped in-tree (v1+ extensions)** include: a **limited Sigma → rule DSL** compiler (`POST /api/v1/siem/sigma/compile`), **STIX indicator ingest** and **IOC enrichment** on event ingest, a **WebSocket** alert stream at `/ws/alerts?token=`, a **per-source UEBA-style** volume summary, **case investigations** CRUD, **Prometheus** metrics at `/metrics` when enabled, an IDS **drift** summary and **explanation proxy** (tree feature importance) on inference, and a **command palette (⌘K)** on the UI.

Remaining themes: full Sigma parity, a real TAXII **client** with scheduling, distributed recon workers, OIDC, multi-tenant RLS, HSM, PQC, LLM triage, Neo4j, eBPF, Helm/Terraform, and more — all expanded in the roadmap.

## Legal and ethical use

**Read this before running anything.** SentinelOps contains offensive security tooling — port scanners, subdomain brute-forcers, and a web path fuzzer — bundled with the defensive pieces. Those capabilities are there so you can practise the full attacker-defender loop in a lab you own. They are **not** a licence to test networks you don't own.

- Only run the `recon` module against hosts, domains, and IP ranges that you own, that your employer has contracted you to test, or for which you hold explicit written authorisation (a bug-bounty program in-scope list counts, out-of-scope does not).
- Unauthorised scanning, credential harvesting, or traffic interception against third-party systems is illegal in most jurisdictions (CFAA in the US, Computer Misuse Act in the UK, IT Act in India, etc.) — getting caught is on you.
- The cryptographic primitives in this codebase are fit for portfolio-grade demos. **Do not** put production secrets, PII, or regulated data in a SentinelOps Vault instance without first replacing the software master key with a real HSM/KMS and going through a proper review.
- The ML IDS model is trained on NSL-KDD, which is a teaching dataset with well-known coverage gaps. It is **not** a substitute for a commercial IDS on a real network.
- This software is provided **"AS IS"**, without warranty of any kind (see the Apache 2.0 `LICENSE` file for the formal language). The authors and contributors accept no liability for damage, downtime, legal trouble, or any other consequence arising from your use of this code. You are the sole responsible party for how, where, and against what you run it.

If any of the above is unclear, stop and get advice before running the tool — don't guess.

## Security

If you find a vulnerability, please see [SECURITY.md](SECURITY.md) for disclosure. Don't open a public issue.

### Dependency audits (frontend / npm)

From the repo root, check and apply **Node** dependency fixes (visible in CI and local `npm install` output):

```bash
cd frontend
npm audit                 # list known issues in the dependency tree
npm audit fix             # apply non-breaking semver-safe updates first (preferred)
```

`npm audit fix --force` may pull **major** upgrades and **can break** the Next.js app or eslint config — only use it in a branch, then run `npm run typecheck`, `npm run lint`, and `npm run build` before merging.

Optional (Python backend, same machine):

```bash
cd backend && . .venv/bin/activate  # or your venv
pip install pip-audit && pip-audit -r requirements.txt
```

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). The Apache 2.0 license grants you broad rights (commercial use, modification, distribution, sublicensing) in exchange for retaining attribution and the license notice, and it includes a patent grant that MIT does not. It also ships with an explicit **Disclaimer of Warranty** and **Limitation of Liability** — how you use this project is entirely your responsibility (see the section above).

## Acknowledgements

- NSL-KDD dataset curators at the University of New Brunswick.
- MITRE ATT&CK for the technique taxonomy.
- The shadcn/ui, Framer Motion, and Three.js communities.
