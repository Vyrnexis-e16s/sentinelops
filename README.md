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

Because this is a portfolio piece, I wanted to be honest about what's here versus what a production build would need. A running list of known gaps and interesting extensions lives in [`docs/ROADMAP.md`](docs/ROADMAP.md). Highlights:

- Rule engine for SIEM (Sigma rule compiler)
- STIX/TAXII feed ingestion
- Distributed recon with dedicated worker fleet
- Online learning for the IDS model (drift detection)
- HSM-backed KEKs in Vault (currently software KEKs)
- Multi-tenant separation and RBAC beyond the single-org model

## Security

If you find a vulnerability, please see [SECURITY.md](SECURITY.md) for disclosure. Don't open a public issue.

## License

MIT — see [LICENSE](LICENSE). You can use this commercially, but remember the recon module is designed for authorised testing only; how you use it is on you.

## Acknowledgements

- NSL-KDD dataset curators at the University of New Brunswick.
- MITRE ATT&CK for the technique taxonomy.
- The shadcn/ui, Framer Motion, and Three.js communities.
