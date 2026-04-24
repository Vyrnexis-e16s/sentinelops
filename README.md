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

**Detection & SIEM**
- Sigma rule compiler — parse Sigma YAML into the native detection AST so the community rule packs work out of the box.
- STIX/TAXII feed ingestion for threat intel, with automatic enrichment of incoming events against known IOCs.
- WebSocket live alert stream on the dashboard (plumbing exists, UI binding pending).
- UEBA baseline per user/host — deviation scoring beyond the current IQR+z detector.
- Kafka/Redpanda event bus option for high-throughput ingest, replacing the current direct-to-Postgres path.

**Offensive / Recon**
- Distributed recon with a dedicated worker fleet and rate-limit-aware scheduling.
- Authenticated web scanning (session replay + JWT bearer support).
- Nuclei-compatible template runner so the community library works against the same target model.
- Recon scheduler with diff alerts — notify when a target's attack surface changes between runs.

**ML & Network IDS**
- Online learning for the IDS model with drift detection, confidence-gated rollout, and shadow inference.
- Expand training data beyond NSL-KDD — CIC-IDS2017 / UNSW-NB15 / custom PCAP captures.
- Explainable predictions via SHAP so the analyst sees *why* a flow was flagged.
- Optional GPU inference path for the heavier models.

**Crypto & Vault**
- HSM-backed KEKs via PKCS#11 — SoftHSM for local, AWS CloudHSM / GCP Cloud HSM for prod. Currently uses software KEKs.
- Key rotation flow (wrap-unwrap-rewrap) with zero downtime.
- Post-quantum KEM hybrid for the key-wrap step (Kyber alongside the existing KDF).
- S3 / MinIO object-storage backend instead of local filesystem.

**Platform & Operations**
- Multi-tenant separation and proper RBAC (workspace → team → user) with row-level security in Postgres.
- SSO via OIDC (Auth0 / Okta / Keycloak) on top of the existing WebAuthn baseline.
- Case management — group related alerts into investigations, assign owners, track state and SLA.
- Observability: OpenTelemetry traces, Prometheus metrics, a Grafana dashboard pack.
- Helm chart + Terraform module for one-command deploys to EKS / GKE / AKS.

**UX & Accessibility**
- Mobile-responsive variant of the dashboard (currently degrades to tablet only).
- Full keyboard navigation + screen-reader pass — the animations should never get in the way of operating the app.
- Command palette (Cmd-K) with cross-module search.

**Research / experimental**
- LLM-assisted alert triage — local model served via vLLM, no paid-API default.
- Graph-based attack reconstruction in Neo4j, BFS from high-severity nodes to surface the kill chain.
- eBPF host-telemetry agent (tiny Go binary, no kernel modules) streaming syscalls + network events into the SIEM module.

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

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). The Apache 2.0 license grants you broad rights (commercial use, modification, distribution, sublicensing) in exchange for retaining attribution and the license notice, and it includes a patent grant that MIT does not. It also ships with an explicit **Disclaimer of Warranty** and **Limitation of Liability** — how you use this project is entirely your responsibility (see the section above).

## Acknowledgements

- NSL-KDD dataset curators at the University of New Brunswick.
- MITRE ATT&CK for the technique taxonomy.
- The shadcn/ui, Framer Motion, and Three.js communities.
