# Roadmap

What's here now, what landed recently, and what a **production** build would still need. This is a living document.

## Shipped (v1)

- Monorepo: FastAPI backend, Next.js 14 frontend, scikit-learn ML pipeline.
- Four modules: SIEM, Recon, IDS, Vault (end-to-end with Docker Compose).
- Two UI themes: Tactical Night, Quantum Aurora; Three.js globe + aurora shader.
- JWT + WebAuthn; AES-256-GCM envelope encryption; hash-chained audit log.
- NSL-KDD RandomForest + committed artifact; CI, pytest / Vitest / Playwright.

## Shipped (v1.x extensions, portfolio)

- **Sigma (subset) → rule DSL** — `POST /api/v1/siem/sigma/compile` and `POST /api/v1/siem/rules/from-sigma` (no pipelines/aggregations; see OpenAPI for limits).
- **STIX 2.1 indicator parse** — `POST /api/v1/siem/threat-intel/stix` stores IOCs; ingest path enriches events and raises **threat intel** alerts (see `threat.intel.ioc` in the alert stream).
- **WebSocket live alerts** — `WS /ws/alerts?token=<JWT>` (Redis channel `siem.alerts`); dashboard binds when a token is available.
- **UEBA-style baselines (light)** — `GET /api/v1/siem/ueba/summary` (per-`source` volume + z-score vs 30d baseline).
- **Case management (MVP)** — investigations CRUD under `/api/v1/siem/investigations`.
- **Prometheus** — `GET /metrics` when `EXPOSE_PROMETHEUS` is true; configurable in `.env`.
- **IDS** — `GET /api/v1/ids/drift/summary?feature=…` on stored inferences; `explain: true` on infer returns a **tree-model proxy** (not full SHAP).
- **UI** — Command palette (⌘K / Ctrl+K) for cross-module jump.

## Detection & SIEM (next)

- **Sigma** — full compiler: condition trees, `1 of` filters, aggregations, pipelines, `windash` field mappings, official Sigma **correlations**; community rule pack CI.
- **STIX/TAXII** — persistent TAXII 2.1 client (Discovery, API Root, `GET /collections/…/objects`), feed scheduling, error budgets, and versioned last-seen.
- **WebSocket** — back-pressure, replay buffer for missed alerts after reconnect, role-scoped rooms.
- **UEBA** — per-user and per-entity **seasonal** baselines (EWMA / STL), peer groups, not only global source volume.
- **Kafka / Redpanda** — optional ingest bus with exactly-once semantics into Postgres or ClickHouse hot tier; `KAFKA_BOOTSTRAP` in config is a placeholder.
- **Elastic / OpenSearch** — hot/warm for search-heavy deployments (explicit non-goal for v1, noted for honesty).

## Offensive / Recon (next)

- **Distributed workers** — dedicated recon fleet, shard targets, **rate limits** and scope enforcement per legal agreement.
- **Authenticated scanning** — session cookies, `Authorization: Bearer` replay, form login macros.
- **Nuclei** — template model compatibility or runner bridge against the same target object model.
- **Recon diff & scheduler** — cron/interval jobs, `diff` between runs, alerts on attack-surface change.

## ML & Network IDS (next)

- **Online learning** — drift detection on feature distributions, shadow inference, canary promote; ties to a feature store.
- **Datasets** — CIC-IDS2017, UNSW-NB15, custom PCAP feature extraction in the same schema as NSL-KDD.
- **SHAP** — true Shapley values (e.g. TreeSHAP) when the dependency budget allows.
- **GPU inference** — ONNX Runtime + CUDA for larger models; batch GPU path.
- **Shadow mode** — compare challenger models without affecting alert output.

## Crypto & Vault (next)

- **HSM / PKCS#11** — `HSM_PKCS11_LIB` is reserved; replace software KEK with HSM/Cloud HSM; SoftHSM for local dev.
- **Key rotation** — wrap-unwrap-rewrap with two KEKs (overlap window), zero user-visible downtime.
- **Post-quantum hybrid** — ML-KEM (Kyber) in the key-wrap path (`PQC_KYBER_HYBRID` flag placeholder).
- **S3/MinIO** — blob backend instead of local FS (`S3_VAULT_ENDPOINT`).

## Platform & operations (next)

- **Multi-tenant + RBAC** — workspace → team → user; Postgres **RLS**; OIDC for SSO (`OIDC_ISSUER` placeholder).
- **OpenTelemetry** — traces API → workers → DB; trace IDs on audit entries; Grafana/Tempo/Loki pack under `infra/observability/` (folder TBD in repo).
- **Helm + Terraform** — EKS / GKE / AKS one-shot with secrets externalized.
- **Grafana dashboard** — JSON for RED metrics, Celery, Postgres.

## UX & accessibility (next)

- **Mobile** — true small-screen layout (dashboard currently tablet-first).
- **A11y** — full keyboard order, focus rings, screen reader labels, `prefers-reduced-motion` for Framer/Three.
- **Command palette** — search alerts by ID, paste Sigma, jump to investigation (extends current module-only palette).
- **i18n** — `next-intl` (or similar) with English as the seed locale.

## Research / experimental (next)

- **LLM triage** — local open model (vLLM / llama.cpp), optional offline-only; no paid API as default; prompt templates per MITRE technique.
- **Neo4j** — `NEO4J_URI` reserved; BFS/shortest path on alert/entity graph for kill chain narrative.
- **eBPF** — small Go agent streaming syscalls + socket events into SIEM normalisation.
- **Deception / honey-tokens** — salted fake credentials in Vault that fire a high-severity alert when accessed.

## Data & ML platform (next)

- **Feast** (or similar) for offline/online feature parity.
- **Synthetic traffic** — generative or replay harness for end-to-end detection tests.
- **Drift** — connect IDS drift API to auto-retrain policy (currently observability only).

## Known gaps / non-goals (unchanged in spirit)

- Not an enterprise SIEM at petabyte scale; hot path is still Postgres for this repo.
- Recon is **not** a Burp replacement for deep authenticated testing.
- IDS remains a teaching model unless you swap artifacts and retrain.
- i18n, Windows-native dev guide: still on the “nice to have” list.

## How to propose changes

Open an issue with the `roadmap` label, or include roadmap bullet references in a PR description so reviewers can map scope.
