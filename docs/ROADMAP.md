# Roadmap

What's here now, what's next, and what I deliberately chose not to build yet. This is a living document — I update it as I ship.

## Shipped (v1)

- Monorepo scaffold with FastAPI backend, Next.js 14 frontend, scikit-learn ML pipeline.
- Four modules working end-to-end: SIEM, Recon, IDS, Vault.
- Two runtime-switchable UI themes (Tactical Night, Quantum Aurora).
- Three.js 3D globe, WebGL aurora shader, Framer Motion micro-interactions.
- JWT + WebAuthn auth with per-user passkeys.
- AES-256-GCM envelope encryption for Vault files.
- Hash-chained append-only audit log.
- NSL-KDD RandomForest model trained and artifact committed.
- Docker Compose stack, Makefile, GitHub Actions CI.
- pytest + Vitest + Playwright smoke tests.

## Next up (v1.1)

- **Sigma rule compiler** for SIEM — parse Sigma YAML into our native detection AST.
- **STIX/TAXII feed ingestion** so the CVE lookup isn't NVD-only.
- **WebSocket live alert stream** on the dashboard (plumbing exists, UI binding pending).
- **Recon scheduler** — cron-style recurring scans with diff alerts.
- **Playwright e2e coverage** for each module, not just the dashboard.

## Medium-term (v1.2 - v1.5)

- **Online learning for the IDS model.** Track feature drift, retrain nightly on new captures, confidence-gated rollout.
- **HSM-backed KEKs in Vault.** Replace the software master key with PKCS#11 (SoftHSM for local, AWS CloudHSM / GCP Cloud HSM in prod).
- **Multi-tenant RBAC.** Current model assumes a single org; add workspace → team → user hierarchy with row-level security in Postgres.
- **SSO (OIDC).** Integrate with Auth0, Okta, Keycloak.
- **Case management.** Group related alerts into investigations, assign owners, track state.

## Researchy / experimental

- **LLM-assisted alert triage.** Give the analyst a summary of what happened, why it fired, and what to check next. Probably a local model served via vLLM — I don't want to wire this to a paid API by default.
- **Graph-based attack reconstruction.** Load alerts into a Neo4j graph, run BFS from high-severity nodes to surface the kill chain.
- **eBPF-based host telemetry agent.** Tiny Go binary that streams syscalls + network events into the SIEM module without kernel modules.
- **Post-quantum key-wrap.** Kyber (ML-KEM) alongside the existing HKDF-based wrap so Vault secrets survive the harvest-now-decrypt-later era.
- **Explainable IDS predictions.** SHAP per-flow so the analyst sees which features drove the classification.
- **UEBA baselines.** Per-user / per-host behavioural baselines with deviation scoring on top of the current static detectors.
- **Deception / honey-tokens.** Salted fake credentials inside Vault that fire a high-severity alert the moment they're accessed.

## Platform & operations

- **OpenTelemetry everywhere.** Traces from the API through Celery through the frontend, with a Grafana/Tempo/Prometheus pack shipped in `infra/observability/`.
- **Helm chart + Terraform module** for one-command deploys to EKS / GKE / AKS.
- **Command palette (Cmd-K)** with cross-module search so you can jump from a SIEM alert to the related recon target to the vault audit entry without leaving the keyboard.
- **Accessibility pass.** Full keyboard navigation, screen-reader labels on every interactive element, respect for `prefers-reduced-motion` across all Framer Motion animations.
- **Mobile-responsive dashboard.** Currently degrades to tablet; needs a deliberate small-screen pass.
- **i18n scaffolding.** `next-intl` with English as the seed locale.

## Data & ML

- **CIC-IDS2017 / UNSW-NB15** added to the training pipeline alongside NSL-KDD, with a dataset selector flag.
- **GPU inference path** (ONNX Runtime w/ CUDA) for the heavier models.
- **Synthetic traffic generator** to fuzz the detection pipeline end-to-end.
- **Feature store** (Feast) so offline training features match online inference features.

## Known gaps / explicit non-goals

- Not an enterprise SIEM replacement. Hot storage is Postgres, not Elasticsearch — fine for demo volumes, don't try to pipe a real SOC into it.
- Recon module does not do authenticated web scans or business-logic fuzzing. Use Burp Suite for that.
- IDS model is trained on NSL-KDD, which is well-known to have coverage gaps against modern traffic. Considered a teaching model, not a prod detector.
- No mobile UI. The dashboard degrades gracefully to tablet size; below that it's not designed.
- No Windows dev setup docs — the stack works on WSL2 but I haven't written it up.

## How to propose changes

Open an issue with the `roadmap` label. If you want to pick up an item, comment on the issue so we don't double up.
