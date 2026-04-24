# Production hardening (practical baseline)

This project is a **serious full-stack security reference** with real APIs, auth, and workers. It is **not** a certified commercial SOC or SIEM. Use this list to move from “docker-compose on a laptop” toward a defensible deployment.

## Scope and claims

- Be precise in READMEs and issues: what is **in scope** (e.g. passkey auth, API modules, optional Prometheus) and **out of scope** (Splunk/Elastic parity, 24/7 support, compliance certification).
- Treat `make seed` and similar scripts as **development conveniences**, not production data paths.

## Configuration

- **Secrets:** rotate `SECRET_KEY`, `VAULT_MASTER_KEY`, DB passwords, and JWT settings; use a real secret manager in cloud deployments.
- **Recon allowlist:** set `RECON_TARGET_ALLOWLIST` in production to restrict which domains, hostnames, or CIDRs users may add as recon targets. Leave empty only in trusted lab environments.
- **CORS** and `WEBAUTHN_ORIGIN` / `WEBAUTHN_RP_ID` must match the real UI origin in production.
- **TLS** everywhere: terminate HTTPS at a reverse proxy or load balancer; do not expose raw HTTP to the public internet for the app or API.

## Operations

- Run multiple API replicas behind a load balancer; scale Celery workers for recon jobs.
- **Backups** for PostgreSQL: tested restore, not only dumps.
- **Redis** persistence expectations documented (AOF vs snapshot) if you rely on it beyond caching.
- **Log aggregation** (structured JSON logs → your SIEM or log stack) and **alerting** on 5xx rate and job failures.
- **Metrics:** enable `/metrics` only on internal network or with auth, per your threat model.

## Security

- **Dependency and image scanning** in CI (e.g. `pip-audit`, `pnpm audit`, Trivy on images).
- **Rate limits** and abuse controls on public-facing auth and recon-adjacent endpoints.
- **Incident response** process and **SECURITY.md** for coordinated disclosure.
- Re-read the [Legal and ethical use](../README.md#legal-and-ethical-use) section before exposing offensive tooling (recon) to the internet.

## Quality bar in CI

- Keep **lint, typecheck, and tests** green on the default branch; treat failures as release blockers for anything you label “release candidate.”

For research ideas and future work, see [ROADMAP.md](ROADMAP.md).
