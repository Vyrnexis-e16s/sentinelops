# SentinelOps setup scripts

Two entry points (pick your OS):

| Platform | Script | Notes |
|----------|--------|--------|
| **Windows** (Windows PowerShell 3+ or PowerShell 7+ `pwsh`) | `sentinelops-dev.ps1` | Run from repo root: `.\scripts\sentinelops-dev.ps1` |
| **Linux** (Ubuntu / Debian / WSL) | `sentinelops-dev.sh` | `chmod +x scripts/sentinelops-dev.sh` then `./scripts/sentinelops-dev.sh` |

## What they do

1. Ensure `.env` exists (copy from `.env.example` if needed).
2. Find **Python ≥ 3.11** (Windows: `py -3.12` / `-3.11`; Linux: `python3.12`, `python3.11`, `python3`).
3. Create **`backend/.venv`** and **`ml/.venv`**, upgrade `pip`, install each `requirements.txt`.
4. Require **Node.js 18+**, then install frontend deps (**pnpm** if installed, else **npm**).
5. Run **`pnpm run typecheck`** (or `npm run typecheck`) and **`lint`**.
6. In **full** mode (default): require a running Docker engine, then run **`docker compose up -d --build`** (or `docker-compose`) for `infra/docker/docker-compose.yml` — the database, cache, and containerized app stack are expected to come up this way.

Logs are written under **`logs/sentinelops-dev-*.log`**.

## Modes

### Windows (`sentinelops-dev.ps1`)

- **Default / `full`**: local venvs + npm, then **Docker Compose** (required; fails if Docker is not installed or the engine is not running).
- **`-Mode local`**: venvs + npm only — use when you are not using the provided Compose stack.
- **`-Mode docker`**: only Docker Compose (skips venv/npm).
- **`-TryUpgradePython`**: if Python is missing or too old, try `winget install Python.Python.3.12` (may require elevation).

### Linux (`sentinelops-dev.sh`)

Environment variables:

| Variable | Meaning |
|----------|---------|
| `MODE=full` | default: venv + node + **docker compose** (fails if Docker is unavailable) |
| `MODE=local` | venv + node only (no Docker) |
| `MODE=docker` | only compose |
| `SENTINELOPS_APT_INSTALL=1` | run `sudo apt-get install` for Python 3.12 / venv (Ubuntu) |

## After setup

- **Docker**: UI http://localhost:3000 — API http://localhost:8000/docs — seed:  
  `docker compose -f infra/docker/docker-compose.yml exec backend python -m app.scripts.seed`
- **Local backend** (from activated `backend/.venv`):  
  `uvicorn app.main:app --reload` (set `SECRET_KEY` / `VAULT_MASTER_KEY` in `.env` first).
- **Local frontend**: `cd frontend && pnpm dev` (or `npm run dev`).

These scripts do **not** auto-upgrade the system Python on Linux (use your distro or `SENTINELOPS_APT_INSTALL=1`); on Windows, optional `winget` is opt-in.
