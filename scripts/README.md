# SentinelOps setup scripts

Two entry points (pick your OS):

| Platform | Script | Notes |
|----------|--------|--------|
| **Windows** (Windows PowerShell 3+ or PowerShell 7+ `pwsh`) | `sentinelops-dev.ps1` | Run from repo root: `.\scripts\sentinelops-dev.ps1` |
| **Linux** (Ubuntu / Debian / Kali / Fedora / **WSL**, etc.) | `sentinelops-dev.sh` or `sentinelops-wsl.sh` (same) | `chmod +x scripts/sentinelops-dev.sh` then `./scripts/sentinelops-dev.sh` from the repo in Linux — **do not** run the whole thing with `sudo` (it breaks venv and npm; use a normal user). If Python is missing, use `SENTINELOPS_APT_INSTALL=1` only for the **apt** step on Debian family. **PEP 668** (Kali, Debian, Ubuntu) blocks system `pip install`; the script now skips that and only installs in `backend/.venv` and `ml/.venv` via `ensurepip` there. |

## What they do

1. Ensure `.env` exists (copy from `.env.example` if needed).
2. Find **Python ≥ 3.11** (Windows: `py -3.13`…`3.11`; Linux: `python3.12`+). If none: **winget** installs Python 3.12/3.13 (Windows, unless `-NoWingetPython`); on apt-based Linux, **`SENTINELOPS_APT_INSTALL=1`** runs `sudo apt` for Python 3.12+ / venv / pip. Then run **`ensurepip` + `pip install -U pip setuptools wheel`** on that interpreter, then the same **inside** each venv.
3. Create **`backend/.venv`** and **`ml/.venv`**, `pip install -U pip`, install each `requirements.txt`.
4. Require **Node.js 20+** (Next.js 16), then install frontend deps (**pnpm** if installed, else **npm**).
5. Run **`pnpm run typecheck`** (or `npm run typecheck`) and **`lint`**.
6. In **full** mode (default): require a running Docker engine, then ensure the compose stack is up. If **`docker compose ps`** shows every service **running**, the scripts **skip** `up -d --build` and log that Docker is already up; otherwise they run **`docker compose up -d --build`** (or `docker-compose`).

Logs are written under **`logs/sentinelops-dev-*.log`**.

## Lifecycle commands

The scripts expose lifecycle commands. `--all` and `--restart` go through the **same setup pipeline** as the default invocation but force a rebuild; `--stop`, `--status`, and `--logs` short-circuit and only need Docker.

| Command (Linux/WSL) | Command (PowerShell) | What it does |
|---|---|---|
| `--all` | `-All` | Full bring-up: venvs + Node + `docker compose up -d --build --force-recreate` + run dev seed. Use for a clean, "everything-ready" first-time start. |
| `--restart` | `-Restart` | `docker compose up -d --build --force-recreate` and wait for `/health`. **Rebuilds images that changed** and recreates every container so volume-mounted source is reread — this is the command to use after editing code or env. |
| `--stop` | `-Stop` | `docker compose down`. Containers removed; **named volumes (Postgres, Redis) preserved**, so data survives. |
| `--status` | `-Status` | `docker compose ps` for the project — shows what's up and health states. |
| `--logs` | `-Logs` | Tails the last 200 lines of every service (`docker compose logs --tail 200`). |
| `--migrate` | `-Migrate` | `docker compose exec backend alembic upgrade head` (apply DB migrations; requires running stack). |
| `--smoke` | `-Smoke` | Runs `scripts/_smoke-all-tools.sh` (bash, curl, python3) against `http://localhost:8000`. On Windows PowerShell, WSL (or `bash` on `PATH` such as Git Bash) is used. |
| `--setup-llm` | `-SetupLlm` | **Local Ollama (optional):** finds `ollama` on the machine, pulls `qwen2.5:7b` (draft) and `llama3.1:8b` (refine), and writes `.env.llm.local.generated` with `SENTINELOPS_LLM_BASE_URL` for `127.0.0.1:11434`. Merge those lines into `.env`. Override model tags with env `SENTINELOPS_LLM_DRAFT_MODEL` / `SENTINELOPS_LLM_MODEL` when invoking the script. If the API runs in Docker, point the base URL at the host: `http://host.docker.internal:11434/v1` (and add `extra_hosts` for Linux). |
| `--bootstrap` | `-Bootstrap` | **Prerequisites:** `bootstrap-prereqs.sh --check` (no sudo) reports Python / Node / Docker. With **`--auto`** (or env `SENTINELOPS_AUTO_INSTALL=1`), on **apt** Linux: `sudo apt` installs `docker.io`, Node 20 (NodeSource), Python venv. **Not** a full OS installer: Fedora/Arch, air‑gapped, or non‑`winget` Windows still need manual steps. On Windows, `-Auto` can `winget` Node (and the rest of the script already can `winget` Python). |
| `--auto` | `-Auto` | Sets `SENTINELOPS_AUTO_INSTALL=1` for that run. Combine with `--all` for “full stack + best‑effort dep install” on supported platforms (see above). |
| `--help` / `-h` | `-Help` | Print full help and exit. |

Examples:

```bash
# Linux / WSL
./scripts/sentinelops-dev.sh --help
./scripts/sentinelops-dev.sh --all          # one-shot fresh start (rebuild + seed)
./scripts/sentinelops-dev.sh --restart      # apply code/config changes
./scripts/sentinelops-dev.sh --stop
./scripts/sentinelops-dev.sh --status
# Optional: Ollama + two local models for VAPT LLM (draft → refine)
./scripts/sentinelops-dev.sh --setup-llm
# Or directly:
# bash scripts/setup-local-llm.sh
```

```powershell
# Windows PowerShell / pwsh
.\scripts\sentinelops-dev.ps1 -Help
.\scripts\sentinelops-dev.ps1 -All
.\scripts\sentinelops-dev.ps1 -Restart
.\scripts\sentinelops-dev.ps1 -Stop
.\scripts\sentinelops-dev.ps1 -Status
.\scripts\sentinelops-dev.ps1 -SetupLlm
# Or: .\\scripts\\setup-local-llm.ps1
```

## Modes

### Windows (`sentinelops-dev.ps1`)

- **Default / `full`**: local venvs + npm, then **Docker Compose** (required; fails if Docker is not installed or the engine is not running).
- **`-Mode local`**: venvs + npm only — use when you are not using the provided Compose stack.
- **`-Mode docker`**: only Docker Compose (skips venv/npm).
- **`-TryUpgradePython`**: with an existing Python, run **`winget upgrade`** for Python 3.13/3.12 (keeps a winget-based install current).
- **`-NoWingetPython`**: do not auto-**`winget install`** Python; fail if 3.11+ is not already on `PATH` after `Get-PythonPath`.

### Linux (`sentinelops-dev.sh`)

Environment variables:

| Variable | Meaning |
|----------|---------|
| `MODE=full` | default: venv + node + **docker compose** (fails if Docker is unavailable) |
| `MODE=local` | venv + node only (no Docker) |
| `MODE=docker` | only compose |
| `SENTINELOPS_APT_INSTALL=1` | run **`sudo apt-get install`** (and a best-effort **upgrade**) for `python3.12`, venv, `python3-pip` when 3.11+ is missing |

## After setup

- **Docker**: UI http://localhost:3000 — API http://localhost:8000/docs — seed:  
  `docker compose -f infra/docker/docker-compose.yml exec backend python -m app.scripts.seed`
- **Local backend** (from activated `backend/.venv`):  
  `uvicorn app.main:app --reload` (set `SECRET_KEY` / `VAULT_MASTER_KEY` in `.env` first).
- **Local frontend**: `cd frontend && pnpm dev` (or `npm run dev`).

On **Linux**, unsupervised `sudo` is not run unless **`SENTINELOPS_APT_INSTALL=1`**. On **Windows**, **`winget` install/upgrade of Python** runs when it is on `PATH` and you did not pass **`-NoWingetPython`**.

**Kali, Debian, Ubuntu (incl. WSL):** If you used **`sudo ./scripts/sentinelops-dev.sh`**, you may have root-owned `backend/.venv`. Fix: `sudo chown -R "$USER:$USER" backend ml frontend/node_modules` (as needed) or `rm -rf backend/.venv ml/.venv` and re-run **without** sudo. A broken venv with no `pip` is fixed the same way after installing **`python3-venv`** (and `python3.13-venv` on Kali 3.13) via apt.

## Local LLM (Ollama / VAPT)

Full install, environment variables, Docker host access, and troubleshooting: **[`docs/LOCAL_LLM.md`](../docs/LOCAL_LLM.md)**. Short path: `bash scripts/setup-local-llm.sh` or `.\scripts\setup-local-llm.ps1`, merge `.env.llm.local.generated` into `.env`, restart the API, then use the VAPT page.
