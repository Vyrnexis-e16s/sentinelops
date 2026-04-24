#!/usr/bin/env bash
# SentinelOps — venvs, Node, typecheck, then Docker Compose (required in MODE=full for DB, Redis, API, UI).
# Usage:
#   chmod +x scripts/sentinelops-dev.sh
#   ./scripts/sentinelops-dev.sh                # full: venv + node + docker compose (Docker required)
#   MODE=local ./scripts/sentinelops-dev.sh     # venv + node only
#   MODE=docker ./scripts/sentinelops-dev.sh   # only: docker compose up -d --build
#   SENTINELOPS_APT_INSTALL=1 ./scripts/sentinelops-dev.sh   # apt (sudo) when Python 3.11+ missing — only for the apt step, not the whole script
# WSL (Ubuntu, Kali, Debian, etc.): same script — from Linux: cd to repo, ./scripts/sentinelops-dev.sh  (or ./scripts/sentinelops-wsl.sh)
# Do NOT run the whole script with sudo; it breaks venv/node ownership. Use a normal user; PEP 668 distros (Kali/Debian) are handled.
set -euo pipefail

MODE="${MODE:-full}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${REPO_ROOT}/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/sentinelops-dev-$(date +%Y%m%d-%H%M%S).log"
log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"; }
logerr() { echo "[$(date -Iseconds)] ERROR: $*" | tee -a "$LOG_FILE" >&2; }
log "Repository: $REPO_ROOT MODE=$MODE log=$LOG_FILE"
if [[ "$(id -u)" -eq 0 ]]; then
  log "WARN: Running as root is not recommended (venv, npm, and files become root-owned). Use your normal WSL user; only use sudo when apt install prompts (SENTINELOPS_APT_INSTALL=1) or for docker if your group setup requires it."
fi

if [[ ! -f "$REPO_ROOT/.env" && -f "$REPO_ROOT/.env.example" ]]; then
  cp "$REPO_ROOT/.env.example" "$REPO_ROOT/.env"
  log "Created .env from .env.example"
fi

# 'docker compose' (v2) or legacy 'docker-compose' (v1)
docker_compose() {
  (cd "$REPO_ROOT" || exit 1
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose -f infra/docker/docker-compose.yml "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose -f infra/docker/docker-compose.yml "$@"
  else
    echo "ERROR: need 'docker compose' or 'docker-compose' on PATH" >&2
    return 127
  fi
  )
}

# True when every service in the compose file has a running container
compose_all_running() {
  (cd "$REPO_ROOT" || return 1
  local f="infra/docker/docker-compose.yml" exp r
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    exp=$(docker compose -f "$f" config --services 2>/dev/null | awk 'NF' | wc -l | tr -d ' \t')
    r=$(docker compose -f "$f" ps -q --status running 2>/dev/null | awk 'NF' | wc -l | tr -d ' \t')
    [[ -n "$exp" && "$exp" -ge 1 && -n "$r" && "$r" = "$exp" ]]
  elif command -v docker-compose >/dev/null 2>&1; then
    exp=$(docker-compose -f "$f" config --services 2>/dev/null | awk 'NF' | wc -l | tr -d ' \t')
    r=$(docker-compose -f "$f" ps 2>/dev/null | grep -cE '[[:space:]]Up([[:space:]]|\()' 2>/dev/null || true)
    r=${r:-0}
    [[ -n "$exp" && "$exp" -ge 1 && -n "$r" && "$r" -ge "$exp" ]]
  else
    return 1
  fi
  )
}

run_compose_or_skip() {
  if compose_all_running; then
    log "Docker / Docker Compose: stack is already up (all services running). Skipping: docker compose up -d --build"
    return 0
  fi
  log "docker compose up -d --build (starting or rebuilding stack)"
  docker_compose up -d --build
}

if [[ "$MODE" == "docker" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    logerr "Install Docker: https://docs.docker.com/engine/install/"
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    logerr "Docker engine is not running. Start the Docker service, then retry."
    exit 1
  fi
  run_compose_or_skip 2>&1 | tee -a "$LOG_FILE"
  dce="${PIPESTATUS[0]}"
  if [[ "$dce" -ne 0 ]]; then
    logerr "docker compose failed (exit $dce). See: $LOG_FILE"
    exit 1
  fi
  log "http://localhost:3000  |  http://localhost:8000/docs"
  exit 0
fi

# --- find Python 3.11+ ---
find_python() {
  local c out
  for c in python3.13 python3.12 python3.11 python3; do
    if command -v "$c" >/dev/null 2>&1; then
      if out=$("$c" -c "import sys; assert sys.version_info>=(3,11); print(sys.executable)" 2>/dev/null); then
        echo "$out"
        return 0
      fi
    fi
  done
  return 1
}

apt_install_python() {
  log "SENTINELOPS_APT_INSTALL=1: apt — python3-venv, python3-pip, and python 3.12+…"
  sudo apt-get update
  sudo apt-get install -y python3-venv python3-pip
  # Pin 3.12 if available; also pull 3.13-venv on modern Kali/Debian when default is 3.13
  sudo apt-get install -y python3.12-venv python3.12 python3.12-dev 2>/dev/null || true
  sudo apt-get install -y python3.13-venv 2>/dev/null || true
  sudo apt-get install -y --only-upgrade python3-venv python3-pip 2>/dev/null || true
  sudo apt-get install -y --only-upgrade python3.12 python3.12-venv 2>/dev/null || true
}

PYTHON_PATH="$(find_python 2>/dev/null || true)"
if [[ -z "$PYTHON_PATH" && "${SENTINELOPS_APT_INSTALL:-0}" == "1" ]] && command -v apt-get >/dev/null 2>&1; then
  apt_install_python
  PYTHON_PATH="$(find_python 2>/dev/null || true)"
fi
if [[ -z "$PYTHON_PATH" ]]; then
  logerr "Python 3.11+ required (only older python3 may be on PATH). Install 3.12+ or: SENTINELOPS_APT_INSTALL=1 $0 (apt, uses sudo)"
  exit 1
fi
log "Python: $($PYTHON_PATH -c 'import sys; print(sys.executable, sys.version)')"

# PEP 668: Debian, Kali, Ubuntu, etc. mark system Python as "externally managed" — do not pip install on it
is_externally_managed() {
  local py="$1"
  "$py" -c 'import sys, pathlib
v = "%d.%d" % (sys.version_info[0], sys.version_info[1])
for base in (sys.prefix, "/usr", "/usr/local"):
    p = pathlib.Path(base) / "lib" / ("python" + v) / "EXTERNALLY-MANAGED"
    if p.is_file():
        raise SystemExit(0)
raise SystemExit(1)
' 2>/dev/null
}

# Optional: upgrade pip on the *interpreter* only when PEP 668 does not block (no-op on venvs)
ensure_pip_on_interpreter() {
  local py="$1"
  if is_externally_managed "$py"; then
    log "PEP 668 (externally managed system Python): skipping system-level pip. Dependencies install only in backend/.venv and ml/.venv."
    return 0
  fi
  log "Upgrading pip on non-managed interpreter: $py"
  if ! "$py" -m pip --version >/dev/null 2>&1; then
    log "pip not on PATH for $py; ensurepip…"
    "$py" -m ensurepip --upgrade 2>&1 | tee -a "$LOG_FILE" || true
  fi
  if ! "$py" -m pip --version >/dev/null 2>&1; then
    log "pip still missing on $py (continuing; venv will use ensurepip)" "WARN"
    return 0
  fi
  "$py" -m pip install --upgrade pip setuptools wheel 2>&1 | tee -a "$LOG_FILE" || log "pip upgrade on base Python (non-fatal)" "WARN"
}
ensure_pip_on_interpreter "$PYTHON_PATH"

# Venvs are not subject to PEP 668; bootstrap pip *inside* each venv
ensure_venv_pip() {
  local vroot="$1"
  local p="$vroot/bin/python"
  [[ -x "$p" ]] || { logerr "Missing $p"; return 1; }
  if ! "$p" -m pip --version >/dev/null 2>&1; then
    log "Bootstrapping pip inside venv: $vroot (python -m ensurepip)"
    "$p" -m ensurepip --upgrade 2>&1 | tee -a "$LOG_FILE" || true
  fi
  if ! "$p" -m pip --version >/dev/null 2>&1; then
    logerr "venv at $vroot has no pip. Install: sudo apt install python3-venv   (Kali/Debian/Ubuntu) or dnf install python3-virtualenv (Fedora), then: rm -rf $vroot && re-run this script as a normal user (not sudo)."
    return 1
  fi
  return 0
}

# --- backend venv ---
BK="$REPO_ROOT/backend"
if [[ ! -x "$BK/.venv/bin/python" ]]; then
  log "Creating backend/.venv"
  (cd "$BK" && "$PYTHON_PATH" -m venv .venv)
fi
ensure_venv_pip "$BK/.venv" || exit 1
BN="$BK/.venv/bin/python"
"$BN" -m pip install --upgrade pip 2>&1 | tee -a "$LOG_FILE"
"$BN" -m pip install -r "$BK/requirements.txt" 2>&1 | tee -a "$LOG_FILE"

# --- ml venv ---
ML="$REPO_ROOT/ml"
MR="$ML/requirements.txt"
if [[ -f "$MR" ]]; then
  MN="$ML/.venv/bin/python"
  if [[ ! -x "$MN" ]]; then
    log "Creating ml/.venv"
    (cd "$ML" && "$PYTHON_PATH" -m venv .venv)
  fi
  ensure_venv_pip "$ML/.venv" || exit 1
  MN="$ML/.venv/bin/python"
  "$MN" -m pip install --upgrade pip 2>&1 | tee -a "$LOG_FILE"
  "$MN" -m pip install -r "$MR" 2>&1 | tee -a "$LOG_FILE" || log "ml pip: non-zero exit (check log)" "WARN"
fi

# --- Node 18+ ---
if ! command -v node >/dev/null 2>&1; then
  logerr "Install Node 18+ (https://github.com/nodesource/distributions#installation-instructions) or nvm"
  exit 1
fi
NVER="$(node -p "parseInt(process.versions.node, 10)" 2>/dev/null || echo 0)"
if [[ "$NVER" -lt 18 ]]; then
  logerr "Node 18+ required, got: $(node -v)"
  exit 1
fi
log "Node: $(node -v)"
cd "$REPO_ROOT/frontend"
if command -v pnpm >/dev/null 2>&1; then
  pnpm install 2>&1 | tee -a "$LOG_FILE"
  pnpm run typecheck 2>&1 | tee -a "$LOG_FILE"
  pnpm run lint 2>&1 | tee -a "$LOG_FILE"
else
  npm install 2>&1 | tee -a "$LOG_FILE"
  npm run typecheck 2>&1 | tee -a "$LOG_FILE"
  npm run lint 2>&1 | tee -a "$LOG_FILE"
fi
cd "$REPO_ROOT"

if [[ "$MODE" == "full" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    logerr "Full setup requires Docker (Postgres, Redis, API, stack). Start Docker, then re-run. Or: MODE=local for venv/node only."
    logerr "  https://docs.docker.com/engine/install/"
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    logerr "Docker engine is not running. Start the Docker service, then retry. Or: MODE=local"
    exit 1
  fi
  run_compose_or_skip 2>&1 | tee -a "$LOG_FILE"
  dce="${PIPESTATUS[0]}"
  if [[ "$dce" -ne 0 ]]; then
    logerr "docker compose failed (exit $dce). See: $LOG_FILE"
    exit 1
  fi
  log "UI http://localhost:3000  —  seed: docker compose -f infra/docker/docker-compose.yml exec backend python -m app.scripts.seed"
fi

log "Finished OK"
echo ""
if [[ "$MODE" == "full" ]]; then
  echo "Docker stack is up. Venv + dev without Docker: MODE=local ./scripts/sentinelops-dev.sh"
else
  echo "Run locally (two terminals):"
  echo "  backend:  cd $REPO_ROOT/backend && . .venv/bin/activate && uvicorn app.main:app --reload --host 127.0.0.1"
  echo "  frontend: cd $REPO_ROOT/frontend && pnpm dev"
fi
exit 0
