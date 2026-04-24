#!/usr/bin/env bash
# SentinelOps — venvs, Node, typecheck, then Docker Compose (required in MODE=full for DB, Redis, API, UI).
# Usage:
#   chmod +x scripts/sentinelops-dev.sh
#   ./scripts/sentinelops-dev.sh                # full: venv + node + docker compose (Docker required)
#   MODE=local ./scripts/sentinelops-dev.sh     # venv + node only
#   MODE=docker ./scripts/sentinelops-dev.sh   # only: docker compose up -d --build
#   SENTINELOPS_APT_INSTALL=1 ./scripts/sentinelops-dev.sh   # sudo: install/upgrade python3.12+ when missing or <3.11
set -euo pipefail

MODE="${MODE:-full}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${REPO_ROOT}/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/sentinelops-dev-$(date +%Y%m%d-%H%M%S).log"
log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"; }
logerr() { echo "[$(date -Iseconds)] ERROR: $*" | tee -a "$LOG_FILE" >&2; }
log "Repository: $REPO_ROOT MODE=$MODE log=$LOG_FILE"

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
  log "SENTINELOPS_APT_INSTALL=1: apt install/upgrade python3.12, venv, pip…"
  sudo apt-get update
  sudo apt-get install -y python3.12-venv python3.12 python3.12-dev python3-pip
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

ensure_pip() {
  local py="$1"
  log "Checking pip (ensurepip + upgrade) for: $py"
  if ! "$py" -m pip --version >/dev/null 2>&1; then
    log "pip not found; running ensurepip…"
    "$py" -m ensurepip --upgrade 2>&1 | tee -a "$LOG_FILE" || true
  fi
  if ! "$py" -m pip --version >/dev/null 2>&1; then
    logerr "pip is still unavailable for $py. On Debian/Ubuntu: sudo apt install python3-pip python3-venv"
    exit 1
  fi
  "$py" -m pip install --upgrade pip setuptools wheel 2>&1 | tee -a "$LOG_FILE" || log "pip upgrade on base Python (non-fatal, venv will retry)" "WARN"
}
ensure_pip "$PYTHON_PATH"

# --- backend venv ---
BK="$REPO_ROOT/backend"
BN="$BK/.venv/bin/python"
if [[ ! -x "$BN" ]]; then
  log "Creating backend/.venv"
  (cd "$BK" && "$PYTHON_PATH" -m venv .venv)
fi
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
