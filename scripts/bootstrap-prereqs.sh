#!/usr/bin/env bash
# Optional prerequisite bootstrap (Linux apt only) for SENTINELOPS_AUTO_INSTALL=1.
# Paths are from PATH; never hardcode user directories.
#   bash scripts/bootstrap-prereqs.sh --check
#   SENTINELOPS_AUTO_INSTALL=1 bash scripts/bootstrap-prereqs.sh
set -euo pipefail

is_apt() { command -v apt-get >/dev/null 2>&1; }

node_major() {
  if command -v node >/dev/null 2>&1; then
    node -p "parseInt(process.versions.node,10)" 2>/dev/null || echo 0
  else
    echo 0
  fi
}

have_python_311() {
  local c
  for c in python3.13 python3.12 python3.11 python3; do
    command -v "$c" >/dev/null 2>&1 || continue
    if "$c" -c "import sys; assert sys.version_info>=(3,11)" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

have_docker_engine() {
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

log() { echo "[bootstrap] $*"; }
logerr() { echo "[bootstrap] ERROR: $*" >&2; }

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

# --- report only ---
report() {
  if have_python_311; then
    for c in python3.13 python3.12 python3.11 python3; do
      command -v "$c" >/dev/null 2>&1 || continue
      if "$c" -c "import sys; assert sys.version_info>=(3,11)" 2>/dev/null; then
        log "Python 3.11+: OK ($c)"
        break
      fi
    done
  else
    log "Python 3.11+: MISSING"
  fi
  local nj; nj="$(node_major)"
  if [[ "${nj}" -ge 20 ]]; then
    log "Node 20+: OK ($(node -v 2>/dev/null))"
  else
    log "Node 20+: MISSING (node major=${nj})"
  fi
  if have_docker_engine; then
    log "Docker: OK"
  else
    log "Docker: MISSING or engine not running"
  fi
}

if ! is_apt; then
  if [[ "$CHECK" -eq 1 ]]; then
    log "Non-apt OS: no apt auto-install. Install Python 3.11+, Node 20+, Docker with your package manager."
    report
    exit 0
  fi
  if [[ "${SENTINELOPS_AUTO_INSTALL:-0}" == "1" ]]; then
    logerr "AUTO_INSTALL is only implemented for apt (Debian/Ubuntu/Kali). Install deps manually."
    exit 1
  fi
  exit 0
fi

# apt-based
if [[ "$CHECK" -eq 1 ]]; then
  report
  exit 0
fi

if [[ "${SENTINELOPS_AUTO_INSTALL:-0}" != "1" ]]; then
  exit 0
fi

log "SENTINELOPS_AUTO_INSTALL=1 — using apt+sudo to fill gaps…"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y

if ! have_python_311; then
  log "Installing Python 3.12+ and venv…"
  sudo apt-get install -y python3-venv python3-pip
  sudo apt-get install -y python3.12-venv python3.12 python3.12-dev 2>/dev/null || true
  sudo apt-get install -y python3.13-venv 2>/dev/null || true
fi

if [[ "$(node_major)" -lt 20 ]]; then
  log "Installing Node.js 20.x (NodeSource)…"
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi

if ! have_docker_engine; then
  log "Installing docker.io and docker-compose-plugin…"
  sudo apt-get install -y docker.io docker-compose-plugin
  sudo usermod -aG docker "$USER" 2>/dev/null || true
  sudo systemctl enable --now docker 2>/dev/null || true
  if have_docker_engine; then
    log "Docker: OK"
  else
    log "Docker: install may need a new login (docker group) or: sudo systemctl start docker"
  fi
fi

log "Done."
exit 0
