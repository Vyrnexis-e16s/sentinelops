#!/usr/bin/env bash
# Make a host-installed Ollama listen on 0.0.0.0:<port> so a Docker container
# (e.g. SentinelOps backend) can reach it via host.docker.internal.
#
# By default Ollama binds to 127.0.0.1:11434, which the container cannot reach
# even with `extra_hosts: host-gateway`. This drops a systemd override at
# /etc/systemd/system/ollama.service.d/override.conf that sets OLLAMA_HOST and
# restarts the service. Idempotent — re-running it is safe.
#
# Usage:
#   bash scripts/bind-ollama-host.sh            # bind to 0.0.0.0:11434
#   OLLAMA_BIND=192.168.1.10 bash scripts/bind-ollama-host.sh
#   OLLAMA_PORT=11500       bash scripts/bind-ollama-host.sh
#
# Requires: systemd (Linux/WSL2 distro running Ollama as a service) + sudo or root.
# Detects launchd (macOS) and prints the equivalent manual step instead.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
mkdir -p "${REPO_ROOT}/logs"
LOG="${REPO_ROOT}/logs/bind-ollama-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

OLLAMA_BIND="${OLLAMA_BIND:-0.0.0.0}"
OLLAMA_PORT="${OLLAMA_PORT:-11434}"
TARGET="${OLLAMA_BIND}:${OLLAMA_PORT}"

log() { echo "[bind-ollama] $*"; }

if [[ "$(uname -s)" == "Darwin" ]]; then
  log "macOS detected. Run instead:  launchctl setenv OLLAMA_HOST ${TARGET}"
  log "  then quit and relaunch the Ollama app, or: brew services restart ollama"
  exit 0
fi

if ! command -v systemctl >/dev/null 2>&1; then
  log "ERROR: systemctl not found. This script targets systemd-based Linux/WSL2."
  log "  Run Ollama manually with:  OLLAMA_HOST=${TARGET} ollama serve"
  exit 1
fi

have_unit=0
if systemctl cat ollama.service >/dev/null 2>&1; then
  have_unit=1
elif [[ -f /etc/systemd/system/ollama.service || -f /lib/systemd/system/ollama.service || -f /usr/lib/systemd/system/ollama.service ]]; then
  have_unit=1
fi
if [[ "${have_unit}" -ne 1 ]]; then
  log "ERROR: ollama.service was not found under systemd."
  log "  Install Ollama from https://ollama.com (the install.sh script registers a service)."
  log "  Or run manually:  OLLAMA_HOST=${TARGET} ollama serve"
  exit 1
fi

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
  if ! command -v sudo >/dev/null 2>&1; then
    log "ERROR: not running as root and sudo is unavailable."
    exit 1
  fi
  SUDO="sudo"
fi

OVERRIDE_DIR="/etc/systemd/system/ollama.service.d"
OVERRIDE_FILE="${OVERRIDE_DIR}/override.conf"

log "Writing systemd override → ${OVERRIDE_FILE}  (OLLAMA_HOST=${TARGET})"
$SUDO mkdir -p "${OVERRIDE_DIR}"
$SUDO tee "${OVERRIDE_FILE}" >/dev/null <<EOF
[Service]
Environment="OLLAMA_HOST=${TARGET}"
EOF

log "Reloading systemd and restarting ollama…"
$SUDO systemctl daemon-reload
$SUDO systemctl restart ollama

# Give the daemon a moment to rebind.
for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 1
  if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "(^|:)${OLLAMA_PORT}\$"; then
    break
  fi
done

LISTEN_LINE="$(ss -ltn 2>/dev/null | awk -v p=":${OLLAMA_PORT}" '$4 ~ p {print $4; exit}')"
if [[ -z "${LISTEN_LINE}" ]]; then
  log "WARN: nothing listening on port ${OLLAMA_PORT} yet. Check:  systemctl status ollama"
  exit 1
fi
log "Listening on: ${LISTEN_LINE}"

if curl -fsS -m 5 "http://127.0.0.1:${OLLAMA_PORT}/api/tags" >/dev/null 2>&1; then
  log "API OK at http://127.0.0.1:${OLLAMA_PORT}/api/tags"
else
  log "WARN: API probe failed at http://127.0.0.1:${OLLAMA_PORT}/api/tags"
fi

if [[ "${OLLAMA_BIND}" != "127.0.0.1" ]]; then
  log "Containers on the same host can now reach Ollama via:"
  log "  http://host.docker.internal:${OLLAMA_PORT}/v1   (with extra_hosts: host-gateway on Linux)"
  log "  http://172.17.0.1:${OLLAMA_PORT}/v1            (default Docker bridge gateway)"
fi

log "Log file: ${LOG}"
log "Done."
