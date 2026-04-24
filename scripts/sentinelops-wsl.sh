#!/usr/bin/env bash
# WSL, native Linux, cloud VMs — same as sentinelops-dev.sh. Use a normal user (not sudo) so venv/Node are owned correctly.
# Example (any distro):  cd /path/to/sentinelops  &&  ./scripts/sentinelops-wsl.sh
# From Windows drive in WSL:  cd /mnt/c/Users/.../sentinelops  &&  ./scripts/sentinelops-wsl.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$here/sentinelops-dev.sh" "$@"
