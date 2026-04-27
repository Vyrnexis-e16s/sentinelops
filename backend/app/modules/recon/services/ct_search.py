"""Certificate Transparency log search via crt.sh (public JSON API — no key required)."""
from __future__ import annotations

import ipaddress
from typing import Any

import httpx

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

CRT_SH_JSON = "https://crt.sh/json"


def _query_param_for_target(target: str) -> str:
    """Build crt.sh `q` — domain uses wildcard suffix; IP uses as-is."""
    t = target.strip()
    try:
        ipaddress.ip_address(t.split("%")[0])
        return t
    except ValueError:
        pass
    # Broad search: any cert name under this domain
    if not t.startswith("%."):
        return f"%.{t}"
    return t


async def fetch_crt_sh_entries(
    target: str,
    *,
    timeout: float | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """Return raw CRT entries and an error string if the HTTP layer failed."""
    q = _query_param_for_target(target)
    to = timeout or max(30.0, float(settings.recon_timeout_seconds) * 2)
    async with httpx.AsyncClient(timeout=to, headers={"User-Agent": "SentinelOps-Recon/1.0"}) as client:
        try:
            r = await client.get(CRT_SH_JSON, params={"q": q})
            r.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("crt.sh.http", target=target, error=str(exc))
            return [], str(exc)
    try:
        data = r.json()
    except Exception as exc:  # noqa: BLE001
        return [], f"Invalid JSON from crt.sh: {exc}"
    if not isinstance(data, list):
        return [], "Unexpected crt.sh response shape"
    return data, None
