"""Asyncio TCP connect scanner with banner grabbing."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Iterable

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)


# Broad “lab” set: web, remote admin, mail, file shares, and common database/cache ports.
# When the API receives no explicit port list, this tuple is used (see ``scan_host``).
DEFAULT_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 631,
    993, 995, 1110, 1433, 1434, 1521, 1522, 2049, 2375, 2376, 3050, 3306, 3307, 3389,
    5000, 5432, 5433, 5500, 5601, 5900, 5984, 5985, 5986, 6000, 6379, 7000, 7001,
    8000, 8008, 8080, 8123, 8443, 8888, 9000, 9042, 9090, 9200, 9300, 11211, 27017,
    27018, 27019, 50000,
)


@dataclass(slots=True)
class PortResult:
    port: int
    state: str  # open|closed|filtered
    banner: str | None


async def _scan_port(host: str, port: int, timeout: float) -> PortResult:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except asyncio.TimeoutError:
        return PortResult(port=port, state="filtered", banner=None)
    except (ConnectionRefusedError, OSError):
        return PortResult(port=port, state="closed", banner=None)

    banner: str | None = None
    try:
        data = await asyncio.wait_for(reader.read(128), timeout=min(timeout, 1.0))
        if data:
            banner = data.decode("utf-8", errors="replace").strip() or None
    except asyncio.TimeoutError:
        banner = None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
    return PortResult(port=port, state="open", banner=banner)


async def scan_host(
    host: str,
    ports: Iterable[int] | None = None,
    *,
    concurrency: int | None = None,
    timeout: float | None = None,
) -> list[PortResult]:
    ports_list = list(ports) if ports else list(DEFAULT_PORTS)
    sem = asyncio.Semaphore(concurrency or settings.recon_max_concurrency)
    t = timeout or float(settings.recon_timeout_seconds)

    async def bounded(p: int) -> PortResult:
        async with sem:
            return await _scan_port(host, p, t)

    results = await asyncio.gather(*(bounded(p) for p in ports_list))
    open_ports = [r for r in results if r.state == "open"]
    log.info("portscan.done", host=host, tested=len(ports_list), open=len(open_ports))
    return results
