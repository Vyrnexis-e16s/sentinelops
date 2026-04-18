"""Port-scan smoke tests against a localhost listener."""
from __future__ import annotations

import asyncio

import pytest

from app.modules.recon.services import portscan


@pytest.mark.asyncio
async def test_open_port_detected(unused_tcp_port: int) -> None:
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", unused_tcp_port)
    try:
        async with server:
            results = await portscan.scan("127.0.0.1", [unused_tcp_port], timeout=1.0)
            assert any(r["port"] == unused_tcp_port and r["state"] == "open" for r in results)
    finally:
        server.close()


@pytest.mark.asyncio
async def test_closed_port_reported() -> None:
    # 1 is virtually never open; if the test env has tcpmux running this will be flaky.
    results = await portscan.scan("127.0.0.1", [1], timeout=0.2)
    assert results[0]["state"] in ("closed", "filtered")
