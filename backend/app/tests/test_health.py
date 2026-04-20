"""Smoke tests."""
import pytest


@pytest.mark.asyncio
async def test_health(client) -> None:
    r = await client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["env"] == "test"


@pytest.mark.asyncio
async def test_root_redirect(client) -> None:
    r = await client.get("/", follow_redirects=False)
    assert r.status_code in (307, 308)
    assert r.headers["location"].endswith("/docs")


@pytest.mark.asyncio
async def test_openapi(client) -> None:
    r = await client.get("/openapi.json")
    assert r.status_code == 200
    spec = r.json()
    paths = spec["paths"]
    assert "/api/v1/siem/events" in paths or any(p.startswith("/api/v1/siem") for p in paths)
    assert any(p.startswith("/api/v1/recon") for p in paths)
    assert any(p.startswith("/api/v1/ids") for p in paths)
    assert any(p.startswith("/api/v1/vault") for p in paths)
    assert any(p.startswith("/api/v1/auth") for p in paths)
