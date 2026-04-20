"""Pytest fixtures: in-memory SQLite + httpx ASGI client."""
from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

# Force test env BEFORE any app import.
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-test-secret-key-test-secret-key-yo")
os.environ.setdefault("VAULT_MASTER_KEY", "0" * 64)
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("CELERY_BROKER_URL", "memory://")
os.environ.setdefault("CELERY_RESULT_BACKEND", "cache+memory://")


@pytest_asyncio.fixture
async def app() -> AsyncIterator:
    from app.core.config import get_settings
    from app.core.db import dispose_engine, init_db, reset_engine_for_tests
    from app.main import create_app

    get_settings.cache_clear()
    reset_engine_for_tests("sqlite+aiosqlite:///:memory:")
    await init_db()

    application = create_app()
    yield application
    await dispose_engine()


@pytest_asyncio.fixture
async def client(app):
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c
