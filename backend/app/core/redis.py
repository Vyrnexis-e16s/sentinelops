"""Async Redis client factory and FastAPI dependency."""
from __future__ import annotations

from collections.abc import AsyncIterator

import redis.asyncio as aioredis

from app.core.config import settings

_client: aioredis.Redis | None = None


async def init_redis() -> aioredis.Redis:
    global _client
    if _client is None:
        _client = aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=False,
            health_check_interval=30,
        )
    return _client


async def close_redis() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


def set_redis_for_tests(client: aioredis.Redis) -> None:
    """Tests inject a fakeredis instance here."""
    global _client
    _client = client


async def get_redis() -> AsyncIterator[aioredis.Redis]:
    client = await init_redis()
    yield client
