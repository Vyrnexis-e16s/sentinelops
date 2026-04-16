"""Redis pub/sub fan-out for real-time UI updates."""
from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import redis.asyncio as aioredis

from app.core.logging import get_logger
from app.core.redis import get_redis

log = get_logger(__name__)


CHANNEL_AUDIT = "audit.events"
CHANNEL_ALERTS = "siem.alerts"
CHANNEL_RECON = "recon.findings"
CHANNEL_IDS = "ids.inferences"


async def publish(channel: str, payload: dict[str, Any]) -> int:
    """Publish a JSON payload on a Redis channel. Returns subscriber count."""
    client = await _client()
    msg = json.dumps(payload, default=str).encode("utf-8")
    n = await client.publish(channel, msg)
    log.debug("event_published", channel=channel, subscribers=n)
    return int(n)


async def subscribe(channel: str) -> AsyncIterator[dict[str, Any]]:
    """Subscribe to a channel and yield decoded JSON messages."""
    client = await _client()
    pubsub = client.pubsub()
    await pubsub.subscribe(channel)
    try:
        async for msg in pubsub.listen():
            if msg.get("type") != "message":
                continue
            data = msg.get("data")
            if isinstance(data, bytes):
                try:
                    yield json.loads(data.decode("utf-8"))
                except json.JSONDecodeError:
                    log.warning("event_decode_failed", channel=channel)
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()


async def _client() -> aioredis.Redis:
    async for c in get_redis():
        return c
    raise RuntimeError("Redis unavailable")
