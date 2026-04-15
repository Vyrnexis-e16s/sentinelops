"""Async SQLAlchemy engine, session factory, and FastAPI dependency."""
from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _build_engine(url: str | None = None) -> AsyncEngine:
    url = url or settings.database_url
    # SQLite async (used in tests) does not support some pool options.
    engine_kwargs: dict[str, Any] = {"echo": False, "future": True}
    if url.startswith("sqlite"):
        engine_kwargs["connect_args"] = {"check_same_thread": False}
    else:
        engine_kwargs["pool_pre_ping"] = True
        engine_kwargs["pool_size"] = 10
        engine_kwargs["max_overflow"] = 20
    return create_async_engine(url, **engine_kwargs)


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = _build_engine()
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            autoflush=False,
            class_=AsyncSession,
        )
    return _session_factory


def reset_engine_for_tests(url: str) -> None:
    """Used by the test harness to swap in a sqlite-in-memory engine."""
    global _engine, _session_factory
    _engine = _build_engine(url)
    _session_factory = async_sessionmaker(
        bind=_engine, expire_on_commit=False, autoflush=False, class_=AsyncSession
    )


async def dispose_engine() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding an ``AsyncSession`` scoped to the request."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Best-effort schema bootstrap.

    In production we drive this via Alembic; in dev we want ``docker compose up``
    to just work, so we ``create_all`` against the metadata as a fallback. If the
    DB is unreachable we log and continue — the readiness probe will report
    degraded.
    """
    import structlog

    log = structlog.get_logger(__name__)
    try:
        from app import models  # noqa: F401  triggers import side effects

        engine = get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(models.Base.metadata.create_all)
        log.info("db_schema_ready")
    except Exception as exc:  # pragma: no cover
        log.warning("db_init_failed", error=str(exc))
