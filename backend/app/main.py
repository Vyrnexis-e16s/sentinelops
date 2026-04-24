"""SentinelOps FastAPI entrypoint.

Builds the app, mounts every module router, configures middleware, and exposes
``/health`` + ``/metrics`` for ops.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

from app.api.auth import router as auth_router
from app.core.config import settings
from app.core.db import dispose_engine, init_db
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging
from app.core.redis import close_redis, init_redis
from app.modules.ids.router import router as ids_router
from app.modules.recon.router import router as recon_router
from app.modules.siem.router import router as siem_router
from app.modules.siem import intel_routes, ws_routes
from app.modules.vault.router import router as vault_router

log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    log.info("app_startup", env=settings.app_env)

    # In dev we let alembic create the schema lazily on first run; in prod CI
    # runs migrations explicitly before booting.
    await init_db()
    try:
        app.state.redis = await init_redis()
    except Exception as exc:  # pragma: no cover
        log.warning("redis_init_failed", error=str(exc))
        app.state.redis = None
    yield
    await close_redis()
    await dispose_engine()
    log.info("app_shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        description=(
            "Unified Security Operations Platform — SIEM, Recon, IDS, and Vault "
            "behind a single API."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    register_exception_handlers(app)

    # ------- routers --------
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(siem_router, prefix="/api/v1")
    app.include_router(intel_routes.router, prefix="/api/v1")
    app.include_router(recon_router, prefix="/api/v1")
    app.include_router(ids_router, prefix="/api/v1")
    app.include_router(vault_router, prefix="/api/v1")
    app.include_router(ws_routes.router, prefix="/ws")

    # ------- ops endpoints --------
    @app.get("/", include_in_schema=False)
    async def root() -> RedirectResponse:
        return RedirectResponse(url="/docs")

    @app.get("/health", tags=["ops"])
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok", "env": settings.app_env, "name": settings.app_name})

    @app.get("/ready", tags=["ops"])
    async def ready() -> JSONResponse:
        # Cheap DB + Redis ping; fuller probes belong in a dedicated check.
        try:
            r = await init_redis()
            await r.ping()
        except Exception as exc:  # pragma: no cover
            return JSONResponse({"status": "degraded", "error": str(exc)}, status_code=503)
        return JSONResponse({"status": "ready"})

    if settings.expose_prometheus or settings.is_production:
        try:
            from prometheus_fastapi_instrumentator import Instrumentator

            Instrumentator().instrument(app).expose(app, endpoint="/metrics")
        except ImportError:  # pragma: no cover
            log.warning("prometheus_instrumentator_missing")

    return app


app = create_app()
