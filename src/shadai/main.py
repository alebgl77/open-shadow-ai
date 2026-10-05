"""FastAPI application entry point for ShadAI."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import JSONResponse, Response

from shadai import __version__
from shadai.api.agent import router as agent_router
from shadai.api.audit import router as audit_router
from shadai.api.auth import router as auth_router
from shadai.api.auth import users_router as users_admin_router
from shadai.api.catalog import router as catalog_router
from shadai.api.dashboard import router as dashboard_router
from shadai.api.detections import router as detections_router
from shadai.api.exports import router as exports_router
from shadai.api.governance import router as governance_router
from shadai.api.ingestion import router as ingestion_router
from shadai.api.network import router as network_router
from shadai.api.scim import router as scim_router
from shadai.api.sso import router as sso_router
from shadai.config import get_config, validate_security
from shadai.database import close_all, init_clickhouse, init_postgres, init_redis
from shadai.security.crypto import init_crypto
from shadai.security.scim import SCIMError
from shadai.utils.logging import setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    config = get_config()
    setup_logging(config.server.log_level)
    validate_security(config)
    try:
        await init_postgres(config.database)
        init_clickhouse(config.database)
        await init_redis(config.database)
        init_crypto(config.security.encryption_key)
        from shadai.database import get_postgres_session
        from shadai.engine.catalog_loader import sync_catalog

        async for session in get_postgres_session():
            await sync_catalog(session, config.catalog)
        yield
    finally:
        await close_all()


app = FastAPI(
    title="Open Shadow AI",
    version=__version__,
    description="Shadow AI Discovery, Correlation & Governance Platform",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# ── Middleware ────────────────────────────────────────────────────
config = get_config()
cors_origins = config.server.cors_origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    expose_headers=["X-Total-Count"],
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# ── API Routers ──────────────────────────────────────────────────

app.include_router(auth_router)
app.include_router(users_admin_router)
app.include_router(dashboard_router)
app.include_router(detections_router)
app.include_router(catalog_router)
app.include_router(governance_router)
app.include_router(exports_router)
app.include_router(audit_router)
app.include_router(agent_router)
app.include_router(ingestion_router)
app.include_router(network_router)
app.include_router(scim_router)
app.include_router(sso_router)


# ── Health + Metrics ─────────────────────────────────────────────
@app.get("/health")
@app.get("/api/v1/health")
async def health_check():
    return {"status": "ok", "version": __version__}


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/ready")
@app.get("/api/v1/ready")
async def readiness():
    from sqlalchemy import text
    from starlette.responses import JSONResponse

    from shadai.database import get_clickhouse, get_postgres_session, get_redis

    checks = {}
    try:
        async for session in get_postgres_session():
            await asyncio.wait_for(session.execute(text("SELECT event_id FROM ingest_receipts LIMIT 0")), timeout=5)
            await asyncio.wait_for(
                session.execute(text("SELECT session_version, username_key FROM users LIMIT 0")), timeout=5
            )
        checks["postgres"] = True
    except Exception:
        checks["postgres"] = False
    try:
        redis = await get_redis()
        checks["redis"] = bool(await asyncio.wait_for(redis.ping(), timeout=5))
    except Exception:
        checks["redis"] = False
    try:
        await asyncio.wait_for(
            asyncio.to_thread(
                get_clickhouse().execute, "SELECT event_id, evidence_type, identity_sid FROM events LIMIT 0"
            ),
            timeout=5,
        )
        checks["clickhouse"] = True
    except Exception:
        checks["clickhouse"] = False
    ready = all(checks.values())
    return JSONResponse(
        {"status": "ready" if ready else "unavailable", "checks": checks}, status_code=200 if ready else 503
    )


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    # Pydantic input/context can contain credentials: never echo the submitted input.
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {"loc": list(error["loc"]), "type": error["type"], "msg": error["msg"]} for error in exc.errors()
            ]
        },
    )


@app.exception_handler(SCIMError)
async def scim_error(request, exc):
    from shadai.api.scim import response

    return response(exc.body(), exc.status, {"WWW-Authenticate": "Bearer"} if exc.status == 401 else {})


class BodyLimitMiddleware:
    def __init__(self, app, max_bytes=2 * 1024 * 1024):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            size += len(body)
            if size > self.max_bytes:
                if scope.get("path", "").startswith("/api/v1/scim/v2"):
                    from shadai.api.scim import response

                    return await response(SCIMError(413, "Request too large", None).body(), 413)(scope, receive, send)
                return await JSONResponse({"detail": "Request too large"}, status_code=413)(scope, receive, send)
            chunks.append(body)
            if not message.get("more_body", False):
                break
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


app.add_middleware(BodyLimitMiddleware)
