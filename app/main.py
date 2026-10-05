"""FastAPI application entry point.

About sync vs async: the route handlers here are plain `def`, not `async def`.
Argon2id is deliberately slow and CPU-heavy (around 100 ms per hash). Inside
an `async def` handler it would block the event loop and stall every other request.
FastAPI runs plain `def` handlers in a thread pool, which avoids that problem, and it
lets us use the simpler synchronous psycopg and Redis clients.
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from psycopg_pool import PoolTimeout
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.cache import create_redis
from app.config import Settings, get_settings
from app.db import create_pool
from app.routes import auth
from app.security import passwords
from app.security.sessions import SessionStore

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    app.state.db_pool = create_pool(settings.database_url.get_secret_value())
    app.state.redis = create_redis(settings.redis_url.get_secret_value())
    app.state.sessions = SessionStore(
        app.state.redis,
        idle_timeout_seconds=settings.session_idle_timeout_seconds,
        absolute_timeout_seconds=settings.session_absolute_timeout_seconds,
    )
    try:
        yield
    finally:
        app.state.db_pool.close()
        app.state.redis.close()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    # Interactive API docs are handy while developing, but in production they give
    # attackers a free map of every endpoint, so they're turned off there.
    docs_enabled = not settings.is_production

    app = FastAPI(
        title="SWE Auth",
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    app.state.settings = settings

    passwords.configure_hashing_limits(
        settings.password_hash_max_concurrency, settings.password_hash_queue_timeout_seconds
    )
    passwords.warm_up()

    app.add_middleware(SecurityHeadersMiddleware)
    _install_error_handlers(app)
    app.include_router(auth.router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        """Liveness: is the process up? Deliberately touches no dependencies.

        `async def` so it runs on the event loop and never waits for a worker thread:
        if the thread pool is saturated, liveness must still answer.
        """
        return {"status": "ok"}

    @app.get("/ready")
    def ready(request: Request, response: Response) -> dict[str, str]:
        """Readiness: can we reach Postgres and Redis?

        On failure, the response only says "unavailable". The real error goes to the
        server log. Sending exception text to clients can leak hostnames, usernames,
        or library versions.
        """
        try:
            with request.app.state.db_pool.connection() as conn:
                conn.execute("SELECT 1")
            request.app.state.redis.ping()
        except Exception:
            logger.exception("Readiness check failed")
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return {"status": "unavailable"}
        return {"status": "ready"}

    return app


SECURITY_HEADERS = {
    # Auth responses contain personal data and Set-Cookie headers. Browsers, proxies,
    # and CDNs must never cache them (think: shared computer, back button).
    "Cache-Control": "no-store",
    # Don't let browsers guess ("sniff") a different content type than we declared.
    "X-Content-Type-Options": "nosniff",
    # Never leak our URLs to other sites through the Referer header.
    "Referrer-Policy": "no-referrer",
    # Our pages must not be framed by other sites (clickjacking).
    "X-Frame-Options": "DENY",
}


class SecurityHeadersMiddleware:
    """Adds SECURITY_HEADERS to every response, including unexpected 500 errors.

    A plain ASGI middleware instead of @app.middleware("http"). Starlette builds its
    default 500 response in an outer layer that runs AFTER user middleware has given up,
    so that response had no security headers (found by the security review). Here we
    catch unhandled exceptions ourselves and send a generic 500 through the same
    header-adding path. The full traceback goes to the server log, never to the client.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def send_with_headers(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers[name] = value
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        except Exception:
            logger.exception("Unhandled error while serving %s", scope.get("path"))
            if response_started:
                raise  # too late to send a clean response; let the server close it
            fallback = JSONResponse(
                {"detail": "Internal server error."},
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
            await fallback(scope, receive, send_with_headers)


def _install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        """422 responses WITHOUT echoing the submitted values.

        FastAPI's default 422 body includes an "input" field containing what the client
        sent. For a login request that's the PASSWORD, which would then sit in browser
        devtools, proxy logs, and error trackers. We keep only where and why it failed.
        """
        errors = [
            {
                "loc": list(err.get("loc", ())),
                "msg": err.get("msg", ""),
                "type": err.get("type", ""),
            }
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, content={"detail": errors}
        )

    @app.exception_handler(PoolTimeout)
    async def db_pool_exhausted(request: Request, exc: PoolTimeout) -> JSONResponse:
        # All DB connections busy for POOL_TIMEOUT_SECONDS: fail fast and tell clients to
        # back off, instead of letting requests pile up.
        logger.warning("Database pool exhausted; returning 503")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "The service is busy. Please try again shortly."},
            headers={"Retry-After": "1"},
        )

    @app.exception_handler(passwords.PasswordHashingBusyError)
    async def hashing_busy(
        request: Request, exc: passwords.PasswordHashingBusyError
    ) -> JSONResponse:
        # 503 + Retry-After tells well-behaved clients to back off briefly.
        logger.warning("Password hashing capacity exhausted; returning 503")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "The service is busy. Please try again shortly."},
            headers={"Retry-After": "1"},
        )


app = create_app()
