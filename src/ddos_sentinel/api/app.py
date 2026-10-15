"""FastAPI lifespan owns the lab; browser controls use strict Host/Origin and CSRF checks."""

import hmac
import re
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ddos_sentinel.api.routes import router
from ddos_sentinel.core.config import LabConfig
from ddos_sentinel.core.database import Database
from ddos_sentinel.lab.runtime import Runtime


class BrowserBoundary:
    def __init__(self, app: ASGIApp, token: str) -> None:
        self.app, self.token = app, token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        host = request.headers.get("host", "")
        peer = request.client.host if request.client else ""
        origin = request.headers.get("origin")
        valid_origin = not origin or origin in {f"http://{host}", f"http://{host}/"}
        detail = None
        if not re.fullmatch(r"(?:127\.0\.0\.1|localhost)(?::\d{1,5})?", host) or peer not in {
            "127.0.0.1",
            "::1",
        }:
            detail = "loopback Host and client required"
        elif not valid_origin:
            detail = "cross-origin requests are forbidden"
        elif scope["method"] not in {"GET", "HEAD", "OPTIONS"}:
            supplied = request.headers.get("x-csrf-token", "")
            cookie = request.cookies.get("sentinel_csrf", "")
            if not (
                hmac.compare_digest(supplied.encode(), self.token.encode())
                and hmac.compare_digest(cookie.encode(), self.token.encode())
            ):
                detail = "valid same-origin CSRF token and cookie required"
            content_length = request.headers.get("content-length", "0")
            if not content_length.isdigit() or int(content_length) > 8192:
                detail = "control request exceeds 8 KiB"
        if detail:
            await JSONResponse({"detail": detail}, status_code=403)(scope, receive, send)
            return

        async def secured_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"cache-control", b"no-store"),
                        (
                            b"content-security-policy",
                            b"default-src 'self'; script-src 'self'; "
                            b"style-src 'self'; img-src 'self' data:; connect-src 'self'; "
                            b"frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                        ),
                    ]
                )
                message["headers"] = headers
            await send(message)

        # Bound streamed/chunked JSON as well as declared Content-Length.
        total = 0

        async def bounded_receive() -> Message:
            nonlocal total
            message = await receive()
            total += len(message.get("body", b""))
            if total > 8192:
                raise ValueError("control request exceeds 8 KiB")
            return message

        await self.app(scope, bounded_receive, secured_send)


def create_app(config: LabConfig | None = None, db: Database | None = None) -> FastAPI:
    config = config or LabConfig()
    db = db or Database(Path(".sentinel/sentinel.db"))
    runtime = Runtime(config, db)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        async with runtime:
            yield

    app = FastAPI(
        title="DDoS Sentinel", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None
    )
    app.state.runtime = runtime
    app.state.csrf = secrets.token_urlsafe(32)
    app.state.simulation_task = None
    app.state.last_error = None
    app.add_middleware(BrowserBoundary, token=app.state.csrf)
    app.mount(
        "/static",
        StaticFiles(directory=Path(__file__).parents[1] / "web" / "static"),
        name="static",
    )
    app.include_router(router)

    @app.exception_handler(ValueError)
    async def invalid_value(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=400)

    @app.exception_handler(RequestValidationError)
    async def invalid_payload(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [{key: item[key] for key in ("loc", "msg", "type")} for item in exc.errors()]
        return JSONResponse({"detail": errors}, status_code=422)

    return app
