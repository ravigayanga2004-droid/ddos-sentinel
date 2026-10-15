"""Temporary loopback HTTP service with bounded body reading and clean shutdown."""

import asyncio
import contextlib
import hmac
import re
import socket
import time
from collections import deque
from collections.abc import Callable, Iterator
from typing import Any

import uvicorn
from fastapi import FastAPI
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ddos_sentinel.core.audit import audit
from ddos_sentinel.core.authorization import LabAuthorization, issue_authorization
from ddos_sentinel.core.config import LabConfig
from ddos_sentinel.core.database import Database
from ddos_sentinel.core.models import TrafficSample, new_id
from ddos_sentinel.core.safety import ENDPOINTS
from ddos_sentinel.lab.telemetry import Telemetry

Guard = Callable[[str, str, int], int | None]


class EmbeddedServer(uvicorn.Server):
    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        """The owning CLI/server handles signals; this child must not replace handlers."""
        yield


class ServiceMiddleware:
    def __init__(self, app: ASGIApp, lab: "TemporaryLab") -> None:
        self.app = app
        self.lab = lab
        self.connections: deque[tuple[Any, ...]] = deque(maxlen=4096)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = time.monotonic()
        headers = dict(scope.get("headers", []))
        auth = self.lab.authorization
        valid = auth is not None and hmac.compare_digest(
            headers.get(b"x-sentinel-lab", b""), auth.token.encode()
        )
        raw_client = headers.get(b"x-synthetic-client", b"").decode("ascii", errors="ignore")
        client = raw_client if valid and re.fullmatch(r"client-\d{1,3}", raw_client) else "local"
        raw_request = headers.get(b"x-sentinel-request", b"").decode("ascii", errors="ignore")
        request_id = (
            raw_request if valid and re.fullmatch(r"[0-9a-f]{32}-\d{1,5}", raw_request) else None
        )
        path = scope.get("path", "/")
        endpoint = path if path in ENDPOINTS else "/unknown"
        peer = tuple(scope.get("client") or ())
        new_connection = peer not in self.connections
        if new_connection:
            self.connections.append(peer)
        self.lab.telemetry.active += 1
        active = self.lab.telemetry.active
        status, size = 499, 0
        mitigated = False

        async def observed_send(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        async def reject(code: int, detail: str) -> None:
            await JSONResponse({"detail": detail}, status_code=code)(scope, receive, observed_send)

        try:
            if not valid and path != "/health":
                await reject(403, "application-owned lab capability required")
                return
            if path not in ENDPOINTS:
                await reject(404, "built-in endpoint required")
                return
            limit = self.lab.config.limits.max_request_body_bytes
            try:
                declared = int(headers.get(b"content-length", b"0"))
            except ValueError:
                await reject(400, "invalid content length")
                return
            if declared < 0 or declared > limit:
                await reject(413, "request exceeds body-size limit")
                return
            # Do not pass a retained request body to storage or logs.
            async with asyncio.timeout(2):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    size += len(chunk)
                    if size > limit:
                        await reject(413, "request exceeds body-size limit")
                        return
                    if not message.get("more_body", False):
                        break
            if self.lab.guard is not None and (code := self.lab.guard(client, path, size)):
                mitigated = True
                await reject(code, "temporary local mitigation")
                return

            async def empty_receive() -> Message:
                return {"type": "http.request", "body": b"", "more_body": False}

            await self.app(scope, empty_receive, observed_send)
        except TimeoutError:
            await reject(408, "bounded request read timeout")
        finally:
            self.lab.telemetry.active -= 1
            self.lab.telemetry.add(
                TrafficSample(
                    endpoint=endpoint,
                    status=status,
                    latency_ms=(time.monotonic() - started) * 1000,
                    client_id=client,
                    size=min(size, 65536),
                    active=active,
                    simulation_id=self.lab.simulation_id if valid else None,
                    new_connection=new_connection,
                    mitigation=mitigated,
                    request_id=request_id,
                )
            )


def create_test_service(config: LabConfig, telemetry: Telemetry) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/")
    async def index() -> dict[str, str]:
        return {"service": "DDoS Sentinel temporary lab"}

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "healthy",
            "active_requests": telemetry.active,
            "completed_requests": telemetry.completed,
            "rolling": telemetry.window().model_dump(),
        }

    @app.api_route("/api/test", methods=["GET", "POST"])
    async def test_endpoint() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/slow-test")
    async def slow() -> dict[str, bool]:
        await asyncio.sleep(config.artificial_latency_ms / 1000)
        return {"ok": True}

    @app.get("/error-test")
    async def error() -> JSONResponse:
        return JSONResponse({"detail": "controlled synthetic failure"}, status_code=503)

    return app


class TemporaryLab:
    def __init__(self, config: LabConfig, db: Database, guard: Guard | None = None) -> None:
        self.config, self.db, self.guard = config, db, guard
        self.id = new_id()
        self.telemetry = Telemetry()
        self.simulation_id: str | None = None
        self.authorization: LabAuthorization | None = None
        self.server: EmbeddedServer | None = None
        self.task: asyncio.Task[None] | None = None
        self.socket: socket.socket | None = None
        self.simulation_lock = asyncio.Lock()
        self.target = ""

    async def __aenter__(self) -> "TemporaryLab":
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.bind(("127.0.0.1", self.config.target.port))
            self.socket.listen(128)
            self.target = f"http://127.0.0.1:{self.socket.getsockname()[1]}"
            self.authorization = issue_authorization(self.target, self.id)
            application = ServiceMiddleware(create_test_service(self.config, self.telemetry), self)
            self.server = EmbeddedServer(
                uvicorn.Config(
                    application,
                    host="127.0.0.1",
                    log_level="error",
                    access_log=False,
                    lifespan="off",
                    timeout_keep_alive=2,
                    timeout_graceful_shutdown=1,
                    limit_concurrency=110,
                    h11_max_incomplete_event_size=8192,
                )
            )
            self.task = asyncio.create_task(self.server.serve(sockets=[self.socket]))

            def revoke_ownership(completed: asyncio.Task[None]) -> None:
                if self.authorization:
                    self.authorization.active = False

            self.task.add_done_callback(revoke_ownership)
            async with asyncio.timeout(5):
                while not self.server.started:
                    if self.task.done():
                        await self.task
                        raise RuntimeError("temporary service failed to start")
                    await asyncio.sleep(0.01)
            with self.db.connection() as connection:
                self.db.put(
                    "labs",
                    {
                        "id": self.id,
                        "name": self.config.lab_name,
                        "target": self.target,
                        "status": "RUNNING",
                        "configuration": self.config.model_dump(),
                    },
                    connection=connection,
                )
                self.db.put(
                    "targets",
                    {"id": self.id, "lab_id": self.id, "target": self.target},
                    connection=connection,
                )
            audit(self.db, "lab.started", lab_id=self.id, target=self.target)
            return self
        except BaseException:
            await self.close()
            raise

    async def close(self) -> None:
        if self.authorization:
            self.authorization.active = False
        if self.server:
            self.server.should_exit = True
        if self.task:
            try:
                await asyncio.wait_for(self.task, 3)
            except (TimeoutError, asyncio.CancelledError):
                self.task.cancel()
                await asyncio.gather(self.task, return_exceptions=True)
        if self.socket:
            self.socket.close()
        self.db.put(
            "labs",
            {
                "id": self.id,
                "name": self.config.lab_name,
                "target": self.target,
                "status": "STOPPED",
                "configuration": self.config.model_dump(),
                "end_time": time.time(),
            },
        )
        audit(self.db, "lab.stopped", lab_id=self.id)

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
