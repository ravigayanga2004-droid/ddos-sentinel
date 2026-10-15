"""Expiring local middleware controls; no firewall changes or shell execution."""

import re
import time
from collections import defaultdict, deque
from typing import Literal

from pydantic import Field, model_validator

from ddos_sentinel.core.audit import audit
from ddos_sentinel.core.config import StrictModel
from ddos_sentinel.core.database import Database
from ddos_sentinel.core.safety import ENDPOINTS
from ddos_sentinel.response.incidents import IncidentManager

Mode = Literal[
    "global-throttle",
    "client-rate-limit",
    "endpoint-rate-limit",
    "block-client",
    "body-size-limit",
    "circuit-breaker",
    "cooldown",
]


class MitigationRequest(StrictModel):
    mode: Mode
    reason: str = Field(min_length=3, max_length=200)
    ttl: float = Field(default=30, gt=0, le=300)
    rate: int = Field(default=5, ge=1, le=200, strict=True)
    client_id: str | None = Field(default=None, max_length=16)
    endpoint: str | None = None
    body_limit: int = Field(default=1024, ge=0, le=65536, strict=True)
    incident_id: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def valid_scope(self) -> "MitigationRequest":
        if self.mode == "block-client" and not self.client_id:
            raise ValueError("block-client requires a synthetic client id")
        if self.client_id and not re.fullmatch(r"client-\d{1,3}", self.client_id):
            raise ValueError("only built-in synthetic client identifiers can be blocked")
        if self.mode == "endpoint-rate-limit" and self.endpoint not in ENDPOINTS:
            raise ValueError("endpoint-rate-limit requires a built-in endpoint")
        if self.endpoint is not None and self.endpoint not in ENDPOINTS:
            raise ValueError("unsupported endpoint")
        return self


class Mitigator:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def enable(self, request: MitigationRequest) -> str:
        # Validate a related incident before persisting any action.
        if request.incident_id:
            incident = self.db.get("incidents", request.incident_id)
            if incident["status"] not in {"OPEN", "ACKNOWLEDGED", "MITIGATING"}:
                raise ValueError("cannot mitigate a closed incident")
        active = self.status()
        if len(active) >= 32:
            raise ValueError("at most 32 local mitigation actions can be active")
        now = time.time()
        action = {
            **request.model_dump(),
            "status": "ACTIVE",
            "start_time": now,
            "expires_at": now + request.ttl,
        }
        with self.db.connection() as connection:
            action_id = self.db.put("mitigation_actions", action, connection=connection)
            if request.mode == "block-client":
                self.db.put("blocked_clients", {**action, "id": action_id}, connection=connection)
        if request.incident_id and incident["status"] != "MITIGATING":
            IncidentManager(self.db).transition(request.incident_id, "MITIGATING")
        audit(
            self.db,
            "mitigation.enabled",
            mode=request.mode,
            reason=request.reason,
            expires_at=now + request.ttl,
            incident_id=request.incident_id,
        )
        return action_id

    def status(self, *, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        active = []
        for action in self.db.list("mitigation_actions", limit=100000, status="ACTIVE"):
            if action["expires_at"] <= now:
                self._disable(action, "EXPIRED")
            else:
                active.append(action)
        return active

    def _disable(self, action: dict, status: str = "DISABLED") -> None:
        action["status"] = status
        self.db.put("mitigation_actions", action)
        if action["mode"] == "block-client":
            self.db.put("blocked_clients", action)
        self.hits.pop(action["id"], None)
        audit(
            self.db,
            "mitigation.disabled",
            mode=action["mode"],
            reason=action["reason"],
            status=status,
        )

    def disable(self, mode: str) -> int:
        actions = [action for action in self.status() if action["mode"] == mode]
        for action in actions:
            self._disable(action)
        return len(actions)

    def reset(self) -> int:
        actions = self.status()
        for action in actions:
            self._disable(action)
        self.hits.clear()
        audit(self.db, "mitigation.reset", count=len(actions))
        return len(actions)

    def unblock(self, client_id: str) -> int:
        actions = [
            action
            for action in self.status()
            if action["mode"] == "block-client" and action["client_id"] == client_id
        ]
        for action in actions:
            self._disable(action)
        return len(actions)

    def check(self, client_id: str, endpoint: str, size: int) -> int | None:
        active = self.status()
        live_ids = {action["id"] for action in active}
        for key in list(self.hits):
            if key.split(":", 1)[0] not in live_ids:
                del self.hits[key]
        now = time.monotonic()
        for action in active:
            mode = action["mode"]
            if mode == "block-client" and action["client_id"] == client_id:
                return 403
            if mode in {"circuit-breaker", "cooldown"}:
                return 503 if mode == "circuit-breaker" else 429
            if mode == "body-size-limit" and size > action["body_limit"]:
                return 413
            if mode == "endpoint-rate-limit" and action["endpoint"] != endpoint:
                continue
            if mode not in {"global-throttle", "client-rate-limit", "endpoint-rate-limit"}:
                continue
            key = action["id"] + (":" + client_id if mode == "client-rate-limit" else "")
            hits = self.hits[key]
            while hits and hits[0] <= now - 1:
                hits.popleft()
            if len(hits) >= action["rate"]:
                return 429
            hits.append(now)
        return None
