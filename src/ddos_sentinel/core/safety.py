"""Network boundary checks without DNS resolution or external probes."""

from urllib.parse import urlsplit

from pydantic import Field

from ddos_sentinel.core.config import Limits, StrictModel

SCENARIOS = (
    "normal",
    "burst",
    "endpoint-concentration",
    "connection-churn",
    "slow-request-pattern",
    "synthetic-distributed",
    "error-spike",
)
ENDPOINTS = ("/", "/health", "/api/test", "/slow-test", "/error-test")


def validate_target(url: str) -> str:
    """Return a canonical loopback origin; paths, credentials and aliases are forbidden."""
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid target port") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or port is None
        or not 1 <= port <= 65535
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or "\\" in url
    ):
        raise ValueError("target must be an HTTP loopback origin with an explicit valid port")
    return f"http://127.0.0.1:{port}"


class SimulationOptions(StrictModel):
    scenario: str = "normal"
    duration: float = Field(default=10, gt=0, le=60)
    rate: int = Field(default=10, ge=1, le=200, strict=True)
    clients: int = Field(default=5, ge=1, le=100, strict=True)
    body_size: int = Field(default=0, ge=0, le=65536, strict=True)
    dry_run: bool = False
    authorized: bool = False

    def check(self, limits: Limits) -> None:
        if self.scenario not in SCENARIOS:
            raise ValueError(f"scenario must be one of: {', '.join(SCENARIOS)}")
        for value, ceiling, name in (
            (self.duration, limits.max_duration_seconds, "duration"),
            (self.rate, limits.max_requests_per_second, "rate"),
            (self.clients, limits.max_clients, "clients"),
            (self.body_size, limits.max_request_body_bytes, "body size"),
        ):
            if value > ceiling:
                raise ValueError(f"{name} exceeds configured limit {ceiling}")
        if not self.authorized:
            raise ValueError("explicit authorization is required for every simulation")
