"""Privacy-preserving telemetry and explainable detection records."""

import time
from typing import Literal
from uuid import uuid4

from pydantic import Field

from ddos_sentinel.core.config import StrictModel

Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
IncidentStatus = Literal["OPEN", "ACKNOWLEDGED", "MITIGATING", "RESOLVED", "FALSE_POSITIVE"]
SEVERITIES = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def new_id() -> str:
    return uuid4().hex


class TrafficSample(StrictModel):
    timestamp: float = Field(default_factory=time.time)
    endpoint: str
    status: int = Field(ge=0, le=599)
    latency_ms: float = Field(ge=0)
    client_id: str
    size: int = Field(ge=0, le=65536)
    active: int = Field(ge=0)
    simulation_id: str | None = None
    new_connection: bool = False
    mitigation: bool = False
    request_id: str | None = Field(default=None, max_length=40)


class Window(StrictModel):
    timestamp: float = Field(default_factory=time.time)
    seconds: float = Field(default=1, gt=0)
    count: int = 0
    rps: float = 0
    latency_p50: float = 0
    latency_p95: float = 0
    error_rate: float = 0
    concurrency: int = 0
    endpoints: dict[str, float] = Field(default_factory=dict)
    clients: int = 0
    mean_size: float = 0
    health: float = 1
    service_available: bool = True
    throttled: int = 0
    rejected: int = 0
    churn: float = 0
    dropped_samples: int = 0


class Detection(StrictModel):
    id: str = Field(default_factory=new_id)
    timestamp: float = Field(default_factory=time.time)
    rule: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    explanation: str
    observed: float
    expected: float
    threshold: float
    endpoint: str | None = None
    simulation_id: str | None = None
    incident_id: str | None = None
    status: str = "NEW"
