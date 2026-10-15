"""Versioned, validated baselines built only from explicitly selected normal traffic."""

import math
import statistics
import time
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from ddos_sentinel.core.audit import audit
from ddos_sentinel.core.config import StrictModel
from ddos_sentinel.core.database import Database
from ddos_sentinel.core.models import TrafficSample
from ddos_sentinel.core.safety import ENDPOINTS
from ddos_sentinel.lab.telemetry import summarize


class Baseline(StrictModel):
    schema_version: Literal[1] = 1
    timestamp: float = Field(default_factory=time.time, ge=0)
    source_simulation: str = Field(default="reference", max_length=64)
    sample_count: int = Field(default=1, ge=1, le=100000)
    duration_seconds: float = Field(default=1, gt=0, le=3600)
    average_rps: float = Field(default=5, ge=0, le=10000)
    peak_rps: float = Field(default=8, ge=0, le=10000)
    rps_stddev: float = Field(default=0, ge=0, le=10000)
    latency_p50: float = Field(default=5, ge=0, le=60000)
    latency_p95: float = Field(default=20, ge=0, le=60000)
    error_rate: float = Field(default=0, ge=0, le=1)
    endpoints: dict[str, float] = Field(
        default_factory=lambda: {
            "/": 1 / 3,
            "/health": 1 / 3,
            "/api/test": 1 / 3,
        }
    )
    concurrency: int = Field(default=1, ge=0, le=1000)
    mean_size: float = Field(default=0, ge=0, le=65536)
    health: float = Field(default=1, ge=0, le=1)

    @model_validator(mode="after")
    def consistent(self) -> "Baseline":
        if self.peak_rps < self.average_rps or self.latency_p95 < self.latency_p50:
            raise ValueError("baseline peak/percentile cannot be smaller than average/median")
        if set(self.endpoints) - set(ENDPOINTS):
            raise ValueError("baseline contains unsupported endpoints")
        if any(
            not math.isfinite(value) or not 0 <= value <= 1 for value in self.endpoints.values()
        ):
            raise ValueError("invalid endpoint probability")
        if not math.isclose(sum(self.endpoints.values()), 1, abs_tol=0.01):
            raise ValueError("endpoint probabilities must sum to one")
        return self


class BaselineStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    def current(self) -> Baseline | None:
        rows = self.db.list("traffic_baselines", limit=1)
        return Baseline.model_validate(rows[0]["baseline"]) if rows else None

    def save(self, baseline: Baseline) -> None:
        self.db.put("traffic_baselines", {"id": "current", "baseline": baseline.model_dump()})
        audit(self.db, "baseline.saved", simulation_id=baseline.source_simulation)

    def create(self, simulation_id: str | None = None, window_seconds: int = 60) -> Baseline:
        simulations = self.db.list("simulations")
        candidates = [
            row
            for row in simulations
            if row["parameters"]["scenario"] == "normal"
            and row["status"] == "COMPLETED"
            and (simulation_id is None or row["id"] == simulation_id)
        ]
        if not candidates:
            raise ValueError("run a completed normal simulation before creating a baseline")
        simulation = candidates[0]
        rows = self.db.list("traffic_samples", limit=100000, simulation_id=simulation["id"])
        cutoff = simulation["end_time"] - window_seconds
        samples = [
            TrafficSample.model_validate({k: v for k, v in row.items() if k != "id"})
            for row in rows
            if row["timestamp"] >= cutoff
        ]
        if not samples:
            raise ValueError("the normal simulation has no retained telemetry")
        if any(sample.mitigation or not 200 <= sample.status < 400 for sample in samples):
            raise ValueError("baseline requires successful normal traffic without mitigation")
        duration = min(window_seconds, simulation["end_time"] - simulation["start_time"])
        summary = summarize(samples, duration)
        buckets: dict[int, int] = {}
        start = max(simulation["start_time"], cutoff)
        for sample in samples:
            bucket = int(sample.timestamp - start)
            buckets[bucket] = buckets.get(bucket, 0) + 1
        bucket_rates = [
            buckets.get(index, 0) / min(1, duration - index)
            for index in range(math.ceil(duration))
            if duration - index > 0
        ]
        baseline = Baseline(
            source_simulation=simulation["id"],
            sample_count=len(samples),
            duration_seconds=duration,
            average_rps=summary.rps,
            peak_rps=max(summary.rps, *bucket_rates),
            rps_stddev=statistics.pstdev(bucket_rates) if len(bucket_rates) > 1 else 0,
            latency_p50=summary.latency_p50,
            latency_p95=summary.latency_p95,
            error_rate=summary.error_rate,
            endpoints=summary.endpoints,
            concurrency=summary.concurrency,
            mean_size=summary.mean_size,
            health=summary.health,
        )
        self.save(baseline)
        return baseline

    def reset(self) -> None:
        self.db.delete("traffic_baselines")
        audit(self.db, "baseline.reset")

    def export(self, path: Path) -> None:
        baseline = self.current()
        if baseline is None:
            raise ValueError("no learned baseline exists")
        path.write_text(baseline.model_dump_json(indent=2), encoding="utf-8")

    def import_file(self, path: Path) -> Baseline:
        if path.stat().st_size > 1048576:
            raise ValueError("baseline import exceeds 1 MiB")
        baseline = Baseline.model_validate_json(path.read_text(encoding="utf-8"))
        self.save(baseline)
        return baseline
