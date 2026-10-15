"""Strict JSON configuration. Safety ceilings cannot be raised in configuration."""

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class Target(StrictModel):
    host: str = "127.0.0.1"
    port: int = Field(default=0, ge=0, le=65535, strict=True)
    protocol: Literal["http"] = "http"
    service_type: Literal["temporary_test_service"] = "temporary_test_service"

    @field_validator("host")
    @classmethod
    def loopback_only(cls, value: str) -> str:
        if value not in {"127.0.0.1", "localhost"}:
            raise ValueError("only 127.0.0.1 or localhost is authorized; no DNS targets")
        return value


class Safety(StrictModel):
    localhost_only: Literal[True] = True
    allow_private_networks: Literal[False] = False
    allow_public_targets: Literal[False] = False
    synthetic_traffic_only: Literal[True] = True
    require_explicit_authorization: Literal[True] = True
    dry_run: bool = False


class Limits(StrictModel):
    max_duration_seconds: float = Field(default=60, gt=0, le=60)
    max_clients: int = Field(default=100, ge=1, le=100, strict=True)
    max_requests_per_second: int = Field(default=200, ge=1, le=200, strict=True)
    max_request_body_bytes: int = Field(default=65536, ge=0, le=65536, strict=True)


class DetectionConfig(StrictModel):
    baseline_window_seconds: int = Field(default=60, ge=1, le=3600, strict=True)
    alert_threshold: Literal["low", "medium", "high"] = "medium"
    window_seconds: float = Field(default=1, ge=0.1, le=10)


class LabConfig(StrictModel):
    lab_name: str = Field(default="local-training-lab", min_length=1, max_length=80)
    target: Target = Target()
    safety: Safety = Safety()
    limits: Limits = Limits()
    detection: DetectionConfig = DetectionConfig()
    artificial_latency_ms: int = Field(default=250, ge=0, le=2000, strict=True)
    retention_days: int = Field(default=7, ge=1, le=90, strict=True)
    max_telemetry_rows: int = Field(default=50000, ge=100, le=100000, strict=True)


def load_config(path: Path | None) -> LabConfig:
    """Read bounded JSON; reject unknown options rather than silently ignoring them."""
    if path is None:
        return LabConfig()
    if path.stat().st_size > 65536:
        raise ValueError("configuration exceeds 64 KiB")
    return LabConfig.model_validate_json(path.read_text(encoding="utf-8"))
