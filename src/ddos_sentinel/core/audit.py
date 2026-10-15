"""Structured action logging with an explicit metadata allowlist."""

import json
import logging
import sqlite3
from typing import Any

from ddos_sentinel.core.database import Database

logger = logging.getLogger("ddos_sentinel.audit")
SAFE_FIELDS = frozenset(
    {
        "scenario",
        "duration",
        "rate",
        "clients",
        "body_size",
        "dry_run",
        "simulation_id",
        "lab_id",
        "mode",
        "reason",
        "status",
        "incident_id",
        "target",
        "expires_at",
        "count",
    }
)


def audit(
    db: Database, action: str, *, connection: sqlite3.Connection | None = None, **metadata: Any
) -> None:
    record = {"action": action, "metadata": {k: v for k, v in metadata.items() if k in SAFE_FIELDS}}
    db.put("audit_logs", record, connection=connection)
    logger.info(json.dumps(record, allow_nan=False))
