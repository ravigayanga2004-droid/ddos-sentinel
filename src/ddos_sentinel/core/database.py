"""Transactional SQLite repository with bounded telemetry and parameterized values."""

import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ddos_sentinel.core.models import new_id

TABLES = frozenset(
    {
        "labs",
        "targets",
        "simulations",
        "traffic_samples",
        "traffic_baselines",
        "detections",
        "incidents",
        "mitigation_actions",
        "blocked_clients",
        "service_health",
        "audit_logs",
        "configuration",
    }
)


class Database:
    """Each transaction owns a connection; usable across CLI processes and ASGI threads."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            for table in sorted(TABLES):
                connection.execute(f"""CREATE TABLE IF NOT EXISTS {table} (
                    id TEXT PRIMARY KEY, timestamp REAL NOT NULL,
                    severity TEXT, status TEXT, simulation_id TEXT,
                    incident_id TEXT, detection_type TEXT, data TEXT NOT NULL
                )""")
                for column in (
                    "timestamp",
                    "severity",
                    "status",
                    "simulation_id",
                    "incident_id",
                    "detection_type",
                ):
                    connection.execute(
                        f"CREATE INDEX IF NOT EXISTS ix_{table}_{column} ON {table} ({column})"
                    )
            connection.execute("PRAGMA user_version=1")

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _table(table: str) -> str:
        if table not in TABLES:
            raise ValueError("unknown database table")
        return table

    def put(
        self,
        table: str,
        data: dict[str, Any],
        *,
        connection: sqlite3.Connection | None = None,
    ) -> str:
        table = self._table(table)
        record = dict(data)
        record.setdefault("id", new_id())
        record.setdefault("timestamp", time.time())
        values = (
            record["id"],
            record["timestamp"],
            record.get("severity"),
            record.get("status"),
            record.get("simulation_id"),
            record.get("incident_id"),
            record.get("rule"),
            json.dumps(record, allow_nan=False),
        )
        query = f"""INSERT INTO {table}
            (id,timestamp,severity,status,simulation_id,incident_id,detection_type,data)
            VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
            timestamp=excluded.timestamp,severity=excluded.severity,status=excluded.status,
            simulation_id=excluded.simulation_id,incident_id=excluded.incident_id,
            detection_type=excluded.detection_type,data=excluded.data"""
        if connection is not None:
            connection.execute(query, values)
        else:
            with self.connection() as transaction:
                transaction.execute(query, values)
        return str(record["id"])

    def get(self, table: str, record_id: str) -> dict[str, Any]:
        table = self._table(table)
        with self.connection() as connection:
            row = connection.execute(
                f"SELECT data FROM {table} WHERE id=?", (record_id,)
            ).fetchone()
        if row is None:
            raise ValueError(f"{table}: record not found")
        return dict(json.loads(row[0]))

    def list(
        self,
        table: str,
        *,
        limit: int = 1000,
        simulation_id: str | None = None,
    ) -> list[dict[str, Any]]:
        table = self._table(table)
        if not 1 <= limit <= 100000:
            raise ValueError("invalid row limit")
        where = " WHERE simulation_id=?" if simulation_id else ""
        args: tuple[Any, ...] = (simulation_id, limit) if simulation_id else (limit,)
        with self.connection() as connection:
            rows = connection.execute(
                f"SELECT data FROM {table}{where} ORDER BY timestamp DESC,id DESC LIMIT ?", args
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def delete(self, table: str, record_id: str | None = None) -> None:
        table = self._table(table)
        with self.connection() as connection:
            if record_id is None:
                connection.execute(f"DELETE FROM {table}")
            else:
                connection.execute(f"DELETE FROM {table} WHERE id=?", (record_id,))

    def retain(self, days: int, max_rows: int, *, now: float | None = None) -> None:
        """Bound all event tables; preserve current state and active incident/action records."""
        cutoff = (time.time() if now is None else now) - days * 86400
        with self.connection() as connection:
            for table in sorted(TABLES - {"traffic_baselines", "configuration"}):
                connection.execute(
                    f"DELETE FROM {table} WHERE timestamp < ? "
                    "AND (status IS NULL OR status IN "
                    "('COMPLETED','CANCELLED','FAILED','DRY_RUN','RESOLVED',"
                    "'FALSE_POSITIVE','EXPIRED','DISABLED','STOPPED','NEW'))",
                    (cutoff,),
                )
                connection.execute(
                    f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} "
                    "WHERE status IS NULL OR status NOT IN "
                    "('RUNNING','OPEN','ACKNOWLEDGED','MITIGATING','ACTIVE','STOPPING') "
                    "ORDER BY timestamp DESC LIMIT -1 OFFSET ?)",
                    (max_rows,),
                )
            connection.execute("PRAGMA incremental_vacuum")
