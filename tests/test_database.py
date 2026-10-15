from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from ddos_sentinel.core.audit import audit
from ddos_sentinel.core.database import TABLES, Database


def test_schema_sql_safety_and_rollback(tmp_path: Path) -> None:
    db = Database(tmp_path / "data.db")
    for table in TABLES:
        assert db.list(table) == []
    payload = "'; DROP TABLE labs; --"
    db.put("labs", {"id": payload, "name": payload})
    assert db.get("labs", payload)["name"] == payload
    with pytest.raises(ValueError):
        db.list(payload)
    with pytest.raises(RuntimeError), db.connection() as connection:
        db.put("labs", {"id": "rollback"}, connection=connection)
        raise RuntimeError("rollback")
    with pytest.raises(ValueError):
        db.get("labs", "rollback")


def test_concurrent_access_and_retention(tmp_path: Path) -> None:
    db = Database(tmp_path / "data.db")
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda index: db.put("traffic_samples", {"id": str(index)}), range(40)))
    assert len(db.list("traffic_samples")) == 40
    db.put("traffic_samples", {"id": "old", "timestamp": 1})
    db.put("mitigation_actions", {"id": "active", "timestamp": 1, "status": "ACTIVE"})
    db.retain(7, 10)
    assert len(db.list("traffic_samples")) == 10
    assert db.get("mitigation_actions", "active")["status"] == "ACTIVE"
    assert "old" not in {row["id"] for row in db.list("traffic_samples")}


def test_audit_never_logs_arbitrary_secrets(tmp_path: Path) -> None:
    db = Database(tmp_path / "data.db")
    audit(db, "test", token="SECRET", body="PRIVATE", rate=10)
    assert db.list("audit_logs")[0]["metadata"] == {"rate": 10}
