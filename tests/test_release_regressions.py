import asyncio
import json
import socket
import sqlite3
import sys
import time
from contextlib import closing
from pathlib import Path

import httpx
import pytest

from ddos_sentinel.analysis.baseline import BaselineStore
from ddos_sentinel.api.app import create_app
from ddos_sentinel.core.config import LabConfig
from ddos_sentinel.core.database import Database
from ddos_sentinel.core.safety import SimulationOptions
from ddos_sentinel.lab.runtime import Runtime
from ddos_sentinel.lab.service import TemporaryLab
from ddos_sentinel.response.mitigation import MitigationRequest, Mitigator


async def test_chunked_body_is_bounded(tmp_path: Path) -> None:
    db = Database(tmp_path / "chunked.db")
    async with TemporaryLab(LabConfig(), db) as lab:
        assert lab.authorization

        async def body():
            for _ in range(9):
                yield b"x" * 8192

        async with httpx.AsyncClient(trust_env=False) as client:
            response = await client.post(
                lab.target + "/api/test",
                content=body(),
                headers={"X-Sentinel-Lab": lab.authorization.token},
            )
        assert response.status_code == 413
        assert lab.telemetry.samples[-1].size <= 65536


async def test_bound_port_failure_preserves_other_listener(tmp_path: Path) -> None:
    db = Database(tmp_path / "busy.db")
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        port = occupied.getsockname()[1]
        config = LabConfig.model_validate({"target": {"port": port}})
        with pytest.raises(OSError):
            async with TemporaryLab(config, db):
                pytest.fail("occupied port must not be reused")
        assert occupied.getsockname()[1] == port


async def test_unavailable_service_is_critical(tmp_path: Path) -> None:
    db = Database(tmp_path / "unavailable.db")
    async with Runtime(LabConfig(), db) as runtime:
        assert runtime.lab.server and runtime.lab.task
        task = asyncio.create_task(
            runtime.run(SimulationOptions(duration=3.2, rate=20, authorized=True))
        )
        await asyncio.sleep(0.2)
        runtime.lab.server.should_exit = True
        await runtime.lab.task
        assert runtime.lab.socket
        runtime.lab.socket.close()
        with pytest.raises(ValueError, match="service stopped"):
            await task
        assert db.list("simulations")[0]["status"] == "FAILED"
        assert any(
            row["rule"] == "service-unavailable" and row["severity"] == "CRITICAL"
            for row in db.list("detections")
        )


async def test_mitigated_traffic_cannot_train_normal_baseline(tmp_path: Path) -> None:
    db = Database(tmp_path / "baseline.db")
    async with Runtime(LabConfig(), db) as runtime:
        runtime.mitigator.enable(MitigationRequest(mode="cooldown", reason="Lab test"))
        await runtime.run(SimulationOptions(duration=0.3, rate=20, authorized=True))
        with pytest.raises(ValueError, match="without mitigation"):
            BaselineStore(db).create()


async def test_client_timeouts_are_detection_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = Database(tmp_path / "timeout.db")

    async def timeout(*args, **kwargs):
        raise httpx.ReadTimeout("synthetic local transport failure")

    async with Runtime(LabConfig(), db) as runtime:
        monkeypatch.setattr(httpx.AsyncClient, "request", timeout)
        record = await runtime.run(SimulationOptions(duration=0.3, rate=20, authorized=True))
        assert record["network_errors"] >= 3
        assert record["metrics"]["service_availability"] == 0
        assert any(row["rule"] == "service-degradation" for row in db.list("detections"))


def test_mitigation_link_validation_has_no_partial_writes(tmp_path: Path) -> None:
    db = Database(tmp_path / "atomic.db")
    with pytest.raises(ValueError, match="incident not found"):
        Mitigator(db).enable(
            MitigationRequest(mode="cooldown", reason="Lab test", incident_id="bad")
        )
    assert db.list("mitigation_actions") == []
    assert db.list("audit_logs") == []


def test_unknown_database_schema_rejected(tmp_path: Path) -> None:
    path = tmp_path / "future.db"
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA user_version=99")
    with pytest.raises(ValueError, match="schema version"):
        Database(path)


async def test_dashboard_shutdown_cancels_job_and_removes_capability(tmp_path: Path) -> None:
    db = Database(tmp_path / "shutdown.db")
    app = create_app(LabConfig(), db)
    async with app.router.lifespan_context(app):
        runtime = app.state.runtime
        task = asyncio.create_task(
            runtime.run(
                SimulationOptions(
                    scenario="slow-request-pattern",
                    duration=10,
                    clients=3,
                    rate=20,
                    authorized=True,
                )
            )
        )
        runtime.tasks.add(task)
        await asyncio.sleep(0.15)
    assert task.cancelled()
    assert runtime.lab.authorization and not runtime.lab.authorization.active
    assert runtime.lab.task.done()
    assert db.list("simulations")[0]["status"] == "CANCELLED"
    assert db.list("labs")[0]["status"] == "STOPPED"


async def test_standalone_lab_stop_across_processes(tmp_path: Path) -> None:
    path = tmp_path / "standalone.db"
    common = [sys.executable, "-m", "ddos_sentinel.cli", "--database", str(path), "lab"]
    process = await asyncio.create_subprocess_exec(
        *common, "start", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        deadline = time.monotonic() + 10
        db = None
        while time.monotonic() < deadline:
            if path.exists():
                db = Database(path)
                if any(row.get("managed_by") == "lab-command" for row in db.list("labs")):
                    break
            await asyncio.sleep(0.05)
        else:
            pytest.fail("standalone service failed to become ready")
        stopper = await asyncio.create_subprocess_exec(
            *common, "stop", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        output, error = await asyncio.wait_for(stopper.communicate(), 10)
        assert stopper.returncode == 0, error.decode()
        assert json.loads(output)["stop_requests"] == 1
        await asyncio.wait_for(process.communicate(), 10)
        assert process.returncode == 0
        assert db and db.list("labs")[0]["status"] == "STOPPED"
    finally:
        if process.returncode is None:
            process.terminate()
            await process.communicate()


@pytest.mark.parametrize("scenario", ["error-spike", "slow-request-pattern"])
def test_conflicting_body_scenario_rejected(scenario: str) -> None:
    with pytest.raises(ValueError, match="cannot be combined"):
        SimulationOptions(scenario=scenario, body_size=1, authorized=True).check(LabConfig().limits)
