import asyncio
import socket
from pathlib import Path

import httpx
import pytest

from ddos_sentinel.core.config import LabConfig
from ddos_sentinel.core.database import Database
from ddos_sentinel.core.models import TrafficSample
from ddos_sentinel.core.safety import SimulationOptions
from ddos_sentinel.lab.service import TemporaryLab
from ddos_sentinel.lab.simulator import simulate
from ddos_sentinel.lab.telemetry import Telemetry


async def test_lifecycle_and_no_unowned_requests(tmp_path: Path) -> None:
    db = Database(tmp_path / "lab.db")
    async with TemporaryLab(LabConfig(), db) as lab:
        port = int(lab.target.rsplit(":", 1)[1])
        async with httpx.AsyncClient(trust_env=False) as client:
            assert (await client.get(lab.target + "/health")).status_code == 200
            assert (await client.get(lab.target + "/api/test")).status_code == 403
    assert lab.authorization and not lab.authorization.active
    assert lab.task and lab.task.done()
    with socket.socket() as probe:
        probe.settimeout(0.2)
        assert probe.connect_ex(("127.0.0.1", port)) != 0
    assert db.get("labs", lab.id)["status"] == "STOPPED"


async def test_dry_run_no_requests(tmp_path: Path) -> None:
    db = Database(tmp_path / "lab.db")
    async with TemporaryLab(LabConfig(), db) as lab:
        result = await simulate(lab, SimulationOptions(authorized=True, dry_run=True))
        assert result["status"] == "DRY_RUN"
        assert not lab.telemetry.samples
        assert result["scheduled"] == 0


@pytest.mark.parametrize("scenario", ["normal", "connection-churn", "synthetic-distributed"])
async def test_bounded_traffic(
    tmp_path: Path, scenario: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://8.8.8.8:8888")
    db = Database(tmp_path / "lab.db")
    async with TemporaryLab(LabConfig(), db) as lab:
        result = await simulate(
            lab,
            SimulationOptions(scenario=scenario, duration=0.4, rate=20, clients=3, authorized=True),
        )
        assert 1 <= result["scheduled"] <= 8
        assert result["completed"] > 0
        assert lab.telemetry.active == 0
        samples = db.list("traffic_samples")
        assert samples
        assert max(sample["active"] for sample in samples) <= 3
        assert all("body" not in sample and "headers" not in sample for sample in samples)


async def test_cancellation_stops_requests(tmp_path: Path) -> None:
    db = Database(tmp_path / "lab.db")
    async with TemporaryLab(LabConfig(), db) as lab:
        task = asyncio.create_task(
            simulate(
                lab,
                SimulationOptions(
                    scenario="slow-request-pattern",
                    duration=10,
                    rate=20,
                    clients=3,
                    authorized=True,
                ),
            )
        )
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert db.list("simulations")[0]["status"] == "CANCELLED"
        completed = lab.telemetry.completed
        await asyncio.sleep(0.3)
        assert lab.telemetry.completed == completed
        assert lab.telemetry.active == 0
        assert not lab.simulation_lock.locked()


async def test_body_size_guard(tmp_path: Path) -> None:
    db = Database(tmp_path / "lab.db")
    async with TemporaryLab(LabConfig(), db) as lab:
        assert lab.authorization
        async with httpx.AsyncClient(trust_env=False) as client:
            response = await client.post(
                lab.target + "/api/test",
                content=b"s" * 65537,
                headers={"X-Sentinel-Lab": lab.authorization.token},
            )
        assert response.status_code == 413
        assert all(sample.size <= 65536 for sample in lab.telemetry.samples)


def test_telemetry_is_bounded_and_private() -> None:
    telemetry = Telemetry(capacity=2)
    for _ in range(3):
        telemetry.add(
            TrafficSample(
                endpoint="/", status=200, latency_ms=1, client_id="client-1", size=0, active=1
            )
        )
    assert len(telemetry.samples) == 2
    assert telemetry.dropped == 1
    assert telemetry.window().count == 2
