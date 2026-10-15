from pathlib import Path

import pytest

from ddos_sentinel.analysis.baseline import Baseline, BaselineStore
from ddos_sentinel.analysis.classification import classify
from ddos_sentinel.analysis.detection import Detector
from ddos_sentinel.analysis.metrics import evaluation_metrics
from ddos_sentinel.core.config import LabConfig
from ddos_sentinel.core.database import Database
from ddos_sentinel.core.models import Detection, Window
from ddos_sentinel.core.safety import SimulationOptions
from ddos_sentinel.lab.runtime import Runtime
from ddos_sentinel.response.incidents import IncidentManager


@pytest.mark.parametrize(
    ("window", "expected"),
    [
        (Window(count=40, rps=40), "request-rate"),
        (Window(count=15, rps=15, endpoints={"/api/test": 1}), "endpoint-concentration"),
        (Window(count=20, rps=20, churn=20), "connection-churn"),
        (
            Window(count=8, rps=8, latency_p95=300, concurrency=3, endpoints={"/slow-test": 1}),
            "slow-resource-occupation",
        ),
        (Window(count=8, rps=8, error_rate=1, health=0), "error-spike"),
        (Window(count=8, rps=8, error_rate=1, health=0), "service-degradation"),
        (Window(count=25, rps=25, clients=20), "coordinated-synthetic-clients"),
        (Window(count=25, concurrency=25), "high-concurrency"),
        (Window(count=10, throttled=10), "repeated-mitigation-responses"),
    ],
)
def test_explainable_rules(window: Window, expected: str) -> None:
    detections = Detector().evaluate(window, "simulation")
    detection = next(row for row in detections if row.rule == expected)
    assert detection.explanation and detection.observed > detection.threshold
    assert detection.simulation_id == "simulation"
    assert "authorized workload change" in detection.explanation
    assert 0 <= detection.confidence <= 1


def test_normal_and_severity_escalation() -> None:
    detector = Detector(Baseline(), "low")
    assert not detector.evaluate(
        Window(count=5, rps=5, endpoints={"/": 0.3, "/health": 0.4, "/api/test": 0.3})
    )
    assert any(row.severity == "LOW" for row in detector.evaluate(Window(count=12, rps=12)))
    detector.evaluate(Window(count=40, rps=40))
    detector.evaluate(Window(count=40, rps=40))
    assert (
        next(
            row for row in detector.evaluate(Window(count=40, rps=40)) if row.rule == "request-rate"
        ).severity
        == "HIGH"
    )
    assert classify(detector.evaluate(Window(count=40, rps=40))) == ["elevated HTTP volume"]


async def test_baseline_lifecycle(tmp_path: Path) -> None:
    db = Database(tmp_path / "lab.db")
    store = BaselineStore(db)
    with pytest.raises(ValueError):
        store.create()
    async with Runtime(LabConfig(), db) as runtime:
        await runtime.run(SimulationOptions(duration=0.4, rate=10, authorized=True))
    baseline = store.create()
    assert baseline.sample_count >= 3
    assert baseline.average_rps > 0
    path = tmp_path / "baseline.json"
    store.export(path)
    store.reset()
    assert store.current() is None
    assert store.import_file(path) == baseline
    path.write_text('{"sample_count": -1, "command": "exec"}')
    with pytest.raises(ValueError):
        store.import_file(path)
    assert store.current() == baseline


@pytest.mark.parametrize(
    "data",
    [
        {"average_rps": float("inf")},
        {"endpoints": {"http://evil": 1}},
        {"endpoints": {"/": 2}},
        {"endpoints": {"/": float("nan")}},
        {"schema_version": 2},
        {"latency_p50": 100, "latency_p95": 10},
    ],
)
def test_invalid_baseline(data: dict) -> None:
    with pytest.raises(ValueError):
        Baseline.model_validate(data)


def test_incident_grouping_and_lifecycle(tmp_path: Path) -> None:
    db = Database(tmp_path / "lab.db")
    manager = IncidentManager(db)
    detection = Detection(
        rule="request-rate",
        severity="MEDIUM",
        confidence=0.8,
        explanation="Test",
        observed=50,
        expected=5,
        threshold=20,
        simulation_id="sim",
    )
    incident_id = manager.record([detection], Window(rps=50), "owned-service")
    assert incident_id
    manager.record(
        [detection.model_copy(update={"id": "other", "severity": "HIGH"})],
        Window(rps=80),
        "owned-service",
    )
    assert len(db.list("incidents")) == 1
    assert db.get("incidents", incident_id)["peak_rps"] == 80
    assert db.get("incidents", incident_id)["severity"] == "HIGH"
    assert all(row["incident_id"] == incident_id for row in db.list("detections"))
    manager.transition(incident_id, "ACKNOWLEDGED", "Investigating")
    manager.recover("sim", Window())
    assert db.get("incidents", incident_id)["status"] == "ACKNOWLEDGED"
    manager.recover("sim", Window(count=5, health=1))
    assert db.get("incidents", incident_id)["recovery_time"] is not None
    with pytest.raises(ValueError):
        manager.transition(incident_id, "ACKNOWLEDGED")


def test_metrics_do_not_invent_ground_truth() -> None:
    assert evaluation_metrics([], [])["scenario_detection_rate"] is None


@pytest.mark.parametrize(
    ("scenario", "rule"),
    [
        ("burst", "request-rate"),
        ("endpoint-concentration", "endpoint-concentration"),
        ("connection-churn", "connection-churn"),
        ("slow-request-pattern", "slow-resource-occupation"),
        ("error-spike", "error-spike"),
    ],
)
async def test_scenario_detection_end_to_end(tmp_path: Path, scenario: str, rule: str) -> None:
    db = Database(tmp_path / "lab.db")
    async with Runtime(LabConfig(), db) as runtime:
        result = await runtime.run(
            SimulationOptions(scenario=scenario, duration=1.3, rate=50, clients=20, authorized=True)
        )
    assert any(row["rule"] == rule for row in db.list("detections"))
    assert result["metrics"]["time_to_detect_seconds"] is not None
