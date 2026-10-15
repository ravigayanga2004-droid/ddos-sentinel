"""Application orchestration shared by CLI, dashboard and the harmless demo."""

import asyncio
import time
from typing import Any

from ddos_sentinel.analysis.baseline import BaselineStore
from ddos_sentinel.analysis.detection import Detector
from ddos_sentinel.analysis.metrics import simulation_metrics
from ddos_sentinel.core.config import LabConfig
from ddos_sentinel.core.database import Database
from ddos_sentinel.core.models import TrafficSample
from ddos_sentinel.core.safety import SimulationOptions
from ddos_sentinel.lab.service import TemporaryLab
from ddos_sentinel.lab.simulator import simulate
from ddos_sentinel.lab.telemetry import summarize
from ddos_sentinel.response.incidents import IncidentManager
from ddos_sentinel.response.mitigation import Mitigator


class Runtime:
    def __init__(self, config: LabConfig, db: Database) -> None:
        self.config, self.db = config, db
        self.baselines = BaselineStore(db)
        self.mitigator = Mitigator(db)
        self.incidents = IncidentManager(db)
        self.lab = TemporaryLab(config, db, self.mitigator.check)
        self.tasks: set[asyncio.Task[dict[str, Any]]] = set()
        self.last_window = self.lab.telemetry.window()

    async def __aenter__(self) -> "Runtime":
        self.db.retain(self.config.retention_days, self.config.max_telemetry_rows)
        await self.lab.__aenter__()
        return self

    async def __aexit__(self, *exc: object) -> None:
        for task in self.tasks:
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.lab.close()
        self.db.retain(self.config.retention_days, self.config.max_telemetry_rows)

    async def run(self, options: SimulationOptions) -> dict[str, Any]:
        detector = Detector(self.baselines.current(), self.config.detection.alert_threshold)
        last_observed = time.time()

        def observe(simulation_id: str, seconds: float) -> None:
            nonlocal last_observed
            now = time.time()
            samples = [
                sample
                for sample in self.lab.telemetry.samples
                if sample.simulation_id == simulation_id and sample.timestamp >= now - seconds
            ]
            window = summarize(samples, seconds, self.lab.telemetry.active)
            self.last_window = window
            detections = detector.evaluate(window, simulation_id)
            self.incidents.record(detections, window, self.lab.target)
            if not detections and window.throttled == 0 and window.rejected == 0:
                for incident in self.db.list("incidents"):
                    if incident["affected_service"] == self.lab.target:
                        self.incidents.recover(incident["simulation_id"], window)
            self.db.put("service_health", {**window.model_dump(), "simulation_id": simulation_id})
            last_observed = now

        record = await simulate(self.lab, options, observe)
        if record["status"] != "DRY_RUN":
            observe(record["id"], max(0.1, time.time() - last_observed))
        rows = self.db.list("traffic_samples", limit=100000, simulation_id=record["id"])
        samples = [
            TrafficSample.model_validate({k: v for k, v in row.items() if k != "id"})
            for row in rows
        ]
        record["metrics"] = simulation_metrics(
            record, samples, self.db.list("incidents", simulation_id=record["id"])
        )
        self.db.put("simulations", record)
        self.db.retain(self.config.retention_days, self.config.max_telemetry_rows)
        return record
