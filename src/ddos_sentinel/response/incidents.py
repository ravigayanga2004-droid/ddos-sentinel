"""Transactionally group detections within a simulation and record analyst decisions."""

import json
import time
from typing import Any

from ddos_sentinel.core.audit import audit
from ddos_sentinel.core.database import Database
from ddos_sentinel.core.models import SEVERITIES, Detection, IncidentStatus, Window, new_id


class IncidentManager:
    def __init__(self, db: Database) -> None:
        self.db = db

    def record(self, detections: list[Detection], window: Window, service: str) -> str | None:
        if not detections:
            return None
        simulation_id = detections[0].simulation_id
        with self.db.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT data FROM incidents WHERE simulation_id=? "
                "AND status IN ('OPEN','ACKNOWLEDGED','MITIGATING') "
                "ORDER BY timestamp DESC LIMIT 1",
                (simulation_id,),
            ).fetchall()
            first = min(detection.timestamp for detection in detections)
            incident: dict[str, Any] = (
                json.loads(rows[0][0])
                if rows
                else {
                    "id": new_id(),
                    "timestamp": first,
                    "start_time": first,
                    "end_time": None,
                    "detection_time": first,
                    "mitigation_time": None,
                    "recovery_time": None,
                    "simulation_id": simulation_id,
                    "status": "OPEN",
                    "severity": "INFO",
                    "affected_service": service,
                    "affected_endpoint": None,
                    "detection_types": [],
                    "peak_rps": 0,
                    "peak_concurrency": 0,
                    "notes": "",
                    "recommended_actions": [
                        "Inspect the baseline and scenario parameters.",
                        "Apply a temporary local control if warranted.",
                    ],
                }
            )
            incident["peak_rps"] = max(incident["peak_rps"], window.rps)
            incident["peak_concurrency"] = max(incident["peak_concurrency"], window.concurrency)
            for detection in detections:
                if SEVERITIES[detection.severity] > SEVERITIES[incident["severity"]]:
                    incident["severity"] = detection.severity
                if detection.rule not in incident["detection_types"]:
                    incident["detection_types"].append(detection.rule)
                if detection.endpoint:
                    incident["affected_endpoint"] = detection.endpoint
                linked = detection.model_copy(update={"incident_id": incident["id"]})
                self.db.put("detections", linked.model_dump(), connection=connection)
            self.db.put("incidents", incident, connection=connection)
        return str(incident["id"])

    def transition(
        self, incident_id: str, status: IncidentStatus, notes: str = ""
    ) -> dict[str, Any]:
        if status not in {"ACKNOWLEDGED", "MITIGATING", "RESOLVED", "FALSE_POSITIVE"}:
            raise ValueError("unsupported incident transition")
        if len(notes) > 2000:
            raise ValueError("analyst notes exceed 2000 characters")
        incident = self.db.get("incidents", incident_id)
        if incident["status"] in {"RESOLVED", "FALSE_POSITIVE"}:
            raise ValueError("incident is already closed")
        incident["status"] = status
        if notes:
            incident["notes"] = notes
        if status == "MITIGATING" and incident["mitigation_time"] is None:
            incident["mitigation_time"] = time.time()
        if status in {"RESOLVED", "FALSE_POSITIVE"}:
            incident["end_time"] = time.time()
        self.db.put("incidents", incident)
        audit(self.db, "incident.transition", incident_id=incident_id, status=status)
        return incident

    def recover(self, simulation_id: str, window: Window) -> None:
        """Recovery requires observed successful traffic, never an idle window alone."""
        if window.count < 3 or window.health < 0.99 or window.error_rate > 0.01:
            return
        for incident in self.db.list("incidents", simulation_id=simulation_id):
            if incident["status"] in {"OPEN", "ACKNOWLEDGED", "MITIGATING"}:
                incident["recovery_time"] = time.time()
                incident["end_time"] = time.time()
                incident["status"] = "RESOLVED"
                self.db.put("incidents", incident)
                audit(self.db, "incident.recovered", incident_id=incident["id"])
