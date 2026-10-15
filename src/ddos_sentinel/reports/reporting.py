"""Generate consistent JSON, Markdown and autoescaped HTML reports."""

import json
import time
from bisect import bisect_left, bisect_right
from collections import defaultdict
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ddos_sentinel import __version__
from ddos_sentinel.analysis.baseline import BaselineStore
from ddos_sentinel.analysis.metrics import evaluation_metrics, simulation_metrics
from ddos_sentinel.core.config import LabConfig
from ddos_sentinel.core.database import Database
from ddos_sentinel.core.models import TrafficSample
from ddos_sentinel.response.mitigation import Mitigator

LIMITATIONS = [
    "Synthetic loopback HTTP observations cannot establish a real distributed attack.",
    "Small samples and incomplete training can cause false positives or missed findings.",
    "Null measurements were not observed; manual resolution is not measured recovery.",
    "Mitigation response fractions are not causal effectiveness measurements.",
    "No upstream protection, packet capture, production IDS/IPS, SIEM, EDR or WAF is provided.",
    "Exports include retained metadata only; retention may have removed older evidence.",
]


def build_report(db: Database, config: LabConfig) -> dict[str, Any]:
    Mitigator(db).status()  # Persist expiries before taking the export snapshot.
    simulations = db.list("simulations", limit=100000)
    incidents = db.list("incidents", limit=100000)
    detections = db.list("detections", limit=100000)
    baseline = BaselineStore(db).current()
    actions = db.list("mitigation_actions", limit=100000)
    traffic = db.list("traffic_samples", limit=100000)
    by_simulation: dict[str, list[TrafficSample]] = defaultdict(list)
    by_lab: dict[str, list[TrafficSample]] = defaultdict(list)
    simulation_labs = {simulation["id"]: simulation["lab_id"] for simulation in simulations}
    incidents_by_simulation: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for incident in incidents:
        incidents_by_simulation[incident["simulation_id"]].append(incident)
    for row in reversed(traffic):
        sample = TrafficSample.model_validate({k: v for k, v in row.items() if k != "id"})
        if sample.simulation_id:
            by_simulation[sample.simulation_id].append(sample)
            lab_id = simulation_labs.get(sample.simulation_id)
            if lab_id:
                by_lab[lab_id].append(sample)
    times = {lab_id: [sample.timestamp for sample in samples] for lab_id, samples in by_lab.items()}
    for simulation in simulations:
        lab_id = simulation["lab_id"]
        start = bisect_left(times.get(lab_id, []), simulation["start_time"] - 5)
        end = bisect_right(times.get(lab_id, []), simulation.get("end_time", time.time()) + 5)
        simulation["metrics"] = simulation_metrics(
            simulation,
            by_simulation[simulation["id"]],
            incidents_by_simulation[simulation["id"]],
            context_samples=by_lab[lab_id][start:end],
            actions=actions,
        )
    evaluation = evaluation_metrics(simulations, incidents)
    return {
        "tool": "DDoS Sentinel",
        "version": __version__,
        "generated_at": time.time(),
        "executive_summary": {
            "simulations": len(simulations),
            "detections": len(detections),
            "open_incidents": sum(
                row["status"] not in {"RESOLVED", "FALSE_POSITIVE"} for row in incidents
            ),
            "assessment": (
                "Review lab anomalies alongside workload changes; findings are uncertain."
            ),
        },
        "configuration": config.model_dump(),
        "labs": db.list("labs", limit=100000),
        "baseline": baseline.model_dump() if baseline else None,
        "simulations": simulations,
        "detections": detections,
        "incidents": incidents,
        "mitigation_actions": actions,
        "timeline": db.list("service_health", limit=100000),
        "evaluation": evaluation,
        "recommendations": [
            "Learn a representative normal baseline before interpreting alerts.",
            "Compare bounded scenarios with and without a short-lived control.",
            "Review and annotate false positives; keep all experiments local.",
        ],
        "limitations": LIMITATIONS,
    }


def render_report(report: dict[str, Any], format: str) -> str:
    if format == "json":
        return json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
    if format == "markdown":
        # Escape fence delimiters and HTML characters within readable JSON code blocks.
        data = (
            json.dumps(report, indent=2, ensure_ascii=True)
            .replace("`", "\\u0060")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
        )
        summary = report["executive_summary"]
        return (
            "# DDoS Sentinel incident report\n\n"
            f"Version: {__version__}\n\n"
            f"Simulations: {summary['simulations']} | Detections: {summary['detections']} | "
            f"Open incidents: {summary['open_incidents']}\n\n"
            "## Executive assessment\n\n" + summary["assessment"] + "\n\n"
            "## Technical evidence, metrics, recommendations and limitations\n\n"
            "```json\n" + data + "\n```\n"
        )
    if format == "html":
        environment = Environment(
            loader=FileSystemLoader(Path(__file__).parent / "templates"),
            autoescape=select_autoescape(["html"]),
        )
        return environment.get_template("report.html").render(report=report)
    raise ValueError("report format must be json, markdown or html")


def write_report(db: Database, config: LabConfig, format: str, output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_report(build_report(db, config), format), encoding="utf-8")
    return output
