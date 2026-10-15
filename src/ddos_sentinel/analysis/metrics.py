"""Observed performance metrics; unavailable ground truth is represented by null."""

from collections.abc import Sequence
from typing import Any

from ddos_sentinel.core.models import TrafficSample
from ddos_sentinel.lab.telemetry import summarize


def simulation_metrics(
    simulation: dict[str, Any],
    samples: Sequence[TrafficSample],
    incidents: list[dict[str, Any]],
) -> dict[str, Any]:
    start = simulation["start_time"]
    end = simulation.get("end_time", start)
    summary = summarize(samples, max(0.001, end - start))
    detected = [incident["detection_time"] - start for incident in incidents]
    mitigated = [
        incident["mitigation_time"] - incident["detection_time"]
        for incident in incidents
        if incident.get("mitigation_time") is not None
    ]
    recovered = [
        incident["recovery_time"] - incident["detection_time"]
        for incident in incidents
        if incident.get("recovery_time") is not None
    ]
    accepted = sum(200 <= sample.status < 400 for sample in samples)
    before = [sample for sample in samples if sample.timestamp < start]
    during = [sample for sample in samples if start <= sample.timestamp <= end]
    after = [sample for sample in samples if sample.timestamp > end]
    errors = simulation.get("network_errors", 0)
    counts: dict[int, int] = {}
    for sample in during:
        bucket = int(sample.timestamp - start)
        counts[bucket] = counts.get(bucket, 0) + 1
    return {
        "time_to_detect_seconds": min(detected) if detected else None,
        "time_to_mitigate_seconds": min(mitigated) if mitigated else None,
        "time_to_recover_seconds": min(recovered) if recovered else None,
        "requests_accepted": accepted,
        "requests_throttled": summary.throttled,
        "requests_rejected": summary.rejected,
        "network_errors": errors,
        "peak_load_rps": max(
            [summary.rps, *counts.values(), *(incident["peak_rps"] for incident in incidents)]
        ),
        "peak_concurrency": summary.concurrency,
        "service_availability": accepted / (len(samples) + errors) if samples or errors else None,
        "latency_before_ms": summarize(before, 1).latency_p50 if before else None,
        "latency_during_ms": summarize(during, 1).latency_p50 if during else None,
        "latency_after_ms": summarize(after, 1).latency_p50 if after else None,
        "mitigation_effectiveness": None,
        "mitigation_response_fraction": (summary.throttled + summary.rejected) / len(samples)
        if samples
        else None,
    }


def evaluation_metrics(simulations: list[dict], incidents: list[dict]) -> dict[str, Any]:
    completed = [row for row in simulations if row["status"] == "COMPLETED"]
    positives = [row for row in completed if row["parameters"]["scenario"] != "normal"]
    negatives = [row for row in completed if row["parameters"]["scenario"] == "normal"]
    linked = {row["simulation_id"] for row in incidents if row["status"] != "FALSE_POSITIVE"}
    false_positive = {
        row["simulation_id"] for row in incidents if row["status"] == "FALSE_POSITIVE"
    }
    return {
        "scenario_detection_rate": sum(row["id"] in linked for row in positives) / len(positives)
        if positives
        else None,
        "scenario_false_positive_rate": sum(row["id"] in linked for row in negatives)
        / len(negatives)
        if negatives
        else None,
        "analyst_false_positive_incidents": len(
            [row for row in incidents if row["status"] == "FALSE_POSITIVE"]
        ),
        "missed_scenario_opportunities": [
            row["id"] for row in positives if row["id"] not in linked | false_positive
        ],
        "ground_truth_note": "Scenario labels are lab expectations, not production ground truth.",
    }
