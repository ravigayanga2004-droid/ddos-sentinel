"""Observed performance metrics; unavailable ground truth is represented by null."""

from collections.abc import Sequence
from typing import Any

from ddos_sentinel.core.models import TrafficSample
from ddos_sentinel.lab.telemetry import summarize


def simulation_metrics(
    simulation: dict[str, Any],
    samples: Sequence[TrafficSample],
    incidents: list[dict[str, Any]],
    *,
    context_samples: Sequence[TrafficSample] | None = None,
    actions: Sequence[dict[str, Any]] = (),
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
    surrounding = samples if context_samples is None else context_samples
    before = [sample for sample in surrounding if start - 5 <= sample.timestamp < start]
    during = [sample for sample in samples if start <= sample.timestamp <= end]
    after = [sample for sample in surrounding if end < sample.timestamp <= end + 5]
    errors = simulation.get("network_errors", 0)
    unobserved_errors = max(0, errors - sum(sample.status == 0 for sample in samples))
    counts: dict[int, int] = {}
    for sample in during:
        bucket = int(sample.timestamp - start)
        counts[bucket] = counts.get(bucket, 0) + 1
    effectiveness = accepted_load_reduction(simulation, during, actions)
    baseline = simulation.get("baseline_snapshot")
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
        "service_availability": accepted / (len(samples) + unobserved_errors)
        if samples or unobserved_errors
        else None,
        "latency_before_ms": summarize(before, 1).latency_p50 if before else None,
        "latency_during_ms": summarize(during, 1).latency_p50 if during else None,
        "latency_after_ms": summarize(after, 1).latency_p50 if after else None,
        "traffic_phases": {
            "before": summarize(before, 5).model_dump() if before else None,
            "during": summarize(during, max(0.001, end - start)).model_dump() if during else None,
            "after": summarize(after, 5).model_dump() if after else None,
        },
        "baseline_comparison": {
            "rps_ratio": summary.rps / baseline["average_rps"] if baseline["average_rps"] else None,
            "p95_latency_ratio": summary.latency_p95 / baseline["latency_p95"]
            if baseline["latency_p95"]
            else None,
            "error_rate_delta": summary.error_rate - baseline["error_rate"],
        }
        if baseline
        else None,
        "mitigation_effectiveness": effectiveness,
        "effectiveness_note": "Observed accepted-load reduction across an in-run control change; "
        "not a causal estimate. Requires static scheduling and >=3 samples "
        "on each side; otherwise null.",
        "mitigation_response_fraction": (summary.throttled + summary.rejected) / len(samples)
        if samples
        else None,
    }


def accepted_load_reduction(
    simulation: dict[str, Any],
    samples: Sequence[TrafficSample],
    actions: Sequence[dict[str, Any]],
) -> float | None:
    """Measure a transparent before/after change only when both sides were observed."""
    if simulation["parameters"]["scenario"] == "burst" or not any(s.mitigation for s in samples):
        return None
    start, end = simulation["start_time"], simulation.get("end_time", simulation["start_time"])
    changes = [action["start_time"] for action in actions if start < action["start_time"] < end]
    if len(changes) != 1:
        return None
    boundary = changes[0]
    selected = next(action for action in actions if action["start_time"] == boundary)
    if min(selected.get("expires_at", end), selected.get("end_time", end)) < end:
        return None
    before = [sample for sample in samples if sample.timestamp < boundary]
    after = [sample for sample in samples if sample.timestamp >= boundary]
    if min(boundary - start, end - boundary) < 0.25 or min(len(before), len(after)) < 3:
        return None
    before_rate = sum(200 <= sample.status < 400 for sample in before) / (boundary - start)
    after_rate = sum(200 <= sample.status < 400 for sample in after) / (end - boundary)
    return 1 - after_rate / before_rate if before_rate else None


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
