from ddos_sentinel.analysis.metrics import simulation_metrics
from ddos_sentinel.core.models import TrafficSample


def sample(timestamp: float, status: int = 200, mitigation: bool = False) -> TrafficSample:
    return TrafficSample(
        timestamp=timestamp,
        endpoint="/",
        status=status,
        latency_ms=10,
        client_id="client-0",
        size=0,
        active=1,
        mitigation=mitigation,
    )


def test_observed_effectiveness_and_surrounding_traffic() -> None:
    simulation = {
        "start_time": 10,
        "end_time": 12,
        "parameters": {"scenario": "normal"},
        "baseline_snapshot": {"average_rps": 3, "latency_p95": 10, "error_rate": 0},
    }
    samples = [
        sample(10.1),
        sample(10.4),
        sample(10.7),
        sample(11.1),
        sample(11.4, 429, True),
        sample(11.7, 429, True),
    ]
    context = [sample(9), *samples, sample(13)]
    metrics = simulation_metrics(
        simulation, samples, [], context_samples=context, actions=[{"start_time": 11}]
    )
    assert abs(metrics["mitigation_effectiveness"] - 2 / 3) < 0.001
    assert metrics["latency_before_ms"] == metrics["latency_after_ms"] == 10
    assert metrics["requests_throttled"] == 2
    assert metrics["traffic_phases"]["before"]["count"] == 1
    assert metrics["baseline_comparison"]["rps_ratio"] == 1


def test_do_not_invent_effectiveness_or_double_count_network_failures() -> None:
    simulation = {
        "start_time": 10,
        "end_time": 12,
        "network_errors": 1,
        "parameters": {"scenario": "normal"},
    }
    metrics = simulation_metrics(simulation, [sample(10.1), sample(11, 0)], [])
    assert metrics["service_availability"] == 0.5
    assert metrics["mitigation_effectiveness"] is None
    assert metrics["latency_before_ms"] is None
    controlled_error = simulation_metrics(simulation, [sample(10.1, 503)], [])
    assert controlled_error["requests_rejected"] == 0
    circuit_breaker = simulation_metrics(simulation, [sample(10.1, 503, True)], [])
    assert circuit_breaker["requests_rejected"] == 1
