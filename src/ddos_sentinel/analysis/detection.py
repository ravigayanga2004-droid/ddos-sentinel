"""Explainable, conservative rules. An anomaly is evidence, not proof of an attack."""

from ddos_sentinel.analysis.baseline import Baseline
from ddos_sentinel.core.models import SEVERITIES, Detection, Severity, Window


class Detector:
    def __init__(self, baseline: Baseline | None = None, threshold: str = "medium") -> None:
        self.baseline = baseline or Baseline()
        self.reference_only = baseline is None
        self.minimum = SEVERITIES[threshold.upper()]
        self.previous_rps = 0.0
        self.rate_windows = 0

    def evaluate(self, window: Window, simulation_id: str | None = None) -> list[Detection]:
        base = self.baseline
        results: list[Detection] = []

        def rule(
            name: str,
            observed: float,
            expected: float,
            threshold: float,
            severity: Severity,
            explanation: str,
            endpoint: str | None = None,
        ) -> None:
            if observed <= threshold or SEVERITIES[severity] < self.minimum:
                return
            reference = (
                " Reference defaults are in use; learn a normal baseline."
                if self.reference_only
                else ""
            )
            results.append(
                Detection(
                    timestamp=window.timestamp,
                    rule=name,
                    severity=severity,
                    confidence=0.65 if self.reference_only else 0.85,
                    explanation=explanation
                    + " This may be an authorized workload change."
                    + reference,
                    observed=observed,
                    expected=expected,
                    threshold=threshold,
                    endpoint=endpoint,
                    simulation_id=simulation_id,
                )
            )

        rate_threshold = max(
            20, base.average_rps * 2.5, base.peak_rps * 1.5, base.average_rps + 3 * base.rps_stddev
        )
        rule(
            "service-unavailable",
            float(not window.service_available),
            0,
            0,
            "CRITICAL",
            "The owned service has stopped. Traffic generation was terminated.",
        )
        self.rate_windows = self.rate_windows + 1 if window.rps > rate_threshold else 0
        rule(
            "request-rate",
            window.rps,
            base.average_rps,
            rate_threshold,
            "HIGH" if self.rate_windows >= 3 else "MEDIUM",
            "Request rate exceeds the baseline and static noise floor.",
        )
        if window.rps <= rate_threshold:
            rule(
                "small-rate-deviation",
                window.rps,
                base.average_rps,
                max(10, base.average_rps * 1.5),
                "LOW",
                "Small request-rate deviation.",
            )
        rule(
            "sudden-rate-increase",
            window.rps - self.previous_rps,
            0,
            max(20, base.average_rps * 2),
            "MEDIUM",
            "Request rate rose abruptly between windows.",
        )
        rule(
            "high-concurrency",
            window.concurrency,
            base.concurrency,
            max(10, base.concurrency * 3),
            "MEDIUM",
            "Concurrent service work exceeds normal.",
        )
        if window.count >= 3:
            rule(
                "high-latency",
                window.latency_p95,
                base.latency_p95,
                max(150, base.latency_p95 * 3),
                "HIGH",
                "95th-percentile latency is elevated.",
            )
            rule(
                "error-spike",
                window.error_rate,
                base.error_rate,
                max(0.2, base.error_rate + 0.15),
                "HIGH",
                "Controlled service error rate is elevated.",
            )
            endpoint, fraction = max(
                window.endpoints.items(), key=lambda item: item[1], default=("/", 0)
            )
            rule(
                "endpoint-concentration",
                fraction,
                base.endpoints.get(endpoint, 0),
                max(0.8, base.endpoints.get(endpoint, 0) + 0.3),
                "MEDIUM",
                "A single endpoint receives a disproportionate share of traffic.",
                endpoint,
            )
            rule(
                "connection-churn",
                window.churn,
                base.average_rps / 5,
                max(8, base.average_rps * 1.5),
                "MEDIUM",
                "New local TCP connections per second exceed the reference rate.",
            )
            if window.endpoints.get("/slow-test", 0) > 0.5:
                rule(
                    "slow-resource-occupation",
                    window.latency_p95 * window.concurrency,
                    base.latency_p95 * base.concurrency,
                    max(400, base.latency_p95 * 6),
                    "HIGH",
                    "Slow endpoint latency and concurrent work occupy lab resources.",
                    "/slow-test",
                )
            if window.rps > max(15, base.average_rps * 2):
                rule(
                    "coordinated-synthetic-clients",
                    window.clients,
                    1,
                    10,
                    "MEDIUM",
                    "Many synthetic client labels are active at an elevated request rate.",
                )
            rule(
                "service-degradation",
                1 - window.health,
                1 - base.health,
                0.8,
                "CRITICAL",
                "Most observed requests failed; inspect service health and controlled errors.",
            )
        rule(
            "repeated-mitigation-responses",
            window.throttled + window.rejected,
            0,
            5,
            "MEDIUM",
            "Repeated local throttle or rejection responses indicate mitigation pressure.",
        )
        self.previous_rps = window.rps
        return results
