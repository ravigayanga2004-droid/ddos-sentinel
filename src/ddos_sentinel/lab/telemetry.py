"""Bounded rolling metadata, with latency percentiles computed transparently."""

import math
import statistics
import time
from collections import Counter, deque
from collections.abc import Sequence

from ddos_sentinel.core.models import TrafficSample, Window


def percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def summarize(samples: Sequence[TrafficSample], seconds: float, active: int = 0) -> Window:
    seconds = max(seconds, 0.001)
    count = len(samples)
    endpoints = Counter(sample.endpoint for sample in samples)
    errors = sum(sample.status == 0 or sample.status >= 500 for sample in samples)
    return Window(
        seconds=seconds,
        count=count,
        rps=count / seconds,
        latency_p50=statistics.median([sample.latency_ms for sample in samples]) if count else 0,
        latency_p95=percentile([sample.latency_ms for sample in samples], 0.95),
        error_rate=errors / count if count else 0,
        concurrency=max([active, *(sample.active for sample in samples)]),
        endpoints={endpoint: value / count for endpoint, value in endpoints.items()},
        clients=len({sample.client_id for sample in samples}),
        mean_size=statistics.mean(sample.size for sample in samples) if count else 0,
        health=1 - errors / count if count else 1,
        throttled=sum(sample.status == 429 for sample in samples),
        rejected=sum(
            sample.status in {403, 413} or (sample.status == 503 and sample.mitigation)
            for sample in samples
        ),
        churn=sum(sample.new_connection for sample in samples) / seconds,
    )


class Telemetry:
    def __init__(self, capacity: int = 20000) -> None:
        self.samples: deque[TrafficSample] = deque(maxlen=capacity)
        self.active = 0
        self.completed = 0
        self.dropped = 0

    def add(self, sample: TrafficSample) -> None:
        if len(self.samples) == self.samples.maxlen:
            self.dropped += 1
        self.samples.append(sample)
        self.completed += 1

    def window(self, seconds: float = 1, *, now: float | None = None) -> Window:
        cutoff = (time.time() if now is None else now) - seconds
        samples = [sample for sample in self.samples if sample.timestamp >= cutoff]
        return summarize(samples, seconds, self.active).model_copy(
            update={"dropped_samples": self.dropped}
        )
