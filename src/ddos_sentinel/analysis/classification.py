"""Describe observed patterns without asserting an actual distributed attack."""

from collections.abc import Sequence

from ddos_sentinel.core.models import Detection


def classify(detections: Sequence[Detection]) -> list[str]:
    labels = {
        "request-rate": "elevated HTTP volume",
        "sudden-rate-increase": "bursty HTTP volume",
        "endpoint-concentration": "endpoint concentration",
        "connection-churn": "connection churn",
        "slow-resource-occupation": "slow endpoint resource occupation",
        "coordinated-synthetic-clients": "coordinated synthetic client labels",
        "error-spike": "service error degradation",
        "high-latency": "latency degradation",
        "service-degradation": "severe service degradation",
    }
    return sorted({labels[detection.rule] for detection in detections if detection.rule in labels})
