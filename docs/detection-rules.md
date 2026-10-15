# Detection rules and measurements

Rules compare rolling completed-request windows with a stored normal baseline. The
default window is one second. A shorter final window is evaluated at the end. Rates
measure observed completions, so they can differ from scheduled request rates. All
rules report the observed value, reference, threshold, confidence and explanation.
Reference defaults are explicitly labelled when no normal baseline has been learned.

| Rule | Trigger | Severity |
| --- | --- | --- |
| request-rate | RPS > max(20, mean x 2.5, peak x 1.5, mean + 3 standard deviations) | MEDIUM; HIGH after 3 windows |
| small-rate-deviation | RPS > max(10, mean x 1.5), below the main threshold | LOW |
| sudden-rate-increase | window-to-window increase > max(20, mean x 2) | MEDIUM |
| high-concurrency | concurrent work > max(10, baseline x 3) | MEDIUM |
| high-latency | p95 > max(150 ms, baseline p95 x 3) | HIGH |
| error-spike | error fraction > max(0.20, baseline + 0.15) | HIGH |
| endpoint-concentration | endpoint share > max(0.80, baseline share + 0.30) | MEDIUM |
| connection-churn | observed new connections/s > max(8, mean RPS x 1.5) | MEDIUM |
| slow-resource-occupation | slow endpoint majority and p95 x concurrency > max(400, baseline p95 x 6) | HIGH |
| coordinated-synthetic-clients | >10 labels and RPS > max(15, mean x 2) | MEDIUM |
| service-degradation | >80% observed request failure | CRITICAL |
| repeated-mitigation-responses | >5 throttle/rejection responses per window | MEDIUM |

Latency/error/distribution/churn/coordination/health rules require at least three
observations. The alert threshold filters LOW/MEDIUM/HIGH rules. INFO is reserved for
informational events. Normal requests use three endpoints; low-sample windows can
still produce noise. Tune the baseline and review findings rather than assuming attacks.

`baseline create` uses the most recent completed `normal` simulation and its last
configured baseline-window seconds. It stores average/peak RPS, population standard
deviation of one-second buckets, median/p95 latency (nearest rank), error fraction,
endpoint probabilities, peak concurrency, average size and observed health. Baselines
are deliberately never learned automatically from anomalous traffic. Small training
runs are useful for demos but are statistically weak. Imports validate schema version,
finite values, ranges, percentiles, known endpoints, and distribution totals.

Metrics use seconds and milliseconds as labelled. Time to detect = first detection -
simulation start; time to mitigate = first linked mitigation - first detection;
time to recover = observed recovery - first detection. Manual resolution is not measured
recovery. Recovery requires at least three successful observations with no detections
or mitigation responses in the same owned service; idle time does not prove recovery.

Availability = successful (2xx/3xx) responses / (observed responses + network errors).
Mitigation response fraction = (429 + 403/413/503 responses) / observed responses;
controlled 503 errors can overlap with rejection counts, so this is not causal proof
of mitigation effectiveness. Causal effectiveness is null until a comparable experiment
is designed. Detection rate = detected non-normal completed scenarios / non-normal
completed scenarios. Scenario false-positive rate = alerted normal completed scenarios /
normal completed scenarios. Analyst false positives are counted separately. These
scenario labels are expectations, not validated production attack ground truth.

Unobserved before/after latency and unreached lifecycle milestones are null, never
invented zeros. Process CPU time is measured using Python's process clock; portable
RSS memory measurement is unavailable without an optional OS-specific dependency.
