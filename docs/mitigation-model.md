# Reversible mitigation

All controls run inside the temporary test service, sharing actions from the selected
SQLite database. Nothing modifies the OS firewall. Actions have a mandatory reason,
start time, TTL (at most 300 seconds), status, optional linked incident and audit trail.
Expiry is evaluated on requests and status reads; no request is blocked past expiry.
Use `mitigation reset --yes` to disable all controls. CLI and dashboard use the same
database; rate counters remain local to each service process.

| Mode | Behavior |
| --- | --- |
| global-throttle | Sliding one-second accepted-request budget per service |
| client-rate-limit | Separate sliding budget per synthetic client label |
| endpoint-rate-limit | Budget for one built-in endpoint |
| block-client | Temporary 403 for one synthetic client label |
| body-size-limit | 413 for metadata size above a reduced limit |
| circuit-breaker | Temporary 503 for requests |
| cooldown | Temporary 429 cooldown response |

At most 32 actions may be active. No automatic mitigation is enabled: an analyst
chooses a mode and TTL after inspecting a finding. A linked incident enters MITIGATING
and records its first mitigation time. Controls can be disabled individually by mode;
blocks can be removed with `mitigation unblock client-0`. Resets and expiry are audited.
The normal hard body limit and read timeout apply independently of mitigation actions.

Synthetic labels are trusted only for capability-authenticated lab traffic. They are
not real network identities or a production authentication system. Global and client
limits are teaching controls and are not an upstream DDoS defense.
