# Configuration

Create JSON with `ddossentinel init lab.json`, or copy `examples/local-lab.json`.
Validate before use: `ddossentinel validate lab.json`. Select it using the global
option **before** the command: `ddossentinel --config lab.json simulate normal --yes`.
Database paths are selected separately with `--database .sentinel/sentinel.db`.
All paths are relative to the working directory, unless you supply an absolute path.
No environment files, commands, plugins or scripts are loaded from configuration.
`--body-size` uses a fixed payload on `/api/test` and cannot be combined with the
slow-request-pattern or error-spike scenarios, whose controlled endpoints use GET.

| Setting | Default | Validation |
| --- | --- | --- |
| lab_name | local-training-lab | 1–80 characters; escaped in dashboard |
| target.host | 127.0.0.1 | literal 127.0.0.1 or localhost only; no DNS |
| target.port | 0 | 0 picks an ephemeral port; otherwise 1–65535 |
| target.protocol | http | temporary loopback HTTP only |
| target.service_type | temporary_test_service | application-owned services only |
| safety.localhost_only | true | cannot be disabled |
| safety.allow_private_networks | false | cannot be enabled |
| safety.allow_public_targets | false | cannot be enabled |
| safety.synthetic_traffic_only | true | cannot be disabled |
| safety.require_explicit_authorization | true | cannot be disabled |
| safety.dry_run | false | true forces all runs to be dry |
| limits.max_duration_seconds | 60 | >0 to 60 |
| limits.max_clients | 100 | 1–100 |
| limits.max_requests_per_second | 200 | 1–200 |
| limits.max_request_body_bytes | 65536 | 0–65536 |
| detection.baseline_window_seconds | 60 | 1–3600; last part of selected normal run |
| detection.alert_threshold | medium | low, medium, high |
| detection.window_seconds | 1 | 0.1–10 |
| artificial_latency_ms | 250 | 0–2000; only /slow-test |
| retention_days | 7 | 1–90 |
| max_telemetry_rows | 50000 | 100–100000 per event table |

The JSON file is limited to 64 KiB. Unknown fields, unsupported target types, invalid
ports, infinite/NaN values, conflicting safety overrides and over-limit numbers fail
validation. Integer limits reject booleans. Baseline imports are separately bounded
to 1 MiB and have a strict versioned schema. Exported baseline files contain only
aggregate traffic statistics and may be committed deliberately if they contain no
private lab metadata; this repository does not include generated training data.
