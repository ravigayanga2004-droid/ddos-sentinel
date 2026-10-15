# DDoS Sentinel

A local-first defensive laboratory for learning normal HTTP traffic, detecting unusual
patterns, testing reversible mitigation and measuring incident response. Runs entirely
on your machine with Python, FastAPI and SQLite. No Docker, paid APIs, cloud services,
external target infrastructure or traffic-generation scripts are needed.

**Authorized local experiments only.** The application owns every target service and
binds to `127.0.0.1`. It rejects public addresses, public domains, private network
targets and arbitrary URLs. Every simulation requires fresh explicit consent. This
project teaches observation and response; it does not provide an attack tool.

## Quick start

Python **3.11+** is required. Installation downloads Python packages; experiments
themselves need no external network. Run these commands from the repository root.

**Windows PowerShell**

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]" -c constraints.txt
.\.venv\Scripts\ddossentinel.exe serve
```

Activation is optional. If you prefer, use `.\.venv\Scripts\Activate.ps1`, then
the shorter commands below. There is no need to change the machine execution policy.

**Linux**

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]" -c constraints.txt
ddossentinel serve
```

Some Linux distributions package venv separately; install your distribution's Python
venv package if `python3 -m venv` is unavailable.

**macOS**

```sh
# Use an installed Python 3.11+ interpreter.
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]" -c constraints.txt
ddossentinel serve
```

Open **http://127.0.0.1:8765**. The dashboard starts its own temporary loopback test
service on an ephemeral port. Run `normal`, learn its baseline, then try an
`error-spike` or another bounded scenario. Inspect findings, try a short-lived control,
reset it and run normal traffic to observe recovery. Ctrl+C stops dashboard jobs and
the owned service. Use `serve --port 8766` if the dashboard port is occupied.

For runtime dependencies only, use `python -m pip install -r requirements.txt`.
`python -m ddos_sentinel.cli` is an alternative to the `ddossentinel` entry point.

## A complete CLI experiment

```sh
ddossentinel init lab.json
ddossentinel validate lab.json
ddossentinel --config lab.json simulate normal --duration 10 --rate 6 --yes
ddossentinel baseline create
ddossentinel baseline show
ddossentinel simulate burst --duration 5 --rate 50 --clients 10 --yes
ddossentinel simulate error-spike --duration 3 --rate 20 --yes
ddossentinel incidents list
ddossentinel detections list
ddossentinel report --format json
ddossentinel report --format markdown
ddossentinel report --format html
```

Each CLI `simulate` creates, owns and stops a fresh test service. It never attaches to
an arbitrary listener or the service in another process. Results, baselines and actions
share `.sentinel/sentinel.db`. Use the dashboard or demo to compare multiple runs and
observe recovery within the same service lifecycle. `--yes` explicitly authorizes that
single invocation; without it the command prompts. Even dry runs require consent:

```sh
ddossentinel simulate --dry-run burst --duration 5 --rate 50 --yes
ddossentinel --database .sentinel/other.db --json status
```

Global `--config`, `--database`, and `--json` options go **before** the command.
Data output is JSON on stdout; Rich safety information goes to stderr. `--json` also
makes the pre-simulation safety summary JSON. `--help` is available for every command.
Reports default to the ignored `reports/` directory; set `--output path` to choose one.

## Features and commands

| Feature | Commands / behavior |
| --- | --- |
| Configuration | `init <config>`, `validate <config>`, global `--config` |
| Lab service | `lab start` in the foreground; `lab stop` requests its graceful shutdown |
| Service endpoints | `/`, `/health`, `/api/test`, `/slow-test`, `/error-test`; no files or external calls |
| Scenarios | `normal`, `burst`, `endpoint-concentration`, `connection-churn`, `slow-request-pattern`, `synthetic-distributed`, `error-spike` |
| Baselines | `baseline create/show/reset/export/import`; versioned statistical summaries |
| Detection | `detections list`, `detections show <id>`; observed values, thresholds and explanations |
| Incidents | `incidents list/show/acknowledge/resolve/export`; notes and false-positive decisions |
| Local controls | `mitigation status/enable/disable/reset/unblock`; expiring, reversible middleware |
| Reports | `report --format json/markdown/html`; executive summary and technical evidence |
| Dashboard | `serve`; traffic chart, current metrics, baseline, findings, incidents, controls and history |
| Demo | `python scripts/demo.py`; prompts for every predefined experiment |

`lab start` is a standalone service demonstration. Its public loopback `/health`
endpoint can be inspected locally; synthetic endpoints require an internal capability.
`lab stop` only affects standalone commands using the same database. Stop `serve` using
Ctrl+C. No process is killed and no persistent background service is installed.

### Incident and mitigation examples

Replace the example IDs with IDs returned by your local commands:

```sh
ddossentinel incidents show INCIDENT_ID
ddossentinel incidents acknowledge INCIDENT_ID --notes "Reviewing the controlled workload"
ddossentinel mitigation enable global-throttle --reason "Lab cooldown" --rate 5 --ttl 30 --incident-id INCIDENT_ID
ddossentinel mitigation status
ddossentinel mitigation disable global-throttle
ddossentinel mitigation enable block-client --client-id client-0 --reason "Synthetic client test" --ttl 15
ddossentinel mitigation unblock client-0
ddossentinel mitigation reset --yes
ddossentinel incidents resolve INCIDENT_ID --notes "Reviewed and closed"
ddossentinel incidents export INCIDENT_ID --output reports/incident.json
ddossentinel baseline export baseline.json
ddossentinel baseline import baseline.json
ddossentinel baseline reset --yes
```

Additional modes are `client-rate-limit`, `endpoint-rate-limit` (use `--endpoint`),
`body-size-limit` (use `--body-limit`), `circuit-breaker`, and `cooldown`. There is no
automatic mitigation by default. Actions affect only owned services using the chosen
database. They need a reason and expire within 300 seconds; at most 32 are active.
Per-service rate counters are in memory. Nothing modifies the host firewall or external
systems. Manual incident resolution records an analyst decision; observed recovery is
measured separately. Use `incidents resolve ... --false-positive` for reviewed noise.

## Visible safety ceilings

| Control | Hard maximum |
| --- | --- |
| Simulation duration | 60 seconds |
| Scheduled rate | 200 HTTP requests/second |
| Synthetic clients / request concurrency | 100 |
| Request body | 65,536 bytes |
| Configurable artificial latency | 2,000 ms |
| Mitigation TTL | 300 seconds |

Configuration can lower these values, never raise them. Body tests use a fixed harmless
payload, never user-supplied content. The scheduler spaces requests, drops opportunities
when clients are occupied and never accumulates an unbounded queue. Requests stop at the
duration deadline, followed by a bounded drain of service work already received.
Cancellation awaits client tasks and records the cancelled run. Dry runs validate and
audit parameters without sending requests. Local HTTP is the only supported protocol
for these ephemeral services; HTTPS and private-network labs are deliberately unsupported.

There are no raw packet generators, SYN/UDP floods, IP spoofing, reflection,
amplification, botnets, arbitrary-target requests, stealth, persistence or evasion.
HTTPX ignores environment proxies and never follows redirects. Synthetic client IDs
are metadata labels, not spoofed network identities.

## Detection and measurement

Normal baselines use explicit training runs, rolling averages, population standard
deviation, endpoint distributions and latency percentiles. No opaque machine-learning
claims are made. Rules cover volume, rate changes, concurrency, latency, error spikes,
endpoint concentration, churn, slow work, synthetic coordination, degraded service
and repeated mitigation responses. Each finding includes severity, a heuristic
confidence label, uncertainty, observed value, reference, threshold and related IDs.

Related detections form one active incident per simulation. Severity can escalate;
analysts can acknowledge, annotate, resolve or mark false positives. Successful
observed traffic in the same service can establish recovery; idle time cannot.

Reports include selected configuration and safety settings, simulation parameters,
baseline snapshots/comparisons, traffic before/during/after when observed, timeline,
findings, incidents, controls, detection/mitigation/recovery times, availability,
scenario detection/false-positive rates, missed lab expectations, recommendations,
limitations and tool version. Unobserved values are `null`. Observed accepted-load
reduction is computed only when an in-run control change has enough comparable samples;
it is not a causal effectiveness claim. See [rule formulas](docs/detection-rules.md).

## Privacy and trust

SQLite and bounded in-memory buffers store request metadata only. Bodies, cookies,
authorization headers, capability tokens and arbitrary URL queries are not stored.
Structured action audits use an allowlist of fields. Do not put secrets in analyst
notes or mitigation reasons. Database files, logs, reports, captures, `.env`, credentials
and the virtual environment are excluded from Git. Default telemetry retention is
seven days and 50,000 rows per history table; active state and the current baseline
are preserved. Review active incidents regularly.

The dashboard is for a trusted single-user machine. It binds to loopback, checks
Host/client/Origin, validates strict control payloads, uses CSRF tokens and confirmations,
escapes user content and loads all assets locally under a strict CSP. These controls
are not a substitute for authentication on a multi-user or remotely exposed server.

## Test and demo

```sh
python -m pytest -q
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src
python scripts/demo.py --yes
```

The demo's `--yes` explicitly authorizes each of its four predefined local experiments.
It trains a baseline, triggers errors, demonstrates throttling and reset, observes
healthy traffic, renders JSON/Markdown/HTML reports, stops the service and removes its
temporary database and working reports. To retain only exported reports, add
`--output reports/demo`. Tests use temporary directories and a network tripwire that
rejects external connections and DNS.

Optional headless browser QA (Windows uses installed Edge):

```sh
python -m pip install -e ".[ui]" -c constraints.txt
python scripts/check_dashboard.py
```

Local validation and actual results are recorded in [docs/validation.md](docs/validation.md).
The CI matrix covers Python 3.11/3.14 on Windows, Linux and macOS when run on GitHub;
remote CI results are not implied by the local checks.

## Project map

```text
src/ddos_sentinel/
├── core/        Safety, authorization, configuration, SQLite, records, audits
├── lab/         Temporary service, simulation, telemetry, orchestration
├── analysis/    Baselines, detection, classification, measurement
├── response/    Incidents and expiring mitigation
├── commands/    CLI groups by feature
├── api/         FastAPI routes, lifespan and browser security
├── reports/     Exports and standalone report template
├── web/         Dashboard templates and local assets
└── cli.py       CLI entry point
tests/           Unit, integration, lifecycle and security regression tests
scripts/         Self-cleaning demo and optional browser smoke test
examples/        Safe default JSON configuration
docs/            Architecture, rules, safety, configuration, development and validation
```

Start with [architecture](docs/architecture.md), [safety](docs/safety-model.md),
[configuration](docs/configuration.md), [detection rules](docs/detection-rules.md),
[mitigation](docs/mitigation-model.md), [development](docs/development.md), or
[troubleshooting](docs/troubleshooting.md).

## Limits and next steps

DDoS Sentinel is **not a replacement** for an ISP or upstream DDoS protection service,
a CDN/WAF, a production load-testing platform, a network IDS/IPS, a complete SIEM or
an EDR platform. It observes its own synthetic HTTP requests, not real internet traffic.
ASGI request concurrency approximates service work; it is not kernel socket occupancy.
Connection-churn counts use a bounded cache. CPU time is measured for the process;
portable RSS memory measurement is unavailable. Tiny windows and weak baselines can
produce noise. Active state is retained intentionally; graceful shutdown cannot be
guaranteed after an OS crash or forced kill. Use local storage for SQLite.

Useful future work includes longer validated training datasets, calibrated rule
evaluation, optional portable resource metrics, richer report visualizations and
schema migrations. Any extension must preserve explicit consent, owned local targets,
fixed ceilings, privacy and reversible controls. Never use this project against a
system without authorization.

MIT licensed; see [LICENSE](LICENSE). Feature branches and merge commits document real
implementation stages. Nothing is pushed automatically.
