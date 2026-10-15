# Local validation record

Validated on **2026-10-16**, Windows, Python **3.14.7**, in a newly created `.venv`.
The package was installed in editable mode with its development dependencies. Exact
verified dependency versions are recorded in `constraints.txt`.

| Check | Actual result |
| --- | --- |
| `python -m pytest -q` | **107 passed**, latest full run 48.67 seconds |
| `python -m ruff check src tests scripts` | Passed |
| `python -m ruff format --check src tests scripts` | Passed; 46 files formatted |
| `python -m mypy src` | Passed; 32 source files, Python 3.11 type target |
| `python -m pip check` | No broken requirements |
| `node --check src/ddos_sentinel/web/static/dashboard.js` | Passed |
| Installed `ddossentinel --version` and config validation | Passed; version 0.1.0 |
| `python scripts/demo.py --yes` | Passed; four bounded experiments, findings, throttling, reset, recovery and cleanup |
| JSON / Markdown / HTML reports | Generated and checked in the demo, CLI, API and packaged-wheel smoke |
| `python scripts/check_dashboard.py` | Passed using installed Edge headlessly |
| Desktop / mobile layout | Desktop screenshot inspected; 390px mobile viewport checked for horizontal overflow |
| Real loopback dashboard | Browser reached an ephemeral Uvicorn dashboard on 127.0.0.1; both services then stopped |
| `python -m pip wheel . --no-deps --wheel-dir dist` | Passed |
| `python scripts/check_package.py dist/ddos_sentinel-0.1.0-py3-none-any.whl` | Passed with isolated wheel imports, assets, service, reports and cleanup |

The tests cover public IP/domain/private-target rejection, ownership and fresh consent,
hard limits, dry runs, normal traffic, cancellation and no subsequent requests, service
lifecycle, all major abnormal scenarios, baseline lifecycle/import validation, severity,
incident grouping, action activation/expiry/reset, actual middleware behavior, SQL
injection, concurrent SQLite access, rollback, retention, dashboard security/escaping,
report privacy and sensitive-body non-storage. Test-wide socket and DNS guards reject
external connections; an AST regression guard checks for raw-packet and script/shell
execution APIs in the application package.

Release regression checks additionally cover chunked body limits, occupied ports,
unavailable-service detection and ownership revocation, client timeout evidence and
request correlation, contaminated baseline rejection, atomic mitigation linking,
unknown database versions, dashboard shutdown during a running job, and standalone
`lab start` / `lab stop` across processes. A failed client observation takes precedence
over a late service response and the correlation index stays bounded.

The demo and verification tools use temporary directories, remove their temporary
databases/reports and close their services. Generated repository-local screenshots,
wheel/build outputs and caches are ignored and uncommitted; automatic approval review
rejected their cleanup with "blocked by policy", including a more granular attempt.
No more specific reason was supplied. These generated directories therefore remain
locally, alongside the retained working virtual environment. No runtime databases,
logs, captures, secrets or generated reports are committed.

## Git milestones

These local branches represent actual implementation and validation work; their feature
commits are merged into `main` without rewriting the original commit or backdating work.

| Branch | Work |
| --- | --- |
| `feature/safety-foundation` | Configuration, hard limits, ownership capabilities, SQLite, audits and safety tests |
| `feature/traffic-lab` | Temporary service, metadata, paced scenarios and cancellation tests |
| `feature/detection-response` | Baselines, rules, incident lifecycle, measurements and expiring controls |
| `feature/dashboard-cli` | Feature CLI, dashboard, browser boundary, reports, documentation and CI |
| `test/release-validation` | Packaging, failure/cleanup regressions, service-exit safety and validation record |

No push is performed. The configured GitHub CI matrix has **not** been run remotely.
Only Windows / Python 3.14.7 was executed locally; Python 3.11 and other platforms await
the configured CI jobs. Successful checks are evidence for this revision, not a claim
that software can be proven 100% defect-free or suitable for production DDoS protection.

Remaining limits: synthetic loopback observations, heuristic uncalibrated confidence,
short training windows, approximate concurrency/churn, no portable RSS measurement,
and observational rather than causal mitigation effectiveness. Active state is preserved
by retention and should be reviewed by the analyst. Forced process termination cannot
complete graceful history finalization. See the README and safety model for scope.
