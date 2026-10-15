# Development and verification

Use Python 3.11+ and a virtual environment. From the repository root:

```sh
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]" -c constraints.txt
python -m pytest -q
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src
python scripts/demo.py --yes
```

The optional constraints file records exact dependency versions verified on the local
development interpreter. Omit `-c constraints.txt` when intentionally updating versions,
then rerun checks. CI exercises Python 3.11 and 3.14 on Linux, Windows and macOS. A CI
configuration does not mean those remote jobs have already run.

The tests use temporary directories and ephemeral loopback servers. A test-wide DNS /
socket tripwire rejects external network access, including accidentally inherited
proxies. End-to-end scenario tests exercise the real TCP service, not just mocked
HTTP responses. Additional tests cover capabilities, hard limits, cancellation,
baseline import validation, incident grouping, reversible controls, reports, CSRF,
Host/Origin checks, escaping, transactions, SQL injection and retention. An AST guard
helps prevent raw-packet or script-execution APIs from entering the package; it is a
regression guard, not a formal proof of security.

For optional real-browser verification:

```sh
python -m pip install -e ".[ui]" -c constraints.txt
# Windows uses installed Microsoft Edge by default; no browser download needed.
python scripts/check_dashboard.py
# Linux/macOS: install a test browser, then run with the default Chromium channel.
python -m playwright install chromium
python scripts/check_dashboard.py --output .sentinel/dashboard.png
```

This test starts an ephemeral local dashboard, blocks external page requests, verifies
JavaScript, consent, simulation, baseline learning and a mobile viewport, then closes
the browser and both services and deletes its temporary database. Screenshots are
optional and ignored by Git when placed under `.sentinel/`.

Build a distributable wheel with `python -m pip wheel . --no-deps --wheel-dir dist`.
Then run `python scripts/check_package.py dist/ddos_sentinel-0.1.0-py3-none-any.whl`.
The package check compares archive files with the current source and runs an isolated
import/service/dashboard/report smoke test without processing editable-install paths.
Package data includes all dashboard and report templates/assets. Never commit virtual
environments, generated traffic, databases, logs or secrets. Use focused feature commits
and real milestone branches; do not manufacture dates or rewrite history.
