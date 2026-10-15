# Troubleshooting

- **Command not found:** activate `.venv` and install editable mode. You can also use
  `python -m ddos_sentinel.cli --help` without relying on the console-script PATH.
- **PowerShell activation is restricted:** activation is optional; run
  `.\.venv\Scripts\python.exe` and `.\.venv\Scripts\ddossentinel.exe` directly. No
  machine execution-policy change is needed.
- **Port already in use:** leave the lab target port at zero. Use `serve --port 8766`
  if dashboard port 8765 is occupied. No arbitrary bind-host option is provided.
- **Authorization declined:** each simulation requires confirmation or its own `--yes`.
  The dashboard checkbox resets after each start. Dry runs also need consent.
- **No baseline:** run `simulate normal --duration 10 --rate 6 --yes`, then
  `baseline create`. No automatic learning happens during abnormal workloads.
- **No alerts:** low rate, a short duration, high thresholds or an oversized baseline
  can explain this. Try a bounded `error-spike` and inspect raw rule explanations.
  A missed lab expectation is not evidence of real-world detection coverage.
- **Mitigations seem to continue:** inspect `mitigation status`; actions share the
  selected database. Reset with `mitigation reset --yes`. TTL is capped at 300 seconds.
- **Lab stop has no effect on the dashboard:** it only requests shutdown of standalone
  `lab start` processes sharing the same database. Stop `serve` using Ctrl+C.
- **Stale RUNNING records after a forced process kill:** graceful shutdown could not
  complete. Inspect timestamps/standalone heartbeat; historical status is not a process
  supervisor. The OS closes the socket and an in-memory capability cannot survive restart.
- **Database locked:** avoid placing the database on network filesystems. SQLite uses
  WAL and a busy timeout but cannot guarantee writes on a broken or read-only disk.
- **Missing old evidence:** retention intentionally prunes histories. Lower row caps
  can discard samples needed for a baseline; train again or increase the bounded cap.
- **Recovery metrics are null:** run observed successful traffic in the same dashboard
  lab after resetting controls. Idle windows or manual resolution do not prove recovery.
- **Browser says disconnected or CSRF rejected:** open exactly the printed loopback
  address and reload after restarting the server. Tokens rotate on restart. Embedded
  third-party pages and cross-origin control requests are rejected.
- **Optional browser test cannot launch:** Windows needs installed Edge or a named
  installed Chromium channel. Else install Playwright Chromium in a development setup.
- **Unobserved metrics:** the tool does not invent before/after samples, portable RSS
  values or causal mitigation effectiveness. Observed before/after load reduction is
  available only when its documented sampling conditions hold. See
  `docs/detection-rules.md` for formulas.
