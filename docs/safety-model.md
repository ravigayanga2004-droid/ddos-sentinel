# Safety model

DDoS Sentinel generates synthetic HTTP requests to a temporary service it owns on
127.0.0.1. It never accepts an arbitrary target URL through its CLI or dashboard.
`localhost` in configuration is normalized to the numeric loopback address without DNS.
Private network targets, public addresses, external domains, HTTPS, credentials in URLs,
redirects, proxies, plugin scripts, shell commands and raw packets are unsupported.
HTTPS is unnecessary for the ephemeral loopback service; other protocols fail validation.

Safety configuration cannot disable consent or enable external access. Hard ceilings:
60 seconds, 200 requests/second, 100 concurrent synthetic clients/connections and
65,536 bytes per request body. Configurations may only lower these limits.
Every simulation, including a dry run, needs fresh explicit consent. A live lab issues
an in-process ownership capability which is revoked on shutdown. A fabricated or stale
capability cannot authorize a simulation. This protects against accidental targeting;
Python code running with the user's privileges can of course change the program.

Traffic uses HTTPX with environment proxies disabled, redirects disabled and fixed
built-in endpoints. Synthetic client identifiers are labels, never spoofed IP addresses.
The scheduler spaces requests and drops scheduling opportunities when concurrency is full.
It never creates an unbounded backlog. Cancellation cancels and awaits every client task.

The test service authenticates synthetic traffic using a random per-lab capability,
checks body size while consuming bounded chunks, and stores only summary metadata.
Capabilities, bodies, cookies, authorization headers and arbitrary URLs are never stored.
The local dashboard has loopback Host/Origin checks, same-origin CSRF tokens, a strict
content security policy, escaped templates and explicit simulation/reset confirmations.
It is intended for a trusted single-user machine, not hostile multi-user hosting.

Mitigation acts only inside the test service. It does not touch the host firewall,
routing, external services or permanent operating-system settings. All actions expire
and can be disabled. Audits contain an allowlisted set of metadata fields.

Only use this project on systems you own and are authorized to test. It is a teaching
and measurement lab, not an attack tool, production DDoS protection, CDN/WAF, load-testing
platform, network IDS/IPS, SIEM or EDR. Installation may download Python packages;
experiments require no external network or services.
