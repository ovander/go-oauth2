# Socrate suite — e2e / security / performance harness

The scripts and captured results behind
[`docs/E2E-SECURITY-PERF-REPORT-v1.3.0.md`](../../docs/E2E-SECURITY-PERF-REPORT-v1.3.0.md).

They assemble a production-shaped local stack (Postgres, the server, both
console BFFs, a backendkit-only sample app in `demoapp/`, and Caddy on
`*.localhost`), then drive it:

- `flows*.py`, `security.py`, `pentest.py`, `resilience.py`, `policy_rules.py`,
  `defenses.py`, `hardening.py` — stdlib-only HTTP/protocol checks.
- `*.cjs` — Playwright/Chromium browser flows (`harness.cjs` is shared).
- `sweep.js` — k6 capacity sweep; the B6 scenarios in `../perf` cover the rest.
- `smtp_sink.py` — a throwaway SMTP catcher for email flows.
- `results/` — captured output from the run recorded in the report. Tokens and
  secrets have been redacted; treat the values as fixtures, not credentials.

These are assessment scaffolding, not a CI suite: they expect the local stack
described in the report's §2 and hard-code sandbox ports. `demoapp/go.mod` had
its local `replace` directive stripped for committing; restore it (or `go mod
edit -replace`) to build against a working tree.
