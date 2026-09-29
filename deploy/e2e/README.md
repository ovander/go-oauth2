# Socrate suite — e2e / security / performance harness

The scripts behind the suite's end-to-end, security and performance test report (the v1.3.0
report and its captured results are kept with the maintainers).

They assemble a production-shaped local stack (Postgres, the server, both
console BFFs, a backendkit-only sample app in `demoapp/`, and Caddy on
`*.localhost`), then drive it:

- `flows*.py`, `security.py`, `pentest.py`, `resilience.py`, `policy_rules.py`,
  `defenses.py`, `hardening.py` — stdlib-only HTTP/protocol checks.
- `*.cjs` — Playwright/Chromium browser flows (`harness.cjs` is shared).
- `sweep.js` — k6 capacity sweep; the B6 scenarios in `../perf` cover the rest.
- `smtp_sink.py` — a throwaway SMTP catcher for email flows.
- `results/` — where a run writes its output (git-ignored; captured results stay out of the
  public repository).

These are assessment scaffolding, not a CI suite: they expect the local stack
described above and hard-code sandbox ports. `demoapp/go.mod` had
its local `replace` directive stripped for committing; restore it (or `go mod
edit -replace`) to build against a working tree.
