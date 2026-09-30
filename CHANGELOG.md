# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases follow the platform programme (current line: **v1.x — Foundations & Additive
Capabilities**, non-breaking).

## [Unreleased]

## [1.6.0] - 2026-09-30

Minor release on the **v1.x** line. Magic links work: the email opens the app's own page, which
posts the token to the verify endpoint. An app's backend can look up one of its members with its
service-account token. **Migration `0026`** adds the nullable `apps.magic_link_url` column (it runs
at start-up, without `AUTO_MIGRATE`). No new environment variable. One behaviour change: an app
without a `magic_link_url` gets `409` from `POST /api/apps/{app_id}/service/magic-link` instead of
a `202` and an email whose link answered 405. Set the field with `PUT /api/admin/apps/{id}` for each
app that sends magic links.

### Added

- **`GET /api/apps/{app_id}/service/users/{user_id}`: an app's backend looks up one of its members
  with its service-account token.** The existing `GET /api/apps/{app_id}/users/{user_id}` needs a
  user token from an app admin, so a service token got `401`, and backendkit's `GetUserAsService`
  could not work. The new route returns the same body, only for a member of that app (anyone else
  is a `404`, a Socrate admin included). It sits under `ServiceAccountMiddleware` like the other
  `/service` routes (the token's `sub` must be `app:{app_id}`).

### Fixed

- **Magic links open the app's own page.** The email linked to `GET /api/auth/magic-link/verify`,
  an endpoint that only accepts POST (so that mail scanners cannot consume the token), so every
  magic link answered 405. An app now registers the page its magic-link emails open,
  `magic_link_url` (new, optional, on `POST`/`PUT /api/admin/apps`, and in `AppResponse`). The
  email links to that page with `token` and `client_id` in the query; the page posts them to the
  verify endpoint, as the backendkit integration guide already describes. The URL must be `https`
  (`http` only for localhost) and share an origin with one of the app's `redirect_uris`. A change
  to it is audited like a redirect URI change. An app without it gets `409` from
  `POST /api/apps/{app_id}/service/magic-link` instead of a `202` and an email with a dead link.
  Migration `0026` adds the nullable `apps.magic_link_url` column.

## [1.5.3] - 2026-09-30

Patch release on the **v1.x** line. A Socrate admin or superadmin is never an app member, even if a
role row reaches the database directly; the legacy-data carry-over is safe on a non-empty new
server; apps on a separate VPS are documented. No migration, no new environment variable. One
behaviour change: a global `admin` holding explicit app roles no longer carries them in
`app_roles`, like a superadmin (it keeps `admin` on every app through its global role).

### Security

- **A Socrate admin or superadmin is never an app member, and an app member is never a Socrate
  admin.** The two global roles are one platform profile (`IsGlobalAdmin`) with access to every
  app. Before this change, the admin API refused only a *superadmin* as an app member, so a
  global `admin` could be added with any app role. A `user_app_roles` row written directly
  (e.g. by a data migration from a server that did not enforce the rule, or left over when a
  member was made a Socrate admin) was honoured for both roles. That put a platform account
  within reach of that app's admins, whose member actions (force password reset, resend
  verification, role change) are gated on membership, and added the role to its tokens.
  - The `user_app_roles` repository now ignores the rows of both global roles on every read
    (`FindByUserAndApp`, `FindByUser`, `FindAllByUser`, `GetUserRolesMap`, and `FindByApp` as
    before). The membership gate therefore refuses such a target.
  - `Create` and `Update` refuse to write one (`ErrGlobalAdminAppRole`); `Delete` still removes
    a stray row.
  - The admin API refuses to add a Socrate admin to an app with any app role (403).

  Both roles keep their global access to every app. **Behaviour change:** a global `admin` that
  held explicit app roles no longer carries them in `app_roles`, as for a superadmin; it still
  gets `admin` on every app through its global role. Remove such rows with
  `DELETE FROM user_app_roles r USING users u WHERE u.id = r.user_id AND u.role IN ('admin','superadmin')`.

- **The carry-over no longer gives a Socrate admin an app role.** A Socrate admin or
  superadmin (one platform profile, global access) is never an app member, because as an app
  member the platform account would be exposed to that app's admins (e.g. a forced password
  reset). `deploy/migration/carry-over.sh` wrote role rows straight into the database, so a legacy
  admin kept its legacy app roles. It now drops role rows whose user is an admin or superadmin on
  the new server, and `carry-over-preflight.sh` lists them. Rows already carried are removed with
  `DELETE FROM user_app_roles r USING users u WHERE u.id = r.user_id AND u.role IN ('admin','superadmin')`.

- **The carry-over imports no legacy global role except superadmin.** It copied each legacy
  user's global `role` as-is, so a legacy global `admin` would have arrived as a platform admin
  on the new server, with access to the admin console. A carried user now arrives as a plain
  `user` unless its legacy role is `superadmin`; its app roles are kept. `carry-over-preflight.sh`
  lists every demotion, and warns about each legacy superadmin that would be imported.

### Fixed

- **Carry-over into a non-empty new server no longer loses or misassigns identities.**
  `deploy/migration/carry-over.sh` assumed an empty target. Its `ON CONFLICT DO NOTHING`
  silently skipped any legacy user or app whose id or email was already taken on the new
  server, typically by the first superadmin, the console clients or a hand-registered app. A
  skipped user's `sub` then pointed at someone else or changed, and a skipped app's roles
  attached to another app. Its sequence reset could also move the id sequences backwards.
  - New `carry-over-preflight.sh` (read-only) names every such collision, checks the id
    reservation and reports MFA users.
  - New `reserve-legacy-ids.sh` moves the new server's id sequences past the legacy ranges.
  - New `move-user-to-legacy-id.sh` gives an account created on the new server its legacy id
    without rewriting the HMAC-chained audit rows: the old row is retired, a copy is inserted
    under the legacy id, and recovery codes, roles and owned apps move with it.
  - `carry-over.sh` gains `EXCLUDE_USERS` for obsolete accounts, and only ever moves sequences
    forward.

  The procedure is in `deploy/migration/README.md`. No server code change.

### Added

- **Apps on a separate VPS (docs and deploy scripts).** `docs/DEPLOYMENT-VPS-MULTI-APP.md` §6.7
  documents running relying-party apps on their own VPS. OAuth calls stay on the public issuer.
  The loopback-only admin API is reached through a restricted SSH tunnel: one key, one forward,
  only from the apps address, no shell, pinned host key. Caddy trusts `X-Forwarded-For` from
  that single address only. The section also gives the verification checks and the undo steps.
  `deploy/scripts/socrate-apps-access.sh` (Socrate VPS) and `deploy/scripts/apps-socrate-tunnel.sh`
  (apps VPS) implement it; both are idempotent and dry-run by default.

### Changed

- Docs: `docs/DEPLOYMENT-VPS-MULTI-APP.md` §4.4 now describes the client-IP chain as the code
  implements it. Socrate takes the **leftmost** `X-Forwarded-For` entry from a trusted peer
  (the section said it walked from the right). The BFFs replace the header with the address they
  resolved instead of appending to it. The invariants, the Caddy conventions and the security
  checklist now allow the one `trusted_proxies` exception of §6.7. No code change.

## [1.5.2] - 2026-09-29

Patch release on the **v1.x** line. An unknown `client_id` at the token endpoint is answered
`401 invalid_client`, like a wrong secret, instead of `500`, and is now audited. No migration, no
new environment variable, no change to the token contract.

### Fixed

- **Unknown `client_id` at the token endpoint answers `401 invalid_client`, not `500`.** The three
  grants turned a missing app into `ErrAppNotFound`, which the token handler did not map, so an
  unknown client got `500 server_error` (immediately on `client_credentials`; on the code and
  refresh grants when the code or token was valid). It is now answered exactly like a wrong
  secret (`invalid_client`, same description; RFC 6749 §5.2), so the response does not reveal
  which clients exist, and audited as `client_auth_failed` with reason `unknown_client`, which it
  was not before. Only a real not-found is treated this way: any other app-lookup error, such as
  the database being unavailable, stays a `500`.

## [1.5.1] - 2026-09-29

Patch release on the **v1.x** line. The admin API's OAuth client lifecycle events now audit the
client IP resolved from `TRUSTED_PROXIES`, not a forwarding header any peer can send. No
migration, no new environment variable, no change to the token contract.

### Fixed

- **Client-lifecycle audit events use the trusted client IP.** `LogFromRequest` (the admin API's
  OAuth client lifecycle events) read the leftmost `X-Forwarded-For`, then `X-Real-IP`, from any
  peer, ignoring `TRUSTED_PROXIES`, so a peer could choose the address that was audited. It now
  uses the IP `middleware.ClientIP` resolved (forwarding headers honoured only from trusted
  proxies), falling back to the bare peer address; the unused `extractIPAddress` is removed. The
  User-Agent there is also cut on a character boundary, so an over-long one can no longer make
  PostgreSQL reject the row.

## [1.5.0] - 2026-09-29

Minor release on the **v1.x** line. It fixes three defects found after v1.4.0 went live — audit
rows without a client IP, cluster jobs running once per instance, and fake build info on the
dashboard health endpoint — and completes the build info with the Go toolchain. **One migration
(0025, additive)**; no new environment variable; no change to the token contract (`/version`
only gains a field).

### Added

- **`/version` reports the Go toolchain.** The response (also `/api/version`) gains
  `go_version`, the toolchain that compiled the binary (`runtime.Version()`, e.g. `go1.27.1`),
  so the build info is complete; the startup log line carries it too. Additive: the existing
  `version`, `commit`, `branch` and `build_time` keys are unchanged.

### Fixed

- **Dashboard health reports the real build.** `GET /api/admin/dashboard/health`, shown in the
  monitoring console's System Health card, returned a hard-coded `version: "1.0.0"` and
  `details.go_version: "1.21+"`; it now returns the binary's version and Go toolchain.
- **Scheduled jobs run once per interval across a cluster, as documented.** With the shared
  (`STATE_BACKEND=postgres`) scheduler, the advisory lock only stopped two instances running a job
  at the same moment. Instances tick on their own schedules, so each ran it once per interval:
  N instances rotated the signing key N times as often (the "once per cluster" promise in
  `bootstrap.go`). `cluster.Every` now also records each job's last completed run in the new
  `cluster_job_runs` table (**migration 0025**) and skips a tick when another instance completed
  the job within 90% of the interval; a failed run is not recorded, so the next tick retries. If
  the table cannot be read it falls back to the previous behaviour and logs a warning.
  Single-instance deployments (the default in-memory state backend) are unaffected.
  `TestTryWithLock_OnlyOneOfManyRuns` no longer depends on timing (it holds the lock until every
  other caller has tried), and the lock tests close their connection pools, so
  `go test -race -count=50` no longer exhausts `max_connections`.
- **Audit rows written by the auth and OAuth services carry the client IP and User-Agent.**
  `authService`/`oauthService.logSecurityEvent` wrote every row with both empty, so login, lockout,
  password, MFA and token events had no IP: the monitoring console's Geo analytics, location
  anomalies, sessions, suspicious IPs and unique-attacker counts saw none of them. The builder now
  takes both from the request context, where `middleware.ClientIP` already stores the
  trusted-proxy-aware IP (it now also stores the User-Agent, `contextkeys.UserAgentKey`); the
  User-Agent is cut to the 500-byte column on a character boundary. Rate limiting, IP blocking and
  auto-defense were not affected: they read the IP from the request directly. Rows written before
  the upgrade keep their empty IP.

## [1.4.0] - 2026-09-29

Minor release on the **v1.x** line, and the first under the Apache-2.0 licence and the
`github.com/ovander/go-oauth2` module path. It ships three fixes found by the v1.3.0 end-to-end
test pass (F2, F3, F8), the migration tooling for moving applications to a new Socrate instance,
and the public-repository kit. No migration, no new environment variable, no change to the
token contract.

### Changed

- README states v1.4.0; the pre-deploy checklist's example deploy tag is `v1.4.0`.
- **Licence: Apache-2.0** (`LICENSE`). The README had declared MIT with no licence file, and
  `pkg/logger` still carried a proprietary header from another product; both are gone.
- **Module path `github.com/ovander/go-oauth2`** (was `github.com/ovandermoten/go-oauth2`, which
  did not match the repository, so `go get` failed). Imports, the Makefile's `-ldflags` package
  path and the docs follow. No behaviour change.
- `make deploy` now requires `VPS=user@host` (it defaulted to one maintainer's host) and stages
  files in the remote user's home directory.

### Fixed

- **Refresh grant honours the global-admin bypass** (#255). A superadmin signed in to a client
  without a membership row lost the session at the first refresh (500 at the BFF). A dead grant
  (`ErrRoleNotFound` / `ErrUserNotFound`) now answers `invalid_grant` (400) instead of
  `server_error` (500), and the `token_revoked` audit row on the client-authenticated
  `/oauth/revoke` path no longer fails its foreign key and gets dropped.
- **Live event stream starts at the tip** (#263, F3). `GET /api/admin/events/stream` without
  `last_event_id` seeded from 0 and replayed the oldest audit rows until its write timeout;
  it now seeds from `MAX(id)`. An explicit `last_event_id` still resumes.
- **Audit-integrity status says `not_scanning`** (#263, F8) when the background scanner is
  disabled, instead of claiming `verified` for rows that are only stamped.
- CI: golangci-lint is built with `go.mod`'s toolchain, so the lint job runs again (#254).

### Added

- `SECURITY.md` (private vulnerability reporting, scope, supported versions), `CONTRIBUTING.md`,
  `CLAUDE.md`, `CODEOWNERS`, issue forms, a pull-request template, and a **`Release` workflow**
  that publishes a tag's CHANGELOG section as the GitHub release.
- `deploy/PRE-DEPLOY-CHECKLIST.md`, the on-host configuration the repository cannot verify;
  `socrate.service` marked as the canonical unit (#264).
- `deploy/migration/`: the application compatibility prompt, the confirmed v1.3.0 OP contract,
  and `carry-over.sh`, the ID-preserving data migration (#265, #266).
- `deploy/e2e/`: the end-to-end, security and performance harness used for v1.3.0 (#256).

### Removed

- Internal planning and audit documents left the public tree (`docs/program/`, the `docs/CR-*`
  change requests and audit passes, the v1.3.0 test report and its captured results). Product
  docs stay; three were renamed: `docs/AUTH-FLOWS.md`, `docs/GEO-ANALYTICS-API.md`,
  `docs/TEST-STRATEGY.md`.

## [1.3.0] - 2026-09-27

Minor release on the **v1.x — Foundations & Additive Capabilities** line. It is
the first tag since v1.1.1, so it also ships everything listed under 1.2.0
below, which was never tagged on its own. Closes the pass-3 and pass-4 security
findings, adds the extensibility surface (per-client scope policy, declarative
custom claims, in-process hooks, outbound webhooks, and the policy decision
point: on the admin API in `off`/`shadow`/`enforce` modes, as a decide
endpoint for applications, and with a decision log for the SOC),
observability (Prometheus metrics, log-redaction guard, k6 baseline) and
multi-instance groundwork (shared state, cluster locks), and moves the build
toolchain to Go 1.27.1. Migrations `0015`–`0024` run forward only: take a
database backup before upgrading. Read the upgrade notes below first — P3-1
and P3-9 change who may call the admin API and how MFA is disabled.

> **Upgrade note (P3-2):** client-IP attribution no longer trusts headers from
> arbitrary peers. `TRUSTED_PROXIES` now **defaults to loopback**
> (`127.0.0.1/32,::1/128`), which matches the documented same-host Caddy/BFF
> topology. If your reverse proxy connects from another address, set
> `TRUSTED_PROXIES` to it or rate limits, IP blocks and auto-defense will key
> on the proxy's address instead of the client's. Set `TRUSTED_PROXIES=none`
> only when Socrate is exposed directly with no proxy.

> **Upgrade note (P3-1):** `/api/admin/*` now requires a **global admin**
> (`role=admin` or `role=superadmin`), and `/api/admin/superadmins/*` requires
> `role=superadmin`. Accounts that used the admin or monitoring console with a
> plain `user` role — relying on console-side UI gating or OAuth scopes — will
> now receive 403 and must be promoted to a global admin role.

> **Upgrade note (P3-9):** `POST /api/profile/mfa/disable` now requires a JSON
> body `{"password": "...", "code": "..."}` — the account password (when the
> account has one) and a current TOTP code or an unused recovery code. A bare
> authenticated POST returns 400/401 and leaves MFA enabled.

> **Upgrade note (P3-4):** authorization requests that send `code_challenge`
> must also send `code_challenge_method=S256`. An omitted method (previously
> accepted and verified as *plain*) or `plain` is now rejected with
> `invalid_request`, matching what discovery has always advertised.

### Added

- **Policy decisions for applications (A4 part 2 / EPIC-11).**
  `POST /api/apps/{app_id}/service/policy/decide` lets an application's
  backend, authenticated by its client-credentials token, ask the PDP about one
  of its own users. The subject is resolved by Socrate — role, attributes,
  forced password change and role in the calling application — from either the
  user's access token (verified with exactly `AuthMiddleware`'s checks, now
  shared as `middleware.VerifyUserToken`, and the only source of `scopes`,
  `amr` and `auth_time`) or a user id; a user who is not a member of the
  calling application is `404`, indistinguishable from one that does not exist.
  The application supplies only the action, the resource and the request
  context. The admin action namespace is refused; a locked subject is denied
  without evaluation. Every answer carries the central `POLICY_MODE`, so the
  application's enforcement point knows whether to ignore, log or honour it —
  one switch on Socrate moves every application from shadow to enforce with no
  redeploy. Denials in shadow and enforce go to the decision log with
  `source=decide_api`, the caller's `client_id` and its correlation id. The
  matching backendkit release adds `socrate.Client.Decide` and the `pep`
  enforcement package.
- **Policy decision point on the admin API (A4 part 1 / EPIC-10 / RFC-005).**
  Authorisation rules as data: `internal/policy` evaluates declarative JSON
  rules — RBAC over the global role, ABAC over the A2 user attributes, token
  facts (`scopes`, `amr`, `auth_time` age) and request context (IP, CIDR,
  country with GeoIP, hour) — with `all`/`any`/`not`, attribute-to-attribute
  comparisons for object-level checks, and `require_fresh_auth` /
  `require_mfa` obligations. **Deny overrides, default deny**, and a comparison
  against a missing attribute is *unknown* rather than false: an unknown allow
  does not allow and an unknown deny denies, so incomplete data can make the
  policy stricter, never looser. The rule set is stored as immutable numbered
  versions (migration `0023`) with optimistic concurrency (`409` on a stale
  base) and forward-only restore; every save is validated as a whole and every
  problem reported at once. Version 1 is seeded with a **baseline that restates
  the existing code gates** (`RequireGlobalAdmin`, superadmin-only management,
  forced password change, step-up on the 16 destructive routes) — a router
  test walks every admin route for every kind of principal and asserts the two
  agree everywhere. `POLICY_MODE=off|shadow|enforce` (default `off`): in
  `shadow` the admin API's new enforcement point evaluates every request,
  never changes a response, and records every would-be denial and every
  disagreement with the code gates (`pdp_deny_code_allow` /
  `pdp_allow_code_deny`) in a decision log keyed by correlation id
  (migration `0024`) and `socrate_policy_divergences_total`; in `enforce` a deny
  is `403 policy_denied` (or `elevation_required` / `mfa_required`), and an
  allow still has to pass every code gate — enforcing can remove access, never
  grant it. The superadmin-only policy API (`/api/admin/policy`: get, save,
  validate, simulate with a per-rule trace, versions, restore, catalogue,
  decisions; step-up on writes; `policy_updated` / `policy_restored` audited)
  is exempt from the policy it edits, so a bad rule can never make itself
  unfixable. `POLICY_REFRESH_INTERVAL` bounds cross-instance staleness (10s);
  `POLICY_DECISION_RETENTION_DAYS` (30) is swept by one instance under an
  advisory lock. The decide endpoint for applications and backendkit's PEP
  client are part 2; the console editor is part 3. See `docs/EXTENSIBILITY.md`.
- **The policy decision log for the SOC (A4 part 3).**
  `GET /api/admin/security/policy-decisions` serves the decision log to the
  monitoring console — global admins with `monitoring:read` — with filters for
  correlation id, outcome, divergence, source, calling client and time, and
  `…/policy-decisions/summary` returns the dashboard counts (denials, enforced
  denials, divergences by kind, denials by source) for a window, grouped in the
  database. Decision rows are security telemetry, the same class as the
  security events that console already shows; the rules themselves remain
  superadmin-only under `/api/admin/policy`. The console views are in
  oauth2-admin (policy editor) and oauth2-monitoring (decision log).
- **Multi-instance readiness (B5 / EPIC-13).** `internal/cluster` coordinates the
  background jobs through PostgreSQL advisory locks, so each runs once across
  the cluster rather than once per instance: **schema migration** takes a
  *blocking* lock (a second instance starting simultaneously waits rather than
  racing the same migration), while **key rotation**, **used-token pruning**,
  the **audit-chain integrity scan** and the **shared-state sweep** take a
  try-lock per tick. Webhook delivery is deliberately left uncoordinated — the
  outbox already claims rows with `FOR UPDATE SKIP LOCKED`, so every instance
  dispatching is throughput, not duplication. There is no leader to elect or
  fail over: whoever wins the tick does the work, and a crashed winner costs one
  interval. Locks are taken on a **dedicated pinned connection**, because a
  session-level advisory lock belongs to the connection that took it and a
  pooled one would return to the pool still holding it.
  `GET /health/readiness` now reports the database, the signing key and the
  shared-state backend by name, so a load balancer removes an instance that
  booted but cannot mint a token — and says which dependency failed.
  `deploy/caddy/socrate-ha.caddy` and a new runbook section cover the Caddy
  side. Gated on `STATE_BACKEND=postgres`; a single-instance deployment on the
  default in-memory backend behaves exactly as before.
- **Performance baseline (B6).** k6 scenarios in `deploy/perf/` (`discovery`,
  `token_refresh`, `login`, `client_credentials`, `introspect`) with a runner,
  a seeder, and **measured** numbers published in
  `docs/PERFORMANCE-BASELINE.md`. A `perf smoke` CI job boots a real server
  against Postgres and gates `discovery` and `token_refresh` on every pull
  request. Headline result on 4 vCPU: discovery p95 **0.8 ms**; public-client
  token refresh p95 **22 ms at 89 rps**, saturating cleanly near **110 rps**;
  password login p95 **93 ms** (bcrypt cost 10). All scenarios use k6's
  constant-arrival-rate executor, so a saturated endpoint shows as rising
  latency rather than as quietly reduced load.
- **Shared state for multi-instance deployments (B4 / EPIC-13).**
  `STATE_BACKEND=memory|postgres` (default `memory`, unchanged behaviour) moves
  the rate-limit counters and the DPoP replay cache into the database already
  configured — no new infrastructure. This is what a second instance needs to
  be correct: with in-process state, N instances each enforce a rate limit
  independently (a 5/min limit becomes 5N/min) and **a DPoP proof replayed
  against a different instance is accepted**, because only the instance that
  saw it first remembers the `jti`. Counters use a single
  `INSERT … ON CONFLICT DO UPDATE … RETURNING`, and the replay check is a
  conditional upsert that decides first-use atomically — a SELECT-then-INSERT
  would let two instances both accept one proof. Both tables are `UNLOGGED`
  (migrations `0020`/`0021`), matching what memory already gives on restart.
  Two deliberate differences from the in-memory limiter, both documented:
  windows are **fixed** rather than sliding, so the worst case across a
  boundary is 2×limit; and the rate limiter **fails open** on a store error
  (the endpoints it guards need the same database, so nothing is left to
  brute-force) while the replay store **fails closed**. `STATE_SWEEP_INTERVAL`
  evicts expired rows, `STATE_OP_TIMEOUT_MS` bounds one round trip. Auto-defense
  counters remain per-instance — see `docs/EXTENSIBILITY.md`.
- **Migration and shared-state integration tests.** CI now runs a Postgres
  service, so `TEST_DATABASE_URL` is set and the SQL is actually exercised:
  the whole migration chain applies to an empty database and re-applies as a
  no-op, the shared-state tables are asserted `UNLOGGED`, concurrent counter
  increments lose no counts, and exactly one of N concurrent replay claims is
  accepted. Without the variable these tests skip, so the suite still runs
  with no database.
- **Outbound webhooks — the delivery dispatcher (A3, part 2 of 2).** The outbox
  is now drained. A pass claims due deliveries with
  `SELECT … FOR UPDATE SKIP LOCKED` under a lease, so several instances can
  dispatch concurrently without double-sending, and a process that dies
  mid-flight releases its rows instead of stranding them (delivery is
  at-least-once — deduplicate on `event_id`). Each request is signed
  `X-Socrate-Signature: t=<unix>,v1=<hex>` — HMAC-SHA256 over `<t>.<raw body>`,
  with the timestamp inside the signed material so a captured delivery cannot be
  replayed indefinitely — alongside `X-Socrate-Event`, `X-Socrate-Delivery` and
  `X-Socrate-Attempt`. A `2xx` is terminal success; `410 Gone` is taken as "stop
  sending" and dead-letters immediately; anything else retries with 30s → 1m →
  2m → 4m → 8m backoff capped at 15 minutes, dead-lettering after
  `WEBHOOK_MAX_ATTEMPTS` (default 6). Dead deliveries are kept for inspection and
  replayable via `POST /api/admin/webhooks/deliveries/{id}/requeue`. The send
  path re-applies the SSRF guard **at connect time** and dials by the checked IP,
  so DNS cannot change between check and connect; redirects are refused outright,
  connection reuse and proxies are disabled, each attempt is bounded by
  `WEBHOOK_SEND_TIMEOUT`, and the response body is discarded after a bounded
  read. `WEBHOOKS_MODE=off` (default) starts no dispatcher.
- **Outbound webhooks — subscriptions and the transactional outbox (A3, part 1
  of 2).** Operators can register delivery targets
  (`/api/admin/webhooks`, global admin + fresh step-up) with an event filter
  over a v1 catalogue (`user.*`, `login.*`, `client.*`, `token.*`,
  `security.*`), optionally scoped to one client. A subscription's signing
  secret is generated server-side, returned exactly once, stored encrypted with
  `SECRET_KEY_BASE` and rotatable; without that key, registration is refused
  rather than storing a signing key in the clear. Audited events in the
  catalogue are written to `webhook_deliveries` **in the same transaction as the
  security audit row**, inside a savepoint — so a delivery can never exist
  without its audit entry, and a failed enqueue never costs the audit row. The
  payload is frozen at enqueue time so a retry re-sends identical bytes; it
  omits the audit row's integrity hashes, the user agent, and any credential.
  Target URLs go through a new `internal/shared/ssrf` guard: https only, no
  credentials in the URL, and a host resolving only to public addresses —
  loopback (where the admin API listens), RFC 1918, link-local
  (`169.254.169.254`), CGNAT, and the IPv4-mapped and NAT64 spellings of each
  are all refused, checked at registration and again at connect time. The
  catalogue is an allow-list, so a new internal audit event never starts leaking
  to subscribers by default. `WEBHOOKS_MODE=off` (default) enqueues nothing.
  Schema steps `0018` and `0019`. **The dispatcher (claim, sign, retry,
  dead-letter) is the following change**; until it lands, deliveries accumulate
  as `pending`. See `docs/EXTENSIBILITY.md`.
- **Custom claims via declarative mapping (A2).** A client can declare
  `claim_mappings` (admin API `POST/PUT /api/admin/apps`) projecting
  server-held values into its tokens: `user.attributes.<key>`, `user.email`,
  `user.name`, `user.id`, `app_role`, `app.id`, `app.client_id` or a
  `literal:` constant, targeted at the access token, the ID token or both.
  Per-user values come from a new free-form attribute set, replaced through
  `PUT /api/admin/users/{id}/attributes` (global admin only; audited as
  `update_user_attributes`, recording attribute names, never values).
  Every mapped claim is namespaced with `CLAIMS_NAMESPACE` (default
  `https://socrate/`) and the merge refuses any name already present, so a
  mapping can never shadow or overwrite a registered claim. Bounded on both
  sides: 32 attributes / 4 KB per user, 2 KB of custom claims per token —
  over the cap the custom claims are dropped whole and logged, and the token
  is still issued with the standard claim set. Unsupported sources, unknown
  targets and unusable claim names are refused at write time. Schema steps
  `0016` (`users.attributes`) and `0017` (`apps.claim_mappings`), both jsonb
  defaulting to `{}`, so every existing client and user is unaffected. See
  `docs/EXTENSIBILITY.md`.
- **In-process hooks (A6).** `internal/hooks`: `OnBeforeTokenIssue` (veto or
  observe every grant — authorization code, refresh, client_credentials, JSON
  password login, magic link; the first error or a panic fails closed and the
  token endpoint answers `403 access_denied`), `OnAfterLogin` and
  `OnUserProvisioned` (observers; panics recovered). See
  `docs/EXTENSIBILITY.md`.
- **Prometheus metrics (plan B1 / EPIC-4).** `GET /metrics` on the admin port
  (loopback only): RED counters/histograms per router and chi route pattern,
  `socrate_tokens_issued_total{grant,outcome}`,
  `socrate_security_events_total{event_type,success}` (every persisted audit
  event), `socrate_rate_limit_hits_total{route}`, `socrate_ip_blocks_total`,
  `socrate_signing_key_age_seconds`, `socrate_db_pool_*`, `socrate_build_info`.
  No label ever carries a user, client, IP or token. Scrape config, alert rules
  (SLOs + security signals, plan B7), Grafana dashboard and a Promtail example
  under `deploy/observability/`; catalogue and log schema in
  `docs/OBSERVABILITY.md`.
- **Log redaction guard (plan B3).** `pkg/logger/redaction_guard_test.go` fails
  the build when any log call in the tree carries a secret-bearing expression.
- **Per-client scope policy (A1, closes P3-8).** Clients carry an
  `allowed_scopes` list (admin API `POST/PUT /api/admin/apps`, `allowed_scopes`
  in the response). `SCOPE_POLICY_MODE=off|observe|enforce` (default `off`)
  applies it at `/oauth/authorize` and at every grant — refresh included, so a
  scope withdrawn from a client stops being renewable — with a `scope_denied`
  security event in `observe` and `enforce`, and `invalid_scope` in `enforce`.
  An empty list means unrestricted, so existing registrations are unaffected.
  Policy entries must be supported scopes. Schema step `0015` adds the column.

### Fixed

- **A fresh install could not boot with `AUTO_MIGRATE=true`.** Migration `0005`
  creates `magic_link_tokens` with a unique constraint named
  `uq_magic_link_token_hash`, while the GORM model tags `TokenHash` with
  `uniqueIndex` and so expects `uni_magic_link_tokens_token_hash`. On a brand-new
  database `migrate.Run` creates the table first, then `AutoMigrate` issues
  `ALTER TABLE magic_link_tokens DROP CONSTRAINT uni_magic_link_tokens_token_hash`
  for a constraint that does not exist — SQLSTATE 42704, fatal at startup. This
  is the documented first-deploy path, so a new install failed to start.
  Migration `0022` renames the constraint to the name GORM derives; guarded both
  ways, so it is a no-op on databases that already agree. Found while building
  the B6 baseline, and verified by booting against an empty database.

### Changed

- **Build toolchain: Go 1.26.8 → Go 1.27.1** (`go.mod` toolchain line and
  `golang:1.27.1-alpine`; CI follows go.mod and fails on drift). The `go`
  line stays `1.25.13`, and that line — not the toolchain — sets GODEBUG
  defaults, so the defaults Go 1.26 and 1.27 changed (`cryptocustomrand`,
  `tlssecpmlkem`, `urlstrictcolons`, `tracebacklabels`,
  `x509sslcertoverrideplatform`) keep their previous behaviour until that
  line is raised deliberately. Build, vet, golangci-lint v2.14.0 and the full
  `-race` suite (with the PostgreSQL integration tests) pass on 1.27.1.
- **golangci-lint v2.5.0 → v2.14.0** in CI, still built with go.mod's
  toolchain. v2.5.0 cannot load Go 1.27's export data, so this is the
  prerequisite for moving to Go 1.27; it found two issues, both fixed (see
  Security for the DPoP one).
- **Build toolchain: Go 1.25.13 → Go 1.26.8.** Go 1.25 went out of support
  when Go 1.27 was released, and the 2026-08-28 security releases shipped for
  1.26 and 1.27 only. `go.mod` now pins `toolchain go1.26.8` (the `go`
  language minimum stays 1.25.13), the Dockerfile builds on
  `golang:1.26.8-alpine` — previously `golang:1.25-alpine` — and CI fails if
  the job's Go or the Dockerfile's image drifts from the pin. golangci-lint is
  now built with the job's toolchain, since the prebuilt v2.5.0 binary (Go
  1.25) refuses a module targeting Go 1.26. The suite builds, vets, lints and
  passes `-race` on 1.26.8, and on 1.27.1 as well.
- **Documented: client-secret verification is bcrypt cost 12 (~273 ms), which
  caps every confidential-client endpoint at ~14 requests/second per 4 vCPU.**
  That covers `client_credentials`, `introspect`, `revoke`, and the
  authorization-code and refresh grants for confidential clients. Public clients
  (PKCE) skip it entirely and run roughly 12x faster. No behaviour is changed
  here — the finding, its measurement and the options (a keyed hash over a
  high-entropy secret, or cost 10) are written up in
  `docs/PERFORMANCE-BASELINE.md` so the tradeoff is decided deliberately rather
  than inherited.

### Security

- **deps: `golang.org/x/crypto` `v0.28.0` → `v0.55.0`** (and `golang.org/x/text`
  `v0.40.0` → `v0.41.0` with it). `govulncheck` listed 22 advisories against
  v0.28.0, none reachable — only `x/crypto/bcrypt` is imported — and 3 remain
  at v0.55.0: GO-2026-6354/6355 in `x/crypto/ssh` (fixed in v0.56.0) and
  GO-2026-5932 (`x/crypto/openpgp`, no fix), all in packages this module does
  not use. v0.55.0 is the newest release that still declares `go 1.25`;
  v0.56.0+ require `go 1.26`, which would raise the `go` directive and change
  the GODEBUG defaults the module is built with, so that step waits for a
  deliberate directive bump.
- **DPoP proof keys are parsed with `ecdsa.ParseUncompressedPublicKey`**
  instead of the deprecated `elliptic.Curve.IsOnCurve` (flagged by
  staticcheck SA1019 once golangci-lint moved to v2.14.0). The key in a DPoP
  proof header is attacker-chosen; off-curve points, coordinates ≥ p and the
  point at infinity were already rejected and still are — now by the
  constant-time `crypto/internal/nistec` code — and are covered by new tests.
  One tightening: a coordinate longer than 32 bytes is now refused
  (RFC 7518 §6.2.1.2 requires full-length coordinates), where leading zero
  bytes were previously tolerated. A coordinate one byte short (an encoder
  dropping a leading zero) is still accepted and yields the same thumbprint,
  so no existing binding changes.
- **PKCE by omission closed (P3-4).** An authorization request that carried a
  `code_challenge` but no `code_challenge_method` was stored with an empty
  method and verified at the token endpoint as `verifier == challenge` — plain
  PKCE, which the explicit `plain` branch already rejected. `Authorize` now
  refuses any method other than `S256` (`ErrPKCEMethodUnsupported` →
  `invalid_request`), and `VerifyPKCE` treats an empty method with a stored
  challenge as an error rather than a plain comparison.
- **Hosted login feeds auto-defense (P3-5).** The password path of
  `POST /oauth/authorize` now records failed and successful attempts with the
  IP-based auto-defense service exactly like `POST /api/auth/login`, so
  browser-path password spraying is blocked by the same thresholds instead of
  being throttled only by per-account lockout.
- **Dead `POST /auth/login` removed (P3-6).** The standalone form handler
  authenticated without an app context, set an `access_token` cookie nothing
  consumed, and still counted against the victim's failed-login lockout.
  `GET /auth/login` now forwards OAuth-parameterised requests to
  `/oauth/authorize` and otherwise renders an informational page without a
  password form.
- **App-admin mail actions limited to app members (P3-7).**
  `POST /api/apps/{app_id}/users/{user_id}/resend-verification` and
  `.../reset-password` verified only that the user existed, so an app-admin
  could trigger verification / password-reset mail for any user ID on the
  platform. Both now require a `user_app_roles` row for the target in that
  app and return 404 `user not in app` otherwise (same as `GET .../users/{id}`).
- **MFA disable requires re-authentication (P3-9).** See the upgrade note.
  Every failure returns the same 401 so the response does not reveal which
  factor was wrong; `Disable` fails closed if no user service is wired.
- **Legacy client-secret comparison is constant-time (P3-9).**
  `CheckClientSecret`'s SHA-256 migration branch compared hex strings with
  `==` despite its comment; it now uses `crypto/subtle`.
- **App-users handler no longer echoes internal errors (P2-2).** Every
  `err.Error()` forwarded to the caller in `app_users_handler.go` (list,
  create, assign/update/remove role, token generation, mail sending, the
  `email_error` field) is replaced by a static message; the detail is logged.
  `ErrRoleNotFound` on update/remove maps to 404 instead of a 400 carrying the
  error text.
- **Locked accounts and deactivated clients can no longer obtain tokens
  (P3-3).** The refresh-token grant checked token version and role but not
  the account's lock state or the client's `active` flag, and `Authorize` /
  the authorization-code grant ignored `active` entirely — so an
  admin-blocked user (or a deactivated OAuth client) kept minting valid JWTs
  for external resource servers until the refresh TTL. All three paths now
  return `ErrAccountLocked` / the new `ErrAppInactive` (token endpoint:
  `invalid_grant` "account is locked" / `unauthorized_client` "client is
  deactivated"; authorize: `access_denied` / `unauthorized_client`).
  `userService.Block` additionally bumps `token_version`, so blocking is a
  revocation event for every outstanding token rather than a lock that only
  this server's own middleware honours.

- **`client_credentials` grant validates scope and enforces DPoP (P2-5).**
  The grant skipped `validateScope` and `requireDPoP`, unlike the code and
  refresh grants: a service account could mint a token with an arbitrary
  scope string (including `admin`) and a DPoP-required client could obtain
  a bearer-only token. Both checks now run; an unknown scope is
  `invalid_scope`, a missing proof `invalid_dpop_proof`. A deactivated
  client is also refused here.

- **Hosted signup / accept-invite forms no longer render raw errors
  (P2-1).** `internal/web/handler.go` put `err.Error()` straight into the
  page for unauthenticated browsers, which for a wrapped failure meant
  driver/GORM text ("failed to create user: pq: duplicate key …") or SMTP
  detail. Both forms now map known sentinels to static messages, pass the
  password-policy hints through, and log-and-replace everything else —
  the same policy the JSON API adopted for M1.

- **`/api/admin` had no authorisation gate (P3-1 / CRIT-01, Critical).**
  `AuthMiddleware` verified the bearer and placed the user's role in the
  request context, but nothing checked it; `RequireGlobalAdmin()` existed and
  was unused. Combined with open self-signup on any `client_id`, any
  authenticated user could `POST /api/admin/superadmins` (201), reset a
  superadmin's password, rewrite the unowned first-party console client's
  `redirect_uris`, and drive every monitoring/SOC endpoint. `ADMIN_SCOPE_MODE`
  is opt-in and `scope=admin` is grantable to anyone, so scopes were never a
  boundary. The `/api/admin` group now applies `RequireGlobalAdmin()` directly
  after `AuthMiddleware`, and the `/superadmins` subtree additionally requires
  `role=superadmin` (mirroring `AdminLogin`, which already restricted the
  admin portal password login to superadmins). A regression test walks every
  registered `/api/admin` route through the real router with real signed
  tokens: `role=user` → 403 everywhere; `role=admin` → 403 on
  `/superadmins/*` only; `role=superadmin` → admitted. Traceability:
  `docs/CR-platform-zero-trust-verification.md` CRIT-01,
  `docs/CR-socrate-suite-security-pass3.md` §1.3.

- **Client-IP spoofing via chi `RealIP` closed (P3-2; GO-2026-5775 /
  GO-2026-5777).** `chimiddleware.RealIP` was installed unconditionally on all
  three routers and rewrote `RemoteAddr` from `True-Client-IP` / `X-Real-IP` /
  leftmost `X-Forwarded-For` for **any** peer, so the login/token rate
  limiters, IP blocking, auto-defense (which could be made to block an
  arbitrary IP of the attacker's choosing) and security-audit attribution all
  trusted a client-chosen address — exploitable through Caddy, which passes
  `True-Client-IP`/`X-Real-IP` through untouched. `RealIP` is removed and
  replaced by `middleware.ClientIP(trustedCIDRs)`, which resolves the IP once
  per request via `GetClientIPSafe` (proxy headers honoured **only** when the
  TCP peer is in `TRUSTED_PROXIES`) into the request context, never mutates
  `RemoteAddr`, and feeds `GetClientIP` for every attribution sink (auth /
  admin-login auto-defense, token-abuse and DPoP audit sinks, secret-rotation
  activity log). `GetClientIP`'s doc comment, which claimed it "always trusts
  proxy headers" (P2-4), is corrected. The request logger gains a `client_ip`
  field alongside the raw `remote`. Regression tests prove an untrusted peer
  cannot escape the rate limiter by rotating any of the three headers, and
  that a trusted loopback proxy's `X-Forwarded-For` still keys per client.
  Supersedes pass-2 items P2-3/P2-4. Traceability:
  `docs/CR-socrate-suite-security-pass3.md` §1.3.

- **deps: clear the current `govulncheck` findings.** Go toolchain `1.25.11` →
  `1.25.13` (GO-2026-6088/6089/6090/6091, GO-2026-5972, GO-2026-5856 in
  `html/template`, `net/http`, `crypto/tls`, `encoding/xml`, `encoding/asn1`),
  `golang.org/x/text` `v0.29.0` → `v0.39.0` (GO-2026-5970), and
  `github.com/go-chi/chi/v5` `v5.1.0` → `v5.3.0` (GO-2026-5775/5777; note the
  chi release only *deprecates* `RealIP` — the actual fix is the item above).

## [1.2.0] - 2026-06-25

> Never tagged: these changes first shipped in a tag with **v1.3.0**.

Minor release on the **v1.x — Foundations & Additive Capabilities** line
(non-breaking). Hardens the Tier-0 admin control plane (loopback bind,
least-privilege scopes, fresh-auth step-up on destructive operations), completes
the first-party PKCE admin-console login path end-to-end, and ships the backend
deployment kit.

> **Upgrade note (#205):** the admin API now binds to **loopback (`127.0.0.1`)
> by default** instead of all interfaces. Single-host deployments fronted by a
> same-host reverse proxy or BFF need no change. **Multi-host or container
> deployments must set `ADMIN_BIND_HOST=0.0.0.0`** (and keep the admin port
> firewalled / network-policied) or the admin API will be unreachable from other
> hosts.

### Added
- **Admin API / Least-privilege scopes:** Opt-in OAuth-scope enforcement
  (`ADMIN_SCOPE_MODE=off|enforce`, default **off**) that confines a
  least-privilege client (the monitoring console/BFF) to its own routes, so a
  BFF compromise cannot reach the full admin surface. A new
  `RequireScope(scope, enforce)` middleware checks the access token's `scope`
  claim — `admin` is a super-scope satisfying any requirement; `monitoring:read`
  / `monitoring:write` confine the monitoring routes. In `enforce` mode the
  admin router gates reads → `monitoring:read`, mutations → `monitoring:write`,
  and privileged console routes (apps, user management, superadmins, settings,
  stats) → `admin`; `/profile`, `/elevate`, `/change-password` stay ungated.
  Mirrors the DPoP/token-exchange mode pattern, so it cannot lock out the admin
  console until deliberately enabled. _Traceability: #201, #209._
- **Observability / Audit integrity:** New read-only
  `GET /api/admin/security/audit-integrity` endpoint surfacing the
  tamper-evidence health of the security audit log over a period — per-row HMAC
  stamp coverage, hash-chain linkage count, the count and recent detail of
  integrity violations recorded by the scheduled scanner, and a
  `verified`/`violations_detected`/`not_configured` status. Read-only: it never
  consults the signing key (verification remains the scanner's responsibility);
  it only surfaces the scanner's findings. _Traceability: RFC-007 → #199, #200._
- **Ops / Deployment kit:** Backend deployment kit complementing `make deploy` —
  a multi-stage **Dockerfile** (distroless static nonroot; fixes
  `make docker-build`, which referenced a missing Dockerfile), a hardened
  **systemd unit** (`deploy/systemd/socrate.service`: no-login user,
  `ProtectSystem=strict`, dropped capabilities, syscall allowlist, only the keys
  dir writable), a **Caddyfile** example (public `:8080`; admin API stays
  loopback), a production **env template**, a one-time VPS **bootstrap script**,
  and a deployment **runbook** (`deploy/README.md`). _Traceability: #206._
- **Observability / Version (admin console):** Added a **`/api/version`** alias
  (both the OAuth `:8080` and Admin `:8081` routers) returning the same
  `{version, commit, branch, build_time}` payload as the existing `/version`
  route. The admin SPA probes `/api/version` on startup and previously got a
  `404`; the endpoint is unauthenticated and non-sensitive (the build version is
  already emitted on every response via `X-App-Version`). `/version` is retained.
  _Traceability: C4 → EPIC-4 → RFC-008 → #207._

### Changed
- **Security / Admin bind:** The admin API now binds to **loopback
  (`127.0.0.1`) by default** via the new `ADMIN_BIND_HOST` setting (was: all
  interfaces, secure only if the operator remembered to firewall it). By default
  the Tier-0 control plane is unreachable from the public internet with no
  firewall — a same-host reverse proxy (Caddy) or BFF fronts it over localhost.
  Multi-host/container deployments set `ADMIN_BIND_HOST=0.0.0.0` and rely on
  network policy (a warning is logged when not bound to loopback). See the
  upgrade note above. _Traceability: #205._

### Fixed
- **Identity / CORS (admin console):** The `/oauth/token` (and refresh) call from
  a browser SPA was **blocked by CORS** even with the SPA origin correctly in
  `ALLOWED_ORIGINS`. The admin console sends an `X-Requested-By` header on these
  calls as a **custom-header CSRF defense**, but it was outside the server's
  `AllowedHeaders` list. go-chi/cors emits `Access-Control-Allow-Origin` only
  when the origin **and** method **and** every requested header are allowed, so
  the unknown header **silently aborted the preflight** — a bare `200` with no
  CORS headers, which the browser reports as the misleading "No
  'Access-Control-Allow-Origin' header is present". `X-Requested-By` is now
  explicitly allow-listed (the origin allow-list remains the gate; H-06 is
  unaffected). _Traceability: C9 → EPIC-9 → RFC-011 → #195._
- **Identity / Hosted login (admin console):** A global **admin/superadmin can now
  complete the hosted login** (`/oauth/authorize`) for any app **without an
  explicit per-app membership** — consistent with `middleware.RequireAppAdmin`,
  which already lets global admins bypass per-app role checks. Previously
  `authService.Login` always required a `user_app_roles` row, so a platform
  superadmin could not sign in to the first-party PKCE admin console (nothing
  seeds that membership), failing with a misleading "Login failed". Non-admins
  still require a membership row. Also fixed the authorize login handler to map
  errors with `errors.Is` instead of equality, so **wrapped** errors
  (role-not-found, locked, unverified) render their accurate message instead of
  the generic fallback. _Traceability: C9 → EPIC-9 → RFC-011 → #191._
- **Identity / Hosted login (admin console):** Completed the global-admin bypass
  on the **authorization-code issuance** path (`oauthService.Authorize`), the
  sibling of the login fix above. A global **admin/superadmin can now obtain an
  authorization code** for any app without an explicit `user_app_roles` row, so
  the first-party PKCE admin console flow no longer fails at the consent step
  with `server_error` / "authorization failed". The consent handler now maps
  `Authorize` errors with `errors.Is` (instead of equality), so a wrapped
  role-not-found renders `access_denied`, and `re-auth required` / `PKCE
  required` map to the correct OAuth codes (`login_required` /
  `invalid_request`) instead of the generic `server_error`. Non-admins without a
  membership row are still rejected. _Traceability: C9 → EPIC-9 → RFC-011 → #193._
- **Observability / Security events:** `SecurityAuditLog.CorrelationID`
  (RFC-008 end-to-end request tracing) was stored but **dropped at the DTO
  boundary**, so the monitoring SPA could not pivot from a security event to its
  originating request. It is now serialised in `SecurityEventResponse` and mapped
  in `FromSecurityAuditLog`. _Traceability: RFC-008 → #197._
- **Observability / Security reports:** Generated security reports were stored in
  two package-level in-memory maps, so they were **lost on restart** and
  invisible to other instances (a report generated on instance A returned `404`
  from instance B behind a load balancer). Reports now persist in a new
  `security_reports` table (jsonb payload, included in `AutoMigrate`); generation,
  status, and download read/write the table, and expired reports are cleaned up
  best-effort on generation. _Traceability: RFC-007 → #198._

### Security
- **Admin API / Fresh-auth step-up:** The mutating monitoring endpoints now
  require a **recent authentication** (Tier-0 `RequireFreshAuth` step-up), not
  merely a valid session — `POST /users/{id}/revoke-tokens`,
  `POST`/`DELETE /security/blocked-ips`, and `POST`/`PUT`/`DELETE /alerts/rules`.
  These join the already-gated destructive admin operations (app delete, secret
  rotation, user block, superadmin CUD). Read endpoints and the routine
  alert-acknowledge action stay ungated; when `ADMIN_ELEVATION_MAX_AGE` is `0`
  the gate is a pass-through. _Traceability: #201 → #204._

## [1.1.1] - 2026-06-24

### Fixed
- **Observability / Startup:** Polished startup logs — the caller hook now
  **shortens non-module paths** to their last two segments (e.g.
  `runtime/proc.go:7670`) so an **absolute build path can never leak** in
  `caller` (the one place #181 didn't cover: package-init logs whose caller is
  the Go runtime). The self-referential `✅ Logger initialized` line is demoted
  to DEBUG (the effective level is now in the startup summary as `log_level`),
  and the admin server logs a single consistent `listening … — ensure it is
  firewalled` line. _Traceability: C4 → EPIC-4 → RFC-008 → #187._

## [1.1.0] - 2026-06-24

### Changed
- **Observability / Startup:** The startup flow now emits a single **structured
  configuration summary** at `info` — version, environment, issuer, mode, ports,
  the full **security posture** (DPoP / token-exchange / refresh-reuse / audience
  modes, admin-MFA policy), the **admin-console hardening** flags (PKCE console
  client, elevation window, password-login state), and the scheduled-job
  intervals — the one line an operator greps to confirm a deployment. The ~16
  per-service `… initialized` lines are **demoted to DEBUG** so info-level
  startup is concise, and production emits explicit **safety warnings** (non-https
  issuer, deprecated password login enabled). _Traceability: C4 → EPIC-4 →
  RFC-008 → #183._

### Fixed
- **Observability / Logging:** The log `caller` field is now **accurate and
  module-relative**. Previously `SetReportCaller` reported this package's thin
  wrappers (every line showed `pkg/logger/logger.go`), and paths were absolute
  build paths. A caller hook now walks the stack to the **real call site** (e.g.
  `internal/handler/oauth_handler.go:543`), preserves a `caller` already set by
  the GORM logger, and drops the misleading `file` field. _Traceability:
  C4 → EPIC-4 → RFC-008 → #181._

### Fixed
- **Observability / Logging (HIGH-06):** GORM no longer logs **every SQL
  statement at `info`**. Successful queries — which carry bound parameters
  (emails, password hashes, reset/refresh tokens, IPs) — now log at **DEBUG**,
  and the GORM level is configurable via **`DB_LOG_LEVEL`** (`silent|error|warn|
  info`, default **`warn`**): at the default only **slow queries** (Warn) and
  **errors** (Error) are logged, and normal queries aren't even rendered. This
  closes the audit's HIGH-06 (secrets/PII in info-level logs) and removes the
  startup/runtime SQL flood. To see SQL, set `DB_LOG_LEVEL=info` **and**
  `LOG_LEVEL=debug`. _Traceability: C4 → EPIC-4 → RFC-008 → #179._

### Added
- **Identity / Admin console (Tier-0):** The first-party **admin console is now a
  public Authorization Code + PKCE client**, auto-registered at startup
  (`ADMIN_CONSOLE_CLIENT_ID` + `ADMIN_CONSOLE_REDIRECT_URIS`) as public,
  PKCE-mandatory and secretless with exact-match redirect URIs. The legacy
  `POST /api/admin/login` password flow is **deprecated** (always emits a
  `Deprecation: true` header, RFC 8594) and can be refused with
  `403 password_login_disabled` via `ADMIN_PASSWORD_LOGIN_ENABLED=false`
  (default keeps it on — backward compatible). Adds `docs/ADMIN-SPA-MIGRATION.md`,
  the end-to-end contract for the admin SPA. _Traceability: OAuth 2.1 (PKCE) →
  admin session hardening → #176._

### Added
- **Identity / Admin console (Tier-0):** The most destructive admin operations
  — delete OAuth client, rotate client secret, create/delete superadmin, block
  user — now require **step-up**: an authentication (`auth_time`, RFC 9068) no
  older than `ADMIN_ELEVATION_MAX_AGE` (default 5 min; `0` disables). A stale
  token gets `403 elevation_required`; the admin re-authenticates via
  `POST /api/admin/elevate` (password + MFA → fresh-`auth_time` access token, no
  new session). A merely refreshed session is correctly **not** fresh. Reuses the
  existing RFC 9068 `auth_time` and the codebase's step-up pattern. _Traceability:
  C9 → EPIC-9 → RFC-011 → #174._

### Added
- **Identity / Admin console (Tier-0):** `must_change_password` is now
  **enforced**. A flagged admin gets `403 password_change_required` on every
  `/api/admin/*` route except the new `POST /api/admin/change-password`, which
  verifies the current password, validates the new one, and revokes the admin's
  tokens (token-version bump → re-login). Previously the flag was set and
  returned but never enforced. _Traceability: C9 → EPIC-9 → #172._

### Added
- **Identity / Admin console (Tier-0):** The admin console can now **refresh
  silently** via an **HttpOnly refresh-token cookie** that JavaScript cannot read
  (XSS-safe). When `ADMIN_CONSOLE_CLIENT_ID` is set, `/oauth/token` delivers that
  client's refresh token as `HttpOnly; Secure; SameSite=Strict; Path=/oauth/token`
  and **omits it from the JSON body**; it is read back from the cookie on refresh
  (running the single hardened grant — rotation + replay + DPoP) and **cleared on
  logout**. The access token stays a Bearer token in the body. Inert when the env
  var is unset. _Traceability: C8 → EPIC-8 → RFC-003 → #170._

### Fixed
- **Identity / Refresh (Tier-0):** Collapsed refresh-token handling to **exactly
  one hardened code path**. `POST /api/auth/refresh` previously used a separate,
  weaker implementation (no rotation, no replay detection, no DPoP); it now
  delegates to the same `/oauth/token` refresh grant (single-use rotation,
  replay → token-family revocation, token-version + DPoP binding). The client is
  derived from the refresh token's `aud`; confidential clients must use
  `/oauth/token` with client authentication. _Traceability: C14 → EPIC-14 →
  RFC-012 → #167._

### Added
- **Observability / Logging:** Logs are now emitted as **structured JSON in
  production** (clean ingestion by ELK/Loki/Datadog) and human-readable **text in
  development/test**, chosen by `selectFormatter` — an explicit `LOG_FORMAT`
  (`json`|`text`) wins, otherwise it derives from `ENV` (unset ⇒ production ⇒ JSON,
  matching config's fail-safe default). The request logger now logs **by outcome
  level** so error rates are queryable/alertable by level: **5xx → Error,
  4xx → Warn, else Info** (previously every request handled at Info). Documented
  `LOG_FORMAT` in `.env.example`. Completes the 3-slice RFC-008 logging track
  (context correlation #158, DEBUG flow-tracing #160, this). _Traceability:
  C4 → EPIC-4 → RFC-008 → #162._

### Added
- **Observability / Logging:** Added **DEBUG flow-tracing** at the OAuth decision
  points — token-endpoint grant dispatch, authorization-code validated/issuing,
  refresh validated/rotating, and introspection active/inactive — as structured,
  secret-free traces that carry the request `correlation_id` (via
  `logger.FromContext`). Off at the default `LOG_LEVEL=info` (no prod noise);
  invaluable for diagnosing a failing test or a production incident with
  `LOG_LEVEL=debug`. No secrets/tokens/PII are logged (only ids, scope, and
  decision flags). _Traceability: C4 → EPIC-4 → RFC-008 → #160._

### Added
- **Observability / Logging:** Service-layer logs can now be **traced to a single
  request end-to-end** (RFC-008). New `logger.FromContext(ctx)` stamps the
  `correlation_id` (the same id the request logger and audit log already carry)
  onto operational logs; the OAuth/auth flows' error/warn logs now use it, so a
  failed token-family revocation, JTI-blacklist, or login persistence warning can
  be tied to its request. Nil-safe. _Traceability: C4 → EPIC-4 → RFC-008 → #158._

### Added
- **CI / Test gates (Phase 8):** The **Tier A (security-critical) coverage check
  is now blocking** (docs/TEST-STRATEGY.md) — a **ratchet**
  (`scripts/coverage-gate.sh`, `make coverage-gate`) that fails the build if
  coverage drops below `TIER_A_MIN` (floor **55%**, raised toward the ≥90% target
  as the suites grow, so coverage can only go up). The adversarial (Phase 2) and
  fuzz seed-corpus (Phase 3) suites are already enforced via the blocking
  `go test ./...` job. This turns the test work of Phases 1–4 into an enforced
  guarantee against regressions. _Traceability: C6 → EPIC-6 → RFC-014 → #156._

### Added
- **Tests / Crypto lifecycle (Phase 4):** Added key-lifecycle tests that connect
  the signing-key ring to **token verification** (docs/TEST-STRATEGY.md):
  after a rotation, JWKS exposes both the current and retired `kid` (so a resource
  server can verify either token); and once a retired key is **pruned**, the token
  it signed **no longer verifies** — proving retention must outlive the token TTL
  (RFC-002 / EPIC-3). Complements the existing cross-rotation verification suite
  (which already covers pre/post-rotation, multi-rotation, and after-restart).
  Test-only. _Traceability: C3 → EPIC-3 → RFC-002 / RFC-014 → #154._

### Added
- **Tests / Fuzzing (Phase 3):** Added **Go native fuzz targets** for the
  untrusted-input parsers (docs/TEST-STRATEGY.md): PKCE verification
  (`FuzzVerifyPKCE` — never accepts a mismatched S256 challenge or the downgrade
  `plain` method), redirect-URI validation (`FuzzValidateRedirectURI` — the
  **open-redirect invariant**: any accepted URI must use a safe scheme, carry no
  fragment, and resolve to the registered host), and the RFC 8693 token-exchange
  request parser (`FuzzParse` — no panic, no nil/nil). Seed corpora run as the CI
  smoke; active fuzzing (≈0.5M execs) found no bypass or crash. Test-only.
  _Traceability: C6 → EPIC-6 → RFC-014 / RFC 9700 → #152._

### Added
- **Tests / Adversarial (Phase 2):** Added a **JWT/OAuth adversarial suite**
  (docs/TEST-STRATEGY.md) mapping the OAuth 2.0 Security BCP (RFC 9700) /
  OWASP ASVS attack classes to failing-by-design tests against access-token
  verification: **`alg=none`**, **RS256→HS256 algorithm confusion** (public key
  as HMAC secret), **foreign-key signature**, **tampered signature**, **expired**,
  **wrong issuer** (mix-up), **token-type confusion** (refresh-as-access), and
  malformed input — each asserted **rejected**. Test-only; guards the
  highest-blast-radius verification path. _Traceability: C6 → EPIC-6 → RFC-014 /
  RFC 9700 → #150._

### Added
- **Tests / Integration (Phase 1):** Added a **router-level integration harness**
  (docs/TEST-STRATEGY.md) that drives the OAuth/OIDC endpoints through a
  real `chi` router with the real middleware stack (JSONContentType /
  NoCacheHeaders / DPoP). Covers discovery, JWKS, the token endpoint, and
  introspection end-to-end — asserting routing, status codes, `no-store` headers
  (RFC 7662 §4), content type, method handling (405), and 404s — the HTTP wiring
  that handler unit tests can't see. Test-only; no production change.
  _Traceability: C6 → EPIC-6 → RFC-014 → #148._

### Added
- **CI / Test strategy:** Added `docs/TEST-STRATEGY.md` — the
  identity-server test-assurance plan (risk-tiered coverage, adversarial / fuzz /
  mutation / conformance layers, phased roadmap, and the eventual blocking CI
  gates). **Phase 0:** a **report-only** `coverage` CI job now publishes overall
  and **Tier A** (security-critical) coverage and uploads the profile, plus a
  `make coverage-report` helper. Non-blocking — visibility first; Tier-A
  thresholds become required checks in a later phase. Baseline: Tier A ~55%
  (target ≥90%). _Traceability: C6 → EPIC-6 → RFC-014 → #146._

### Added
- **Observability / Audience binding:** Token-issuance audit rows now carry
  **audience-coverage telemetry** (RFC-001 / EPIC-7, Phase 1): `audience_registered`
  (does the client have registered audiences), `audience_count`, and the active
  `audience_mode`. This is the **parity signal** operators watch before enabling
  audience-scoped enforcement — once coverage approaches 100% for clients that
  call protected resources, resource servers can enforce `aud` with ≈0 legitimate
  denials. Added to the `token_issued` (authorization-code, client-credentials)
  and `token_refreshed` events. Additive telemetry only. _Traceability: C7 →
  EPIC-7 → RFC-001 → #144._

### Fixed
- **Identity / Response caching:** The **userinfo, introspection, and revocation**
  responses are now marked **`Cache-Control: no-store` / `Pragma: no-cache`**.
  These carry sensitive material — PII (userinfo), token metadata (introspection,
  RFC 7662 §4), and token state — and must not be cached by browsers or
  intermediaries (RFC 6749 §5.1 / OIDC Core §5.3.2). Previously only the token
  endpoint set no-store. Added a shared `setNoStore` helper (the token endpoint
  now uses it too). _Traceability: C7 → EPIC-7 → RFC 6749 / RFC 7662 → #142._

### Added
- **Observability / Audit completeness:** Confidential-client **authentication
  failures at the token endpoint are now audited** (RFC-007 / RFC 6749 §3.2.1).
  A missing or wrong `client_secret` on the authorization-code, refresh-token, or
  client-credentials grant emits a `client_auth_failed` event (with `client_id`
  and a `missing_secret`/`invalid_secret` reason) — a credential-stuffing /
  brute-force signal that previously went unrecorded. (Token exchange already
  audited this via its own event.) Additive; success and error responses are
  unchanged. _Traceability: C5 → EPIC-5 → RFC-007 → #140._

### Fixed
- **Docs / Config accuracy:** Corrected stale `DPOP_MODE` and `TOKEN_EXCHANGE_MODE`
  documentation in `config.go`. Both `enforce` values were described as
  "reserved / behaves as observe", but they have been **live since v1.0.0**:
  DPoP `enforce` rejects a present-but-invalid proof (`400 invalid_dpop_proof`),
  and token-exchange `enforce` actually issues the exchanged token. The
  misleading comments could have led an operator to avoid `enforce` thinking it
  was a no-op. Comments only — no behaviour change. _Traceability: C8 → EPIC-8 →
  RFC-003 / RFC-019._

### Added
- **Observability / Audit completeness:** Security-relevant **authorization-code
  grant failures are now audited** (RFC-007 / EPIC-5). The token endpoint emits
  `auth_code_failed` for an invalid / expired / already-used code and for a
  `client_id` mismatch, and `pkce_validation_failed` for a missing or wrong PKCE
  `code_verifier` — all strong signals of code-replay or code-interception
  attacks that previously went unrecorded (the event types existed but were never
  emitted). Each row carries the `client_id` and a `reason`. Additive; success
  paths are unchanged. _Traceability: C5 → EPIC-5 → RFC-007 → #136._

### Fixed
- **Identity / PKCE hardening:** PKCE is now enforced for **public clients at the
  point of use**, not just via the create-time default (OAuth 2.1). The
  authorization and token endpoints gate on a new `App.PKCERequired()`
  (`RequirePKCE || IsPublic`), so a public client can never run an unprotected
  authorization-code flow even if its `require_pkce` flag were cleared by a seed,
  a direct DB row, or a future code path. Confidential clients and clients that
  already set `require_pkce` are unaffected. _Traceability: C7 → EPIC-7 → RFC 7636
  / OAuth 2.1 → #134._

### Added
- **Identity / Mix-up defense:** The **authorization response now carries the
  `iss` parameter** (RFC 9207), and discovery advertises
  `authorization_response_iss_parameter_supported: true`. A client that talks to
  more than one authorization server can verify `iss` matches the AS it sent the
  request to, defending against **IdP mix-up attacks**. Additive — clients that
  ignore `iss` are unaffected. _Traceability: C7 → EPIC-7 → RFC-001 / RFC 9207 →
  #132._

### Added
- **Identity / Refresh-token theft detection:** Refresh-token **reuse detection**
  (OAuth 2.0 Security BCP / RFC 9700 §4.14.2). A reused (already-rotated)
  single-use refresh token is still rejected as before, but `REFRESH_REUSE_MODE`
  now adds a theft response: `off` (default — reject only, unchanged), `observe`
  (also audit a `refresh_token_reuse` security event), or `enforce` (also revoke
  the user's **token family** via a token-version bump, so neither the attacker's
  nor the victim's outstanding tokens survive). The reused token's signature and
  audience are verified before acting, so the subject is trustworthy. Default
  `off` is byte-compatible. _Traceability: C14 → EPIC-14 → RFC-012 / RFC 9700 →
  #130._

## [1.0.0] - 2026-06-22

### Added
- **Discovery:** OIDC discovery now advertises the claims added by recent
  capabilities — `claims_supported` includes `auth_time` (RFC 9068), `acr`/`amr`
  (RFC 8176), `act` (RFC 8693), and `cnf` (RFC 9449) — and a new
  `acr_values_supported: ["pwd","mfa"]`. Relying parties can now discover the
  authentication-context and delegation/DPoP claims the OP may assert. Metadata
  only (a listed claim is not present on every token). _Traceability: C9 →
  EPIC-9 → RFC-001 → #127._

### Added
- **Identity / Delegation:** **Delegation step-up** (RFC 8693 / EPIC-17) — the
  human-actor counterpart to impersonation step-up. A delegation token-exchange
  carries an actor token whose `amr` evidences how that human authenticated, so
  `DELEGATION_STEPUP_MODE` can require it to contain **`mfa`**: `off` (default,
  no check), `observe` (audit a would-be denial but still issue), or `enforce`
  (deny with `invalid_grant`). An actor token minted without `amr` (e.g. a
  non-interactive flow) cannot satisfy enforce. Impersonation (actor-absent) is
  unaffected; every decision is audited (`delegation_stepup`). Builds on the
  `amr` claim from the previous slice. _Traceability: C17 → EPIC-17 → RFC-016 →
  #125._

### Added
- **Identity / Authentication context:** Tokens from an **interactive login** now
  carry **`amr` and `acr`** (RFC 8176 / OIDC, part of the RFC-001 canonical claim
  set) on the access and ID tokens, and introspection surfaces them: `["pwd"]` /
  `pwd` for a password login, `["pwd","otp","mfa"]` / `mfa` when a second factor
  was used. Resource servers can now gate on **authentication strength** (e.g.
  require `mfa`) without a separate channel. Purely additive (`omitempty`) — only
  the interactive `Login`/`AdminLogin` paths populate it; refresh, token-exchange,
  and other flows omit it. _Traceability: C9 → EPIC-9 → RFC-011 / RFC-001 → #123._

### Added
- **Docs / Revocation:** Added a **revocation & token-freshness SLA**
  (`docs/REVOCATION-FRESHNESS-SLA.md`, RFC-012 / EPIC-14) stating the guaranteed
  time-to-revoke per validation strategy — **immediate** for introspecting or
  Socrate-authenticated resource servers, **≤ `ACCESS_TOKEN_TTL`** (default 900s)
  for offline local JWT validators — plus how to tighten it and high-assurance
  guidance. Linked from `API.md`. _Traceability: C14 → EPIC-14 → RFC-012 → #121._

### Added
- **Identity / Revocation hygiene:** A scheduled **used-token cleanup** now prunes
  expired rows from the `used_tokens` table (single-use refresh JTIs + the
  per-token revocation blacklist), which previously grew without bound — nothing
  ever pruned it. Runs every `USED_TOKEN_CLEANUP_INTERVAL_SECONDS` (default
  **3600s / 1h**; `0` disables), with deterministic shutdown like the other
  scheduled jobs. Expired rows are safe to drop — the underlying token no longer
  verifies. _Traceability: C14 → EPIC-14 → RFC-012 → #119._

### Fixed
- **Identity / Revocation propagation:** A token **individually revoked** via
  `/oauth/revoke` (its `jti` blacklisted) is now rejected on the **direct-auth
  hot path** too — `AuthMiddleware` rejects it (401 `token has been revoked`) and
  `OptionalAuthMiddleware` treats it as unauthenticated. Previously only
  introspection honored the blacklist, so a per-token revocation didn't
  propagate to APIs that validate the bearer token directly (EPIC-14 / RFC-012).
  The check is nil-safe (disabled when no revocation store is wired) and fails
  open on a store error, so a transient outage never locks out valid tokens.
  _Traceability: C14 → EPIC-14 → RFC-012 → #117._

### Added
- **Identity / Audience binding / Introspection:** Token introspection now
  **surfaces `aud`** (RFC 7662 §2.2), so a resource server that introspects a
  token — rather than verifying the JWT locally — can confirm its own resource
  identifier is in the audience (RFC-001 / EPIC-7). Carries the `client_id` plus
  any registered audiences under `AUDIENCE_MODE=dual`. Additive; `client_id`
  remains the first audience entry. _Traceability: C7 → EPIC-7 → RFC-001 → #115._

### Added
- **Identity / Audience binding:** Access tokens can now carry the client's
  **registered audiences** in `aud` (RFC-001 / EPIC-7), controlled by
  `AUDIENCE_MODE`: `off` (default — `aud` is the `client_id`, unchanged) or
  `dual` (the registered audiences are added **alongside** the `client_id`). Dual
  is the safe warn/observe step: audience-aware resource servers can begin
  verifying their resource identifier while existing `client_id` verifiers keep
  working. Entries are de-duplicated; a client with no registered audiences is
  unchanged. Only the **access token** is affected (ID/refresh tokens keep the
  `client_id`); verification is unaffected (the server never validated `aud`).
  Canonical-only enforcement is a later (Wave 2) step. _Traceability: C7 →
  EPIC-7 → RFC-001 → #113._

### Added
- **Identity / Audience binding:** Clients can now **register audiences** —
  the resource identifiers (e.g. API URIs) their tokens are intended for, the
  canonical `aud` claim per RFC-001 / EPIC-7. New optional `audiences` field on
  app create/update + `AppResponse`, backed by an additive `apps.audiences`
  `text[]` column (migration 0014, default empty). This is **registration
  only** — token issuance and resource-server enforcement are layered in by
  later (warn → enforce) slices, so there is no behaviour change: `aud` still
  carries the `client_id` today. Existing clients are unaffected (empty set).
  _Traceability: C7 → EPIC-7 → RFC-001 → #111._

### Added
- **Identity / Impersonation:** Impersonation **step-up** (RFC 8693 / EPIC-17).
  Because a back-channel token exchange has no interactive user, the control is
  the **freshness of the impersonated subject's session**: an impersonation
  exchange now requires the subject to have authenticated within
  `IMPERSONATION_MAX_AUTH_AGE` (default **900s**), enforced via
  `IMPERSONATION_STEPUP_MODE` — `off` (default, no check), `observe` (audit a
  would-be denial but still issue), or `enforce` (deny with `invalid_grant`). A
  subject token without `auth_time` can't prove freshness and is treated as
  stale (secure default). Delegation is unaffected, and every decision is
  audited (`stepup`, `subject_auth_age_seconds`). The `amr`-based step-up for the
  human-in-the-loop delegation case is a documented future layer. _Traceability:
  C17 → EPIC-17 → RFC-016 → #109._

### Added
- **Identity / Tokens:** Access tokens now carry **`auth_time`** (RFC 9068
  §2.2.1 / OIDC), and token **introspection surfaces it** (RFC 7662), so a
  resource server can make its own **freshness / step-up** decisions from the
  access token — whether it verifies the JWT locally or introspects — without a
  round-trip to the ID token. The login/refresh flow stamps the session's
  `auth_time` (matching the refresh/ID tokens); tokens with no associated user
  authentication (client-credentials, token-exchange results) omit it. Purely
  additive (`omitempty`); the standalone `GenerateBoundAccessToken` helper stays
  byte-compatible. This is the freshness signal the impersonation **step-up**
  control will build on. _Traceability: C17 → EPIC-17 → RFC-016._

### Added
- **Identity / Impersonation:** Impersonated tokens are now **time-boxed**
  (RFC 8693 / EPIC-17). An access token minted via impersonation (the
  actor-absent token-exchange case) auto-expires on a short, bounded lifetime —
  `IMPERSONATION_TOKEN_TTL` (default **300s**), always capped at the access-token
  TTL — so a leaked impersonation token is usable only briefly. The audit row
  records `impersonation` + `token_ttl_seconds`. Delegation is unaffected (keeps
  the standard access-token TTL), and an unset/zero time-box falls back to the
  access-token TTL (no behaviour change). _Traceability: C17 → EPIC-17 →
  RFC-016 → #105._

### Added
- **Identity / Delegation / Introspection:** Token introspection now **surfaces the
  `act` (actor) claim** (RFC 7662 / RFC 8693 §4.1). When an introspected access
  token was minted via token exchange (delegation/impersonation), the response
  carries `act` — a nestable `{sub, act}` chain — so a resource server can see
  **who is acting on the subject's behalf**, mirroring the existing `cnf`
  surfacing. Ordinary tokens omit `act` (additive, no behaviour change).
  _Traceability: C16 → EPIC-16 → RFC-019 → #103._

### Added
- **Identity / Delegation / DPoP:** Exchanged tokens are now **opportunistically
  DPoP-bound** (RFC 9449 / RFC 8693). When a token-exchange request carries a
  valid DPoP proof (verified by the token-endpoint middleware), the issued
  exchanged access token is sender-constrained via `cnf.jkt` to the requesting
  client's key; without a proof it is an ordinary bearer token (unchanged). The
  audit row records `dpop_bound`. _Traceability: C16 → EPIC-16 → RFC-019 → #101._

### Added
- **Identity / Delegation / Discovery:** OIDC discovery advertises the RFC 8693
  token-exchange grant (`urn:ietf:params:oauth:grant-type:token-exchange` in
  `grant_types_supported`) **when it can actually be issued**
  (`TOKEN_EXCHANGE_MODE=enforce`). It is omitted in `off`/`shadow` (where the
  grant issues nothing), so the metadata never advertises a capability clients
  can't use. _Traceability: C16 → EPIC-16 → RFC-019 → #99._

### Added
- **Identity / Delegation:** OAuth 2.0 **Token Exchange is now live** (RFC 8693 /
  EPIC-16) under `TOKEN_EXCHANGE_MODE=enforce`. A flagged client
  (`allow_token_exchange`, plus `allow_impersonation` for the actor-absent case)
  may exchange a verified subject token for a new access token. The issued token
  is **downscoped** (scope ⊆ the subject's), **audience-bound** (a target
  `audience`/`resource` is required), **short-lived** (access-token TTL), carries
  the subject's `token_version` so revocation still applies, and stamps the `act`
  (actor) claim — the actor token's subject for delegation, `client:<id>` for
  impersonation — keeping **both principals visible** downstream. Confidential
  clients are authenticated; every exchange is audited (`token_exchange`,
  `outcome=issued`). Policy denials surface as the proper RFC 8693 errors
  (`unauthorized_client` / `invalid_scope` / `invalid_target` / `invalid_client`
  / `invalid_grant`). `off`/`shadow` are unchanged (no issuance). Adds
  `issued_token_type` to the token response. _Traceability: C16 → EPIC-16 →
  RFC-019 → #97._

### Added
- **Identity / Delegation:** Token-exchange shadow mode now performs **full
  validation** (RFC 8693 / EPIC-16). `ExchangeToken` verifies the presented
  subject (and, for delegation, actor) tokens, recovers the subject's scope, and
  runs the authorization policy (`authorizeExchange`) — then audits the *would-be*
  decision (`shadow_allow` with the downscoped grant + audience, or `denied` with
  the reason; plus `invalid_subject_token` / `invalid_actor_token` /
  `parse_error`). It still **issues nothing** and reports the grant unsupported.
  This completes the observe step; only issuance (`enforce`) remains.
  _Traceability: C16 → EPIC-16 → RFC-019 → #95._

### Added
- **Identity / Delegation:** Token-exchange grant **dispatch + shadow telemetry**
  (RFC 8693 / EPIC-16). `POST /oauth/token` now recognizes the token-exchange
  grant and routes it to `OAuthService.ExchangeToken`, gated by
  `TOKEN_EXCHANGE_MODE` (`off` default | `shadow` | `enforce`-reserved). In
  `shadow` it parses and classifies the request (delegation vs impersonation),
  audits the attempt with the requesting client and its capability flags
  (`token_exchange` event), and then reports the grant as **unsupported** — no
  token is verified or issued. In `off` the grant is unsupported and nothing is
  audited. This is the observe step: subject/actor verification + the downscope
  policy, and actual issuance, are later slices. No client-visible behaviour
  change (the grant remains unsupported). _Traceability: C16 → EPIC-16 → RFC-019
  → #93._

## [0.3.0] - 2026-06-22

### Added
- **Identity / Delegation:** Token-exchange **authorization policy** (RFC 8693 /
  EPIC-16) as a pure decision function. `authorizeExchange` enforces the agreed
  best-practice rules — default-deny (`allow_token_exchange` required),
  impersonation gated by `allow_impersonation`, **downscope-only** (requested
  scope ⊆ subject scope; empty defaults to the subject's), and **audience-bound**
  (a target audience or resource is required) — returning the downscoped grant +
  bound audience + delegation/impersonation classification, with a typed error
  per violation. It verifies no tokens and mints nothing; wiring it at the token
  endpoint (observe-first) is the next slice. _Traceability: C16 → EPIC-16 →
  RFC-019 → #90._

### Added
- **Identity / Delegation:** Per-client token-exchange capability flags
  (RFC 8693 / EPIC-16). New `apps.allow_token_exchange` and
  `apps.allow_impersonation` columns (migration `0013`, both default false),
  settable via the admin app API (create / update / response), mirroring
  `require_dpop`. `allow_token_exchange` gates the grant (delegation);
  `allow_impersonation` gates the higher-risk impersonation case. These are the
  default-deny **authorization gate** — they do not by themselves enable the
  grant (nothing reads them yet); wiring + the downscope/audience policy are
  later, observe-first slices. _Traceability: C16 → EPIC-16 → RFC-019 → #88._

### Added
- **Identity / Delegation:** Access tokens can now carry the RFC 8693 §4.1 `act`
  (actor) claim — a new `auth.ActClaim` type (nestable, for delegation chains)
  and an optional `Act` field on `AccessTokenClaims`. This keeps both principals
  (the subject and the actor acting on their behalf) visible to downstream
  services. The claim is `omitempty`, so ordinary tokens are byte-for-byte
  unchanged, and **no issuance path sets it yet** — this is the claim-model
  foundation for token exchange; enabling the grant is a later, policy-gated
  slice. _Traceability: C16 → EPIC-16 → RFC-019 → #86._

### Added
- **Identity / Delegation:** New `internal/shared/auth/tokenexchange` package —
  a standalone parser/validator for OAuth 2.0 Token Exchange requests
  (RFC 8693), the foundation for delegation and impersonation (EPIC-16). It
  validates the protocol parameters (`subject_token`/`subject_token_type`,
  optional `actor_token`/`actor_token_type`, `requested_token_type`, audience,
  scope) and classifies a request as delegation (actor present) vs impersonation,
  with a typed error per violation. **Not** wired into the token endpoint — it
  neither verifies tokens nor authorizes an exchange; enabling the grant is a
  later, policy-gated slice. _Traceability: C16 → EPIC-16 → RFC-019 → #84._

### Added
- **Identity / KMS / Ops:** The JWKS endpoint now supports conditional requests
  (RFC 7232). It sends a strong `ETag` over the key set and returns `304 Not
  Modified` (no body) when a verifier sends a matching `If-None-Match`, so an
  unchanged key set revalidates cheaply and a rotation (which changes the ETag)
  is fetched in full. Complements the `Cache-Control` added in the previous
  slice. _Traceability: C3 → EPIC-3 → RFC-002 → #82._

### Added
- **Identity / KMS / Ops:** The JWKS endpoint (`/.well-known/jwks.json`) now
  sends a `Cache-Control` header so resource servers cache the key set instead
  of refetching it on every token verification (RFC-002). The max-age is
  configurable via `JWKS_CACHE_MAX_AGE_SECONDS` (default 300s) and kept modest so
  a rotated key is picked up promptly; `0` disables caching (`no-store`).
  _Traceability: C3 → EPIC-3 → RFC-002 → #80._

### Added
- **Tokens / DPoP / Discovery:** The OIDC discovery document
  (`/.well-known/openid-configuration`) now advertises
  `dpop_signing_alg_values_supported: ["ES256"]` (RFC 9449 §5.1) **when DPoP is
  enabled** (`DPOP_MODE != off`), so clients can discover DPoP support and the
  accepted proof algorithm. The parameter is omitted entirely when DPoP is off.
  Completes the DPoP rollout's discoverability. _Traceability: C8 → EPIC-8 →
  RFC-003 → #78._

### Added
- **Tokens / DPoP:** **Refresh tokens are now sender-constrained** too
  (RFC 9449 §5). When a token is issued for a DPoP request, the refresh token
  also carries `cnf.jkt`, and the `refresh_token` grant requires the refresh
  request to present a DPoP proof for the **same** key — a mismatched or missing
  proof is rejected with `400 invalid_dpop_proof` (`ErrDPoPKeyMismatch`). A
  stolen DPoP-bound refresh token is therefore unusable without the client's
  key. Unbound (ordinary) refresh tokens are unaffected.
  _Traceability: C8 → EPIC-8 → RFC-003 → #76._

### Added
- **Tokens / DPoP / Admin:** The per-client `require_dpop` flag (#72) is now
  manageable through the admin app API. `POST /api/admin/apps` accepts
  `require_dpop` on creation, `PATCH`/`PUT` toggles it (omitted = unchanged), and
  every app response includes `require_dpop`. Mirrors the existing `require_pkce`
  handling. _Traceability: C8 → EPIC-8 → RFC-003 → #74._

### Added
- **Tokens / DPoP:** Per-client **require-DPoP** policy (RFC 9449). A new
  `apps.require_dpop` flag (migration `0012`, default false) makes the token
  endpoint reject an `authorization_code` or `refresh_token` request from that
  client unless it carries a verified DPoP proof (`400 invalid_dpop_proof`). This
  is the strict end-state of the rollout — unlike global `enforce` (which only
  rejects *present-but-invalid* proofs), a require-DPoP client must also supply a
  proof at all. Default-false, so existing clients are unaffected; the flag
  requires DPoP enabled globally (`DPOP_MODE != off`) to be satisfiable.
  _Traceability: C8 → EPIC-8 → RFC-003 → #72._

### Added
- **Tokens / DPoP:** `DPOP_MODE=enforce` now **rejects a present-but-invalid**
  DPoP proof at the token endpoint with `400 invalid_dpop_proof` (RFC 9449 §5) —
  a malformed, expired, replayed, or mismatched proof can no longer be silently
  downgraded to a bearer token. A valid proof still binds the token and a request
  with **no** proof still proceeds (requiring DPoP per client is a later slice),
  so existing non-DPoP clients are unaffected. The token-endpoint middleware
  (`middleware.DPoP`, renamed from `DPoPObserve`) now handles off/observe/enforce.
  _Traceability: C8 → EPIC-8 → RFC-003 → #70._

### Added
- **Tokens / DPoP:** **Opportunistic sender-constraint** at the token endpoint
  (RFC 9449). When a valid DPoP proof accompanies an `authorization_code` or
  `refresh_token` grant (`DPOP_MODE=observe`/`enforce`), the issued **access
  token is now bound** to the proof's key via `cnf.jkt` — the middleware places
  the verified thumbprint on the request context and the grant uses the new
  `TokenService.GenerateTokenSetWithDPoP`. Clients that send no proof, or an
  invalid one, are unaffected and receive an ordinary bearer token (still never
  rejected — that is the enforce slice). Refresh-token binding is a later slice.
  _Traceability: C8 → EPIC-8 → RFC-003 → #68._

### Added
- **Tokens / DPoP:** Observe-mode DPoP telemetry at the token endpoint
  (RFC 9449 rollout). New `middleware.DPoPObserve` verifies a `DPoP` proof on
  `POST /oauth/token` (binding to the request method/URL, with replay detection)
  and logs structured telemetry — valid vs. rejected, with a short `jkt` prefix
  — **without ever changing the response**. Gated by `DPOP_MODE`
  (`off` default | `observe` | `enforce`-reserved); the replay cache and its
  janitor are created only when enabled and stopped on shutdown. This is the
  "warn-mode telemetry" step before token binding/enforcement.
  _Traceability: C8 → EPIC-8 → RFC-003 → #66._

### Added
- **Tokens / DPoP:** Access tokens can now be **sender-constrained** via the
  `cnf.jkt` confirmation claim (RFC 9449 / RFC 7800). New
  `TokenService.GenerateBoundAccessToken(..., jkt)` issues a token bound to a
  DPoP key thumbprint (an empty `jkt` yields an ordinary unbound token, so it is
  safe to call unconditionally), and token **introspection** now surfaces the
  binding (`cnf.jkt`, RFC 7662 §2.2 / RFC 9449 §7) so resource servers can
  require a matching proof. Ordinary tokens carry no `cnf` (backward
  compatible). The token endpoint does not yet read a `DPoP` request header —
  that wiring (observe→enforce) is the next slice.
  _Traceability: C8 → EPIC-8 → RFC-003 → #64._

### Added
- **Tokens / DPoP:** DPoP proof **replay protection** (RFC 9449 §11.1).
  `dpop.MemoryReplayCache` records proof `jti`s for the brief window a proof is
  acceptable (with a background janitor + graceful `Stop`), and the new
  `dpop.VerifyOnce` verifies a proof *and* enforces single use — a replayed
  `jti` is rejected with `ErrReplayed`, while a proof that fails verification
  never consumes its `jti`. Single-instance in-memory store; a shared
  (e.g. Redis) `ReplayCache` for multi-instance deployments is a later slice.
  Still not wired into the token endpoint — that is the next slice.
  _Traceability: C8 → EPIC-8 → RFC-003 → #62._

### Added
- **Tokens / DPoP:** New `internal/shared/auth/dpop` package — standalone
  verification of DPoP proof JWTs (RFC 9449), the foundation for
  sender-constrained access tokens (EPIC-8 / RFC-003). `dpop.Verify` validates a
  proof's `typ` (`dpop+jwt`), algorithm (ES256), embedded public `jwk`,
  signature, `htm`/`htu` request binding, and `iat` freshness, and returns the
  RFC 7638 JWK thumbprint (`jkt`) used to bind a token to the key. Rejects
  non-ES256 proofs, a `jwk` carrying a private key, and stale/future proofs.
  Verified against generated keys and tamper cases. Not yet wired into the token
  endpoint or resource path — those are later slices.
  _Traceability: C8 → EPIC-8 → RFC-003 → #60._

### Added
- **MFA / Recovery codes:** The MFA status endpoint (`GET /api/profile/mfa`) now
  reports `recovery_codes_remaining` so a user (and the UI) can regenerate backup
  codes before running out — reducing the lockout risk of the admin enforce
  policy. Backed by `MFAService.RemainingRecoveryCodes`; the count is only
  computed for enrolled users (0 otherwise). _Traceability: C9 → EPIC-9 →
  RFC-011 → #58._

### Added
- **Audit / Security:** Audit rows are now **hash-chained** (RFC-007), closing
  the gap left by per-row HMACs (which detect mutation but not deletion or
  reordering). Each row carries the previous chained row's hash (`prev_hash`,
  bound into its own `row_hash`); `repository.VerifyAuditChain` flags any row
  whose backward link is broken, and the integrity scanner records a critical
  `audit_integrity_violation` (with `chain_break_row_id`) for each. Appends are
  serialized with a transaction-scoped advisory lock so the chain cannot fork
  under concurrent writes. Adds the nullable `security_audit_logs.prev_hash`
  column via migration `0011`; existing rows keep an empty `prev_hash` and remain
  verifiable for mutation (the chain hash is backward compatible).
  _Traceability: C5 → EPIC-5 → RFC-007 → #56._

### Security
- **MFA / Login recovery:** Login step-up now accepts a one-time **recovery
  code** in place of a TOTP code, completing the backup story (#52): a user who
  has lost their authenticator can submit a recovery code in the `mfa_code`
  field at login. A valid TOTP code is still the common path and never consumes
  a backup code; only when TOTP fails is the value tried (and consumed) as a
  recovery code, with the redemption audited (`mfa_recovery_code_used`).
  _Traceability: C9 → EPIC-9 → RFC-011 → #54._

### Added
- **MFA / Recovery codes:** One-time backup codes for MFA. `MFAService` can now
  `GenerateRecoveryCodes` (10 per set, replacing any prior set; returned once)
  and `RedeemRecoveryCode` (single-use). Codes are stored only as keyed
  HMAC-SHA256 digests (keyed by `SECRET_KEY_BASE`) in a new `mfa_recovery_codes`
  table (migration `0010`) — a database dump alone cannot reveal or verify them.
  Exposed via `POST /api/profile/mfa/recovery-codes` (requires MFA enabled);
  disabling MFA clears any codes. Redemption is not yet wired into the login
  path — that is the next slice. _Traceability: C9 → EPIC-9 → RFC-011 → #52._

### Security
- **MFA / Admin policy:** Admin-portal login (`/api/admin/login`) can now require
  MFA enrollment, governed by `ADMIN_MFA_POLICY` (observe→enforce rollout):
  `off` (default, unchanged), `observe` (allow superadmins without MFA but audit
  each as a `mfa_policy_violation`), or `enforce` (deny with
  `mfa_enrollment_required` / HTTP 403 until the admin enrolls). An unrecognized
  value fails safe to `off`. Default behaviour is unchanged.
  _Traceability: C9 → EPIC-9 → RFC-011 → #50._
- **MFA / Login step-up:** Login now enforces a second factor for MFA-enrolled
  users (RFC-011). When a user with MFA enabled authenticates, `Login` /
  `AdminLogin` require a valid TOTP code: the first password-only request is
  rejected with `mfa_required` (HTTP 401) and the client retries with
  `mfa_code`; a wrong code returns `invalid mfa code` (401) and is audited as a
  failed login (`reason: mfa_invalid`). Wired via `AuthService.WithMFA` and
  active only for users who have opted in by enrolling — users without MFA see
  no change. _Traceability: C9 → EPIC-9 → RFC-011 → #48._

### Added
- **MFA / API:** Self-service TOTP enrollment endpoints (authenticated, under
  `/api/profile/mfa`): `POST /enroll` (returns the secret + `otpauth://`
  provisioning URI), `POST /confirm` (validates a code and enables MFA),
  `POST /disable`, and `GET /mfa` (status). Wires `service.MFAService` into the
  router/bootstrap; a user can only ever change their own MFA (the id comes from
  the authenticated context). `settings/config` now reports `MFAEnabled: true`.
  Login step-up enforcement is the next slice. _Traceability: C9 → EPIC-9 →
  RFC-011 → #46._
- **MFA:** New `service.MFAService` — the TOTP enrollment/verification lifecycle
  (`BeginEnrollment`, `ConfirmEnrollment`, `Verify`, `Disable`, `IsEnabled`).
  Enrollment generates a TOTP secret, stores it **encrypted at rest**
  (`auth.EncryptSecret`, keyed by `SECRET_KEY_BASE`), and leaves MFA disabled
  until a code is confirmed; a database compromise alone does not reveal the
  seed. Adds `users.mfa_secret` / `users.mfa_enabled` (`User.MFASecret` is never
  serialized) via migration `0009` (additive, nullable/defaulted). The service
  is not yet wired into HTTP enrollment or login step-up — that is the next
  slice. Also adds `totp.GenerateCode` (the symmetric counterpart to
  `ValidateCode`). _Traceability: C9 → EPIC-9 → RFC-011 → #44._
- **Security / crypto:** New `auth.EncryptSecret` / `auth.DecryptSecret` —
  authenticated AES-256-GCM encryption (key derived from `SECRET_KEY_BASE` via
  SHA-256, random nonce) for storing short restricted secrets (e.g. TOTP seeds)
  encrypted at rest. Decryption fails on a wrong key or tampered ciphertext.
  _Traceability: C12 (supporting EPIC-9 MFA) → RFC-010/RFC-011 → #42._
- **MFA:** New `internal/shared/auth/totp` package — standard-library TOTP
  (RFC 6238 / HOTP RFC 4226) primitives: `GenerateSecret`, `ProvisioningURI`
  (otpauth:// for authenticator apps), and `ValidateCode` (6 digits, 30s, ±1
  step skew, constant-time). Verified against the RFC 6238 test vectors. First
  building block of MFA; not yet wired into enrollment/login.
  _Traceability: C9 → EPIC-9 → RFC-011 → #40._

### Security
- **Identity / JWT:** Token verification now enforces the issuer
  (`jwt.WithIssuer`) and requires an expiry (`jwt.WithExpirationRequired`): a
  token whose `iss` is not this server's issuer, or that carries no `exp`, is
  rejected at the parser level. Backward compatible — every issued token sets
  both claims. _Traceability: C3 → EPIC-3 → RFC-002 → #38._

### Added
- **Audit / Security / Ops:** The audit-row integrity scan can now run on a
  timer. `AuditIntegrityScanner.StartSchedule(interval, lookback)` runs the scan
  periodically; `Bootstrap` enables it when `AUDIT_INTEGRITY_SCAN_INTERVAL_SECONDS`
  is set (default `0` = disabled; lookback `AUDIT_INTEGRITY_SCAN_LOOKBACK_SECONDS`
  defaults to 24h) and stops the goroutine on graceful shutdown. Default
  behaviour unchanged. _Traceability: C5 → EPIC-5 → RFC-007 → #36._
- **Audit / Security:** Audit-row tamper-evidence is now **actionable**.
  `repository.VerifyAuditRows` batch-verifies stored rows' HMACs, and the new
  `service.AuditIntegrityScanner.Scan` pages audit rows over a time window,
  flags any that fail verification, and records a critical
  `audit_integrity_violation` event (with the offending row id) per tampered
  row. (An opt-in scheduler to run this automatically is a tracked follow-up.)
  _Traceability: C5 → EPIC-5 → RFC-007 → #34._

### Fixed
- **Tests:** Made `TestLOW02_MaxAge_ExactlyAtBoundary_Accepted` deterministic by
  re-anchoring `LastLogin` immediately before the call, eliminating a timing
  flake that surfaced under the slow `-race` CI runner (elapsed setup time could
  push the measured session age one second past the `max_age` boundary).
  _Traceability: C6 → EPIC-6 → RFC-014 → #28._

### Infrastructure
- **CI / lint:** Enabled `staticcheck` in the `golangci-lint` gate. Fixed its 11
  findings: the 9 `SA9003` empty error-branches in `auth_service.go` (failed-login
  counting, account lockout, last-login update) now **log** the previously-silent
  errors via `logger.Warnf` instead of ignoring them; the RFC-7009 revocation
  ignore is made explicit (`_ =`); and a `QF1003` if-chain became a tagged switch.
  Additive logging only — control flow unchanged. _Traceability: C6 → EPIC-6 → RFC-014 → #32._
- **CI / lint:** Added a `golangci-lint` gate (`.golangci.yml`) enforcing
  `errcheck`, `govet`, `ineffassign`, and `unused`, and resolved all 26
  findings (acknowledged fire-and-forget calls with `_ =`, wrapped deferred
  `Close`, removed dead `web.writeJSON`). Test-file `errcheck` is excluded as
  noise; `staticcheck` (incl. SA9003 empty-branch fixes in the auth path) is a
  tracked follow-up. _Traceability: C6 → EPIC-6 → RFC-014 → #30._
- **CI / formatting:** Normalized the entire repository with `gofmt` and added a
  `gofmt` gate to CI so unformatted code fails the build. Formatting-only change
  (no semantics). `golangci-lint` enforcement remains a follow-up.
  _Traceability: C6 → EPIC-6 → RFC-014 → #26._

- **CI:** Added a GitHub Actions workflow (`.github/workflows/ci.yml`) that runs
  `go build`, `go vet`, `go test -race`, and `govulncheck` on every push to
  `main` and every pull request. _Traceability: C6 → EPIC-6 → RFC-014 → #24._

### Security
- **Toolchain:** Bumped the Go directive to `1.25.11`, clearing 12 standard-
  library vulnerabilities (net/textproto, crypto/x509, crypto/tls,
  html/template, net, net/url, os) flagged by the new `govulncheck` CI gate.
  Patch-level bump; no source changes. _Traceability: C6 → EPIC-6 → RFC-014 → #24._

### Added
- **Audit / Security:** Security audit rows are now **tamper-evident** — each
  row carries a keyed HMAC (`row_hash`) over its immutable content, stamped at
  the repository choke point and keyed by `SECRET_KEY_BASE` (held in config,
  never in the DB). `repository.VerifyAuditRowHash` detects any row mutated
  without the secret. Enabled by configuring the secret (disabled otherwise);
  adds the `security_audit_logs.row_hash` column via migration `0008`.
  Detects row *mutation*; deletion/reordering (hash-chaining) is a later slice.
  _Traceability: C5 → EPIC-5 → RFC-007 → #22._

### Changed
- **Audit / Observability:** Direct (hot-path) security audit writes —
  `authService`/`oauthService.logSecurityEvent` (login, token, OAuth events) —
  now also stamp the `correlation_id` from the request context, via a shared
  `newSecurityAuditLog` builder. Completes request-path audit correlation
  coverage left open by #16. _Traceability: C4 → EPIC-4 → RFC-008 → #20._

### Added
- **Audit / Observability:** Admin-action logs now record a `correlation_id`,
  completing correlation coverage across both audit stores. Adds the
  `admin_logs.correlation_id` column via migration `0007` (additive, nullable,
  indexed). _Traceability: C4 → EPIC-4 → RFC-008 → #18._
- **Audit / Observability:** Security audit events now record a `correlation_id`,
  linking each audit row to the request that produced it (derived from the
  request context, or an explicit `SecurityEvent.CorrelationID`). Adds the
  `security_audit_logs.correlation_id` column via migration `0006` (additive,
  nullable, indexed). _Traceability: C5 → EPIC-5 → RFC-007 → #16._
- **Observability:** Request logs now include a `correlation_id` field when a
  correlation ID is present in the request context, so a request can be traced
  end-to-end across log lines. `middleware.CorrelationID()` now runs before the
  request logger in all router stacks so the ID is available when logging.
  _Traceability: C4 → EPIC-4 → RFC-008 → #14._
- **Identity / KMS / Ops:** Scheduled key rotation + retired-key pruning can now
  be enabled at startup via `KEY_ROTATION_INTERVAL_SECONDS` and
  `KEY_RETENTION_SECONDS` (both default `0` = disabled / derive retention from
  `REFRESH_TOKEN_TTL`). `Bootstrap` starts the schedule when an interval is set,
  warns if the interval exceeds `REFRESH_TOKEN_TTL`, and stops the rotation
  goroutine during graceful shutdown. Default behaviour is unchanged.
  _Traceability: C3 → EPIC-3 → RFC-002 → #12._
- **Identity / KMS:** `KeyManager.PruneRetiredKeys(maxAge)` removes retired
  signing keys older than a retention window (mod-time based) from both the
  in-memory ring and the `retired/` directory, bounding ring and JWKS growth
  across rotations. New `StartRotationScheduleWithRetention(interval, retention)`
  prunes automatically after each rotation when `retention > 0`;
  `StartRotationSchedule(interval)` is unchanged (retention disabled). Pruning
  is conservative — a retired key whose file cannot be stat'd/removed is kept.
  _Traceability: C3 → EPIC-3 → RFC-002 → #10._

### Security
- **Identity / JWT:** Pinned token verification to an explicit algorithm
  allow-list of exactly `RS256` via `jwt.WithValidMethods` in
  `verifyToken`. Tokens presenting any other `alg` (`RS384`/`RS512`, `none`,
  or an HMAC algorithm) are now rejected by the parser before the keyfunc
  runs, regardless of the key. Backward compatible — the server only ever
  issues RS256. _Traceability: C3 → EPIC-3 → RFC-002 → #8._

## [0.2.0]

### Added
- **Identity / KMS:** Introduced a `Signer` interface in `internal/shared/auth`
  that abstracts the JWT signing operation, with a default `localSigner`
  (in-process RSA key via `KeyManager`) and a `NewTokenServiceWithSigner`
  injection constructor. This is the "adapters before replacements" seam that
  lets a future KMS/HSM-backed signer be substituted without changing any
  token-generation code. Behaviour is unchanged (RS256 + `kid` header).
  _Traceability: capability C3 → EPIC-3 → RFC-002 → #6._

[Unreleased]: https://github.com/ovander/go-oauth2/compare/v1.6.0...HEAD
[1.6.0]: https://github.com/ovander/go-oauth2/compare/v1.5.3...v1.6.0
[1.5.3]: https://github.com/ovander/go-oauth2/compare/v1.5.2...v1.5.3
[1.5.2]: https://github.com/ovander/go-oauth2/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/ovander/go-oauth2/compare/v1.5.0...v1.5.1
