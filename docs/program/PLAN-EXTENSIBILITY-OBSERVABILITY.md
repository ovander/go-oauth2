# Plan — Extensibility & Policy · Observability & Scale

**Date:** 2026-09-03 · **Baseline:** functionality score 74/100 (README reconciliation), with
*Extensibility & policy* at 4.5/10 and *Observability & scale* at 5.0/10 — the two weakest
domains. **Target after this plan:** both at 8/10, overall ≈ 84/100, with no flag day: every new
control ships `off → observe/shadow → enforce`, exactly as the existing modes do.

The plan maps onto the program's epics so nothing here is a new direction:
EPIC-4 Observability (RFC-008), EPIC-10 Policy Engine (RFC-005), EPIC-11 backendkit PEP
(RFC-004), EPIC-13 Distributed State (RFC-013), EPIC-16 Resilience (RFC-018).

Effort: **S** ≤ 2 days · **M** ≤ 1 week · **L** 2–3 weeks, one engineer, each item one or two PRs.

---

## 1. What "extensible" and "observable" mean here

Today an integrator can change Socrate's behaviour only through env flags and by editing Go. An
operator can see it only through logs, the SOC console and the SSE stream. The gaps, in order of
how often they block a real deployment:

| Gap | Symptom |
|---|---|
| No per-client policy | any client may request `admin` / `monitoring:*`; roles are the only boundary (P3-8) |
| No custom claims | apps that need `tenant_id`, `plan`, `department` in the token must call back to Socrate |
| No outbound events | nothing can react to "user created", "login failed ×10", "client secret rotated" without polling the audit API |
| No policy decision point | authorisation logic is duplicated in every app; the roadmap's PDP has no first implementation |
| No branding / i18n | hosted login is Socrate-branded, English only |
| No metrics / traces | no SLOs, no dashboards, no p99; only logs and the SOC console |
| In-process state | rate limits, DPoP replay, auto-defense, IP-block cache live in one process ⇒ single instance |

---

## 2. Track A — Extensibility & policy (4.5 → 8)

### A1. Per-client allowed scopes (closes P3-8) — **S/M**, first
- `apps.allowed_scopes text[]` (empty = every supported scope, so existing clients are untouched).
- `SCOPE_POLICY_MODE=off|observe|enforce`: `observe` audits `scope_denied` events without refusing;
  `enforce` returns `invalid_scope` at `/oauth/authorize` and at every grant in `/oauth/token`
  (auth code, refresh — downscoping only, `client_credentials`, token exchange).
- Admin API + console: scope picker on the client form; the two console clients get
  `admin` / `monitoring:read monitoring:write` seeded by the runbook.
- Discovery unchanged (`scopes_supported` stays global).
- Tests: each grant × mode; refresh cannot re-widen; observe emits exactly one audit row.

### A2. Custom claims via declarative mapping — **M** — ✅ delivered
- `users.attributes jsonb` (admin-editable, per-app-admin editable for their members) and
  `apps.claim_mappings jsonb`: `{"tenant_id": "user.attributes.tenant_id", "plan": "app_role"}`.
- Sources allowed: `user.attributes.*`, `user.email/name`, `app_role`, `app.id/client_id`,
  literal. Targets: access token, ID token, both. Claims land under a configurable namespace
  (`CLAIMS_NAMESPACE`, default `https://socrate/`) — never overwrite registered claims.
- Implementation: a `ClaimsEnricher` interface called from `TokenService.GenerateTokenSetWithAuth`;
  the mapping enricher is the first implementation, A6 hooks are the second.
- backendkit `jwtauth`: `SocrateClaims.Custom map[string]any` + `ctxutil` accessor.
- Tests: mapping resolution table, namespace collision refused, size cap (token stays < 4 KB).

**As delivered.** Migrations `0016`/`0017`; sources also include `user.id`; mappings accept a
bare-string shorthand (`"tier": "user.attributes.tier"`) alongside the object form; attributes
are set via `PUT /api/admin/users/{id}/attributes` (global admin, audited by attribute *name*)
rather than by app admins — per-app-admin editing is deferred until per-app attribute scoping
exists. The enricher hangs off `TokenService.SetClaimsEnricher` (a setter, not a constructor
argument, so no existing call site changed) and is consulted for both the access and ID tokens.
Caps: 32 attributes / 4 KB per user, 2 KB of custom claims per token — over the cap the set is
dropped whole and logged at error level rather than truncated. The backendkit `jwtauth` accessor
is a follow-up PR in that repo.

### A3. Webhooks with a transactional outbox — **M/L** — ◧ part 1 of 2 delivered
- `webhook_subscriptions` (per app or global-admin; URL, secret, event filter, active) and
  `webhook_deliveries` (outbox: event id, payload, attempts, next_attempt, last_status).
- Events are written to the outbox **in the same transaction** as the security audit row
  (`logSecurityEvent` → outbox), so a delivery can never exist without its audit entry.
- Dispatcher: one goroutine per instance claims rows with `FOR UPDATE SKIP LOCKED`
  (multi-instance-safe from day one, see B4), signs with HMAC-SHA256 over
  `timestamp.body` in `X-Socrate-Signature`, retries with exponential backoff, dead-letters after
  N attempts, exposes the delivery log in the admin API and console.
- **Security rules (non-negotiable):** target URLs must be `https://`, resolve to public
  addresses only (re-resolved at send time; RFC 1918, loopback, link-local and the VPS's own
  addresses refused — SSRF into `:8081` is the obvious attack), no redirects followed, 5 s
  timeout, response body discarded. Secrets shown once, rotatable.
- Event catalogue v1: `user.created|verified|locked|unlocked|blocked|deleted`,
  `login.succeeded|failed|mfa_required`, `client.created|updated|secret_rotated|deactivated`,
  `token.revoked_all`, `alert.fired`, `ip.blocked`.

**As delivered (part 1: subscriptions + outbox).** Tables, admin API
(`/api/admin/webhooks`, global admin + fresh step-up on the mutating routes),
the event catalogue as an *allow-list* over `SecurityEventType`, the
transactional enqueue, and the SSRF guard (`internal/shared/ssrf`) applied at
registration. The enqueue runs inside a savepoint so a failed enqueue costs the
webhook, not the audit row — the plan's "same transaction" guarantee holds in
the direction that matters (no delivery without its audit entry). Routing is
decided against an in-memory subscription cache (refreshed on local writes and
every `WEBHOOK_CACHE_REFRESH`), so the audit hot path adds no query — only the
insert. `WEBHOOKS_MODE=off` is the default and enqueues nothing. Catalogue
deltas: `user.blocked`, `user.deleted`, `alert.fired` and `ip.blocked` have no
`SecurityEventType` behind them yet and are deferred rather than faked;
`client.deactivated` is emitted as `client.deleted`, the event that actually
exists; `login.mfa_required` is `login.mfa_policy_violation`, matching the audit
event. Added beyond the plan: `token.exchanged` and five `security.*` events
that were already audited and are exactly what a SOC subscriber wants.

**Part 2 (next).** The dispatcher: `FOR UPDATE SKIP LOCKED` claiming,
HMAC-SHA256 over `timestamp.body` in `X-Socrate-Signature`, exponential backoff,
dead-lettering after N attempts, connect-time re-resolution through the same
SSRF guard, no redirects, 5 s timeout, response body discarded.

### A4. Policy decision point, shadow first (EPIC-10 / RFC-005) — **L**
- Contract (small on purpose):
  `POST /api/policy/decide` `{principal, app, action, resource, context}` →
  `{allow, reason, obligations[]}`; the same function is callable in-process.
- v1 engine: RBAC (global role, app role) + ABAC over `user.attributes`, `app`, `context`
  (`ip_country`, `auth_time_age`, `amr`), rules stored in Postgres with the backendkit
  `tiering.PolicyRepository` pattern, cached 5 min, versioned, with an admin API and a console
  editor that validates before save.
- `POLICY_MODE=off|shadow|enforce`: in `shadow` the admin routes (and, via backendkit's PEP in
  EPIC-11, the apps) *consult* the PDP and log would-be denials; `enforce` honours it. The
  existing gates (`RequireGlobalAdmin`, `RequireAppAdmin`, `RequireFreshAuth`) become rules, not
  code, only after shadow shows parity for a release.
- Decision log rows carry the correlation id, so a denial is traceable in the SOC console.

### A5. Hosted-page branding and i18n — **M**
- Per-app branding on the `App` record: product name, logo URL (allowlisted to the app's own
  origin, served through `img-src`), primary colour (validated hex → CSS variable). No raw
  HTML/CSS from the database, ever.
- `TEMPLATES_DIR` overlay: operator-supplied templates override the embedded ones, parsed with
  the same `html/template` funcs; a startup check refuses templates that use `template.HTML`.
- Message catalogues (`en`, `fr` to start) selected by `Accept-Language` / `ui_locales`;
  `/oauth/authorize?ui_locales=` honoured per OIDC.

### A6. In-process hooks — **S**, alongside A1
- `hooks.Register(hooks.BeforeTokenIssue, fn)` / `AfterLogin` / `UserProvisioned` /
  `BeforeConsent`. Compile-time Go extension for operators who fork; A2 and A3 are implemented as
  hooks so the mechanism is exercised by the core itself.

---

## 3. Track B — Observability & scale (5.0 → 8)

### B1. Prometheus metrics — **S/M**, first
- `/metrics` on the **admin port only** (loopback; Caddy never routes it), `prometheus/client_golang`.
- RED per route (chi middleware: requests, errors, duration histogram, labelled by route pattern
  and status — never by user or client id), plus domain metrics:
  `socrate_tokens_issued_total{grant,outcome}`, `socrate_logins_total{outcome,method}`,
  `socrate_rate_limit_hits_total{limiter}`, `socrate_ip_blocks_total{reason}`,
  `socrate_refresh_reuse_total`, `socrate_dpop_rejects_total`, `socrate_signing_key_age_seconds`,
  `socrate_audit_chain_lag_seconds`, `socrate_db_pool_*`, `socrate_build_info`.
- backendkit `httpware` gets the same RED middleware so every BFF and app reports alike.
- Ships with `deploy/observability/`: Prometheus scrape config, Grafana dashboard JSON
  (identity overview, auth funnel, security), Alertmanager rules (B7).

### B2. OpenTelemetry traces (RFC-008) — **M**
- `otelhttp` on the three routers and on the BFF proxies, GORM `otelgorm`, outbound HTTP
  (SMTP excluded) instrumented; the existing correlation id becomes a span attribute and is
  emitted as `traceparent` upstream/downstream.
- Exporter via standard `OTEL_EXPORTER_OTLP_ENDPOINT`; off when unset. Sampling default 10 %,
  100 % for 5xx and auth failures (tail-based is out of scope).

### B3. Log conventions and redaction at source — **S**
- One documented schema (`ts, level, msg, correlation_id, trace_id, client_ip, route, user_id?`),
  `LOG_FORMAT=json|text`, per-event sampling for high-volume successes, and a unit test that
  greps the logger for token/secret/password fields (extends the pass-4 check).

### B4. Distributed state adapters (EPIC-13 / RFC-013) — **M/L**
- Define the store interfaces where the state is in-process today:
  `RateLimitStore` (`middleware.RateLimiter`), `dpop.ReplayCache` (already an interface),
  `AutoDefenseStore` (`ipRecords`), `IPBlockCache`, `LoginStateStore` for the hosted flow if any
  server state is added. Memory stays the default.
- **First adapter: Postgres, no new infrastructure.** `UNLOGGED` tables with fixed-window
  counters via `INSERT … ON CONFLICT DO UPDATE … RETURNING`, replay entries with `exp`, a
  sweeper. Correct under N instances; ~1 ms per check on loopback, acceptable for the token
  and login endpoints at this scale.
- Optional Redis adapter behind the same interfaces (`STATE_BACKEND=memory|postgres|redis`)
  for deployments that already run Redis.
- The webhook outbox (A3) and the monitoring BFF's Postgres sessions already follow this model.

### B5. Multi-instance readiness — **M**, after B4
- Key rotation guarded by a Postgres advisory lock (one rotator; the JWKS ring already serves
  current + previous); migrations behind the same lock; sweepers (used tokens, magic links,
  reports) elect a leader with `pg_try_advisory_lock`.
- `/health/readiness` reports DB, key material, and store adapter reachability; Caddy
  `lb_policy first` / `round_robin` example with two Socrate instances in the runbook.
- Acceptance: a k6 run (B6) against two instances behind Caddy shows correct rate limiting,
  no double refresh, no replay acceptance, and key rotation once.

### B6. Performance baseline — **S/M**
- k6 scenarios in `deploy/perf/`: `token_refresh`, `authorize_login_consent`, `introspect`,
  `client_credentials`; CI perf smoke on a Postgres service container with thresholds
  (p95 token < 100 ms at 200 rps on the CI runner) that fail the build on a 25 % regression.
- Publish the numbers in the runbook so operators can size the VPS.

### B7. SLOs and alerting — **S**
- SLOs: token endpoint availability 99.9 %, p99 < 150 ms; login p99 < 400 ms (bcrypt bound);
  revocation freshness per the SLA doc; audit-chain integrity scan lag < 5 min.
- Alertmanager rules for the SLOs plus the security signals already emitted (refresh reuse,
  auto-defense blocks, DPoP rejects, JWKS fetch failures at resource servers).

---

## 4. Sequencing and score projection

| Phase | Weeks | Items | Extensibility | Observability | Overall |
|---|---|---|---|---|---|
| 0 (today) | — | — | 4.5 | 5.0 | 74 |
| 1 — quick wins | 1–3 | A1, A6, B1, B3, B7 | 5.5 | 6.5 | 78 |
| 2 — substance | 4–9 | A2, A3, B4 (Postgres adapter), B6 | 7.0 | 7.0 | 81 |
| 3 — platform | 10–17 | A4 (shadow), A5, B2, B5 (two-instance validation) | 8.0 | 8.0 | 84 |

Order inside each phase is by dependency: A6 before A2/A3; B4 before B5; B1 before B7.
Redis and `POLICY_MODE=enforce` are deliberately outside the plan's exit criteria.

---

## 5. Guardrails

- **No flag day.** Every item defaults to `off` (A1–A4, B2, B4) or is additive (B1, B3, B6,
  B7). Existing clients and consoles behave identically until an operator flips a mode.
- **Security review per item.** A3 (SSRF, signing), A4 (privilege of rule editors — superadmin
  only, fresh-auth), A5 (template injection), B1 (no PII in labels, admin port only) each get
  a pass-4-style check before merge; the audit ledger gains a row per item.
- **One PR per bullet** where possible; `observe` telemetry must exist for a release before
  `enforce` is offered.
- **Docs move with code:** `docs/API.md`, `.env.example`, the runbook and the consoles are
  updated in the same PR as the feature.
