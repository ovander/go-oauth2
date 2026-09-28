# Socrate suite — end-to-end, security and performance test report (v1.3.0)

Date: 2026-09-28 · Suite: go-oauth2, backendkit, oauth2-admin, oauth2-monitoring

This report records the tests run against the v1.3.0 line before deployment: a
full end-to-end pass through both consoles and a backendkit-only sample app,
a security pass (protocol, authorization, injection, JWT, browser), a
penetration-test pass structured on the OWASP WSTG, a defensive-controls pass
with monitoring verification, and a performance pass against the B6 baseline.
It is written to be re-runnable: every check is a script under
[`deploy/e2e/`](../deploy/e2e/), and the method for each area is stated so an
external assessor can reproduce or extend it.

## 1. Commits under test

| Repo | main | Notes |
|---|---|---|
| go-oauth2 | `2ba3b0a` | server + admin API |
| backendkit | `12adfdb` | shared library (bff, socrate, pep, jwtauth) |
| oauth2-admin | `bd8e6f2` | admin console (SPA + BFF) |
| oauth2-monitoring | `2351dbd` | monitoring console (SPA + BFF) |

Two fixes were made during testing and are proposed as separate PRs (§7); the
results below were re-verified with them applied.

## 2. Environment and method

A production-shaped stack was assembled locally, entirely from the shipped
artifacts and deployment kit — not test doubles:

- PostgreSQL 16 on loopback; `go-oauth2` server (public `:8080`, admin `:8081`).
- Both console BFFs (`backendkit/bff`) and a **sample application built only
  from backendkit** (`deploy/e2e/demoapp`, ~260 lines: Authorization Code +
  PKCE via `bff` + `socrate`, resource API guarded by `jwtauth`, policy checks
  via `pep`). This exercises the library the way a third-party integrator would.
- Caddy in front, using the repo's own site blocks adapted to `*.localhost`
  (same routes, same headers, plain-HTTP for the sandbox).
- An SMTP sink so verification/reset/invite/magic-link/credential emails could
  be followed end-to-end.
- Browser flows driven with Playwright/Chromium; a per-page watcher recorded
  every console error, CSP violation, failed request and 4xx/5xx.
- API and protocol flows driven with a small stdlib-only Python harness
  (`deploy/e2e/flows*.py`, `security.py`, `pentest.py`, `resilience.py`,
  `policy_rules.py`, `defenses.py`, `hardening.py`); load with k6 v1.8.1.

The first superadmin was seeded with `socrate-seed`, and both console clients
plus the demo app were registered through the admin API / admin UI exactly as
the runbook (`docs/DEPLOYMENT-VPS-MULTI-APP.md` §4–6) prescribes. Docker images
for all three services also build from the pinned bases and boot with a healthy
readiness probe (server: 24 migrations, policy v1 seeded; BFFs fail closed
without a client id).

## 3. Functional / end-to-end results

All flows were driven through the real UI or the real HTTP surface.

| Area | Result |
|---|---|
| Admin console: sign-in via hosted login + consent, all 12 pages | pass, 0 console/CSP/network errors |
| Admin console: create/update/deactivate/rotate/delete app, block/unlock/revoke/delete user, superadmins CRUD, blocked-IP add/remove, alert-rule CRUD, report generate, profile update, connection tests, CSV export | pass (26/27 API + 17/18 UI; the two gaps were test-setup, not product) |
| Monitoring console: sign-in, all 12 pages, event filter/paginate/detail, correlation-id pivot, blocked-IP block/unblock, alert create + history, policy-decision filters/detail/pivot, audit CSV export, reports | pass (all interactive controls) |
| Demo app (backendkit only): login (code+PKCE), `/api/me` via jwtauth, CSRF-guarded mutation, pep decide (user + app), token-exchange service call, auto-refresh on access-token expiry, logout + refresh-token revocation | pass |
| Account lifecycle: signup → email verify → login; forgot/reset password (single-use, revokes sessions); MFA enrol/confirm/login/recovery-code/disable; magic link (service-initiated, single-use); lockout → admin unlock | pass |
| OAuth/OIDC: refresh rotation + reuse rejection, introspect (active/inactive, client-auth required), revoke, userinfo, ID/refresh token not accepted as access token, `ACCESS_TOKEN_TTL` honoured, end-session | pass |
| Consent deny; consent re-prompt each session | pass |

**Coverage note.** Every write endpoint the two consoles call was exercised
against the live admin API through the BFF (session cookie + `X-CSRF-Token`),
and separately through the UI. The policy decision point was exercised in all
three modes (off/shadow/enforce), from the admin PEP, the app decide endpoint,
and the backendkit `pep` middleware.

## 4. Security results

Structured on OWASP ASVS L2 / WSTG. Full logs in `deploy/e2e/results/`.

**Passed (representative):**

- **Transport/headers:** CSP with `frame-ancestors 'none'`, `X-Content-Type-Options`,
  `Referrer-Policy`, no `Server` banner on all three shipped origins; CSP blocks
  an injected inline script (verified in-browser).
- **Cookies/session:** session cookies are `HttpOnly` + `SameSite=Strict`, not
  readable by JS; no tokens in `localStorage`/`sessionStorage`; **session
  fixation** — a pre-set session id is replaced at login.
- **CSRF:** unsafe methods without `X-CSRF-Token` are refused by both BFFs; the
  hosted login/consent form requires its server-issued `csrf_token`.
- **CORS:** `Access-Control-Allow-Origin` reflects only configured origins;
  `Origin: null` and unknown origins are not reflected.
- **redirect_uri:** path-suffix, host-suffix (`…9003.evil.example`), extra query,
  fragment, `javascript:` and host-swap variants all refused.
- **PKCE/response_type:** `plain` refused, missing PKCE refused for a
  `require_pkce` client, implicit `response_type=token` refused.
- **Open redirect:** BFF `return_to` sanitised (`//evil`, `https://evil`,
  `/\evil`, encoded, `javascript:`).
- **AuthZ:** plain and app-admin users refused on every admin route (401/403);
  an app admin cannot grant a non-app role; profile update cannot change own
  role (no mass assignment); forced browsing to the admin API refused.
- **JWT:** payload tampering, **alg=none**, **HS256/RS256 confusion keyed with
  the public JWKS**, unknown `kid`, and `jku` header injection all refused.
- **Injection:** SQLi/again-union/`;DROP` probes on events/users/logs return
  clean results, never a 5xx or SQL error; login SQLi refused cleanly.
- **Stored XSS:** app name and event details carrying `<img onerror>`/`<script>`
  payloads render inert in both consoles (framework escaping + CSP).
- **BFF path traversal:** encoded/duplicate/dot-segment paths refused (P3-18
  canonical-path guard), now covering `/api/apps/*` as well as `/api/admin/*`.
- **Enumeration:** unknown email and wrong password give identical answers;
  password-reset request is uniform.
- **Password policy:** length and character-class rules enforced.
- **Response hygiene:** token responses carry `Cache-Control: no-store`; 404 and
  malformed JSON leak no stack or framework internals.
- **Opt-in hardening verified when enabled:** `REFRESH_REUSE_MODE=enforce`
  revokes the family on reuse; `SCOPE_POLICY_MODE=enforce` + per-client
  `allowed_scopes` answer `invalid_scope`; token exchange is default-deny,
  downscope-only, audience-bound, records the actor and cannot up-scope; the
  **webhook SSRF guard** refuses loopback/link-local/private/IPv4-mapped/decimal/
  hex hosts and non-`https` schemes, and requires public DNS resolution.

**Findings:** see §6.

## 5. Penetration test (WSTG-structured)

All against the local sandbox; no third-party systems touched.

| WSTG area | Check | Result |
|---|---|---|
| CONF-07 | Host / X-Forwarded-Host injection into emailed links | safe — links use the configured issuer |
| SESS-05 | CSRF on hosted login POST | refused without `csrf_token` |
| INPV | header injection / response splitting via `state` | no injected header |
| ATHZ-01 | forced browsing of admin API unauthenticated | 401 |
| ATHZ-02 | app-scoped IDOR (app-2 service token on app-3) | refused (`token is not authorized for this app`) |
| BUSLOGIC | invite token redirected to another email | email-bound + single-use; only the intended account is created |
| ATHN | client-IP spoofing via `X-Forwarded-For` | ignored unless the peer is a trusted proxy; with `TRUSTED_PROXIES=none`, unique spoofed IPs do **not** dodge the per-IP rate limit |

## 6. Findings

Severity is for the default posture. None blocks a shadow-mode deployment, but
the observability items materially weaken the SOC story and should be scheduled.

### Fixed during testing (PRs proposed, §7)

- **F1 (High) — admin console writes were entirely broken.** The admin BFF
  proxied `/api/admin/*` but not the app-scoped `/api/apps/{id}/…` routes, so
  the console's app **Users/Activity** tabs returned `index.html` and every
  app-scoped write failed. Fixed: route `/api/apps/` through the same
  session-authenticated proxy; Caddy allow-list updated to match. Regression
  test added to the BFF e2e test.
- **F2 (High) — every console session died at its first token refresh.** A
  global admin has no per-app membership row (by design, as for hosted login and
  code issuance), but the **refresh grant** did not apply that rule and returned
  `500`, so a superadmin's admin-console session broke the moment its first
  access token expired. Fixed: honour the global-admin bypass on refresh, map a
  genuinely dead grant (user removed/deleted) to `invalid_grant` (400) instead
  of `server_error` (500) so a BFF ends the session cleanly, and fix a
  foreign-key crash when writing the `token_revoked` audit row for a
  client-authenticated `/oauth/revoke` (attributed to user 0). Tests added.

### Open findings (no fix in this pass)

- **F3 (Medium, observability) — the "live" SSE security feed goes stale under
  any real backlog.** `GET /api/admin/events/stream` starts from event id 0 and
  pages 50 rows per 2 s tick, and the connection is capped by the 15 s server
  `WriteTimeout`. With 50 k audit rows present, a 14 s stream delivered only ids
  1–359; a brand-new event would take ~33 min to surface, and the stream is
  torn down and restarts from 0 first. Suggested fix: initialise `lastEventID`
  to `MAX(id)` at connect (only stream *new* events), let the SPA pass
  `last_event_id`, and give the stream its own long/again write deadline.
- **F4 (Medium, observability) — alert rules are never evaluated.** Rules can be
  created/edited/deleted and are stored, but nothing consumes them: no engine
  matches audit events against rule conditions, and the alert **history is
  always empty**. The monitoring "Alerts" page therefore never fires. Either
  wire an evaluator (audit-event → rule match → `TriggeredAlert` + notify) or
  mark the feature clearly as not-yet-active.
- **F5 (Medium, observability) — service-layer audit events carry no client IP
  or user-agent.** `login_failed/success`, `token_refreshed`, `token_revoked`,
  `client_auth_failed`, `account_locked` are written via `Log()` (not
  `LogFromRequest`), so `ip_address`/`user_agent` are empty. Threat-Intel
  "suspicious IPs" shows blank principals and the SOC cannot pivot most events
  by IP. Thread the request context (or the resolved client IP) into these
  service calls.
- **F6 (Low, forensics) — deleting an app rewrites stamped audit rows.** App
  deletion runs `UPDATE security_audit_logs SET app_id = NULL WHERE app_id = ?`,
  which changes rows already HMAC-stamped for tamper evidence (RFC-007). The
  integrity scanner then reports those rows as violations (reproduced: deleting
  an app flagged its `client_created`/`client_secret_rotated` rows as tampered),
  and the app attribution on historical events is lost. Prefer keeping the id
  (retain the app row soft-deleted, or exclude audit rows from the FK cleanup
  and re-stamp). Related: app deletion emits no `client_deleted`/`client.deleted`
  event.
- **F7 (Low, hardening) — `redirect_uri` scheme compared case-sensitively.**
  `HTTP://…` (uppercase scheme) is accepted where `http://…` is expected. The
  registered host must still match, so exploitability is limited, but the scheme
  should be normalised before comparison.
- **F8 (Low, operability) — audit-integrity scanner is off by default.**
  `AUDIT_INTEGRITY_SCAN_INTERVAL_SECONDS=0` means no background verification,
  yet the Threat-Intel page shows "Audit log integrity: VERIFIED". With the
  scanner enabled, tamper is detected correctly (HMAC + hash-chain, reproduced).
  Consider a safe non-zero default, or label the panel "not scanning" when the
  interval is 0.

### Documentation / harness notes

- The **B6 performance harness** (`deploy/perf`) needs `CLIENT_ID=perf-public`
  for the `token_refresh` scenario (a confidential client turns it into a bcrypt
  benchmark) and the number of pre-minted refresh chains must be ≥ `maxVUs`,
  else most iterations fail on refresh-reuse rejection. Worth a line in
  `docs/PERFORMANCE-BASELINE.md`; the doc is also silent on the rate limits,
  which must be raised for a capacity run.
- The sample app in `deploy/e2e/demoapp` sets no CSP/frame headers — fine for a
  fixture, but `docs/DEPLOYMENT-VPS-MULTI-APP.md` §6.2 should remind integrators
  that those headers are the app's responsibility (the consoles set them).

## 7. Proposed fixes

Two working branches carry F1/F2 and their tests:

- `oauth2-admin` → `fix/bff-app-scoped-routes` (BFF `/api/apps/` route + Caddy
  allow-list + BFF e2e regression test).
- `go-oauth2` → `fix/refresh-global-admin` (global-admin refresh bypass,
  dead-grant → `invalid_grant`, `token_revoked` FK fix, unit + handler tests).

Both were validated locally: gofmt/vet clean, golangci-lint (v2.14.0, built with
go.mod's toolchain) 0 issues, and the full `-race` suite green against Postgres.

## 8. Defensive controls (triggered and observed in monitoring)

| Control | Triggered | Visible in monitoring |
|---|---|---|
| Per-IP login rate limit (5/min) | yes (429 + `Retry-After` + `X-RateLimit-*`) | Prometheus `socrate_rate_limit_hits_total` (not audited as an event — see note) |
| Account lockout (5 failures) | yes (right password then refused) | `account_locked` event; dashboard "Locked accounts" |
| Auto-defense IP block (10 failures/10 min, escalating) | yes (attacker IP then 403 everywhere; neighbour unaffected) | `auto_ip_block` event, Blocked-IPs list with escalation reason, Threat-Intel |
| Manual IP block | yes | Blocked-IPs list; subsequent requests 403 |
| Forged/`alg=none` token, bad client secret | yes (401) | `invalid_token_used`, `client_auth_failed` events, Threat-Intel counters |
| Policy enforce denial | yes | Policy-Decisions log (admin + app), `socrate_policy_decisions_total` |
| Refresh-token reuse (enforce) | yes (family revoked) | `refresh_token_reuse` event |
| Audit tamper (HMAC + hash chain) | yes (with scanner on) | `audit_integrity_violation` events, integrity panel |

The **policy rule language** was exercised as a matrix (40 cases): default-deny,
deny-overrides, `eq/ne/in/not_in/gt/gte/lt/lte/contains/starts_with/cidr/exists`,
`ref` comparisons, `all/any/not`, three-valued logic for missing attributes
(unknown-on-allow does not allow; unknown-on-deny denies), obligations, and
validation (unknown op/attr, bad effect, duplicate ids, empty actions all
refused). Optimistic concurrency (`409` on stale `base_version`) and
forward-only restore were confirmed, including recovery from a deny-all rule.

## 9. Performance

k6 v1.8.1, 4 vCPU, Postgres 16 on loopback, generator co-located (a
conservative floor). Baseline scenarios reproduce `docs/PERFORMANCE-BASELINE.md`
(B6). Rate limits were raised for the capacity runs only.

| Path | Sustained | p95 | Bound by |
|---|---:|---:|---|
| discovery (+JWKS) | ≥ 2000/s | 0.62 ms | framework floor |
| `userinfo` (local JWT verify) | 500/s (1000/s ok) | 3.7 ms (22 ms) | Postgres/verify |
| policy `decide` (app endpoint) | ~585/s | 2.6 ms | evaluation + DB |
| admin API via Caddy + BFF (`/users`) | 300/s | 3.9 ms | BFF proxy + DB |
| admin dashboard aggregate | 60/s | 6.2 ms | multiple aggregates |
| backendkit app API via its BFF (`/api/me`, jwtauth) | 600/s | 1.8 ms | JWKS cache hit |
| app API + `pep` decide on every call | 300/s | 4.9 ms | decide round-trip |
| public-client token refresh | ~110–150/s | tens of ms | Postgres + RS256 |
| password login | ~46/s | 97 ms | **bcrypt cost 10** |
| `client_credentials` / introspect / confidential refresh | **~14/s** | ~290 ms | **bcrypt cost 12** |

The confidential-client ceiling (~14/s on 4 vCPU) is the one hard limit and is
already documented in B6 with its rationale and sizing table. It was reproduced
exactly. Everything not gated by client-secret bcrypt scales an order of
magnitude higher. The stack **fails cleanly at saturation** (latency rises, few
or no errors) rather than collapsing.

## 10. Resilience (DoS)

Bounded, single-host self-tests confirming the built-in limits and recovery:

- Oversized body (3 MiB) rejected at the 1 MiB cap; server healthy after.
- Oversized header block rejected `431`; server healthy after.
- 60 slow-header (slowloris) connections do not stall normal requests; header
  read is bounded by `ReadTimeout=15 s`.
- 1000-request burst fully served; healthy immediately after.
- Malformed/partial/binary requests do not affect the listener.
- Rate-limit refusal is per-IP and self-limiting; other IPs unaffected.

## 11. Certification readiness

No certificate is strictly required unless customers/regulators ask, but for an
identity provider the relevant tracks are:

- **OpenID Foundation conformance** (directly applicable): run the Foundation's
  OP conformance suite (Basic/Config/Refresh profiles) and self-certify. Not yet
  run here.
- **OWASP ASVS L2 + WSTG**: this report is structured to map onto it; suitable
  as the evidence base for an ASVS-aligned review.
- **RFC 9700 / OAuth 2.1 BCP**: largely satisfied (PKCE-only, reuse detection,
  audience binding, no implicit grant).
- **NIST SP 800-63B** (if targeting government): the authenticator controls are
  in place (rate limit, lockout); confirm the TOTP throttling meets §5.2.2.
- **ISO 27001 / SOC 2**: organisational; both expect an **independent
  penetration test** and change-management evidence. The month-long CI gap on
  the private repo would be a change-management finding.
- **EU** (.eu deployment): NIS2 if in scope; ANSSI CSPN is a lighter product
  certification path.

**Recommended before production:** run the OpenID conformance suite, complete
the F3–F5 observability fixes, and commission an independent penetration test.

## 12. Verdict

For the **default posture** (new capabilities off or in shadow), the suite is
**functionally sound and secure enough to deploy**, with two fixes (F1, F2) that
should land first because they break the admin console in normal use. The open
findings are observability and forensic-integrity gaps (F3–F6) plus two low
items (F7, F8); none is a protocol or authorization weakness. Enforce-mode
policy and the opt-in hardening switches all behave correctly when enabled.
