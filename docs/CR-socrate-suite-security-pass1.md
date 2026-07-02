# Socrate Suite — Independent Security & Code Audit

**Date:** 2026-07-02
**Scope:** `go-oauth2` (Socrate identity server), `backendkit` (Go client library),
`oauth2-admin` (Superadmin portal SPA + BFF), `oauth2-monitoring` (SOC dashboard SPA + BFF).
**Method:** Direct code review of each repository. The many self-authored audit/review
documents in the repos were treated as claims to verify, not as evidence. Where practical,
`go build`, `go vet`, `go test -race`, `vitest`, and `npm audit` were run.

---

## Executive summary

The Socrate suite is **well-engineered and security-conscious code that is genuinely close to
production quality** — noticeably above typical hobby-project standard. The cryptographic and
protocol core of the identity server (JWT verification, PKCE, refresh rotation/replay
detection, revocation, key management, redirect validation, CSRF/consent) is correct and
backed by adversarial tests. Both browser consoles have been migrated to a real
Backend-for-Frontend model where the browser holds no OAuth tokens, and that model is
correctly implemented.

**There are no Critical protocol/crypto breaks.** The issues that hold the suite back from
"production-ready" fall into three buckets:

1. **One exploitable access-control bug** in the identity server (intra-tenant privilege
   escalation).
2. **A systemic "fail-open" pattern in both Go BFFs** — when no session cookie is present,
   the request is passed through untouched (CSRF skipped, browser-supplied bearer honored),
   contradicting the flagship "browser never holds a token" guarantee.
3. **Operational and documentation drift** — a build/deploy path bug that would blank the
   admin SPA, missing security headers in one Caddy config, CI that skips the BFF's own
   tests, stale `SECURITY.md`/e2e/audit docs describing superseded architectures, and one
   materially false "Fixed" claim in backendkit.

None of these require deep re-architecting. Fixing the items in the priority list below moves
the whole suite to solidly production-ready.

### Per-repo maturity

| Repository | Rating | Headline issue |
|---|---|---|
| `go-oauth2` (Socrate server) | **Near production-ready** | H1: any app member can perform app-admin user management |
| `backendkit` (library) | **Good — production-capable w/ reservations (B)** | H-1: unauthenticated JWKS-refetch DoS lever |
| `oauth2-admin` (portal) | **Strong core, unshipped (6/10)** | C-1: prod base-path blanks the SPA; H-1: missing Caddy headers |
| `oauth2-monitoring` (SOC) | **Good — production-viable (7.5/10)** | F1: fail-open BFF; F2: session data race |

---

## Cross-cutting findings (affect more than one repo)

### X-1 — Both Go BFFs are fail-open when no session cookie is present *(High)*

Both consoles' BFFs proxy the request untouched when there is no session — skipping CSRF and
forwarding any client-supplied `Authorization` header — as a "dual-mode" migration aid.

- `oauth2-admin/bff/app.go:248-251` (`proxyWithSession`): `s, ok := a.sessionFromRequest(r); if !ok { proxy.ServeHTTP(w, r); return }`. `TestDualModePassThrough` asserts `Bearer browser-token` reaches upstream.
- `oauth2-monitoring/bff/server.go:105-120`: token injection and CSRF only run `if sess := s.currentSession(...); sess != nil`, otherwise the request falls through to `s.proxy.ServeHTTP`.

Impact: CSRF is trivially skippable by dropping the cookie, and the BFF still honors
browser-supplied bearer tokens — directly contradicting the "no tokens in the browser / BFF is
sole client" claim in both READMEs. Real-world exploitability is gated by the upstream admin
API (loopback-only, requires a valid token), which keeps this High rather than Critical, but a
Tier-0 BFF must be **fail-closed**: once auth is enabled, reject `/api/admin/*` without a valid
session. Neither repo has a config flag to disable the weaker path after migration, so it is
effectively permanent.

### X-2 — No rate limiting in any BFF, including step-up *(Medium)*

Neither BFF throttles `/bff/login` or `/bff/elevate`. The step-up endpoints forward passwords
(and MFA codes) to Socrate with zero BFF-side limiting; brute-force resistance depends entirely
on the upstream. (`oauth2-admin/bff/elevate.go`, `oauth2-monitoring/bff/auth.go:91-149`.)
Separately, in `backendkit` the per-tenant HTTP rate limiter is a no-op in the default
deployment because the stock Socrate token carries no `tenant_id`
(`httpware/ratelimit.go:106-112`). So across the suite, brute-force/DoS defense at the edge is
thinner than the docs imply.

### X-3 — Logout does not revoke tokens upstream *(Medium)*

Both BFFs delete the server-side session and clear the cookie on logout but do not call the
issuer's revocation endpoint (`oauth2-admin/bff/app.go:217-222`; monitoring equivalent). The
access/refresh tokens in that session stay valid at Socrate until natural expiry. Socrate
*has* a working `/oauth/revoke` endpoint — the BFFs simply don't call it.

### X-4 — Duplicated, independently-drifting BFF + deploy code *(Low, structural)*

The two BFFs are clearly forked from a common ancestor (near-identical `session.go`,
`config.go`, proxy/allowlist logic) but have since diverged: monitoring added a Postgres
session store and `loginState`; admin added `/api/profile` issuer-proxy and a richer elevate
flow. Bugs fixed in one are not fixed in the other (e.g. X-1 exists in both; the open-redirect
backslash bug F5 exists in monitoring but admin's `sanitizeReturnTo` already rejects `/\`).
The Caddyfiles and systemd units are likewise near-duplicates maintained by hand — admin's
Caddyfile is missing four security headers that monitoring's nginx/Caddy config includes.
Consider extracting a shared BFF module or, at minimum, a shared deploy-config template.

### X-5 — Self-authored security/audit docs are stale or overstated across the suite *(Low, but erodes trust)*

Every repo ships `.md`/`.docx` "security review" / "audit" / "remediation" documents. Recurring
problems:

- **`oauth2-monitoring`**: `AUDIT.md`, `MONITORING-SPA-TIER0-AUDIT.md`, `SECURITY-MONITORING-REVIEW.md` describe the *pre-BFF* architecture (tokens in a Pinia ref, `client_secret` in the browser, a `CallbackView.vue`) that **no longer exists**. Their alarming conclusions are moot; the real code is much better.
- **`oauth2-admin`**: `SECURITY.md` and the entire Playwright e2e suite document a superseded browser-PKCE architecture (`src/services/oauth.ts`, `CallbackView`, `sessionStorage` tokens) that **does not exist in the code**. The e2e tests exercise dead routes and pass/fail for reasons unrelated to the real flows.
- **`backendkit`**: `SECURITY-AUDIT.md` and `CHANGELOG` v1.9.0 claim F-7 "`url.PathEscape` on **all** userID segments — Fixed". Only 6 methods in `client.go` were actually fixed; ~17 methods across `admin.go`/`monitoring.go`/`alerts.go`/`reports.go` still concatenate raw IDs (see backendkit M-1). This is a **materially false "Fixed" claim**.
- **`go-oauth2`**: by contrast, its `docs/CR-*.md` fix claims spot-verified as genuinely implemented — the exception that proves the rule.

Recommendation: delete or clearly date-stamp/mark-as-superseded the stale docs. As written they
would actively mislead the next reviewer, and one overstates the code's actual state.

---

## Repository detail

### 1. `go-oauth2` — Socrate identity server

**Verdict: near production-ready.** Go 1.25, chi v5, GORM/Postgres, golang-jwt v5. ~261 Go
files, ~150 test files. `go build`/`go vet` clean.

**Strengths (verified):** JWT algorithm confusion fully closed (`WithValidMethods(["RS256"])`
+ RSA type assertion + issuer + expiration-required, `internal/shared/auth/token.go:591-604`),
with adversarial tests proving RS384/HS256/`none` rejection. PKCE `plain` rejected, S256-only,
public clients forced to PKCE. Client secrets bcrypt-hashed (cost 12). Refresh rotation +
single-use via atomic `INSERT … ON CONFLICT` JTI ledger with RFC 9700 reuse detection and
family revocation. Revocation honored by both middleware and introspection. Redirect URIs
exact-matched with scheme blocklist and `iss` (RFC 9207) in responses. HMAC-signed consent +
double-submit CSRF. 3072-bit RSA keys with rotation ring, JWKS ETag caching, private key
forced to `0400`. Distroless nonroot image; CI runs gofmt/vet/`-race`/golangci-lint/
govulncheck + a blocking coverage gate.

**Findings:**

- **H1 (High) — Broken access control: any app member can perform app-admin user management.**
  `internal/http/router.go:580-599`. The app-scoped `/api/apps/{app_id}/users` routes are gated
  only by `RequireAppAccess` (passes for *any* role, incl. `viewer`) with **no `RequireAppAdmin`**.
  A low-privileged member can create users, **grant themselves or anyone the `admin` role**,
  change roles, remove users, and force password resets within their tenant. The inconsistency
  is glaring: read-only `/logs` on the same router *is* `RequireAppAdmin`-gated, but destructive
  user-management is not. Cross-tenant access is still prevented (membership required), so this
  is intra-tenant escalation. **Fix: add `RequireAppAdmin` to the `/users` mutating routes.**
- **M1 (Medium) — Raw internal error strings returned to clients.** `internal/handler/auth_handler.go:79,110,153` and widely in admin handlers do `writeError(w, err.Error(), …)`, leaking wrapped service/GORM internals to unauthenticated callers. The OAuth endpoints correctly map sentinels to static strings — the pattern is inconsistent.
- **M2 (Medium) — Login handler uses `switch err {}` equality instead of `errors.Is`.** `auth_handler.go:140-154`. `service.Login` returns *wrapped* errors (`ErrAccountLocked`, `ErrRoleNotFound`, `ErrAppNotFound`), so they miss their branches and fall through to `default: writeError(w, err.Error(), 400)` — wrong status + raw leak.
- **L1 — User-enumeration timing side-channel on login** (`auth_service.go:408-411`): unknown email skips bcrypt, valid email always pays it. Add a dummy bcrypt on the not-found path.
- **L2 — Introspection not audience-bound** (`oauth_service.go:815-885`): any authenticated client can introspect any token.
- **L3 — Confidential client can revoke tokens it doesn't own** (`oauth_handler.go:889-906`): targeted DoS, bounded by needing the token value.
- **L4 — Production config does not require an HTTPS issuer** (`config/config.go:360-409`): an `http://` issuer silently disables redirect-HTTPS enforcement and Secure cookies.

**Doc-vs-reality:** README "✅ Production ready / Security reviewed / Multi-tenant by design"
overclaims relative to H1. Otherwise the `CR-*.md` fix ledger is accurate.

### 2. `backendkit` — shared Go library (v1.9.0)

**Verdict: B / production-capable with reservations.** 11 packages, 5 direct deps.
`go vet` and `go test -race` pass clean.

**Strengths:** Algorithm pinning correct (RS256 + RSA type assertion, `kid` mandatory,
`jwtauth/middleware.go:267-280`). JWKS key hygiene (min 2048-bit, bounded 1 MiB read). Typed
claims with UUID-validated `tenant_id`; unexported context-key type prevents header spoofing.
Fail-closed authz (`tiering.PolicyService.IsAllowed` denies on error; RBAC default-denies).
apierror redacts 5xx bodies. No secrets logged. Functional-options API preserving
compatibility. Exemplary CI (race/vet/lint/govulncheck).

**Findings:**

- **H-1 (High) — Unauthenticated JWKS-refetch: no single-flight, no cooldown, no negative cache.** `jwtauth/middleware.go:292-317`. A token with an unknown (attacker-chosen, pre-signature) `kid` triggers one synchronous outbound `fetchJWKS()` (10 s timeout) **per request** — DoS amplification against both the service and Socrate, plus a thundering herd at TTL expiry. Fix: `singleflight` + minimum-interval cooldown + negative cache.
- **M-1 (Medium) — Path-parameter injection in ~17 socrate methods; the F-7 "Fixed" claim is false.** `admin.go:261,284,300,320,336,353,421,464,484,602,619,740`, `monitoring.go:108`, `alerts.go:100,113,138`, `reports.go:60,80` still do `c.adminURL("/api/admin/users/"+userID)` with no `url.PathEscape`. A `userID` like `42/revoke-tokens` re-routes an admin-JWT-bearing request to a different privileged endpoint.
- **M-2 — `exp` not required** (`middleware.go:267`): no `WithExpirationRequired()`; a token minted without `exp` validates forever. One-line fix.
- **M-3 — Per-tenant rate limiter is a no-op** with stock Socrate (no `tenant_id`); see X-2.
- **M-4 — Data race on `Client.resolvedAppID`** (`client.go:195,214,249`): benign value, real race.
- **M-5 — aigateway OpenAI path ignores `cfg.Model`/`AllowedModels`** — allowlist only enforced for Claude; a policy control that silently does nothing.
- **M-6 — Stale JWKS trusted indefinitely on endpoint outage** — no max staleness bound.
- **Low:** no clock-skew leeway (L-1); validation error cause discarded before logging (L-2); nil-logger panic path (L-3); case-sensitive `Bearer` match (L-4); `statusRecorder` hides `Flusher`/`Hijacker`, breaking SSE behind `Logger` (L-5); `Recover` swallows `http.ErrAbortHandler` (L-6); inbound `X-Request-ID` trusted verbatim (L-7); tiering returns shared cache slices (L-8); ainarration cache ignores `tenantID` (L-9); upstream bodies echoed into error strings (L-10).

**Test depth is inverted relative to risk:** pagination 100%, but socrate client 26.2% (the
~1,500 LOC where M-1 lives is untested), and jwtauth (86%) has **no expired-token / alg-none /
wrong-issuer / unknown-kid** negative tests — the canonical attack cases are unpinned, so a
regression in `WithValidMethods` would ship green. Security posture is opt-in by default
(audience, revocation, tenant enforcement, exp-required all off unless the consumer enables
them); the planned v2.0 default-flip should be prioritized.

### 3. `oauth2-admin` — Superadmin portal (Vue 3 SPA + Go BFF)

**Verdict: 6/10 — strong core, unshipped.** BFF ~1,000 LOC stdlib-only. Go tests pass;
174 vitest pass; `npm audit` 0 vulns; no `v-html`/`eval` in `src/`.

**Strengths:** 256-bit `crypto/rand` session/CSRF/PKCE tokens; correct `__Host-` + HttpOnly +
Secure + SameSite=Strict cookie; constant-time double-submit CSRF on all mutating routes and
`/bff/elevate`; single-use OAuth state; `sanitizeReturnTo` rejects `//`, `/\`, absolute URLs;
cookie stripped before upstream proxy + bearer injected server-side; serialized token refresh;
strict allowlist reverse proxy (path-traversal tested); graceful shutdown + upstream timeouts +
`io.LimitReader`; **best-in-class systemd sandboxing** (`NoNewPrivileges`, `ProtectSystem=strict`,
empty `CapabilityBoundingSet`, `MemoryDenyWriteExecute`, `SystemCallFilter`). ESLint gates XSS
sinks as errors.

**Findings:**

- **C-1 (Critical, functional) — Production base path blanks the SPA.** `vite.config.ts:16` sets `base:'/admin/'` for production, so `dist/index.html` references `/admin/assets/...`, but `deploy/Caddyfile:8-40` serves at the root (`root * /srv/admin/dist`, `try_files {path} /index.html`). Asset requests fall through to `index.html` (HTML with 200), the module script never loads, and the SPA renders blank. README/diagrams confirm `/` is the intended mount.
- **H-1 (High) — Caddy omits mandated security headers.** `deploy/Caddyfile:11-21` sets only HSTS/`X-Content-Type-Options`/CSP/`-Server`; **missing** `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy` — all required by `SECURITY.md` and `src/security/csp.ts`. e2e asserts them against the *dev* server only.
- **H-2 (High) — CI never runs the Go BFF tests.** The four CI jobs (lint/build, vitest, playwright, npm audit) never `cd bff && go test`. The most security-critical component is never gated.
- **H-3 (High) — E2E suite tests a dead architecture.** `e2e/fixtures/api-mocks.ts` mocks browser-driven PKCE (`/auth/callback`, `/oauth/token` exchange) that no longer exists; tests hit dead routes and their green status is not evidence the real flows work.
- **M-1 (Medium) — Dual-mode bearer pass-through** (see X-1): no config flag to disable it after migration.
- **M-2 — Logout doesn't revoke upstream** (see X-3).
- **M-3 — No BFF rate limiting** (see X-2).
- **M-4 — Production CSP weaker than advertised:** Caddy serves `default-src 'self'`, docs/module promise `default-src 'none'` — the "single source of truth, dev==prod" claim is false.
- **M-5 — In-memory session store only:** restart logs out every admin; no horizontal scale.
- **Low:** JWT signature not verified before deriving roles (L-1, loopback-bounded); `/bff/elevate` forwards upstream error body verbatim (L-2); CI runs `eslint --fix` (auto-mutating) instead of `lint:check` (L-3); cookie `MaxAge` = 8 h absolute regardless of 30 min idle (L-4, server-enforced anyway).

**Doc-vs-reality:** `SECURITY.md` describes a dead browser-PKCE architecture
(`src/services/oauth.ts`, `CallbackView`, `sessionStorage` tokens) that does not exist; the
newer `README`/`architecture.md` are accurate.

### 4. `oauth2-monitoring` — SOC dashboard (Vue 3 SPA + Go BFF)

**Verdict: 7.5/10 — good, production-viable with a short fix list.** No Critical findings.
The current code is substantially better than its own stale audit docs claim.

**Strengths:** No `v-html`/`innerHTML` anywhere — every attacker-controlled field (IP, UA,
email, event detail) rendered via escaped `{{ }}` or `JSON.stringify` in `<pre>`; the XSS pivot
the old docs feared is closed. Real BFF token custody; correct `__Host-`/HttpOnly/Secure/
SameSite=Strict cookies; S256 PKCE with 256-bit `crypto/rand` state/verifier, single-use state
w/ 10-min TTL; CSRF double-submit on mutating routes and `/bff/elevate`; SSRF-safe
single-host allowlisted proxy (test-enforced); idle+absolute session expiry with sweeper;
Postgres store with single-statement single-use login; `liveEvents` bounded at 100; strong CSP
(no `ws:`/`wss:`); distroless nonroot BFF image; working end-to-end step-up.

**Findings:**

- **F1 (High) — Fail-open BFF** (see X-1): no-cookie requests bypass CSRF and forward browser bearer.
- **F2 (Medium) — Data race on the shared `*Session`.** `session.go:99-112`, `server.go:112-166`: `Get` returns the live map pointer; `currentSession`/`ensureFresh` mutate `LastSeen`/`AccessToken`/`RefreshToken` under **no lock** (mutex guards only the map). Concurrent requests on one session (dashboard fan-out + SSE) race and can corrupt token state. `-race` would flag it. (The admin BFF, by contrast, locks per-`Session` correctly — another divergence, X-4.)
- **F3 (Medium) — No rate limiting** (see X-2).
- **F4 (Medium) — `LastSeen` write on every request** including GETs → a DB write per read on the Postgres store, compounding F2's lost updates.
- **F5 (Medium) — Open-redirect via backslash in `return_to`.** `auth.go:184-189` allows `/\evil.com` (starts with `/`, not `//`); browsers normalize `\`→`/` into protocol-relative `//evil.com`. (Admin's `sanitizeReturnTo` already handles this — port the fix.)
- **Low:** `.env.production` committed with hardcoded `golfperformance.fr` host + public client id (F6, and the VITE vars are now dead code); `/bff/logout` not CSRF-protected (F7); SPA Dockerfile carries dead pre-BFF ARGs and runs nginx as root, tag-pinned not digest-pinned bases (F8); SSE reconnection is linear-backoff, no jitter, gives up permanently after 5 attempts, no heartbeat watchdog (F9).
- **Info:** JWT decoded without signature verification (F10, loopback-bounded); Trusted Types report-only + CSP report endpoint not implemented (F11); client-side-only RBAC (F12); no session-id rotation after elevation (F13); `monitorStore` not reset on logout (F14).

**Remediation-claims vs reality:** the high-impact remediation items (BFF, no browser tokens,
no client secret, PKCE+state, step-up, CSRF, MON-01/MON-02 fixes) are **genuinely
implemented**. Unfinished: `golfperformance.fr` still hardcoded, CSP report endpoint missing.
The three older audit docs now actively misdescribe the codebase.

---

## Prioritized remediation list (whole suite)

**P0 — before any production deploy**
1. `go-oauth2` **H1**: add `RequireAppAdmin` to `/api/apps/{app_id}/users` mutating routes. *(exploitable privilege escalation)*
2. Both BFFs **X-1 / admin M-1 / monitoring F1**: make the proxy fail-closed once auth is enabled; add a flag to remove dual-mode pass-through after migration.
3. `oauth2-admin` **C-1**: fix the Vite `base` vs Caddy root mismatch (SPA is currently un-loadable in prod).
4. `backendkit` **H-1**: add `singleflight` + cooldown + negative-cache to the JWKS refetch path.

**P1 — before "security reviewed / production ready" claims hold**
5. `oauth2-admin` **H-1** / **M-4**: add the four missing Caddy headers; reconcile prod CSP with the tested module.
6. `oauth2-admin` **H-2**: run `cd bff && go test -race` in CI.
7. `oauth2-monitoring` **F2 / F4**: make the session store `-race`-clean (copy-on-read or lock the struct) and throttle `LastSeen` writes.
8. `backendkit` **M-1**: complete the `url.PathEscape` fix across admin/monitoring/alerts/reports; correct the false "Fixed" ledger entry.
9. `backendkit` **M-2**: set `WithExpirationRequired()` (+ small `WithLeeway`).
10. Suite **X-2 / X-3**: add per-IP/per-session rate limiting to `/bff/login` + `/bff/elevate`; call the issuer revoke endpoint on logout.

**P2 — hardening & hygiene**
11. `go-oauth2` **M1/M2**: static client-facing error strings + `errors.Is`.
12. `oauth2-monitoring` **F5/F6/F7/F8/F9** and `go-oauth2` **L1–L4** as listed.
13. `backendkit`: add the missing negative JWT tests (expired / alg-none / wrong-issuer / unknown-kid); raise socrate-client coverage.
14. Suite **X-4 / X-5**: de-duplicate the two BFFs + deploy configs; delete or date-stamp the stale/overstated audit docs.

---

## Bottom line

This is a coherent, credibly-secured identity platform, not a facade — the hard parts (OAuth
2.1/OIDC protocol correctness, JWT verification, the BFF token-custody model) are done right and
tested. The gap to production is a **short, concrete list**: one access-control fix in the
server, making both BFFs fail-closed, a build-path fix and missing headers in the admin
console, and the backendkit JWKS-DoS + path-escaping completion. The largest *non-code* risk is
the stale/overstated self-audit documentation, which should be pruned so it stops
misrepresenting an otherwise honest codebase.
