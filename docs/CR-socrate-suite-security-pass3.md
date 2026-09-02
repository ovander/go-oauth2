# Socrate Suite — Security Audit, Pass 3

**Date:** 2026-09-02
**Scope:** `go-oauth2` (main @ `649c922`), `backendkit` (main @ `4d146cf`,
tags `v1.11.0`/`v1.11.1`-pending), `oauth2-admin` (main @ `7b7a139`),
`oauth2-monitoring` (main @ `8ff4f93`).
**Companions:** `CR-socrate-suite-security-pass1.md`,
`CR-socrate-suite-security-pass2.md`, `CR-socrate-suite-remediation-plan.md`
(rev. 3 updated alongside this report).

## 0. Headline

Pass 3 was run as four independent, adversarial per-repository audits with a
hard rule: **no finding without a reproduction or a traced code path**, and
every High-or-above claim was re-verified by the coordinator against the code
before it appears here. Two claims from pass 2 turned out to be wrong and are
corrected in §6.

Three things change the picture materially:

1. **`go-oauth2`'s `/api/admin` router has no role gate at all** (§1, P3-1,
   **Critical**). Authentication is enforced; authorisation is not. Combined
   with open self-signup for any `client_id` and the consoles' BFFs not
   gating who may open a session, an outsider can sign up on the
   admin-console client, log in, and `POST /api/admin/superadmins` → 201.
   Reproduced by the auditor against the real router with a `role=user`
   token; every link in the chain (router, `AuthMiddleware`, `Signup`,
   `Login`, BFF callback) independently traced by the coordinator.
2. **Client-IP attribution in `go-oauth2` is attacker-controlled** (§1, P3-2,
   **High**). `chimiddleware.RealIP` is installed unconditionally on all three
   routers, rewriting `RemoteAddr` from `True-Client-IP` / `X-Real-IP` / `XFF`
   for *any* peer. The documented Caddy front-end strips `X-Forwarded-*` from
   untrusted clients but passes `X-Real-IP` and `True-Client-IP` through
   untouched (verified in Caddy's `reverseproxy.go`), so this is exploitable
   in the production topology: rate-limit bypass, IP-block bypass, and
   framing an arbitrary IP (e.g. the corporate NAT) for auto-block.
   **This inverts pass 2's P2-3 analysis**, which was wrong (§6).
3. **The shared BFF gateway never writes refreshed tokens back to the
   session store** (§2, P3-10, **Medium**, availability). Invisible with the
   in-memory store (it hands out the live pointer) but fatal for
   `oauth2-monitoring`'s Postgres store: every durable session dies at its
   first access-token expiry, and idle-expiry never slides on real traffic.
   Verified by the coordinator and independently reproduced by two auditors.

Also confirmed: the P2-8 concurrent-refresh race, rated Medium at 1-in-50 in
pass 2, is **near-deterministic (20/20 trials) for `oauth2-monitoring`**
given its `Promise.all` polling shape plus an SSE stream — with the default
15-minute access-token TTL this logs operators out roughly every 15 minutes.
The `v1.11.x` bump fixes that specific race but not P3-10.

All build/test gates pass on every repo's `main` except `oauth2-admin`'s own
`npm audit --audit-level=high` CI job, which is currently red (§3).

## 1. go-oauth2

**Build/test:** `go build ./... && go vet ./... && go test ./...` — exit 0,
19/19 packages.

### 1.1 Pass-2 items — all still OPEN

No remediation for P2-1…P2-5 has landed. P2-1 (`internal/web/handler.go:403,
:609` raw `err.Error()` to unauthenticated browsers), P2-2
(`app_users_handler.go` ×11 sites), P2-5 (`handleClientCredentialsGrant`
`oauth_service.go:786-826` skips `validateScope`/`requireDPoP`) are unchanged.
P2-3 and P2-4 are superseded by P3-2 below — the pass-2 framing was wrong.

### 1.2 Prior fixes — all intact

H1 (`router.go:589` `RequireAppAdmin`), M1/M2 (`errors.Is` + static strings),
L1 (`auth.CheckDummyPassword`), L2 (`audienceContains`), L3 (revoke ownership),
L4 (https issuer in prod), pgx `v5.9.2`.

### 1.3 New findings

**P3-1 — CRITICAL — `/api/admin` has no role gate. REPRODUCED (auditor, real
router) + TRACED (coordinator).**
`internal/http/router.go:413-418`: the group applies only `AuthMiddleware` and
`RequirePasswordChangeComplete`. `AuthMiddleware` (`internal/middleware/auth.go`)
verifies signature, token version and lock state and puts `user.Role` in the
context — it never checks it. `RequireScope` is a no-op unless
`ADMIN_SCOPE_MODE=enforce` (default off), and even enforced it doesn't help:
`validScopes` (`oauth_service.go:76-88`) lets any user request `scope=admin`
at `/oauth/authorize`. `RequireFreshAuth` only checks `auth_time`.
`middleware.RequireGlobalAdmin()` exists (`role.go:65`) and is unused.
Handlers with **no** in-handler role check include `CreateSuperadmin`
(`admin_handler.go:910`), `UpdateSuperadmin` (`:960`, sets password, not even
behind `freshAuth`), `DeleteSuperadmin`, `ListSuperadmins`, `GetSuperadmin`,
`ListApps`, `CreateApp`, `GetStats`, and every monitoring / dashboard / logs /
settings handler.
Aggravating: `UpdateApp`/`DeleteApp`/`RotateSecret` skip the ownership check
when `app.OwnerID == nil`, and the seeded admin-console client has no owner
(`admin_console_seed.go:37-44`), so any user can rewrite its `redirect_uris`.
Reachability chain (each link traced): `POST /api/auth/signup` accepts any
`client_id` with no per-app allow flag and creates a `UserRoleUser` +
membership row (`auth_service.go:272-317`) → verify own email → `Login`
accepts any app member (`auth_service.go:462-476`) → neither console's BFF
gates roles when minting a session → `/api/admin/*` reached through the BFF
proxy with the member's bearer. In the default single-port config
(`ADMIN_PORT=""`) the admin router is also mounted publicly at `/manage`.
Repro: `role=user` token → `POST /api/admin/superadmins` **201**;
`PUT /api/admin/superadmins/1 {"password":…}` **200**; `GET
/api/admin/settings/config` **200**.
*Fix:* `r.Use(middleware.RequireGlobalAdmin())` on the `/api/admin` group
(`RequireRole("superadmin")` for the superadmins sub-tree); treat
`OwnerID == nil` as admin-only; add a regression test that walks every
`/api/admin` route with a `role=user` token and expects 403.

**P3-2 — HIGH — `chimiddleware.RealIP` unconditional → all IP attribution is
attacker-controlled. REPRODUCED (auditor) + Caddy behaviour VERIFIED
(coordinator, upstream source).**
`router.go:151, :374, :656`. chi v5.1.0 `RealIP` overwrites `r.RemoteAddr`
from `True-Client-IP`, `X-Real-IP` or leftmost `X-Forwarded-For` for any peer;
`GetClientIPSafe(r, nil)` then returns the rewritten address, so
`TrustedProxyCIDRs=nil` ("safe default") is not safe. Repro: login limiter
limit=1 → 2nd request 429 → 4 requests each with a fresh `XFF` all pass;
`IPBlockMiddleware` blocking 203.0.113.9 → 403 → add `True-Client-IP:
198.51.100.77` → 200. `autoDefense.RecordFailedLogin` (`auth_handler.go:189`)
then blocks whatever IP the attacker names. Caddy's `reverse_proxy` deletes
client-supplied `X-Forwarded-*` for untrusted peers but does **not** touch
`X-Real-IP` / `True-Client-IP` (`caddyhttp/reverseproxy/reverseproxy.go`,
`addForwardedHeaders`), so the production topology is exploitable via those
two headers.
*Fix:* remove the three `RealIP` lines (the codebase already has
`GetClientIPSafe` with trusted CIDRs); then finish the P2-3 intent by using
`GetClientIPSafe(r, trustedCIDRs)` at every audit/attribution sink and fix
the `GetClientIP` comment (P2-4).

**P3-3 — MEDIUM — refresh grant ignores account lock and client `Active`;
`Authorize`/auth-code grant ignore `Active`; `BlockUser` doesn't revoke.
REPRODUCED.** `handleRefreshTokenGrant` (`oauth_service.go:646-664`) checks
`TokenVersion` and role only; `userService.Block` (`user_service.go:300-314`)
only calls `LockAccount` (no version bump); `FindByClientID` doesn't filter on
`active`. A blocked user or deactivated client keeps minting valid JWTs for
the refresh TTL (7d default) — this server's own `AuthMiddleware` rejects
locked users, external resource servers validating the JWT do not.
*Fix:* check `IsLocked()`/`Active` in both grants and `Authorize`; bump
`token_version` in `Block`.

**P3-4 — LOW — omitted `code_challenge_method` silently means plain PKCE.
REPRODUCED.** `pkce.go:37-42` `case "":` compares verifier to challenge
directly; `Authorize` never validates the method; discovery advertises S256
only. *Fix:* require `S256` at `Authorize`; treat `""` + non-empty challenge
as an error.

**P3-5 — LOW — hosted login (`POST /oauth/authorize`) and `POST /auth/login`
never feed auto-defense. TRACED.** `oauth_handler.go:371-396`,
`web/handler.go:482-490`. Browser-path password spraying is throttled only
by per-account lockout and the (P3-2-bypassable) rate limiter.

**P3-6 — LOW — `POST /auth/login` is a dead path that increments the victim's
failed-attempt counter and would set an unconsumed `access_token` cookie.
TRACED.** `web/handler.go:482-517`. *Fix:* remove or wire to `/oauth/authorize`.

**P3-7 — LOW — app-admin can trigger password-reset / verification emails for
any user ID, not just app members. TRACED.** `app_users_handler.go:376-499`.

**P3-8 — LOW — no per-client scope policy; `admin`/`monitoring:*` grantable to
anyone. TRACED.** `oauth_service.go:76-88`. Makes `ADMIN_SCOPE_MODE=enforce`
a routing hint, not a boundary.

**P3-9 — INFO —** `POST /api/profile/mfa/disable` needs no password/TOTP
re-verification (`mfa_handler.go:136-149`); `CheckClientSecret` legacy SHA-256
branch uses `==` despite its "constant-time" comment (`password.go:147-149`).

Verified clean (no finding): redirect_uri exact-match + `iss`; auth-code
single-use atomicity; refresh rotation/reuse detection incl. concurrent
`MarkAsUsed`; DPoP proof verification and `cnf.jkt` binding; JWT pins RS256 +
issuer + required `exp`; consent-token HMAC; CSRF double-submit; CORS never
credentialed on wildcard; no string-built SQL; no secrets in logs.

## 2. backendkit

**Build/test:** `go build && go vet && go test -race` — 12/12 packages, clean;
`go vet` copylocks diagnostics only when `Gateway` is deliberately copied
(P3-13).

### 2.1 Pass-2 items

| Item | Status | Evidence |
|---|---|---|
| P2-6 empty CSRF | **CLOSED** (`v1.11.0`) | `session.go:130-138`; `TestMatchCSRFRejectsEmpty` |
| P2-7 fail-open zero value | **CLOSED** (`v1.11.0`) | `DisableAuth`, `gateway.go:41,157`; `TestGatewayZeroValueFailsClosed` |
| P2-8 concurrent refresh | **CLOSED** for the race it targeted (`v1.11.0` + leeway fix on main / `v1.11.1`) — but see P3-10/P3-11 | `gateway.go:106-126`; 8 sessions × 8 callers stress: 0 cross-session mismatches |
| P2-9 AllowPassthrough | acceptable now P2-7 is closed | — |
| P2-10 query-string escaping | **OPEN, REPRODUCED** | `socrate/monitoring.go:168, :226, :266-272`; `GetGeoAnalytics(ctx,"24h&period=9999d&x=1")` → server saw `period=24h&period=9999d&x=1`; `"7d#frag"` silently truncates |

H-1 / M-1 / M-2 re-verified intact, plus an alg-confusion probe (`none`,
HS256-with-RSA-PEM, PS256, RS512, missing `kid`) → all 401.

### 2.2 New findings

**P3-10 — MEDIUM (availability) — `ProxyWithSession` never persists the
refreshed token set or `Touch`. VERIFIED (coordinator) + REPRODUCED (two
auditors, snapshot-store stand-in).**
`bff/gateway.go` ProxyWithSession: `EnsureFresh` → `SetTokens`, then
`Touch`, then proxy — no `g.Store.Put(s)`. `MemoryStore.Get` returns the live
pointer so this is invisible there. `oauth2-monitoring`'s
`PostgresSessionStore.Get` (`session_postgres.go:116-140`) rehydrates a fresh
`*Session` from the row on every call and the console's only `Put` calls are
login, elevate and `/bff/session` (`auth.go:62,180`, `server.go:138`) — never
after a proxy-path refresh. The pre-migration monitoring code did persist
(`d522619^1:bff/server.go` `ensureFresh`), so this is a **migration
regression**. Effects with `BFF_SESSION_DSN` set: (a) request after the first
refresh re-reads the spent rotating refresh token → `invalid_grant` → session
deleted; (b) under `REFRESH_REUSE_MODE=enforce` every expiry looks like token
theft; (c) `last_seen` never slides on API traffic and the SPA calls
`/bff/session` only at bootstrap → active users hit `BFF_SESSION_IDLE`.
*Fix (backendkit):* `g.Store.Put(s)` inside the singleflight closure after a
successful refresh, and after `Touch`; document that `Put` must be
write-through for durable stores; add a snapshot-store regression test.

**P3-11 — MEDIUM — the coalesced refresh runs under the first caller's
`ctx`; cancelling that request logs out every waiter. REPRODUCED.**
`gateway.go:111-121` captures the leader's `r.Context()` into
`Refresher.RefreshToken`. A browser aborting one in-flight request (tab
close, navigation, `EventSource` teardown — the exact SSE-alongside-API shape
`session.go:25` describes) during the once-per-token-lifetime refresh makes
the leader return `context.Canceled`; singleflight hands that to all waiters;
each runs `Store.Delete` + `ClearSession` + 401. Repro end-to-end: 4/4 waiters
got 401 + `Max-Age=-1`, `store.Get` → false. Pre-P2-8 a cancelled request
only hurt itself. Introduced by the P2-8 fix in this engagement.
*Fix:* inside the closure use
`context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)` — the
refresh is a shared resource whose lifetime must not be bound to whichever
request arrived first.

**P3-12 — LOW — any refresh error, including transport/5xx, deletes the
session. REPRODUCED.** `gateway.go:178-183`; `socrate.RefreshToken` returns
untyped errors so callers can't distinguish `invalid_grant` from an outage. A
brief Socrate blip logs out every admin inside the 30 s leeway window.
*Fix:* typed `*socrate.OAuthError{Code}`; tear down only on
`invalid_grant`/`invalid_client`, else 502/503 and keep the session.

**P3-13 — LOW — `Gateway` is no longer copyable (embedded
`singleflight.Group`). REPRODUCED via `go vet`.** Silent API tightening in
`v1.11.0`, not in the CHANGELOG. Both consumers hold `*bff.Gateway`. *Fix:*
document, or hold a lazily-initialised pointer.

**P3-14 — INFO — `Session` prints its secrets through `fmt` `%+v`.** No
`String()` redaction. *Fix:* add one.

## 3. oauth2-admin

**Build/test:** Go `build/vet/test -race` clean; `npm run build` ok (root
asset paths verified); `npm run test:run` 174/174. **`npm audit
--audit-level=high` is red on `main`** (2 high `--omit=dev`: `nanoid`,
`postcss` via `@vue/compiler-sfc`, build-time only) — the CI
`security-audit` job (`ci.yml:150-166`) currently fails; `npm audit fix`
resolves it.

### 3.1 Pass-2 items

- **P2-11 — OPEN, REPRODUCED, re-rated Medium → Low.** `elevate.go:77-83`
  accepts past/missing/garbage `exp` and answers 204; but go-oauth2's
  `AuthMiddleware` uses `WithExpirationRequired()` and the step-up gate keys
  on `auth_time`, so the realistic effect is a *poisoned session* (every
  admin call 401s until the old expiry lapses — and see P3-22), not privilege
  extension.
- **P2-12 — OPEN.** `elevate.go:38` hardcodes `X-CSRF-Token`.
- **P2-13 — OPEN, re-rated Info → HIGH (deployment).** `bff/config.go:123-129`
  validates nothing when `BFF_CLIENT_ID` is empty, and **the shipped default
  is Phase 1**: `deploy/env/admin-bff.env.example` and `bff/.env.example`
  ship Phase 2 commented out, and `deploy/scripts/bootstrap.sh:20` seeds that
  file verbatim. In Phase 1 the BFF is a bare pass-through, so `POST
  /api/admin/login` and — with P3-1 — every `/api/admin/*` route becomes
  internet-reachable through Caddy → BFF → :8081 for anyone holding any user
  token. *Fix:* refuse to start with `BFF_CLIENT_ID` unset unless an
  explicit `BFF_PHASE1_PASSTHROUGH=true` is present; ship the env example
  with Phase 2 enabled.
- **Roles frozen at login — OPEN, downgraded to Info for this console.** The
  SPA never reads `/bff/session`'s roles; `isSuperAdmin` and the router guard
  come from the live `/api/admin/profile`.

Prior fixes X-1, X-2, X-3, C-1, H-1/M-4, H-2 re-verified intact.

### 3.2 Consumer exposure to backendkit `v1.10.0`

P2-6 not reachable (`RandomToken` panics rather than returning `""`;
MemoryStore only). P2-7 not reachable (set explicitly). **P2-8 reachable**:
Dashboard mount fires 5 parallel admin calls (`DashboardView.vue:471-477`)
plus a long-lived SSE `fetch`; the loser gets its session deleted. Resolved
by the bump.

### 3.3 New findings

**P3-15 — MEDIUM — pending login is not bound to the browser → login CSRF /
silent account swap. REPRODUCED (admin) + TRACED (monitoring, same
pattern).** `handleLogin` (`app.go:115-133`) sets no cookie; `handleCallback`
only checks the server-side `state` exists (`app.go:141-144`). Browser A
starts a login; browser B with no cookies presents `callback?code=…&state=S`
→ 302 + session cookie. An attacker completes their own login, captures the
callback URL, and gets a victim admin to open it within the 10-min TTL: the
victim's cookie is overwritten with the attacker's session, and subsequent
profile edits / created apps land in the attacker-readable account.
`oauth2-monitoring` `bff/auth.go` has the identical shape (no login cookie;
`SetSession` only at callback). *Fix:* set `__Host-<console>_login`
(HttpOnly, Secure, SameSite=Lax, nonce) in `handleLogin`, store its hash in
the pending login, require a match in `handleCallback`, clear it.

**P3-16 — LOW (Phase 2) / MEDIUM (Phase 1) — BFF forwards attacker-controlled
IP-attribution headers upstream. REPRODUCED.** With a valid session upstream
received verbatim `X-Real-Ip`, `True-Client-IP`, `Forwarded`,
`X-Forwarded-Host`, `X-Forwarded-Proto`. `NewSingleHostProxy` (stock
`httputil`) only appends XFF; the Caddyfile manages `X-Forwarded-*` but not
the others. Feeds P3-2 directly. Applies to both consoles (same backendkit
proxy). *Fix:* a `Rewrite` hook deleting `X-Real-IP`, `True-Client-IP`,
`Forwarded`, `X-Forwarded-Host` and replacing `X-Forwarded-For` with the
Caddy-provided value — and/or `header_up -X-Real-IP …` in the Caddyfile.
Belongs in `backendkit.NewSingleHostProxy` so both consoles inherit it.

**P3-17 — LOW — BFF rate-limiter key is the leftmost XFF entry, trusted
unconditionally (both consoles). REPRODUCED.** `ratelimit.go:76-91`. Safe
behind Caddy ≥ 2.5 with no `trusted_proxies` (verified: Caddy *replaces*
untrusted XFF), but silently breaks behind a CDN or if the BFF is reachable
directly; the assumption is stated only in a code comment.

**P3-18 — LOW — percent-encoded dot-segments pass the `/api/admin/` allowlist
and are forwarded verbatim (both consoles). REPRODUCED at the BFF; not an
escape end-to-end** (Caddy matches on the decoded path; chi routes on
`RawPath`). Defence-in-depth: reject when `path.Clean(r.URL.Path)` loses the
prefix.

**P3-19 — LOW —** `POST /bff/logout` has no CSRF check (`app.go:188-195`);
relies on SameSite=Strict alone.

**P3-20 — LOW —** `/bff/session` (CSRF token + identity) lacks
`Cache-Control: no-store` (`app.go:175-186`).

**P3-21 — LOW —** `/bff/elevate` forwards upstream non-200 bodies verbatim
(`elevate.go:66-71`), so go-oauth2's raw `err.Error()` leaks reach the
browser.

**P3-22 — LOW — SPA: a 401 never clears auth state. TRACED.**
`api.ts:72-76` pushes `Login` but `authStore.user` stays set, so the router
bounces back to Dashboard; the user is stuck until reload. Realistic trigger:
BFF restart on deploy (MemoryStore). *Fix:* `user.value = null` on 401.

**P3-23 — LOW — production wiring gaps.** `/api/version` is unrouted (SPA
gets `index.html` → permanent `fetchError`); forgot/reset-password posts to
the admin origin and Caddy's `try_files` returns `index.html` **with 200**,
so the user is told an email was sent — non-functional either way.

**P3-24 — INFO — config validation (both consoles).**
`BFF_COOKIE_SECURE=false` accepted alongside an https `PublicOrigin`;
`BFF_SESSION_IDLE=0s` silently disables idle expiry on MemoryStore but means
*expire immediately* on monitoring's Postgres store (`session_postgres.go:131`).

**P3-25 — INFO — docs/deploy drift.** `SECURITY.md` describes the retired
public-PKCE architecture; `bff/Dockerfile` uses `golang:1.24` against
`go 1.25.0`; `install-remote.sh:36` chowns `dist/` to the service user
(should be root-owned). Monitoring has the equivalent (`Dockerfile`,
`nginx.conf`, `.env.production` describe the retired design; `bff/Dockerfile`
`golang:1.23`).

## 4. oauth2-monitoring

**Build/test:** Go `build/vet/test -race` clean; `npm run test:run` 56/56;
`npm run build` ok; `npm audit --omit=dev` 5 advisories, all build tooling
present only because `tailwindcss`/`@tailwindcss/vite` sit under
`dependencies`.

### 4.1 Pass-2 items

- **P2-14 / P2-15 — OPEN**, and broader: every `Exec` result in
  `PostgresSessionStore` is discarded (`session_postgres.go:76, 109, 145,
  152, 155`). A failed `Delete` on logout leaves the session valid with no
  log line. → **P3-28 (Low)** supersedes both.
- **P2-16 — OPEN.** `auth.go:133-137` deletes the session but doesn't clear
  the cookie.
- **Roles frozen — OPEN, bounded**: Socrate's admin API enforces `RequireRole`
  per bearer (`role.go:40`) — *but see P3-1: that enforcement is absent on
  the `/api/admin` group*, so the "bounded" assumption from pass 2 currently
  does not hold either.

Prior fixes F1/X-1, F2 (`-race`), F5, X-3/F7, pgx `v5.9.2`, X-2, CI all intact.
XFF trust in the rate limiter verified safe behind the deployed Caddy (no
`trusted_proxies`, BFF bound to `127.0.0.1:8090`).

### 4.2 Consumer exposure to backendkit `v1.10.0`

- P2-6: negligible — every session is created with `RandomToken(32)`. A
  Postgres row *lacking* the `csrf` key would yield `MatchCSRF("")==true`
  (reproduced) but needs DB write access.
- P2-7: not reachable.
- **P2-8: REPRODUCED through the real handler, 20/20 trials** — 5 parallel
  `/api/admin/*` GETs on one session with a 5 ms token endpoint → 4×401 +
  session deleted every time. `DashboardView.vue:125` `Promise.all` every
  30 s plus the SSE stream is exactly this shape; with Socrate's default
  single-use refresh tokens and 900 s access TTL, **operators should be
  logged out roughly every 15 minutes today**. Under
  `REFRESH_REUSE_MODE=enforce` the losers' reuse would also revoke the token
  family and emit `refresh_token_reuse` events — the SOC console generating
  false theft signals about its own operators. The bump fixes this; P3-10
  then still breaks the Postgres store independently.

### 4.3 New findings

- **P3-10** (§2.2) — verified here as a migration regression.
- **P3-15 / P3-16 / P3-17 / P3-18 / P3-24 / P3-25** apply (§3).
- **P3-28 — LOW — all `Exec` results discarded** (supersedes P2-14/15).
- **P3-29 — LOW — read paths re-`Put` the session, racing logout's
  `Delete` (session resurrection). TRACED.** `server.go:132-140` Get → Touch →
  Put on `/bff/session`; Postgres `Put` is an upsert. *Fix:* touch via
  `UPDATE … WHERE id=$1`; only `INSERT` from the callback.
- **P3-30 — INFO — tokens at rest are plaintext jsonb and land in DB
  backups.** `session_postgres.go:104-113`; `bff.env.example` points at the
  same `socrate` DB that `backup-db.sh` dumps. Document; consider AES-GCM
  wrapping `data` or excluding `bff_sessions` from dumps.
- **P3-31 — INFO —** move `tailwindcss`/`@tailwindcss/vite` to
  `devDependencies`; add `npm audit --omit=dev --audit-level=high` to CI.

SPA verified clean: no browser storage of secrets, no `v-html`/`innerHTML`,
event `details` rendered via `JSON.stringify` inside `<pre>`, CSRF token in
Pinia memory only, router guard installed after `/bff/session` resolves,
edge CSP `script-src 'self'`.

## 5. Cross-cutting

- **Authorisation is the suite's open flank.** P3-1 (no role gate) × open
  signup × P2-13 (Phase 1 shipped by default) × no role gate at BFF session
  creation. Any one closed would blunt the chain; P3-1 is the one that must
  be closed regardless.
- **IP attribution is one connected problem** across P3-2 (server trusts
  spoofable headers), P3-16 (BFFs forward them), P3-17 (BFF limiter keys on
  them). Fix at the server (drop `RealIP`) and at `NewSingleHostProxy` (strip
  on the way in) so both consoles inherit it.
- **The shared gateway's refresh path** needs three backendkit changes
  together: write-through `Put` (P3-10), detached refresh context (P3-11),
  typed refresh errors (P3-12). Then a `v1.12.0` and one bump per console.
- **Both consoles need the login-binding cookie** (P3-15) — same code, best
  done once in `backendkit/bff` (e.g. `LoginBinding` helper) and adopted by
  both.

## 6. Corrections to prior passes

- **Pass 2, P2-3 / §1.x "IP-spoofing downgraded":** pass 2 stated that
  "`GetClientIP` … never honours XFF at all, so an external caller cannot
  influence its output via any header" and downgraded the pass-2 auditor's
  High to a Medium "bucket collapse". The function-level reading was correct;
  the conclusion was wrong, because `chimiddleware.RealIP` rewrites
  `RemoteAddr` *before* `GetClientIPSafe` reads it. The original High was
  right, for a different reason than that auditor gave. Corrected as P3-2;
  P2-3/P2-4 are folded into it.
- **Pass 2, P2-8 severity:** rated Medium on a 1-in-50 synthetic race. For
  `oauth2-monitoring`'s real traffic shape it is near-deterministic (20/20).
- **This engagement's own `v1.11.0`:** the P2-8 singleflight fix shipped with
  an inner re-check using leeway 0 (returned stale tokens inside the
  proactive-refresh window — caught by `oauth2-admin`'s `TestProactiveRefresh`
  during the bump, fixed on `backendkit` main / `v1.11.1`), and introduced
  P3-11 (leader-context propagation), found by this pass. Both are recorded
  here rather than quietly folded in.

## 7. Verification ledger (coordinator)

| Claim | How verified |
|---|---|
| P3-1 no role gate | Read `router.go:413-437`, `auth.go` (no role/aud check), `admin_handler.go:905-1000` (no `IsGlobalAdmin`), `auth_service.go` `Signup`/`Login` (any `client_id`, member login), both BFF callbacks (no role gate) |
| P3-2 RealIP + Caddy passthrough | Read `router.go:151/374/656`, `ratelimit.go:295-325`; fetched Caddy `reverseproxy.go` (`X-Forwarded-*` stripped for untrusted peers; `X-Real-IP`/`True-Client-IP` untouched) |
| P3-10 no write-back | Read `session_postgres.go:116-140`, all `.Put(` sites in monitoring, `server.go:132-140`; SPA `/bff/session` only at bootstrap (both SPAs) |
| P3-15 login not browser-bound | Read `handleLogin`/`handleCallback` in admin (no cookie; state-only) and monitoring `auth.go` (same) |
| Tag integrity | `v1.11.0` resolved via `proxy.golang.org` with `GOSUMDB` on; content contains `DisableAuth` |
| All trees clean after audit | `git status` on all four repos: 0 dirty |

Auditor-reproduced claims not re-executed by the coordinator (traced only):
P3-3, P3-4, P3-11, P3-12, P3-16, P3-17, P3-18, monitoring 20/20 P2-8 trial.
