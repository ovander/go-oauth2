# Socrate Suite — Remediation Plan & Production GO Checklist

**Updated:** 2026-09-03 (rev. 6 — every PR merged; deployment GO)
**Companions:** `docs/CR-socrate-suite-security-pass1.md`,
`docs/CR-socrate-suite-security-pass2.md`,
`docs/CR-socrate-suite-security-pass3.md`.

Rev. 6 replaces rev. 5. §1 is the closed ledger, §2 the hardening round and
what is still open after it, §3 the GO checklist, §4 the verification notes,
§5 the deployment GO statement for the documented single-VPS topology.

**Bottom line: every finding from passes 1–3 that was accepted for a fix is
merged — go-oauth2 (#222–#226), backendkit (`v1.11.1`, `v1.12.0`),
oauth2-admin (#16–#20) and oauth2-monitoring (#29–#31). The suite is GO for
the documented Linux VPS + Postgres + Caddy deployment (§5).** What remains is
product policy (per-client scope policy, self-signup on first-party clients)
and two documented Low/Info residuals.

---

## 1. Closed ledger

### 1.1 Original round (pass 1 → pass 2) — 28 items

go-oauth2 H1, pgx, M1/M2, L1, L2, L3, L4 · backendkit H-1, M-1, M-2, `bff`
package, `Session.Snapshot`, `v1.10.0` · oauth2-admin X-1, X-3, C-1, H-1/M-4,
H-2, X-2, migration, e2e test, tag pin · oauth2-monitoring F1/X-1, F2, F5,
X-3/F7, pgx, X-2, CI, migration, tag pin. All re-verified in pass 3, no
regressions.

### 1.2 Pass-2 items

| ID | Item | Where | Status |
|---|---|---|---|
| P2-6 | empty-CSRF bypass | backendkit #42 → `v1.11.0` | ✅ merged, tagged |
| P2-7 | Gateway fail-open zero value → `DisableAuth` | backendkit #42 → `v1.11.0`; consoles admin #17 / monitoring #29 | ✅ tagged; console bumps merged (admin #17, monitoring #29) |
| P2-8 | concurrent-refresh race | backendkit #42 + #44 → `v1.11.1` | ✅ tagged (see P3-10/11 for what it uncovered, also closed) |
| P2-10 | query-string escaping | backendkit #45 → `v1.12.0` | ✅ tagged |
| P2-13 | Phase 1 shipped by default | re-rated High → **P3-26** | ✅ see below |
| P2-14/15 | Postgres store swallows errors | superseded by P3-28 → monitoring #31 | ✅ merged |
| P2-16 | elevate failure path doesn't clear cookie | monitoring #29 | ✅ merged |
| P2-3 / P2-4 | IP attribution | superseded by **P3-2** | ✅ see below |
| P2-9 | AllowPassthrough compounding | moot once P2-7 closed | ✅ |
| P2-1, P2-5 | go-oauth2 web error hygiene / client_credentials gates | go-oauth2 #225 | ✅ merged |
| P2-2 | `app_users_handler.go` error leaks | go-oauth2 #226 | ✅ merged |
| P2-11, P2-12 | admin elevate `exp` absorption (Low), CSRF header hardcode | admin #20 | ✅ merged |

### 1.3 Pass-3 items — release-blockers and shared infrastructure

| ID | Sev | Item | Where | Status |
|---|---|---|---|---|
| **P3-1** | Critical | `/api/admin` had no role gate (= zero-trust CRIT-01) | go-oauth2 #223 | ✅ merged — `RequireGlobalAdmin()` on the group, `superadmin` on `/superadmins`, route-walking 403 test |
| **P3-2** | High | chi `RealIP` made client IP attacker-controlled (GO-2026-5775/5777) | go-oauth2 #222 | ✅ merged — `RealIP` removed, `middleware.ClientIP` + `TRUSTED_PROXIES` (defaults to loopback) |
| **P3-26** | High (deploy) | admin BFF shipped Phase 1 (bare pass-through) as the seeded default | admin #18, monitoring #30 | ✅ merged — `BFF_PHASE1_PASSTHROUGH=true` opt-in required; env examples ship Phase 2; insecure-cookie-on-https and non-positive lifetimes rejected; migration flags logged as WARNINGs |
| **P3-10** | Medium | `ProxyWithSession` never wrote refreshed tokens / `Touch` back to the store (Postgres sessions died at first expiry) | backendkit #45 → `v1.12.0`; monitoring #29 | ✅ tagged; consumer-level reproduction test in monitoring #29 |
| **P3-11** | Medium | coalesced refresh bound to the leader's request context | backendkit #45 → `v1.12.0` | ✅ tagged — `context.WithoutCancel` + `RefreshTimeout` |
| P3-12 | Low → adopted | any refresh error tore the session down | backendkit #45 (`*socrate.OAuthError`, `IsFatalRefreshError`); admin #17, monitoring #29 (consoles' own token clients now return typed errors; `/bff/elevate` uses the same policy) | ✅ tagged; adoption merged |
| P3-13 | Low | `Gateway` not copyable — document | backendkit #45 | ✅ |
| P3-14 | Info | `Session` `%+v` leaked tokens | backendkit #45 (`String()`/`GoString()`) | ✅ |
| **P3-15** | Medium | pending login not bound to the browser (login CSRF / account swap), both consoles | backendkit #45 (`LoginBinding`); admin #17, monitoring #29 | ✅ tagged; adoption merged, with negative tests |
| P3-16 | Low/Med | BFF forwarded `X-Real-IP` / `True-Client-IP` / `Forwarded` upstream | backendkit #45 (`NewSingleHostProxy` Director) | ✅ inherited by both consoles via the bump |
| P3-24 | Info | config cross-checks (`COOKIE_SECURE=false` on https; `SESSION_IDLE=0s`) | admin #18, monitoring #30 | ✅ merged |
| P3-25 | Info | docs/deploy drift ("Phase 1 (this build)"), Dockerfile Go pins, stale root deploy files, SPA dir ownership, `SECURITY.md` | admin #18 / #20, monitoring #30 / #31 | ✅ merged |
| — | — | `govulncheck` drift (Go 1.25.13 / 1.26.6, chi 5.3.0, x/text 0.39.0) | go-oauth2 #222, backendkit #45 | ✅ |

**Open PRs to merge (any order within a repo; no overlapping files):**
oauth2-admin **#17** (bump + adoption) and **#18** (P3-26); oauth2-monitoring
**#29** (bump + adoption) and **#30** (P3-26).

---

## 2. Closed in this round — the Low/Info hardening PRs

### 2.1 go-oauth2 — #225 and #226 (both merged)

| ID | Sev | Item | Where |
|---|---|---|---|
| P3-3 | Medium | lock / `Active` on refresh, authorize and code grant; `Block` bumps `token_version` | #225 ✅ merged |
| P2-1 | Medium | web handler rendered `err.Error()` | #225 ✅ merged |
| P2-5 | Medium | `client_credentials` skipped `validateScope` / `requireDPoP` | #225 ✅ merged |
| P3-4 | Low | omitted `code_challenge_method` ⇒ plain PKCE — `Authorize` requires S256, `VerifyPKCE` rejects `""` | #226 |
| P3-5 | Low | hosted login feeds auto-defense | #226 |
| P3-6 | Low | dead `POST /auth/login` removed; `GET /auth/login` forwards to `/oauth/authorize` | #226 |
| P3-7 | Low | mail-triggering admin actions limited to app members | #226 |
| P2-2 | Low | `app_users_handler.go` error leaks | #226 |
| P3-9 | Info | MFA disable needs password + TOTP/recovery code; legacy secret compare constant-time | #226 |

### 2.2 oauth2-admin — #17, #18, #20 (all merged)

P3-17, P3-18, P3-19, P3-20, P3-21, P3-22, P3-23, P3-25, P2-11, P2-12 — all in
#20. P3-27 merged as #19. #17 (v1.12.0 bump, P3-15, P3-12) and #18 (P3-26,
P3-24) had been left unmerged since the previous round with only the
npm-audit gate red (fixed by #19); they were rebased, went green and were
merged ahead of #20, which was rebased onto them.

### 2.3 oauth2-monitoring — #31 (merged)

P3-17, P3-18, P3-20, P3-21, P3-22, P3-25, P3-28, P3-29, P3-30, P3-31 — all in
#31, merged (`npm audit fix` also cleared the 10 open advisories there).

### 2.4 Still open after this round

| Item | Kind | Note |
|---|---|---|
| P3-8 — per-client allowed-scopes policy | product decision | `admin` / `monitoring:*` remain grantable to any client; `ADMIN_SCOPE_MODE=enforce` is a routing hint, not a boundary. Bounded by P3-1 (role gate per bearer). Needs a per-app `AllowedScopes` model + admin UI. |
| Self-signup on first-party console clients | product decision | `POST /api/auth/signup` accepts any `client_id`. P3-1 removed the privilege consequence; a per-app `AllowSignup` (default off for the console clients) would remove the reachability. |
| Roles frozen at login | backlog | bounded by P3-1; SPA-side gating may lag a de-privilege until re-login. Re-derive `UserInfo` on refresh in the shared gateway. |
| Shared gateway touch goes through `Put` | residual (Low) | backendkit's throttled touch inside `ProxyWithSession` is an upsert; the consoles' `/bff/session` path now uses an UPDATE-only `Touch` (P3-29), but the proxy path still has the narrow read-races-logout window. Add an optional `Toucher` interface to `bff.Gateway`. |
| Tokens at rest in the monitoring Postgres store | residual (Info) | documented; dumps exclude the rows (P3-30). AES-GCM envelope encryption is the next step if the database is shared. |

---

## 3. Production GO checklist (rev. 6)

**Release-blocking — all closed**
- [x] P3-1 admin role gate — go-oauth2 #223
- [x] P3-2 client-IP spoofing — go-oauth2 #222
- [x] backendkit `v1.11.1` and `v1.12.0` tagged, verified via the module proxy
- [x] monitoring #29 + #30 (P3-10 store fix, P3-15, P3-12, P2-16, P3-26)
- [x] admin #17 + #18 (P3-15, P3-12, P3-26, P3-24, v1.12.0 bump)

**Recommended before the next release — all closed**
- [x] go-oauth2 P3-3, P2-1, P2-5 — #225
- [x] Hardening PRs: go-oauth2 #226, admin #20, monitoring #31

**Routine hardening (Low/Info)** — all merged; only the §2.4 residuals remain.

**Open product decisions (not blocking)**
- [ ] Per-app `AllowSignup` for the console clients (§2.4)
- [ ] Per-client allowed-scopes policy, P3-8 (§2.4)

**Suite-wide**
- [x] Every High+ claim from pass 3 was re-verified by the coordinator before being fixed; two pass-2 claims were corrected in writing (P2-3 downgrade, P2-8 severity)
- [x] Two regressions introduced by this engagement (`v1.11.0` leeway, P3-11 leader context) found by its own tests/audit and fixed before consumers depended on them

---

## 4. Verification notes for this round

- **P3-1** — route-walking test drives the real admin router with real signed
  tokens: `user` → 403 on every registered `/api/admin` route; `admin` → 403
  on `/superadmins/*` only; `superadmin` → admitted; no token → 401.
- **P3-2** — an untrusted peer rotating `True-Client-IP` / `X-Real-IP` /
  `X-Forwarded-For` stays rate-limited (429); a trusted loopback proxy's XFF
  still keys per client; `RemoteAddr` is never mutated. Caddy behaviour
  (replaces XFF for untrusted peers, passes the other two through) verified
  from its source.
- **P3-10** — reproduced twice: in backendkit with a snapshot store, and at
  the consumer level in monitoring #29 through the real handlers with
  Socrate-style single-use rotating refresh tokens across three requests.
- **P3-11** — leader request cancelled mid-refresh; three waiters plus the
  leader all receive the refreshed token, one refresh call.
- **P3-12** — both consoles' token clients now return `*socrate.OAuthError`;
  `invalid_grant`/`invalid_client` → 401 + teardown, 5xx / non-JSON 400 →
  502 + session kept. Found during adoption: without the typed error the
  fatal branch could never fire, so the adoption commit is what makes the
  policy real.
- **P3-15** — a callback with no binding cookie, or another browser's, is a
  400 and mints no session; the cookie-jar e2e flow still completes.
- **P3-26** — Phase 1 without `BFF_PHASE1_PASSTHROUGH=true` fails
  `LoadConfig` with an actionable message; every rejected combination and
  the http-dev exception are tested in both consoles.
- All go-oauth2 and backendkit changes pass `golangci-lint` built with the
  CI toolchain; `govulncheck` verified green in CI after the toolchain bumps.
- **Hardening round (this revision)** — every item carries a negative test:
  P3-4 (`""`/`plain`/`s256` rejected, `S256` accepted; `VerifyPKCE(v, v, "")`
  errors), P3-5 (fake defense records the hosted form's failure/success with
  the client IP), P3-6 (302 to `/oauth/authorize` with parameters preserved;
  no password form otherwise), P3-7 (outsider → 404 before the app lookup,
  member passes), P3-9 (bearer alone / wrong password / wrong code → no
  disable; TOTP or recovery code + password → 204; passwordless account still
  needs a code; nil user service fails closed), P2-2 (`pq:`/`SQLSTATE` never
  echoed). Consoles: XFF trust table and key-rotation from a non-loopback
  peer; `%2e%2e` never reaches the upstream while canonical paths still proxy;
  logout without CSRF keeps the session and revokes nothing (admin); elevate
  5xx body not forwarded; elevate token without `exp` / without
  `access_token` not absorbed; `/bff/session` uses Touch not Put; a failing
  delete surfaces `logout_incomplete`; public issuer posts strip
  cookie/Authorization and hit the 429 budget.

**Assessment:** the round that started as "audit the suite" ends with the
identity server enforcing authorisation on its control plane, IP attribution
that an attacker cannot steer, BFFs that refuse to run open by accident, a
shared gateway whose refresh path is correct for durable stores, and logins
bound to the browser that started them. The Low/Info list has been worked
through; what is left is product policy and two documented residuals.

---

## 5. Deployment GO — Linux VPS, Postgres, Caddy

**Verdict: GO.** Every PR in this plan is merged; on security grounds nothing
blocks the documented topology — one Linux VPS, Caddy as the only public listener,
Postgres on loopback, Socrate on `127.0.0.1:8080`, the admin API on
`127.0.0.1:8081`, the two BFFs on `127.0.0.1:8090/8091`, the SPAs served as
static files.

Operator checklist for that topology (all already in the deploy kits):

1. **go-oauth2** — `TRUSTED_PROXIES` left at its default (loopback) is correct
   for same-host Caddy and the BFFs; set `ADMIN_BIND_HOST=127.0.0.1`; grant the
   console operators a global `admin`/`superadmin` role (P3-1 — plain `user`
   accounts get 403 on `/api/admin`); production `Validate()` must pass
   (HTTPS issuer, non-default `SECRET_KEY_BASE`, token rate limit on).
2. **Both BFFs** — Phase 2 on (`BFF_CLIENT_ID` + `BFF_CLIENT_SECRET` of a
   *confidential* client; the process refuses to start otherwise),
   `BFF_COOKIE_SECURE=true`, `BFF_PUBLIC_ORIGIN` / `BFF_OAUTH_PUBLIC_URL` on
   `https://`, no `BFF_ALLOW_PASSTHROUGH`. Built against backendkit
   ≥ `v1.12.0` — mandatory if `BFF_SESSION_DSN` (Postgres sessions) is used.
3. **Caddy** — the site blocks from `deploy/Caddyfile` in each console repo;
   do **not** set `trusted_proxies` unless another proxy sits in front of
   Caddy (both BFFs and go-oauth2 rely on Caddy replacing client-supplied
   `X-Forwarded-For`); security headers + CSP as shipped; HSTS on.
4. **Postgres** — loopback only; the BFF's DB role limited to its two tables;
   `backup-db.sh` (excludes session rows) scheduled; signing keys backed up
   offline.
5. **Filesystem** — SPA `dist/` directories root-owned; env files
   `0640 root:socrate`; the systemd units' hardening left as shipped.

What GO does *not* mean: the §2.4 items are open by design — any registered
client can still request `admin`/`monitoring:*` scopes (the role gate, not the
scope, is the boundary), and self-signup on the console clients remains
reachable (harmless without a role, but noisy). Decide both before opening
registration to third parties.
