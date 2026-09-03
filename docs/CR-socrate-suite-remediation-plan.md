# Socrate Suite — Remediation Plan & Production GO Checklist

**Updated:** 2026-09-03 (rev. 4, after the pass-3 remediation round)
**Companions:** `docs/CR-socrate-suite-security-pass1.md`,
`docs/CR-socrate-suite-security-pass2.md`,
`docs/CR-socrate-suite-security-pass3.md`.

Rev. 4 replaces rev. 3. §1 is the closed ledger (now including every pass-3
release-blocker), §2 lists what remains open, §3 is the GO checklist, §4 the
verification notes for this round.

**Bottom line: with the four console PRs below merged, the suite is GO on
every finding rated Medium or above.** What remains is Low/Info hardening
and one product decision (self-signup on first-party clients).

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
| P2-7 | Gateway fail-open zero value → `DisableAuth` | backendkit #42 → `v1.11.0`; consoles admin #17 / monitoring #29 | ✅ tagged; console bumps in open PRs |
| P2-8 | concurrent-refresh race | backendkit #42 + #44 → `v1.11.1` | ✅ tagged (see P3-10/11 for what it uncovered, also closed) |
| P2-10 | query-string escaping | backendkit #45 → `v1.12.0` | ✅ tagged |
| P2-13 | Phase 1 shipped by default | re-rated High → **P3-26** | ✅ see below |
| P2-14/15 | Postgres store swallows errors | superseded by P3-28 | open (Low) |
| P2-16 | elevate failure path doesn't clear cookie | monitoring #29 | ✅ in open PR |
| P2-3 / P2-4 | IP attribution | superseded by **P3-2** | ✅ see below |
| P2-9 | AllowPassthrough compounding | moot once P2-7 closed | ✅ |
| P2-1, P2-2, P2-5 | go-oauth2 error hygiene / client_credentials gates | — | open (§2) |
| P2-11, P2-12 | admin elevate `exp` absorption (Low), CSRF header hardcode | — | open (§2) |

### 1.3 Pass-3 items — release-blockers and shared infrastructure

| ID | Sev | Item | Where | Status |
|---|---|---|---|---|
| **P3-1** | Critical | `/api/admin` had no role gate (= zero-trust CRIT-01) | go-oauth2 #223 | ✅ merged — `RequireGlobalAdmin()` on the group, `superadmin` on `/superadmins`, route-walking 403 test |
| **P3-2** | High | chi `RealIP` made client IP attacker-controlled (GO-2026-5775/5777) | go-oauth2 #222 | ✅ merged — `RealIP` removed, `middleware.ClientIP` + `TRUSTED_PROXIES` (defaults to loopback) |
| **P3-26** | High (deploy) | admin BFF shipped Phase 1 (bare pass-through) as the seeded default | admin #18, monitoring #30 | ✅ in open PRs — `BFF_PHASE1_PASSTHROUGH=true` opt-in required; env examples ship Phase 2; insecure-cookie-on-https and non-positive lifetimes rejected; migration flags logged as WARNINGs |
| **P3-10** | Medium | `ProxyWithSession` never wrote refreshed tokens / `Touch` back to the store (Postgres sessions died at first expiry) | backendkit #45 → `v1.12.0`; monitoring #29 | ✅ tagged; consumer-level reproduction test in monitoring #29 |
| **P3-11** | Medium | coalesced refresh bound to the leader's request context | backendkit #45 → `v1.12.0` | ✅ tagged — `context.WithoutCancel` + `RefreshTimeout` |
| P3-12 | Low → adopted | any refresh error tore the session down | backendkit #45 (`*socrate.OAuthError`, `IsFatalRefreshError`); admin #17, monitoring #29 (consoles' own token clients now return typed errors; `/bff/elevate` uses the same policy) | ✅ tagged; adoption in open PRs |
| P3-13 | Low | `Gateway` not copyable — document | backendkit #45 | ✅ |
| P3-14 | Info | `Session` `%+v` leaked tokens | backendkit #45 (`String()`/`GoString()`) | ✅ |
| **P3-15** | Medium | pending login not bound to the browser (login CSRF / account swap), both consoles | backendkit #45 (`LoginBinding`); admin #17, monitoring #29 | ✅ tagged; adoption in open PRs, with negative tests |
| P3-16 | Low/Med | BFF forwarded `X-Real-IP` / `True-Client-IP` / `Forwarded` upstream | backendkit #45 (`NewSingleHostProxy` Director) | ✅ inherited by both consoles via the bump |
| P3-24 | Info | config cross-checks (`COOKIE_SECURE=false` on https; `SESSION_IDLE=0s`) | admin #18, monitoring #30 | ✅ in open PRs |
| P3-25 | Info | docs/deploy drift ("Phase 1 (this build)") | admin #18, monitoring #30 (partial: README/main.go/deploy README wording) | ✅ wording; Dockerfile Go pins still open |
| — | — | `govulncheck` drift (Go 1.25.13 / 1.26.6, chi 5.3.0, x/text 0.39.0) | go-oauth2 #222, backendkit #45 | ✅ |

**Open PRs to merge (any order within a repo; no overlapping files):**
oauth2-admin **#17** (bump + adoption) and **#18** (P3-26); oauth2-monitoring
**#29** (bump + adoption) and **#30** (P3-26).

---

## 2. Still open (none release-blocking)

### 2.1 go-oauth2

| ID | Sev | Item | Effort |
|---|---|---|---|
| P3-3 | Medium | refresh grant ignores account lock / client `Active`; `Authorize`/code grant ignore `Active`; `BlockUser` doesn't bump `token_version` — a blocked user keeps minting JWTs for external resource servers until the refresh TTL | S |
| P2-1 | Medium | `internal/web/handler.go` renders raw `err.Error()` to unauthenticated browsers | S |
| P2-5 | Medium | `client_credentials` grant skips `validateScope` / `requireDPoP` | S |
| P3-4 | Low | omitted `code_challenge_method` ⇒ plain PKCE; require S256 at `Authorize` | S |
| P3-5 | Low | hosted login + `/auth/login` never feed auto-defense | S |
| P3-6 | Low | dead `POST /auth/login` path — remove | S |
| P3-7 | Low | app-admin can send reset/verify mails for any user ID | S |
| P3-8 | Low | no per-client allowed-scopes policy | M |
| P2-2 | Low | `app_users_handler.go` error leaks (now behind the P3-1 gate) | S |
| P3-9 | Info | MFA disable without re-auth; legacy secret compare not constant-time | S |

### 2.2 oauth2-admin

| ID | Sev | Item | Effort |
|---|---|---|---|
| P3-17 | Low | BFF limiter keys on unconditional leftmost XFF — honour only when `RemoteAddr` is loopback; document the Caddy assumption | S |
| P3-18 | Low | encoded dot-segments pass the allowlist — `path.Clean` prefix check | S |
| P3-19 | Low | `/bff/logout` has no CSRF check | S |
| P3-20 | Low | `/bff/session` lacks `Cache-Control: no-store` | S |
| P3-21 | Low | `/bff/elevate` forwards upstream error bodies verbatim | S |
| P3-22 | Low | SPA: a 401 doesn't clear `authStore.user` (stuck after BFF restart) | S |
| P3-23 | Low | `/api/version` unrouted; password-reset posts to the wrong origin and "succeeds" | S |
| P3-27 | Low | CI `npm audit --audit-level=high` red on `main` — `npm audit fix` | S |
| P2-11 | Low | elevate `exp` absorption → poisoned session (not privilege) | S |
| P2-12 | Low | CSRF header name hardcoded in `elevate.go` | S |
| P3-25 | Info | `SECURITY.md` describes the retired architecture; `bff/Dockerfile` Go pin; `dist/` ownership | S |

### 2.3 oauth2-monitoring

| ID | Sev | Item | Effort |
|---|---|---|---|
| P3-17 / P3-18 | Low | as admin | S |
| P3-28 | Low | every `Exec` result in `PostgresSessionStore` discarded (supersedes P2-14/15) — log errors; surface `Delete` failure on logout | S |
| P3-29 | Low | `/bff/session` re-`Put` races logout's `Delete` (resurrection) — `UPDATE` for touch, `INSERT` only at callback | S |
| P3-30 | Info | tokens at rest plaintext in DB backups — document; consider AES-GCM wrap or excluding `bff_sessions` from dumps | M |
| P3-31 | Info | `tailwindcss` under `dependencies` → npm audit noise; add `--omit=dev` audit to CI | S |
| P3-25 | Info | stale root `Dockerfile`/`nginx.conf`/`.env.production`; `bff/Dockerfile` Go pin | S |

### 2.4 Cross-cutting

- **Self-signup on first-party console clients.** `POST /api/auth/signup`
  accepts any `client_id` with no per-app allow flag. P3-1 removed the
  privilege consequence; a per-app `AllowSignup` (default off for the two
  console clients) would remove the reachability too. Product decision.
- **Roles frozen at login.** Bounded now that the admin API enforces roles
  per bearer (P3-1); SPA-side gating may lag a de-privilege until re-login.
  Backlog: re-derive `UserInfo` on refresh in the shared gateway.

---

## 3. Production GO checklist (rev. 4)

**Release-blocking — all closed**
- [x] P3-1 admin role gate — go-oauth2 #223 (merged)
- [x] P3-2 client-IP spoofing — go-oauth2 #222 (merged)
- [x] backendkit `v1.11.1` and `v1.12.0` tagged, verified via the module proxy
- [ ] **Merge** admin #17 + #18 and monitoring #29 + #30 (P3-26, bumps, P3-15, P3-12 adoption, P2-16). Everything is verified in the PRs; this is the last human step for GO.

**Recommended before the next release**
- [ ] go-oauth2 P3-3 (lock/`Active` on refresh and authorize) and P2-1 / P2-5
- [ ] Decide on per-app `AllowSignup` for the console clients (§2.4)

**Routine hardening (Low/Info)**
- [ ] go-oauth2: P3-4, P3-5, P3-6, P3-7, P3-8, P3-9, P2-2
- [ ] admin: P3-17, P3-18, P3-19, P3-20, P3-21, P3-22, P3-23, P3-27, P2-11, P2-12, P3-25
- [ ] monitoring: P3-17, P3-18, P3-28, P3-29, P3-30, P3-31, P3-25

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

**Assessment:** the round that started as "audit the suite" ends with the
identity server enforcing authorisation on its control plane, IP attribution
that an attacker cannot steer, BFFs that refuse to run open by accident, a
shared gateway whose refresh path is correct for durable stores, and logins
bound to the browser that started them. The remaining list is real but
routine.
