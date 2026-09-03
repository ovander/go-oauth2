# Socrate Suite — Remediation Plan & Production GO Checklist

**Updated:** 2026-09-02 (rev. 3, after pass-3 audit)
**Companions:** `docs/CR-socrate-suite-security-pass1.md`,
`docs/CR-socrate-suite-security-pass2.md`,
`docs/CR-socrate-suite-security-pass3.md` (which this revision reflects).

Rev. 3 replaces rev. 2. §1 keeps the closed ledger, §2 records the pass-3
items (P3-*), §3 is the GO checklist, §4 the sequencing.

**Bottom line: the suite is NOT GO for production until P3-1 and P3-2 are
closed.** Everything else is important but not a release-blocker.

---

## 1. Closed ledger

### 1.1 Original round (pass 1 → pass 2) — 28 items, all closed and re-verified in pass 3

go-oauth2 H1, pgx, M1/M2, L1, L2, L3, L4 · backendkit H-1, M-1, M-2, `bff`
package, `Session.Snapshot`, `v1.10.0` · oauth2-admin X-1, X-3, C-1, H-1/M-4,
H-2, X-2, migration, e2e test, tag pin · oauth2-monitoring F1/X-1, F2, F5,
X-3/F7, pgx, X-2, CI, migration, tag pin. No regressions found in pass 3.

### 1.2 Pass-2 items closed since rev. 2

| ID | Item | Where | Status |
|---|---|---|---|
| P2-6 | empty-CSRF bypass | backendkit #42 → `v1.11.0` | ✅ verified |
| P2-7 | Gateway fail-open zero value → `DisableAuth` | backendkit #42 → `v1.11.0` | ✅ verified (breaking rename; consoles' bump pending) |
| P2-8 | concurrent-refresh race | backendkit #42 + #44 → `v1.11.0`/`v1.11.1` | ✅ the race itself; see P3-10/P3-11 for what it uncovered |
| — | `v1.11.0` leeway regression | backendkit #44 | ✅ fixed on main, `v1.11.1` tag pending |
| P2-9 | AllowPassthrough compounding | — | ✅ moot once P2-7 closed |

### 1.3 Pass-2 items still open (carried forward)

P2-1, P2-2, P2-5 (go-oauth2); P2-10 (backendkit); P2-11 (re-rated Low),
P2-12, P2-13 (**re-rated High**, see P3-26) (oauth2-admin); P2-14/15
(superseded by P3-28), P2-16 (oauth2-monitoring); roles-frozen (bounded only
once P3-1 is closed). P2-3/P2-4 are superseded by P3-2.

---

## 2. Pass-3 findings

Effort: S = < 1 day, M = 1–3 days.

### 2.1 go-oauth2

| ID | Sev | Item | Effort |
|---|---|---|---|
| **P3-1** | **CRITICAL** | `/api/admin` has no role gate — any authenticated user (incl. self-signup on any client) can create/reset superadmins, manage clients, and drive SOC config. Fix: `RequireGlobalAdmin()` on the group, `RequireRole("superadmin")` on `/superadmins`, `OwnerID==nil` ⇒ admin-only, route-walking 403 regression test | S |
| **P3-2** | **HIGH** | `chimiddleware.RealIP` unconditional on all routers → spoofable IP for rate limits, IP blocks, auto-block framing, audit logs; exploitable behind Caddy via `X-Real-IP`/`True-Client-IP`. Fix: delete the three `RealIP` lines; use `GetClientIPSafe(r, trustedCIDRs)` at every attribution sink; fix `GetClientIP` comment. Supersedes P2-3/P2-4 | S |
| P3-3 | Medium | refresh grant ignores lock / client `Active`; `Authorize`/code grant ignore `Active`; `BlockUser` doesn't bump `token_version` | S |
| P3-4 | Low | omitted `code_challenge_method` ⇒ plain PKCE; require S256 at `Authorize` | S |
| P3-5 | Low | hosted login + `/auth/login` never feed auto-defense | S |
| P3-6 | Low | dead `POST /auth/login` path (counts failures, would set unconsumed cookie) — remove | S |
| P3-7 | Low | app-admin can send reset/verify mails for any user ID | S |
| P3-8 | Low | no per-client allowed-scopes policy | M |
| P3-9 | Info | MFA disable without re-auth; legacy secret compare not constant-time | S |
| P2-1 | Medium | web-handler raw `err.Error()` (carried) | S |
| P2-5 | Medium | client_credentials skips scope/DPoP (carried) | S |
| P2-2 | Low | app_users_handler error leaks (carried) | S |

### 2.2 backendkit

| ID | Sev | Item | Effort |
|---|---|---|---|
| **P3-10** | **Medium** (availability) | `ProxyWithSession` never `Put`s refreshed tokens / `Touch` → durable stores lose the rotated refresh token; monitoring Postgres sessions die at first expiry and never slide idle. Fix: write-through `Put` in the singleflight closure + after `Touch`; snapshot-store regression test | S |
| **P3-11** | **Medium** | coalesced refresh bound to the leader's request `ctx`; one aborted request logs out all waiters. Fix: `context.WithTimeout(context.WithoutCancel(ctx), 10s)` in the closure | S |
| P3-12 | Low | any refresh error (incl. transport) tears down the session; needs typed `*socrate.OAuthError` and tear-down only on `invalid_grant`/`invalid_client` | M |
| P3-13 | Low | `Gateway` no longer copyable (`singleflight.Group`); document or use a lazy pointer | S |
| P3-14 | Info | `Session` `%+v` prints tokens; add `String()` | S |
| P3-16′ | Low/Med | strip `X-Real-IP`, `True-Client-IP`, `Forwarded`, `X-Forwarded-Host` in `NewSingleHostProxy`'s `Rewrite` so both consoles inherit it | S |
| P3-15′ | Medium | `LoginBinding` helper (nonce cookie ↔ pending state) so both consoles fix login-CSRF once | S |
| P2-10 | Low | query-string escaping in `socrate/monitoring.go` (carried, reproduced again) | S |

Release: ship P3-10/11/12/13/14/16′/15′ + P2-10 as **`v1.12.0`**, then one
bump per console.

### 2.3 oauth2-admin

| ID | Sev | Item | Effort |
|---|---|---|---|
| **P3-26** (= P2-13) | **HIGH** (deploy) | shipped default is Phase 1 (bare pass-through; `bootstrap.sh` seeds the env with `BFF_CLIENT_ID` unset) → `/api/admin/*` internet-reachable. Fix: refuse to start without `BFF_CLIENT_ID` unless `BFF_PHASE1_PASSTHROUGH=true`; ship env example with Phase 2 on | S |
| P3-15 | Medium | login state not bound to browser (login CSRF / account swap) — adopt `backendkit` `LoginBinding` | S |
| P3-16 | Low/Med | forwards attacker IP headers upstream — inherit from backendkit `v1.12.0` | S |
| P3-17 | Low | limiter keys on unconditional leftmost XFF — honour only when `RemoteAddr` is loopback; document the Caddy assumption | S |
| P3-18 | Low | encoded dot-segments pass allowlist — `path.Clean` prefix check | S |
| P3-19 | Low | `/bff/logout` no CSRF | S |
| P3-20 | Low | `/bff/session` no `Cache-Control: no-store` | S |
| P3-21 | Low | `/bff/elevate` forwards upstream error bodies verbatim | S |
| P3-22 | Low | SPA 401 doesn't clear `authStore.user` (stuck after BFF restart) | S |
| P3-23 | Low | `/api/version` unrouted; password-reset posts to wrong origin and "succeeds" | S |
| P3-24 | Info | config cross-checks (`COOKIE_SECURE=false` + https; `SESSION_IDLE=0s`) | S |
| P3-25 | Info | `SECURITY.md`/Dockerfile/README drift; `dist/` ownership | S |
| P3-27 | Low | CI `npm audit --audit-level=high` red on `main` — `npm audit fix` | S |
| P2-11 | Low | elevate `exp` absorption (re-rated; poisoned session, not privilege) | S |
| P2-12 | Low | CSRF header hardcode | S |
| — | — | **bump to backendkit `v1.11.1`** (drop `AuthEnabled: true`) — pending tag; then `v1.12.0` | S |

### 2.4 oauth2-monitoring

| ID | Sev | Item | Effort |
|---|---|---|---|
| P3-10 | Medium | Postgres store broken by missing write-back — fixed by backendkit `v1.12.0`; add an integration test here that exercises refresh through the real store | S |
| P3-15 | Medium | login state not bound to browser (same as admin) | S |
| P3-16 / P3-17 / P3-18 | Low | as admin | S |
| P3-28 | Low | all `Exec` results discarded (supersedes P2-14/15); log every error; surface `Delete` failure on logout | S |
| P3-29 | Low | `/bff/session` re-`Put` races logout `Delete` (resurrection) — `UPDATE` for touch, `INSERT` only at callback | S |
| P3-30 | Info | tokens at rest plaintext in DB backups — document; consider AES-GCM wrap or exclude table from dumps | M |
| P3-31 | Info | `tailwindcss` in `dependencies` → npm audit noise; add `--omit=dev` audit to CI | S |
| P3-24 / P3-25 | Info | config cross-checks (`SESSION_IDLE=0s` means *expire now* on Postgres); stale Dockerfile/nginx/env | S |
| P2-16 | Low | elevate failure path doesn't clear cookie | S |
| — | — | **bump to backendkit `v1.11.1`** (drop `AuthEnabled: true`; closes the 20/20 P2-8 logout-every-15-min) — pending tag; then `v1.12.0` | S |

---

## 3. Production GO checklist (rev. 3)

**Release-blocking**
- [ ] **P3-1** go-oauth2 `/api/admin` role gate + route-walking 403 test
- [x] **P3-2** go-oauth2 drop `RealIP`, `GetClientIPSafe` everywhere — go-oauth2 #222 (`middleware.ClientIP`; `TRUSTED_PROXIES` now defaults to loopback, see the CHANGELOG upgrade note)
- [ ] **P3-26** admin BFF refuses Phase 1 without explicit opt-in; env examples ship Phase 2
- [ ] backendkit `v1.11.1` tag + both consoles bumped (P2-7 consequence; ends monitoring's 15-min logouts)

**Before next release (shared infra)**
- [ ] backendkit `v1.12.0`: P3-10, P3-11, P3-12, P3-13, P3-14, P3-16′, P3-15′, P2-10
- [ ] both consoles bumped to `v1.12.0` and adopting `LoginBinding` (P3-15)
- [ ] monitoring: integration test for refresh through the Postgres store

**go-oauth2 hardening**
- [ ] P3-3 refresh/authorize honour lock + `Active`; `Block` bumps version
- [ ] P2-1, P2-5, P3-4, P3-5, P3-6, P3-7, P3-8, P3-9, P2-2

**Consoles hardening**
- [ ] admin: P3-17, P3-18, P3-19, P3-20, P3-21, P3-22, P3-23, P3-24, P3-25, P3-27, P2-11, P2-12
- [ ] monitoring: P3-17, P3-18, P3-28, P3-29, P3-30, P3-31, P3-24, P3-25, P2-16

**Suite-wide**
- [x] Pass-2 corrections recorded transparently (P2-3 downgrade was wrong; P2-8 severity underrated; `v1.11.0` regression + P3-11 introduced by this engagement)
- [ ] Decide whether self-signup should be allowed on the first-party console clients at all (per-app `AllowSignup`) — reduces P3-1's blast radius even after the gate is in place

---

## 4. Suggested sequencing

1. **P3-1 and P3-2 today.** Both are < 1 day in go-oauth2, both are
   reachable from the internet in the shipped configuration, and P3-1 is a
   full-compromise path. Ship as one go-oauth2 release.
2. **Tag `v1.11.1`, bump both consoles, and land P3-26** in the same day —
   this ends the monitoring 15-minute logouts and closes the Phase-1
   default footgun.
3. **backendkit `v1.12.0`** (P3-10/11/12/13/14/16′/15′ + P2-10) and the two
   console bumps — this is the "make the shared gateway production-grade"
   release; P3-10 is what actually makes the Postgres store usable.
4. Everything else in routine hardening.

**Assessment:** pass 3 found what passes 1 and 2 had been looking *around*:
the server verifies identity meticulously and then doesn't ask who you are
before letting you administer it. That, plus a spoofable client IP and a
default deployment that runs the BFF wide open, is the gap between the
suite's strong token-level security and an actual production posture. All
three are cheap to close; the shared-gateway fixes are the next tier and
belong in one backendkit release rather than three.
