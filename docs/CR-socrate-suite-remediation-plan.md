# Socrate Suite — Remediation Plan & Production GO Checklist

**Updated:** 2026-07-03 (rev. 2, after pass-2 verification)
**Companions:** `docs/CR-socrate-suite-security-pass1.md` (original audit),
`docs/CR-socrate-suite-security-pass2.md` (post-remediation re-audit, which this
revision reflects).

This revision replaces the original P0/P1/P2 list, which is now fully closed
(§1). It records the fresh findings from pass-2 (§2) and an updated GO
checklist (§3).

---

## 1. Original remediation round — complete

All P0 and P1 items from rev. 1 are merged, independently re-verified against
current code in pass-2, and confirmed to have survived the two BFF
consolidation migrations without regression.

| Repo | Item | PR | Pass-2 status |
|---|---|---|---|
| go-oauth2 | H1 — app-user RBAC | #218 | ✅ verified |
| go-oauth2 | pgx SQLi (GO-2026-5004) | #218 | ✅ verified |
| go-oauth2 | M1/M2 — error hygiene, `errors.Is` | #219 | ✅ verified (scope gap found, §2.1) |
| go-oauth2 | L1 — login timing side-channel | #219 | ✅ verified |
| go-oauth2 | L2 — introspection audience-binding | #219 | ✅ verified |
| go-oauth2 | L3 — revoke ownership check | #219 | ✅ verified (documented gap unchanged, as intended) |
| go-oauth2 | L4 — require https:// issuer in prod | #219 | ✅ verified |
| backendkit | H-1 — JWKS-refetch DoS guard | #39 | ✅ verified |
| backendkit | M-1 — path-escaping | #39 | ✅ verified (query-string gap found, §2.1) |
| backendkit | M-2 — exp required + leeway | #39 | ✅ verified |
| backendkit | `bff` shared package (X-4 consolidation) | #38 | ⚠️ new findings, §2.2 |
| backendkit | `Session.Snapshot()`/rehydration | #41 | ✅ verified |
| backendkit | `v1.10.0` tag published | manual | ✅ verified genuine (a stale-tag claim was investigated and refuted, see pass-2 §3.5) |
| oauth2-admin | X-1 — fail-closed proxy | #13 | ✅ verified |
| oauth2-admin | X-3 — logout revocation | #13 | ✅ verified |
| oauth2-admin | C-1 — base-path (blank SPA) | #14 | ✅ verified with a real build |
| oauth2-admin | H-1/M-4 — Caddy headers | #14 | ✅ verified |
| oauth2-admin | H-2 — BFF tests in CI | #14 | ✅ verified |
| oauth2-admin | X-2 — rate limiting | #15 | ✅ verified |
| oauth2-admin | BFF migration onto `backendkit/bff` | #16 | ✅ verified, no regressions (new findings, §2.3) |
| oauth2-admin | e2e cookie-jar test | #12 | ✅ merged, green |
| oauth2-admin | pin to real `v1.10.0` tag | direct commit | ✅ verified |
| oauth2-monitoring | F1/X-1 — fail-closed proxy | #24 | ✅ verified |
| oauth2-monitoring | F2 — session data race | #24 | ✅ verified, re-run under `-race` 5× |
| oauth2-monitoring | F5 — backslash redirect | #24 | ✅ verified |
| oauth2-monitoring | X-3/F7 — logout revoke + CSRF | #24 | ✅ verified |
| oauth2-monitoring | pgx SQLi | #25 | ✅ verified |
| oauth2-monitoring | X-2 — rate limiting | #26 | ✅ verified |
| oauth2-monitoring | CI (previously none) | #26 | ✅ verified, both jobs run |
| oauth2-monitoring | BFF migration onto `backendkit/bff` (incl. Postgres store) | #27 | ✅ verified, no regressions (new findings, §2.4) |
| oauth2-monitoring | pin to real `v1.10.0` tag | #28 | ✅ verified |

**28 items closed. Zero regressions found across two independent BFF
architecture migrations** — the highest-risk change in the whole round.

---

## 2. Pass-2 findings — new remediation items

### 2.1 go-oauth2

| ID | Severity | Item | Effort |
|---|---|---|---|
| P2-1 | Medium | M1 sweep missed `internal/web/handler.go` (Signup/AcceptInvite server-rendered forms leak raw `err.Error()` to unauthenticated browsers) | S |
| P2-2 | Low | `app_users_handler.go` still leaks `err.Error()` at ~10 call sites (now behind H1's admin gate, lower severity than pass-1's framing) | S |
| P2-3 | Medium | Failed-login attribution (`GetClientIP`, never resolves XFF) vs. block enforcement (`GetClientIPSafe`, resolves XFF from trusted proxies) collapses all users behind a trusted reverse proxy into one auto-defense bucket — dilutes lockout / risks a shared-IP block. Switch `auth_handler.go`/`admin_auth_handler.go`/`bootstrap.go`'s audit-log sinks to `GetClientIPSafe(r, trustedCIDRs)` | S |
| P2-4 | Low | `GetClientIP`'s doc comment is factually wrong ("always trusts proxy headers") — fix the comment; this is what caused P2-3 to initially be mis-rated High | S |
| P2-5 | Medium | `handleClientCredentialsGrant` skips `validateScope` and `requireDPoP`, unlike the other two grant types. Not reachable via this server's own `/api/admin` routes today, but unrestricted for any external resource server trusting this issuer's client-credentials tokens | S |

### 2.2 backendkit — `bff` package (new shared infrastructure, first review)

| ID | Severity | Item | Effort |
|---|---|---|---|
| P2-6 | **High** | Empty CSRF token silently disables CSRF protection (`MatchCSRF("", "")` → `true` via `ConstantTimeCompare` on two empty slices) — reproduced. Fix: reject empty `want` in `MatchCSRF` | S |
| P2-7 | Medium/High | `Gateway.AuthEnabled`'s zero value (`false`) is a fully-open pass-through, contradicting the package's documented "fail-closed by default." Not triggered by current consumers (both set the field explicitly) but a footgun for the next one. Fix: `NewGateway(...)` constructor defaulting `AuthEnabled: true`, or invert to `DisableAuth bool` | S |
| P2-8 | Medium | Concurrent `EnsureFresh` calls near token expiry race a single-use rotating refresh token; the losing request's session gets deleted (reproduced: 7/8 concurrent requests 401'd + session deleted in one of 50 trials). Fix: wrap the refresh call in `singleflight` keyed by session ID, mirroring the `jwtauth` H-1 fix already in this module | M |
| P2-9 | Low | `AllowPassthrough` + unset `AuthEnabled` compounds P2-7 — tighten the API (constructor/flag inversion in P2-7 substantially addresses this too) | — |
| P2-10 | Low | Query-string values (not path segments) in `socrate/monitoring.go` (`StreamSecurityEvents`'s `Severity`/`EventType`/`LastEventID`, `GetGeoAnalytics`/`GetTokenStats`'s `period`) aren't `url.QueryEscape`d — same bug class as the M-1 fix, missed because it's a query string not a path segment | S |

See pass-2 §4 for suggested fix code for P2-6/P2-7/P2-8.

### 2.3 oauth2-admin

| ID | Severity | Item | Effort |
|---|---|---|---|
| P2-11 | Medium | `elevate.go`'s expiry-absorption is fail-open on a malformed/already-past `exp` claim — silently *extends* the session's access-token validity window instead of reverting to non-elevated. No test covers this input. Fix: on unparseable/past `exp`, set `accessExpiry` to `now` or reject the elevate call | S |
| P2-12 | Low | CSRF header name hardcoded in `elevate.go` instead of reading the Gateway's configured header (landmine if `Gateway.CSRFHeader` is ever overridden) | S |
| P2-13 | Info | Phase 1 (`BFF_CLIENT_ID` unset) is a fully open bearer pass-through with no CSRF — intentional/documented, but worth a startup assertion so a misconfiguration can't silently select it in production | S |

### 2.4 oauth2-monitoring

| ID | Severity | Item | Effort |
|---|---|---|---|
| P2-14 | Low | `PostgresSessionStore.Get` silently swallows transient DB errors (no logging) — indistinguishable from ordinary session expiry in logs, slows incident diagnosis | S |
| P2-15 | Low | `PostgresSessionStore.Put` silently drops a `json.Marshal` failure (no logging) — same gap, low likelihood | S |
| P2-16 | Low | `handleElevate`'s `EnsureFresh`-failure path deletes the session but doesn't clear the cookie (inconsistent with `ProxyWithSession`'s equivalent path; not a vulnerability) | S |

### 2.5 Cross-cutting (both consoles, not a regression)

Roles are frozen in `Session.User()` at login and never refreshed on token
refresh (`SetTokens`/`applyTokens` never touch `user`). Confirmed pre-existing
in both consoles (diffed against pre-migration code), not introduced by the
`backendkit/bff` migration. If a user is de-privileged upstream mid-session,
the BFF's cached role list (surfaced via `/bff/session`, used for SPA-side UI
gating) stays stale until re-login. Bounded risk assuming the admin API
independently validates roles from each fresh bearer token rather than
trusting anything the BFF asserts — worth a one-line confirmation from
whoever owns that service, and a backlog item to have `Gateway.EnsureFresh`
optionally re-derive `UserInfo` on refresh if that assumption doesn't hold.

---

## 3. Production GO checklist (revised)

**go-oauth2**
- [x] H1, M1 (JSON API), M2, L1, L2, L3 (documented gap), L4, pgx CVE
- [ ] P2-1 web-handler error sweep
- [ ] P2-3/P2-4 IP-attribution consistency + stale comment
- [ ] P2-5 client_credentials scope/DPoP enforcement
- [ ] P2-2 app_users_handler cleanup (P2)

**backendkit**
- [x] H-1, M-1 (path segments), M-2, Session.Snapshot, `v1.10.0` tag
- [ ] **P2-6 empty-CSRF bypass (recommend before next release)**
- [ ] **P2-7 Gateway fail-open zero value (recommend before next release)**
- [ ] **P2-8 concurrent-refresh session-kill race (recommend before next release)**
- [ ] P2-10 query-string escaping (P2)

**oauth2-admin**
- [x] X-1, X-3, C-1 (verified with a real build), H-1/M-4, H-2, X-2, migration, e2e test, tag pin
- [ ] P2-11 elevate expiry fail-open
- [ ] P2-12 CSRF header hardcode (P2)
- [ ] P2-13 Phase-1 startup assertion (P2)

**oauth2-monitoring**
- [x] F1/X-1, F2, F5, X-3/F7, pgx CVE, X-2, CI, migration (incl. Postgres store), tag pin
- [ ] P2-14/P2-15 silent-error logging (P2)
- [ ] P2-16 elevate cookie-clear consistency (P2)

**Suite-wide**
- [x] No open PRs from the audit/remediation round remain unmerged
- [x] Two claims independently investigated and refuted rather than
      accepted at face value (IP-spoofing severity, backendkit tag integrity)
- [ ] Decide on P2-6/P2-7/P2-8 fix-and-release timing for `backendkit`
      (both consoles would need a follow-up dependency bump once released)
- [ ] Cross-cutting roles-frozen-on-refresh: confirm admin API doesn't trust
      BFF-asserted roles (§2.5)

---

## 4. Suggested sequencing

1. **`backendkit` P2-6/P2-7/P2-8** first — shared infrastructure, cheap fixes
   (see pass-2 §4 for sketched code), and every day they're open is a day two
   production consoles depend on them.
2. **go-oauth2 P2-1/P2-3** next — both are real (if not currently critical)
   gaps in controls the original audit specifically targeted (error hygiene,
   brute-force defense).
3. Everything else (P2-2, P2-4, P2-5, P2-9 through P2-16) is Low/Info and can
   be batched into routine hardening work — none are release-blockers.

**Assessment:** the suite went into this round with one exploitable bug and a
systemic architectural gap (the fail-open BFF pattern); it comes out with
neither, plus independently-reproduced confidence that the remediation itself
didn't introduce new ones — except in the one place that hadn't been reviewed
yet (the new shared package), which is exactly what a second pass is for.
