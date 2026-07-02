# Socrate Suite — Remediation Plan & Production GO Checklist

**Date:** 2026-07-02
**Companion to:** `docs/CR-socrate-suite-security-pass1.md` (the audit).
**Goal:** a single, sequenced path from the current state to an overall **GO for
production** across the four repositories.

This plan reflects work already landed in this remediation round (branch
`claude/socrate-suite-audit-3wqcnp` in each repo) and the concrete steps that
remain. Each item lists severity, owner repo, effort, and its gate status.

---

## 1. What landed in this round (done)

| ID | Repo | Fix | Commit |
|---|---|---|---|
| **H1** | go-oauth2 | App-scoped `/api/apps/{id}/users` now gated by `RequireAppAdmin` (was any-member `RequireAppAccess`); regression tests added. | `aa6e205` |
| **X-1 / M-1** | oauth2-admin (bff) | Proxy is **fail-closed**: no valid session ⇒ 401, no pass-through; inbound `Authorization` stripped. Legacy pass-through gated behind `BFF_ALLOW_PASSTHROUGH` (default false). | `1d8e7de` |
| **X-3** | oauth2-admin (bff) | Logout best-effort revokes refresh + access tokens at the issuer before clearing local state. | `1d8e7de` |
| **F1 / X-1** | oauth2-monitoring (bff) | Same fail-closed proxy + `BFF_ALLOW_PASSTHROUGH` flag + inbound-auth stripping. | `acc15e0` |
| **F2** | oauth2-monitoring (bff) | Per-session mutex closes the data race on the shared `*Session` pointer; `-race` test added. | `acc15e0` |
| **F5** | oauth2-monitoring (bff) | `sanitizeReturnTo` rejects backslash + control-char open-redirect vectors. | `acc15e0` |
| **X-3 / F7** | oauth2-monitoring (bff) | Logout revokes tokens upstream **and** enforces CSRF. | `acc15e0` |
| **X-4 (foundation)** | backendkit | New shared, tested `bff` package (fail-closed `Gateway.ProxyWithSession`, race-safe `Session`/store, `SanitizeReturnTo`, PKCE/CSRF/`__Host-` helpers) consuming the `socrate` client — the consolidation target for both consoles. | `feat(bff)` |

All four repos build, vet, and pass `go test -race` (Go) / existing suites after these changes.

**Net effect on GO:** the single exploitable server bug (H1) and the systemic
fail-open BFF pattern (the two highest suite-wide risks) are closed. The
remaining work below is required for a *clean* GO but is lower-risk and largely
mechanical.

---

## 2. Remaining work to reach GO

### P0 — production blockers (must fix before any deploy)

| ID | Repo | Item | Effort | Status |
|---|---|---|---|---|
| **C-1** | oauth2-admin | Vite `base: '/admin/'` vs Caddy root mount ⇒ built SPA loads blank in prod. Set `base: '/'` (or serve under `/admin/` consistently in Caddy) and verify the built `index.html` asset paths resolve. | S | **TODO** |
| **bk-H-1** | backendkit | Unauthenticated JWKS-refetch DoS: a token with an unknown `kid` forces one synchronous outbound fetch per request. Add `golang.org/x/sync/singleflight` + a minimum-refetch cooldown + negative-cache of unknown kids. | M | **TODO** |
| **bk-M-1** | backendkit | Complete the F-7 path-escaping fix: apply `url.PathEscape` to the ~17 remaining `socrate` methods in `admin.go`/`monitoring.go`/`alerts.go`/`reports.go`; correct the false "Fixed" claim in `SECURITY-AUDIT.md`/CHANGELOG. | M | **TODO** |

### P1 — required before "security reviewed / production ready" claims hold

| ID | Repo | Item | Effort | Status |
|---|---|---|---|---|
| **H-1 (deploy)** | oauth2-admin | Caddy is missing `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`. Add them; reconcile prod CSP (`default-src`) with the tested `src/security/csp.ts` module (M-4). | S | **TODO** |
| **H-2 (CI)** | oauth2-admin | CI never runs the BFF Go tests. Add a `cd bff && go test -race ./...` job. | S | **TODO** |
| **bk-M-2** | backendkit | Set `jwt.WithExpirationRequired()` (+ small `jwt.WithLeeway`) so a token minted without `exp` cannot validate forever. | S | **TODO** |
| **X-2** | go-oauth2 / both BFFs | Add per-IP / per-session rate limiting to `/bff/login` and `/bff/elevate` (server already rate-limits its own login/token endpoints; the BFF hop is currently unthrottled). Fix backendkit `httpware` per-tenant limiter no-op for the no-tenant default. | M | **TODO** |
| **bk-tests** | backendkit | Add the missing negative JWT tests (expired, `alg=none`, HS256-with-RSA-key, wrong issuer, unknown/missing `kid`, key rollover); raise `socrate` client coverage (currently 26%). | M | **TODO** |
| **H-3 (e2e)** | oauth2-admin | Playwright suite tests a dead browser-PKCE architecture. Rewrite against the BFF cookie flow (or retire and replace with BFF integration tests). | M | **TODO** |

### P2 — hardening, hygiene, and debt

| ID | Repo | Item | Effort |
|---|---|---|---|
| M1 / M2 | go-oauth2 | Static client-facing error strings + `errors.Is` in `auth_handler.go` (stop leaking wrapped/GORM internals; fix mis-classified locked/role/app errors). | S |
| L1–L4 | go-oauth2 | Dummy-bcrypt on login not-found (timing); audience-bind introspection; client-owns-token check on revoke; require `https://` issuer in prod config. | M |
| F6 | oauth2-monitoring | Remove committed `.env.production` hardcoded host `golfperformance.fr` + now-dead VITE vars; add to `.gitignore`. | S |
| F8 | oauth2-monitoring | SPA Dockerfile: drop dead pre-BFF ARGs, run nginx as non-root, digest-pin bases. | S |
| F9 | oauth2-monitoring | SSE reconnection: add jitter, recover after network restoration (don't give up permanently), add heartbeat watchdog. | M |
| F11 | oauth2-monitoring | Implement the CSP report endpoint or drop the `report-uri`; plan Trusted-Types enforcement flip. | M |
| bk-M3..M6, L* | backendkit | aigateway model/allowlist enforcement (M-5); bounded JWKS staleness (M-6); `resolvedAppID` race (M-4); `X-Request-ID` sanitisation (L-7); `Flusher`/`Hijacker` pass-through in logger (L-5); et al. | M |
| **X-5** | all | Delete or date-stamp the stale/overstated self-audit docs (`oauth2-monitoring/AUDIT.md` et al., `oauth2-admin/SECURITY.md`, backendkit F-7 ledger) so they stop misrepresenting the code. | S |

### Consolidation follow-through (the approved BFF refactor)

The shared `backendkit/bff` package now exists and is tested. To realise the
dedup and make X-1/F2/F5-class bugs fix-once:

1. **Tag a backendkit release** (e.g. `v1.10.0`) that includes the `bff` package
   (and ideally the P0/P1 backendkit fixes above).
2. **oauth2-admin/bff** and **oauth2-monitoring/bff**: replace the hand-rolled
   session store, cookie/CSRF, PKCE, `sanitizeReturnTo`, and proxy code with
   `bff.Gateway` + `bff.MemoryStore`; keep only app-specific wiring (routes,
   config, the SSE/elevate/issuer-proxy specifics). Both already consume, or
   should switch to, the existing `socrate` client for `ExchangeCode` /
   `RefreshToken` / `RevokeToken` instead of duplicating those calls.
3. Add a Postgres `SessionStore` implementation behind the `bff.SessionStore`
   interface (monitoring already has one to port) as a separate adapter so
   in-memory consumers don't pull a DB driver.
4. Delete the duplicated code once both consoles are green on the shared package.

This is **debt reduction, not a GO blocker** — the in-place fixes above already
make the deployed BFFs safe. Sequence it right after P0/P1 so the security
fixes don't have to be maintained in two places for long.

---

## 3. Production GO checklist

A repo is **GO** when every box below is checked. The suite is GO when all four are.

**go-oauth2 (identity server)**
- [x] H1 access-control fix merged + tested
- [ ] M1/M2 error-handling (no raw internal errors to clients)
- [ ] L4 prod config requires `https://` issuer
- [ ] `go test -race ./...`, `go vet`, govulncheck green in CI (already wired)
- [ ] Coverage gate holds; Tier-A floor reviewed

**backendkit (library)**
- [ ] bk-H-1 JWKS refetch hardened (singleflight + cooldown + negative cache)
- [ ] bk-M-1 path-escaping completed across all `socrate` methods; docs corrected
- [ ] bk-M-2 `WithExpirationRequired` + leeway set
- [ ] Negative JWT tests added; `socrate` coverage raised
- [ ] Tag release including the `bff` package

**oauth2-admin (portal)**
- [x] BFF fail-closed + logout revocation merged
- [ ] C-1 base-path fixed; SPA verified to load under Caddy in a staging deploy
- [ ] Caddy security headers complete; CSP reconciled with the module
- [ ] BFF Go tests run in CI
- [ ] e2e suite rewritten against the BFF flow (or replaced)
- [ ] `SECURITY.md` rewritten to match the BFF architecture

**oauth2-monitoring (SOC dashboard)**
- [x] BFF fail-closed + session race + backslash redirect + logout revoke/CSRF merged
- [ ] F6 committed prod host/env removed
- [ ] F8 SPA container hardened (non-root, digest-pinned)
- [ ] F9 SSE reconnection hardened
- [ ] Stale audit docs retired

**Suite-wide**
- [ ] X-2 BFF rate limiting in place (login + elevate)
- [ ] All four repos: dependency scan (govulncheck / `npm audit`) clean at release
- [ ] Consolidation onto `backendkit/bff` completed (post-GO acceptable, but track it)
- [ ] X-5 stale/overstated audit docs pruned suite-wide

---

## 4. Suggested sequencing

1. **Now → GO-critical:** finish P0 (C-1, bk-H-1, bk-M-1). These are the last
   items that are either exploitable or ship-broken.
2. **GO-gate:** P1 (deploy headers, BFF-tests-in-CI, `exp`-required, rate
   limiting, negative JWT tests, e2e rewrite). Flip the GO checklist.
3. **Immediately post-GO:** consolidation follow-through (tag backendkit,
   migrate both BFFs onto `bff.Gateway`, add the Postgres store adapter) so the
   two consoles stop carrying duplicated security-critical code.
4. **Rolling:** P2 hardening + doc cleanup.

**Assessment:** with this round's fixes, the suite has moved from "strong core
with one exploitable bug and a systemic fail-open" to "no known exploitable
break; a short, mostly-mechanical list stands between here and a clean GO." The
critical-path items (C-1, bk-H-1, bk-M-1) are all small-to-medium and
well-understood.
