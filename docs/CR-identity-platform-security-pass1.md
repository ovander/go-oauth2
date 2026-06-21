# Socrate Identity Platform — Principal Identity Security Audit (Pass 1)

**Auditor role:** Principal Identity Security Engineer
**Target:** `github.com/ovandermoten/go-oauth2` ("Socrate") — OAuth 2.0 / OpenID Connect Identity Platform
**Codebase:** 146 Go files, ~33k LOC, Go 1.25, chi router, golang-jwt v5, GORM/PostgreSQL
**Method:** Full-source review of every security-relevant subsystem. Crown-jewel findings verified by hand against source. All findings cite `file:line`.
**Audience:** CTO, CISO, enterprise customers, security auditors, SOC 2 / ISO 27001 assessors, technical due diligence.

> **Bottom line up front.** Socrate is an unusually security-conscious codebase with a documented remediation history (CRIT/HIGH/MED/LOW fixes backed by regression tests), strong OAuth 2.1 flow hygiene, exemplary magic-link and key-rotation engineering, and clean Go. It is undermined by **one disqualifying CRITICAL authorization defect** (any authenticated user can create a platform superadmin), **two HIGH tenant-isolation defects**, and **structural gaps** (no MFA, no KMS/HSM, no CI/CD, no HA, opt-in replay protection, PII/secrets in SQL logs). **In its current state it should not be trusted as the trust anchor for production tenants until the CRITICAL and HIGH findings are remediated.**

---

## Phase 1 — Identity Architecture & Trust Boundaries

### Components (as built)

| Capability | Where | Notes |
|---|---|---|
| Authorization Server | `internal/handler/oauth_handler.go`, `internal/service/oauth_service.go` | Auth-code (+PKCE), refresh, client_credentials. Implicit/hybrid removed. |
| Authentication (IdP) | `internal/service/auth_service.go`, `internal/web/handler.go` | Server-side login + consent pages; password + magic-link. |
| Identity / User Store | `internal/model/user.go`, `gorm_user_repository.go` | Single global `users` table; users are **not** tenant-scoped. |
| Client Registry | `internal/model/app.go`, `app_service.go` | "App" = OAuth client = tenant. Admin-created; no dynamic registration. |
| Token Service | `internal/shared/auth/token.go` | RS256 JWT; access/refresh/id/email/reset/invite/client-creds. |
| JWKS / Keys | `internal/shared/auth/keys.go` | RSA 3072 on local disk; rotation with retired-key ring. |
| Refresh Token Service | `oauth_service.go` (rotation, single-use), `used_tokens` table | JTI single-use + token-version "nuclear" revocation. |
| Consent | `internal/shared/auth/consent_token.go` | HMAC-signed consent token + CSRF double-submit. |
| Admin APIs | `internal/handler/admin_handler.go`, `monitoring_handler.go`, `admin_logs_handler.go` | App/user/superadmin mgmt, monitoring, audit. |
| Service Accounts / M2M | `internal/middleware/service_account.go` | `client_credentials`, `sub=app:{id}`, URL cross-check. |
| Password Flows | `auth_service.go`, `internal/shared/auth/password.go` | bcrypt; reset/verify/invite JWTs. |
| Federation / External IdP | — | **ABSENT.** No SAML, social login, or upstream OIDC brokering. |

### Trust boundaries
1. **Public OAuth/OIDC port** (`newOAuthRouter`) — anonymous + bearer-token clients.
2. **Admin port / `/manage` mount** (`newAdminRouter`, `router.go:571`) — *intended* for platform admins; **enforced only by network placement, not by application authorization** (see CRIT‑01).
3. **Service-account boundary** — token `sub=app:{id}` cross-checked against URL `{app_id}` (`service_account.go:60-69`). **Correctly enforced.**
4. **Signing-key boundary** — private RSA key as plaintext PEM on local filesystem (`0400`), no KMS/HSM. Anyone with file read = token forgery for any tenant.
5. **Database boundary** — full PII/secret exposure via Info-level SQL logging (HIGH‑06).

---

## Phase 2 — OAuth 2.0 Compliance

| RFC | Status | Evidence |
|---|---|---|
| **6749** Core | **Supported** | Auth-code/refresh/client_credentials (`oauth_service.go:236-246`); confidential-client auth enforced (`:302-309`); exact redirect match (`redirect.go:53-66`); `state` mandatory (`oauth_handler.go:124-127`). Implicit removed. |
| **6750** Bearer | **Supported** | `Bearer` type (`oauth_service.go:353`); `invalid_token` 401 on userinfo (`oauth_handler.go:578`). |
| **6819** Threat BCP | **Partial** | Single-use codes, code→client & code→redirect binding, exact redirect match present. Gaps: no resource/audience binding enforced at RS; mix-up `iss` not returned. |
| **7636** PKCE | **Supported (S256 only)** | `plain` rejected (`pkce.go:43-48`); per-client `RequirePKCE` (`oauth_service.go:197,276`). **Not globally mandatory** (MED‑01). |
| **7009** Revocation | **Partial** | JTI blacklist + always-200 (`oauth_handler.go:673-728`). **Does not verify token belongs to the authenticating client** (HIGH‑07). |
| **7662** Introspection | **Supported** | Client auth required (`oauth_handler.go:637-652`); checks JTI blacklist + token_version. Response omits `aud`/`iss`/`nbf`. |
| **8252** Native Apps | **Partial** | Loopback allowed over HTTP (`redirect.go:80-83`); no explicit custom-scheme support; native PKCE not forced beyond per-client flag. |
| **8707** Resource Indicators | **Unsupported** | No `resource` param parsed. `aud = client_id` only (`token.go:176`). |
| **8693** Token Exchange | **Unsupported** | No `token-exchange` grant. |
| **OAuth 2.1 draft** | **Mostly aligned** | Implicit removed, exact redirect match, refresh single-use. **Deviation:** PKCE opt-in, not mandatory for public clients (`IsPublic` unused in flow). |

**Not implemented:** RFC 9126 PAR, RFC 8705 mTLS, RFC 9449 DPoP, RFC 9101 JAR, RFC 7591/7592 dynamic registration, RFC 8628 device flow. These are required for FAPI / financial-grade and enterprise federation.

---

## Phase 3 — OpenID Connect

- **Discovery** (`oauth_service.go:704-729`): issuer, all endpoints, `response_types=["code"]`, `code_challenge_methods=["S256"]`, `id_token_signing_alg=["RS256"]`, `subject_types=["public"]`, claims. **Missing:** `end_session_endpoint`, `acr_values_supported`, `response_modes_supported`, `claims_parameter_supported`.
- **Issuer/Audience/Nonce/State:** `iss` on all tokens; `aud=[client_id]`; `nonce` propagated authorize→code→id_token (`token.go:245`), correctly omitted on refresh; `state` mandatory.
- **Flows:** authorization code only; implicit/hybrid removed (`oauth_service.go:757`).
- **UserInfo** (`oauth_service.go:676-701`): returns sub/email/email_verified/name/preferred_username/role/app_roles — **not scope-gated** (LOW‑08).
- **ID Token** (`token.go:227-247`): standard claims + `at_hash`, `auth_time`, app-scoped `role`/`app_roles`. `max_age` honored via `LastLogin`.
- **Not implemented:** `prompt`, `acr`/`amr`, `claims`/`request`/`request_uri`, **session management, front-channel & back-channel logout** (only RP-initiated `/oauth/logout` with `post_logout_redirect_uri` validation).

---

## Phase 4 — JWT Audit

- **Algorithm:** RS256 only (`token.go:358`). **Alg-confusion & `none` blocked** by method type-assertion `*jwt.SigningMethodRSA` (`token.go:371-373`) — RS↔HS confusion and `alg:none` both rejected. *Gap:* family-wide (RS256/384/512) rather than exactly RS256; no `WithValidMethods` (LOW‑03).
- **kid:** random UUID, rotation-aware via retired ring (`token.go:374-381`). *Gap:* unknown/empty `kid` **falls back to current key** instead of rejecting (`token.go:376-380`) — not a forgery bypass (still needs private key) but defeats strict kid pinning (MED‑04).
- **Claim validation:** `exp`/`nbf` validated by golang-jwt v5 defaults; **`iss` and `aud` are never verified at the crypto layer** — no `WithIssuer`/`WithAudience` (MED‑03). Per-token-type `type` claim checked (`token.go:415-473`) — strong defense against cross-type misuse.
- **Replay:** `jti` + `used_tokens` unique index + `INSERT … ON CONFLICT DO NOTHING` (atomic, TOCTOU-safe; `gorm_used_token_repository.go:40-52`). **But the `usedTokenRepo` is nilable** (`auth_service.go:71`) — replay/single-use for reset/verify/invite/refresh silently no-ops if not wired (HIGH‑05).
- **Revocation:** per-JTI blacklist + `token_version` nuclear revocation (checked in `auth.go:63`, introspect, refresh). client_credentials tokens carry no version → not version-revocable (LOW‑07).
- **Misc:** no clock-skew leeway (LOW‑04); `exp` not required for future token types (LOW‑05); no token size cap; retired keys/JWKS grow unbounded (LOW‑06).

---

## Phase 5 — Authentication

- **Passwords:** bcrypt; **cost 10 for users** vs 12 for client secrets (MED‑12); strength rules (12–72 chars, classes) with an 8-entry common-password list (LOW‑11); no pepper (LOW‑10); constant-time compare. 72-byte cap respects bcrypt truncation.
- **MFA / TOTP / WebAuthn / Passkeys:** **ABSENT entirely** — hardcoded stub `MFAEnabled: false` (`settings_handler.go:46`). **Superadmin login is single-factor** (HIGH‑04).
- **Recovery:** reset (1h) & verify (24h) are signed JWTs, single-use **only if `usedTokenRepo` wired** (HIGH‑05); reset revokes all sessions via token-version bump; enumeration-safe messaging.
- **Magic link (exemplary):** 256-bit `crypto/rand`, hash-only storage, atomic single-use, 15-min TTL, POST-only verify, per-address rate limit, app binding (`magic_link_service.go`).
- **Anti-abuse:** per-account lockout (`MaxFailedAttempts`), per-IP sliding-window rate limits, escalating auto-defense IP blocking (DB-persisted), IP-block middleware **fails closed** on DB outage (`ip_blocking.go:185-193`). *Gaps:* rate limiting is **per-IP, in-memory, single-node** — no per-account/global limit, not shared across instances (MED‑06); auto-defense not wired to admin-login/magic-link/reset (LOW‑12).
- **Enumeration:** login **timing** side-channel (bcrypt runs only when email exists; no dummy-hash) + signup "email already exists" + distinct verified/locked 403s (MED‑05, LOW‑14).
- **Sessions:** stateless JWT (no session fixation surface); tokens returned in JSON body; no device trust / remember-me.

---

## Phase 6 — Client Security

- Public vs confidential modeled correctly; **PKCE force-enabled for public clients at creation** (`app_service.go:114`) but **not enforced in the token/authorize flow** (`IsPublic` unused there) → downgrade surface for misconfigured clients (MED‑01).
- **Client secrets:** bcrypt cost 12, returned once, `json:"-"` (`app.go:12`).
- **Redirect URIs:** per-client exact match, no wildcards (`app.go:45-53`, `redirect.go`).
- **Registration:** admin-only — but `CreateApp` lacks an admin check (CRIT‑01 family): **any authenticated user can register clients and receive secrets** (HIGH within CRIT‑01).
- **Secret rotation:** supported with ownership check + audit + email.

---

## Phase 7 — Tenant Security

- **Model:** tenant = App (OAuth client). **No org/organization layer.** Users are global; membership via `user_app_roles`.
- **Isolation:** per-app role queries consistently scoped by `app_id`; **service-account isolation is robust** (token↔URL app cross-check). **User repository is tenant-blind** (`gorm_user_repository.go`), the root cause of the IDORs below.
- **Cross-tenant defects (verified):**
  - **HIGH‑02 — Cross-tenant IDOR:** `ResendVerification` (`app_users_handler.go:376`) and `ForcePasswordReset` (`:439`) resolve the target by **global `user_id` with no `GetUserRoleForApp` membership check** — any member of any one app can trigger reset/verification emails to **any user in the platform**, with attacker-chosen branding.
  - **HIGH‑01 — Intra-tenant privilege escalation:** app-user write routes are gated by `RequireAppAccess` (any role incl. `viewer`); only `/logs` uses `RequireAppAdmin` (`router.go:487-503`). A viewer can add users, change any member's role to `admin`, and remove users.
- **No tenant spoofing via claims** — app membership is DB-derived, not claim-derived (strength).

---

## Phase 8 — Authorization Model

- **Two dimensions:** global `User.Role` (`user`/`admin`/`superadmin`) and per-app role (`admin`/`manager`/`editor`/`viewer`/`user`).
- **No permission/scope engine** — only role *names*. **`manager`/`editor`/`viewer` are defined but never enforced anywhere** — they collapse to "has any role" (MED‑15). False impression of least privilege.
- **CRITICAL — Broken function-level authorization (CRIT‑01, verified):** the `/api/admin` group applies only `AuthMiddleware` (`router.go:358-359`), which authenticates but **enforces no role** (`auth.go:16-83`). Many handlers do not self-check `IsGlobalAdmin`:
  - `CreateSuperadmin` (`admin_handler.go:791`), `UpdateSuperadmin` (`:841`), `DeleteSuperadmin` (`:899`), `ListSuperadmins` (`:717`), `GetSuperadmin` (`:752`) — **no admin check**; `userService.CreateSuperadmin(ctx, req)` takes no caller identity, so no service-layer guard either.
  - `ListApps` (`:46`), `CreateApp` (`:104`) — no admin check.
  - All monitoring/security endpoints (`monitoring_handler.go`) and audit-log endpoints (`admin_logs_handler.go`) — no role check.
  - **Impact:** Any registered `role=user` with a normal access token can `POST /manage/api/admin/superadmins` → **mint a superadmin → full platform takeover.** In single-port mode this is reachable on the public port; in dual-port mode it is reachable by anyone who can route to the admin port with any valid user token (no app-level authZ).
  - *Note:* mutating **user** endpoints (`DeleteUser`/`BlockUser`/`UnlockUser`/`RevokeUserTokens`) **do** self-check `IsGlobalAdmin` — the inconsistency confirms the superadmin/app/monitoring gaps are omissions, not design.
- **Mass-assignment (latent):** `CreateUserRequest.Role` is honored by `userService.Create`; not exploited in the audited app-user path (server constructs DTO) but a hazard for any other binder (MED‑11).

---

## Phase 9 — Token Lifecycle

- **Access tokens:** stateless, short TTL (default 900s), version-revocable.
- **Refresh tokens:** single-use rotation with concurrent-replay detection (`oauth_service.go:377-393`), version-checked.
- **Revocation:** per-JTI + nuclear token-version. **HIGH‑07:** client-cred `/revoke` path blacklists any presented JTI **without verifying the token's `aud` matches the authenticating client** → a confidential client can force-logout/deny another client's tokens.
- **Logout:** increments token-version (invalidates refresh tokens). No back/front-channel logout.
- **Concurrent/device sessions:** no per-device session registry; no "list/revoke my sessions" for end users (admin has session views).

---

## Phase 10 — Cryptography

- **Primitives:** RSA-3072 (prod) / 2048 (test); `crypto/rand` for keygen, JTIs, magic links, CSRF; correct OIDC `at_hash`. No `math/rand` anywhere.
- **Key storage:** private PEM `0400`, dir `0700`, auto-tightened on load, absolute `KEYS_PATH` enforced in prod. **No KMS/HSM/PKCS#11, no envelope encryption** (HIGH‑03) — the dominant cryptographic risk for a multi-tenant IdP.
- **Rotation:** implemented + tested with retired-key ring; **`StartRotationSchedule` is never called from `bootstrap.go`** → automatic rotation is effectively dead code, and **rotation emits no audit event** (LOW‑18).
- **Algorithm agility:** RSA-only; no ECDSA/EdDSA.
- **Constant-time comparison:** used for client-secret check; verify HMAC compares in csrf/consent are constant-time (spot-confirmed in OAuth review).

---

## Phase 11 — Administration

- **Surface:** broad admin API (apps, users, superadmins, monitoring, audit, settings, alerts, reports).
- **Bootstrap:** `cmd/seed/main.go` creates a superadmin with `MustChangePassword`, **prints a generated password to stdout/logs** (LOW‑16), runs `AutoMigrate` unconditionally (LOW‑17). This seed tool is the de-facto **break-glass** (requires shell + DB); no in-product break-glass or last-superadmin protection.
- **Admin login** correctly restricted to superadmins with lockout + auto-defense — but **the rest of the admin API is not** (CRIT‑01).
- **Config:** env-based; **secure-by-default** (`ENV` defaults to production; `Validate()` hard-fails on weak `SECRET_KEY_BASE`, default DB/issuer, relative `KEYS_PATH`). `.env.example` still advertises the **ignored** `JWT_SECRET` (LOW‑15).
- **Backups / DR / key escrow:** **ABSENT.**

---

## Phase 12 — Logging & Audit

- **Three stores:** `admin_logs`, `security_audit_logs`, `app_activity_logs` — good event taxonomy (failed logins, lockouts, reset, revocation, secret rotation, brute-force, PKCE fail).
- **HIGH‑06 — Secret/PII leak via SQL logging:** GORM logger runs at `glogger.Info` unconditionally (`postgres.go:42`) → every SQL statement with bound parameters (emails, password hashes, reset/refresh tokens, IPs) written to stdout/journald regardless of `ENV`.
- **Audit integrity:** **none** — rows are ordinary mutable/deletable GORM records; no append-only, hash-chaining, WORM, or signing (MED‑09). `DeleteOlderThan` exists.
- **Retention/GDPR:** `CleanupOldLogs` exists but **is never scheduled** → IP/email logs accumulate indefinitely; no erasure path (MED‑14).
- **Correlation IDs:** middleware generates/echoes `X-Correlation-ID` but it is **not propagated into log lines or audit rows** (LOW‑25) — traceability gap.
- **Key rotation:** not audit-logged.

---

## Phase 13 — API Security

- **Security headers:** comprehensive — CSP, HSTS, `X-Frame-Options: DENY`, `nosniff`, Referrer/Permissions policy (`security.go:23-52`). Only soft spots: `style-src 'unsafe-inline'`, deprecated `X-XSS-Protection` (LOW‑22).
- **CORS:** wildcard+credentials footgun **correctly closed** and well-tested (`router.go:28-48`). Admin router shares the same allowlist (LOW‑24); SSE stream sets `ACAO:*` bypassing it (MED‑13).
- **Rate limiting:** memory-bounded LRU sliding window; spoofing-resistant `GetClientIPSafe`. **HIGH‑08:** chi `RealIP` is installed globally and rewrites `RemoteAddr` from untrusted `X-Forwarded-For` **before** the limiter runs → rate-limit & IP-ban bypass when directly internet-exposed.
- **Input:** `MaxHeaderBytes` 16KB, sensible server timeouts. **MED‑08:** no `MaxBytesReader` on JSON handlers (login/signup/admin) → unbounded-body DoS. No `DisallowUnknownFields` (MED‑11). **MED‑10:** ~40 sites return raw `err.Error()` to clients (internal/DB/SMTP detail leak).
- **SQL injection:** **none found** — parameterized GORM throughout, static DDL, no `fmt.Sprintf` SQL, no user-controlled `ORDER BY`.
- **Open-redirect surface** in web login form building (`web/handler.go:493-518`) — relies on downstream authorize validation (LOW‑23).

---

## Phase 14 — Go Security

- **No `math/rand`, no `unsafe`, no `reflect`** in application code.
- **Goroutines:** all background workers (`keys.go`, `ratelimit.go`, `ip_blocking.go`, server lifecycle) have clean stop channels / `WaitGroup` and are wired into graceful shutdown — no leaks.
- **Races:** shared maps guarded by `sync.RWMutex`. One **racy but unused** `RequestTimeout` middleware (`timeout.go:25-55`) writes a `ResponseWriter` concurrently — delete or document (LOW‑20).
- **Panic recovery:** chi `Recoverer` on all routers → generic 500, no stack leak.
- **Context propagation:** handlers consistently pass `r.Context()`.

---

## Phase 15 — Operational Readiness

| Area | State |
|---|---|
| CI/CD | **ABSENT** — no `.github/workflows`, no pipeline. Deploy is a manual `make deploy` scp+`systemctl restart` to a hardcoded VPS; no test gate, staging, or rollback. |
| Metrics | **ABSENT** — no Prometheus/OTel. |
| Tracing | **ABSENT** — correlation ID exists but not propagated. |
| Health/readiness/liveness | Present (`/health*`, DB ping). |
| Graceful shutdown | Present and solid (30s, stops workers, closes DB). |
| Backups / DR | **ABSENT.** |
| HA / multi-region | **Not supported** — in-memory rate limiter, IP-block cache, and process-local report store (`monitoring_handler.go:1317`) break horizontal scaling. |
| Key rotation | Implemented but **not wired** into bootstrap. |
| Secret management | Env vars only; no vault/KMS. |

---

## Phase 16 — Threat Model

| Actor | Key capability vs Socrate | Likely attack | Residual risk (current) |
|---|---|---|---|
| **Anonymous** | Hit public endpoints | Credential stuffing, enumeration, rate-limit bypass via XFF (HIGH‑08), unbounded-body DoS (MED‑08) | **Medium** — timing enumeration + IP-key bypass when directly exposed |
| **Registered user** | Holds a valid access token | **CRIT‑01: create superadmin → full takeover**; HIGH‑01 intra-tenant escalation; HIGH‑02 cross-tenant reset-email abuse; list all clients | **Critical** |
| **Compromised user** | Stolen token | Same as above + use until token-version bump | **Critical** (amplified by CRIT‑01) |
| **Tenant admin** | App admin | Manage own app users | Low *if* CRIT‑01/HIGH‑01 fixed; otherwise can escalate platform-wide |
| **Platform admin** | Superadmin | Full control by design | Low — but **no MFA** (HIGH‑04) makes superadmin phishing catastrophic |
| **Service account** | M2M token | Confined to its app (good isolation) | Low |
| **Malicious insider** | DB/host access | Read plaintext signing key → forge any token (HIGH‑03); alter audit logs (MED‑09); read PII from SQL logs (HIGH‑06) | **High** |
| **Compromised application/RS** | Holds client creds | HIGH‑07 cross-client revocation/DoS; no audience pinning at RS | Medium |
| **Compromised database** | Read/write DB | Signing key not in DB (good); but PII, mutable audit, password hashes (bcrypt-10) | Medium-High |
| **Compromised signing key** | Has private PEM | Forge tokens for any tenant/role until rotation+expiry; rotation not auto-scheduled | **High** |
| **Supply chain** | Dependency/CI | No CI, no SBOM, no dependency pinning policy, no image signing | Medium (small dep tree limits surface) |
| **Nation-state** | All of the above + 0-day | Key exfiltration, persistence | High — no HSM, no tamper-evident audit, no anomaly alerting wired |

---

## Phase 17 — Security Invariants (verified)

| Invariant | Holds? | Evidence |
|---|---|---|
| Every token has exactly one issuer | Set yes; **verified no** | `iss` set on all tokens; never validated at verify (MED‑03) |
| Every token has exactly one audience | Set yes; **enforced no** | `aud=[client_id]`; not checked cryptographically nor at RS |
| Every identity belongs to one tenant | **No** | Users are global; tenancy is membership, not ownership |
| Every refresh token can be revoked | **Yes** | JTI single-use + token-version |
| Every client has explicit redirect URIs | **Yes** | Exact-match, no wildcards |
| Every signing key is trusted | **Partial** | Unknown `kid` falls back to current key (MED‑04) |
| Every admin action is authorized | **NO** | CRIT‑01 — superadmin/app/monitoring/audit endpoints unguarded |
| Every admin action is audited | **Partial** | User-mutation audited; key rotation not; audit log mutable |
| PKCE protects every public client | **No** | Opt-in only (MED‑01) |
| Single-use protects every one-time token | **Conditional** | Only if `usedTokenRepo` wired (HIGH‑05) |

---

## Phase 18 — Architecture Review

- **Layering (DTMA):** clean handler → service → repository separation; DTOs distinct from GORM models (limits over-posting).
- **Abstractions:** repository interfaces are good; **provider/federation and storage(KMS) abstractions are absent**, so adding HSM or upstream IdP is a non-trivial refactor.
- **Coupling/HA:** in-memory singletons (rate limiter, IP cache, report store) couple state to a single process — blocks horizontal scale.
- **Versioning / public API / backward-compat:** `internal/version`; no API versioning scheme (`/v1`) on the JSON API; OpenAPI spec absent.
- **Strength:** extensive, finding-named regression tests (`*_crit_*`, `*_high*`, `*_med*`, `*_find*`) demonstrate a mature remediation discipline.

---

## Phase 19 — Identity Maturity Scorecard (0–10)

| Domain | Score | Rationale |
|---|---:|---|
| OAuth 2.0 | 8 | Strong core & 2.1 posture; no resource indicators/token-exchange/PAR; PKCE opt-in |
| OIDC | 6 | Solid discovery/jwks/id_token/nonce; no prompt/acr/amr, session mgmt, logout channels, scope-gated claims |
| JWT | 7 | Excellent alg-confusion/rotation; iss/aud not verified, kid fallback, opt-in replay |
| Cryptography | 5 | Good primitives & rotation; **no KMS/HSM**, plaintext key on disk, RSA-only |
| Authentication | 4 | bcrypt + exemplary magic link + lockout; **no MFA**, timing enumeration, opt-in replay |
| Authorization | 2 | **CRIT‑01 broken function-level authz**, IDOR, no permission engine, unenforced roles |
| Multi-tenancy | 5 | Strong service-account isolation; cross-tenant IDOR, flat model, no org |
| Operations | 2 | No CI/CD, metrics, tracing, backups, DR, HA; manual deploy; rotation unwired |
| Developer Experience | 6 | Clean layering, good docs/tests; inconsistent guard application |
| Security (posture) | 4 | Strong defenses & remediation history undercut by a disqualifying authz hole + key handling |
| Architecture | 6 | Clean DTMA; HA/abstraction gaps |
| **Overall** | **~4.3** | **Promising and security-aware, but not production-trustworthy until CRIT/HIGH are fixed** |

---

## Phase 20 — Final Verdict

> Each answer is grounded in the findings above. "Conditional" = acceptable **only after** remediating CRIT‑01, HIGH‑01, HIGH‑02 at minimum.

| Trusted as… | Verdict | Why (evidence) |
|---|---|---|
| **Startup IdP** | **Conditional** | Good bones; blocked today by CRIT‑01/HIGH‑01/HIGH‑02. After those + raising bcrypt cost and wiring `usedTokenRepo`, acceptable for low-risk B2B SaaS. |
| **Enterprise IdP** | **No** | No MFA (HIGH‑04), no SSO/federation, no audit integrity (MED‑09), no CI/DR/HA, broken admin authZ. |
| **Healthcare IdP** | **No** | HIPAA needs tamper-evident audit, MFA, key custody (HSM/KMS), retention controls — all absent (HIGH‑03, MED‑09, MED‑14). |
| **Financial-services IdP** | **No** | FAPI unmet — no PAR, mTLS, DPoP, JAR, mandatory PKCE, or sender-constrained tokens. |
| **Government IdP** | **No** | Same enterprise gaps + no FIPS-validated key custody, no accreditation evidence. |
| **Zero-trust identity provider** | **No** | Signing key forgeable from disk (HIGH‑03); no sender-constraining (DPoP/mTLS); aud not enforced (MED‑03); broken admin authZ (CRIT‑01). |
| **Multi-region SaaS identity platform** | **No** | In-memory state (rate limiter, IP cache, report store) precludes HA/multi-region; no shared session/rate store. |
| **Replacement for Auth0** | **No** | Missing MFA, federation, dynamic registration, actions/hooks, anomaly detection, SLA/ops tooling. |
| **Replacement for Keycloak** | **No** | No realms/federation, SAML, LDAP/user federation, identity brokering, admin console maturity, or clustering. |

### What additional code/infrastructure would be required (not yet present)
- **Authorization:** group-level `RequireGlobalAdmin` on `/api/admin` (+ superadmin-specific guard on the superadmin subtree); `RequireAppAdmin` on app-user write routes; `GetUserRoleForApp` checks on reset/verification; a real permission/scope policy engine.
- **Key custody:** KMS/HSM or PKCS#11 signer abstraction + envelope encryption + audited, scheduled rotation.
- **MFA:** TOTP and/or WebAuthn with mandatory step-up for superadmins.
- **Audit integrity:** append-only / hash-chained / signed audit store + enforced retention + erasure workflow.
- **Hardening:** verify `usedTokenRepo` always wired; `WithValidMethods`/`WithIssuer`/`WithAudience`/`WithLeeway`; mandatory PKCE for public clients; `MaxBytesReader` + `DisallowUnknownFields`; remove `chimiddleware.RealIP` or gate it; demote GORM logging in prod.
- **Operations:** CI/CD with tests + dependency/SBOM scanning + image signing; metrics/tracing; backups/DR; shared (e.g. Redis) rate-limit/IP/report state for HA.
- **Standards (for enterprise/financial):** PAR, DPoP/mTLS, JAR, dynamic registration, device flow, federation (SAML + upstream OIDC brokering), back/front-channel logout, session management.

---

## Consolidated Findings Register

### CRITICAL
- **CRIT‑01** Broken function-level authorization on `/api/admin` — any authenticated user can create a superadmin (full platform takeover), list/create OAuth clients, and read monitoring/audit. *Verified.* `router.go:358-359`, `auth.go:16-83`, `admin_handler.go:46,104,717,791`; `user_service.CreateSuperadmin` (no caller identity).

### HIGH
- **HIGH‑01** Intra-tenant privilege escalation — `RequireAppAccess` (any role) on app-user writes; viewer can promote/add/remove users. *Verified.* `router.go:487-500`, `app_users_handler.go:276-373`.
- **HIGH‑02** Cross-tenant IDOR — reset/verification emails to arbitrary global users. *Verified.* `app_users_handler.go:376,439`.
- **HIGH‑03** No KMS/HSM — plaintext RSA signing key on disk → token forgery. `keys.go:112-133`.
- **HIGH‑04** No MFA anywhere, incl. superadmin login. `settings_handler.go:46`, `auth_service.go:374`.
- **HIGH‑05** Replay/single-use protection opt-in (`usedTokenRepo` nilable). `auth_service.go:71`.
- **HIGH‑06** PII/secrets in SQL logs (GORM Info level, all envs). `postgres.go:42`.
- **HIGH‑07** Revocation doesn't verify token↔client ownership → cross-client DoS. `oauth_handler.go:707-724`, `oauth_service.go:625-657`.
- **HIGH‑08** chi `RealIP` undermines safe client-IP logic → rate-limit/IP-ban bypass. `router.go:117,323,553`.

### MEDIUM
M‑01 PKCE not mandatory for public clients · M‑03 iss/aud not verified at JWT layer · M‑04 unknown-kid fallback · M‑05 login timing enumeration + signup leak · M‑06 per-IP/in-memory-only rate limiting · M‑07 audit/auto-defense trust XFF unconditionally · M‑08 unbounded JSON bodies · M‑09 no audit-log integrity · M‑10 internal error leakage · M‑11 no `DisallowUnknownFields` / latent role mass-assignment · M‑12 bcrypt cost 10 · M‑13 SSE `ACAO:*` bypasses CORS · M‑14 no enforced log retention (GDPR) · M‑15 app roles unenforced (no least privilege) · M‑02 consent token not request-bound.

### LOW (selected)
redirect trailing-slash leniency · code_challenge_method not validated to S256 · RS-family method allowlist · no clock skew leeway · `exp` not required · unbounded retired-key/JWKS growth · client_credentials not version-revocable · UserInfo not scope-gated · no `iss` in auth response · no password pepper · weak strength dictionary · auto-defense not wired to admin/magic/reset · lockout counter race · verified/locked enumeration · `.env.example` advertises ignored `JWT_SECRET` · seed prints password · seed unconditional AutoMigrate · key rotation not wired/audited · owner-less apps skip ownership check · racy unused `RequestTimeout` · `no-store` not on login/refresh/userinfo · deprecated `X-XSS-Protection` · web-login open-redirect surface · admin shares CORS allowlist · correlation IDs not propagated.

---

## Notable Strengths (credit where due)
Only auth-code flow (implicit/hybrid removed) · exact redirect matching, no wildcards · PKCE S256-only, `plain` rejected · mandatory `state` + robust CSRF (SameSite=Strict double-submit) + explicit consent · single-use codes & refresh rotation with replay detection · constant-time confidential-client secret check · `alg:none`/RS↔HS confusion blocked · key rotation with retired-key ring surviving restarts · private key `0400`, absolute `KEYS_PATH` in prod · `crypto/rand` throughout, no `math/rand`/`unsafe`/`reflect` · **no SQL injection** · clean goroutine lifecycles + graceful shutdown · IP-block fails closed · comprehensive security headers · CORS wildcard+credentials footgun closed · **exemplary magic-link design** · token-version "nuclear" revocation · service-account tenant isolation · secure-by-default config (defaults to production, hard-fails weak secrets) · **strong, finding-named regression test suite** evidencing real remediation discipline.

---

### Recommended remediation order
1. **CRIT‑01** — add `RequireGlobalAdmin` at the `/api/admin` group + superadmin-specific guard. *(Disqualifying; fix first.)*
2. **HIGH‑01 / HIGH‑02** — `RequireAppAdmin` on app-user writes; membership checks on reset/verification.
3. **HIGH‑06** — demote GORM logging / redact params in production.
4. **HIGH‑08, HIGH‑07, HIGH‑05** — fix IP trust, revocation ownership, mandatory `usedTokenRepo`.
5. **HIGH‑03 / HIGH‑04** — KMS/HSM signer + MFA (mandatory for superadmins).
6. MEDIUM hardening batch (PKCE-mandatory, iss/aud verification, body limits, audit integrity, retention).
7. Operational readiness (CI/CD, metrics, backups/DR, HA state store).

*End of Pass 1. A Pass 2 should re-test CRIT/HIGH remediations and extend to dynamic/DAST testing, dependency/SBOM analysis, and infrastructure review (TLS termination, secret storage, container hardening) — none of which are in this static source audit's scope.*
