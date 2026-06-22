# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases follow the platform program defined in `docs/program/RELEASE-ROADMAP.md`
(current line: **v0.x — Foundations & Additive Capabilities**, non-breaking).

## [Unreleased]

### Added
- **Identity / Audience binding:** Access tokens can now carry the client's
  **registered audiences** in `aud` (RFC-001 / EPIC-7), controlled by
  `AUDIENCE_MODE`: `off` (default — `aud` is the `client_id`, unchanged) or
  `dual` (the registered audiences are added **alongside** the `client_id`). Dual
  is the safe warn/observe step: audience-aware resource servers can begin
  verifying their resource identifier while existing `client_id` verifiers keep
  working. Entries are de-duplicated; a client with no registered audiences is
  unchanged. Only the **access token** is affected (ID/refresh tokens keep the
  `client_id`); verification is unaffected (the server never validated `aud`).
  Canonical-only enforcement is a later (Wave 2) step. _Traceability: C7 →
  EPIC-7 → RFC-001 → #113._

### Added
- **Identity / Audience binding:** Clients can now **register audiences** —
  the resource identifiers (e.g. API URIs) their tokens are intended for, the
  canonical `aud` claim per RFC-001 / EPIC-7. New optional `audiences` field on
  app create/update + `AppResponse`, backed by an additive `apps.audiences`
  `text[]` column (migration 0014, default empty). This is **registration
  only** — token issuance and resource-server enforcement are layered in by
  later (warn → enforce) slices, so there is no behaviour change: `aud` still
  carries the `client_id` today. Existing clients are unaffected (empty set).
  _Traceability: C7 → EPIC-7 → RFC-001 → #111._

### Added
- **Identity / Impersonation:** Impersonation **step-up** (RFC 8693 / EPIC-17).
  Because a back-channel token exchange has no interactive user, the control is
  the **freshness of the impersonated subject's session**: an impersonation
  exchange now requires the subject to have authenticated within
  `IMPERSONATION_MAX_AUTH_AGE` (default **900s**), enforced via
  `IMPERSONATION_STEPUP_MODE` — `off` (default, no check), `observe` (audit a
  would-be denial but still issue), or `enforce` (deny with `invalid_grant`). A
  subject token without `auth_time` can't prove freshness and is treated as
  stale (secure default). Delegation is unaffected, and every decision is
  audited (`stepup`, `subject_auth_age_seconds`). The `amr`-based step-up for the
  human-in-the-loop delegation case is a documented future layer. _Traceability:
  C17 → EPIC-17 → RFC-016 → #109._

### Added
- **Identity / Tokens:** Access tokens now carry **`auth_time`** (RFC 9068
  §2.2.1 / OIDC), and token **introspection surfaces it** (RFC 7662), so a
  resource server can make its own **freshness / step-up** decisions from the
  access token — whether it verifies the JWT locally or introspects — without a
  round-trip to the ID token. The login/refresh flow stamps the session's
  `auth_time` (matching the refresh/ID tokens); tokens with no associated user
  authentication (client-credentials, token-exchange results) omit it. Purely
  additive (`omitempty`); the standalone `GenerateBoundAccessToken` helper stays
  byte-compatible. This is the freshness signal the impersonation **step-up**
  control will build on. _Traceability: C17 → EPIC-17 → RFC-016._

### Added
- **Identity / Impersonation:** Impersonated tokens are now **time-boxed**
  (RFC 8693 / EPIC-17). An access token minted via impersonation (the
  actor-absent token-exchange case) auto-expires on a short, bounded lifetime —
  `IMPERSONATION_TOKEN_TTL` (default **300s**), always capped at the access-token
  TTL — so a leaked impersonation token is usable only briefly. The audit row
  records `impersonation` + `token_ttl_seconds`. Delegation is unaffected (keeps
  the standard access-token TTL), and an unset/zero time-box falls back to the
  access-token TTL (no behaviour change). _Traceability: C17 → EPIC-17 →
  RFC-016 → #105._

### Added
- **Identity / Delegation / Introspection:** Token introspection now **surfaces the
  `act` (actor) claim** (RFC 7662 / RFC 8693 §4.1). When an introspected access
  token was minted via token exchange (delegation/impersonation), the response
  carries `act` — a nestable `{sub, act}` chain — so a resource server can see
  **who is acting on the subject's behalf**, mirroring the existing `cnf`
  surfacing. Ordinary tokens omit `act` (additive, no behaviour change).
  _Traceability: C16 → EPIC-16 → RFC-019 → #103._

### Added
- **Identity / Delegation / DPoP:** Exchanged tokens are now **opportunistically
  DPoP-bound** (RFC 9449 / RFC 8693). When a token-exchange request carries a
  valid DPoP proof (verified by the token-endpoint middleware), the issued
  exchanged access token is sender-constrained via `cnf.jkt` to the requesting
  client's key; without a proof it is an ordinary bearer token (unchanged). The
  audit row records `dpop_bound`. _Traceability: C16 → EPIC-16 → RFC-019 → #101._

### Added
- **Identity / Delegation / Discovery:** OIDC discovery advertises the RFC 8693
  token-exchange grant (`urn:ietf:params:oauth:grant-type:token-exchange` in
  `grant_types_supported`) **when it can actually be issued**
  (`TOKEN_EXCHANGE_MODE=enforce`). It is omitted in `off`/`shadow` (where the
  grant issues nothing), so the metadata never advertises a capability clients
  can't use. _Traceability: C16 → EPIC-16 → RFC-019 → #99._

### Added
- **Identity / Delegation:** OAuth 2.0 **Token Exchange is now live** (RFC 8693 /
  EPIC-16) under `TOKEN_EXCHANGE_MODE=enforce`. A flagged client
  (`allow_token_exchange`, plus `allow_impersonation` for the actor-absent case)
  may exchange a verified subject token for a new access token. The issued token
  is **downscoped** (scope ⊆ the subject's), **audience-bound** (a target
  `audience`/`resource` is required), **short-lived** (access-token TTL), carries
  the subject's `token_version` so revocation still applies, and stamps the `act`
  (actor) claim — the actor token's subject for delegation, `client:<id>` for
  impersonation — keeping **both principals visible** downstream. Confidential
  clients are authenticated; every exchange is audited (`token_exchange`,
  `outcome=issued`). Policy denials surface as the proper RFC 8693 errors
  (`unauthorized_client` / `invalid_scope` / `invalid_target` / `invalid_client`
  / `invalid_grant`). `off`/`shadow` are unchanged (no issuance). Adds
  `issued_token_type` to the token response. _Traceability: C16 → EPIC-16 →
  RFC-019 → #97._

### Added
- **Identity / Delegation:** Token-exchange shadow mode now performs **full
  validation** (RFC 8693 / EPIC-16). `ExchangeToken` verifies the presented
  subject (and, for delegation, actor) tokens, recovers the subject's scope, and
  runs the authorization policy (`authorizeExchange`) — then audits the *would-be*
  decision (`shadow_allow` with the downscoped grant + audience, or `denied` with
  the reason; plus `invalid_subject_token` / `invalid_actor_token` /
  `parse_error`). It still **issues nothing** and reports the grant unsupported.
  This completes the observe step; only issuance (`enforce`) remains.
  _Traceability: C16 → EPIC-16 → RFC-019 → #95._

### Added
- **Identity / Delegation:** Token-exchange grant **dispatch + shadow telemetry**
  (RFC 8693 / EPIC-16). `POST /oauth/token` now recognizes the token-exchange
  grant and routes it to `OAuthService.ExchangeToken`, gated by
  `TOKEN_EXCHANGE_MODE` (`off` default | `shadow` | `enforce`-reserved). In
  `shadow` it parses and classifies the request (delegation vs impersonation),
  audits the attempt with the requesting client and its capability flags
  (`token_exchange` event), and then reports the grant as **unsupported** — no
  token is verified or issued. In `off` the grant is unsupported and nothing is
  audited. This is the observe step: subject/actor verification + the downscope
  policy, and actual issuance, are later slices. No client-visible behaviour
  change (the grant remains unsupported). _Traceability: C16 → EPIC-16 → RFC-019
  → #93._

## [0.3.0] - 2026-06-22

### Added
- **Identity / Delegation:** Token-exchange **authorization policy** (RFC 8693 /
  EPIC-16) as a pure decision function. `authorizeExchange` enforces the agreed
  best-practice rules — default-deny (`allow_token_exchange` required),
  impersonation gated by `allow_impersonation`, **downscope-only** (requested
  scope ⊆ subject scope; empty defaults to the subject's), and **audience-bound**
  (a target audience or resource is required) — returning the downscoped grant +
  bound audience + delegation/impersonation classification, with a typed error
  per violation. It verifies no tokens and mints nothing; wiring it at the token
  endpoint (observe-first) is the next slice. _Traceability: C16 → EPIC-16 →
  RFC-019 → #90._

### Added
- **Identity / Delegation:** Per-client token-exchange capability flags
  (RFC 8693 / EPIC-16). New `apps.allow_token_exchange` and
  `apps.allow_impersonation` columns (migration `0013`, both default false),
  settable via the admin app API (create / update / response), mirroring
  `require_dpop`. `allow_token_exchange` gates the grant (delegation);
  `allow_impersonation` gates the higher-risk impersonation case. These are the
  default-deny **authorization gate** — they do not by themselves enable the
  grant (nothing reads them yet); wiring + the downscope/audience policy are
  later, observe-first slices. _Traceability: C16 → EPIC-16 → RFC-019 → #88._

### Added
- **Identity / Delegation:** Access tokens can now carry the RFC 8693 §4.1 `act`
  (actor) claim — a new `auth.ActClaim` type (nestable, for delegation chains)
  and an optional `Act` field on `AccessTokenClaims`. This keeps both principals
  (the subject and the actor acting on their behalf) visible to downstream
  services. The claim is `omitempty`, so ordinary tokens are byte-for-byte
  unchanged, and **no issuance path sets it yet** — this is the claim-model
  foundation for token exchange; enabling the grant is a later, policy-gated
  slice. _Traceability: C16 → EPIC-16 → RFC-019 → #86._

### Added
- **Identity / Delegation:** New `internal/shared/auth/tokenexchange` package —
  a standalone parser/validator for OAuth 2.0 Token Exchange requests
  (RFC 8693), the foundation for delegation and impersonation (EPIC-16). It
  validates the protocol parameters (`subject_token`/`subject_token_type`,
  optional `actor_token`/`actor_token_type`, `requested_token_type`, audience,
  scope) and classifies a request as delegation (actor present) vs impersonation,
  with a typed error per violation. **Not** wired into the token endpoint — it
  neither verifies tokens nor authorizes an exchange; enabling the grant is a
  later, policy-gated slice. _Traceability: C16 → EPIC-16 → RFC-019 → #84._

### Added
- **Identity / KMS / Ops:** The JWKS endpoint now supports conditional requests
  (RFC 7232). It sends a strong `ETag` over the key set and returns `304 Not
  Modified` (no body) when a verifier sends a matching `If-None-Match`, so an
  unchanged key set revalidates cheaply and a rotation (which changes the ETag)
  is fetched in full. Complements the `Cache-Control` added in the previous
  slice. _Traceability: C3 → EPIC-3 → RFC-002 → #82._

### Added
- **Identity / KMS / Ops:** The JWKS endpoint (`/.well-known/jwks.json`) now
  sends a `Cache-Control` header so resource servers cache the key set instead
  of refetching it on every token verification (RFC-002). The max-age is
  configurable via `JWKS_CACHE_MAX_AGE_SECONDS` (default 300s) and kept modest so
  a rotated key is picked up promptly; `0` disables caching (`no-store`).
  _Traceability: C3 → EPIC-3 → RFC-002 → #80._

### Added
- **Tokens / DPoP / Discovery:** The OIDC discovery document
  (`/.well-known/openid-configuration`) now advertises
  `dpop_signing_alg_values_supported: ["ES256"]` (RFC 9449 §5.1) **when DPoP is
  enabled** (`DPOP_MODE != off`), so clients can discover DPoP support and the
  accepted proof algorithm. The parameter is omitted entirely when DPoP is off.
  Completes the DPoP rollout's discoverability. _Traceability: C8 → EPIC-8 →
  RFC-003 → #78._

### Added
- **Tokens / DPoP:** **Refresh tokens are now sender-constrained** too
  (RFC 9449 §5). When a token is issued for a DPoP request, the refresh token
  also carries `cnf.jkt`, and the `refresh_token` grant requires the refresh
  request to present a DPoP proof for the **same** key — a mismatched or missing
  proof is rejected with `400 invalid_dpop_proof` (`ErrDPoPKeyMismatch`). A
  stolen DPoP-bound refresh token is therefore unusable without the client's
  key. Unbound (ordinary) refresh tokens are unaffected.
  _Traceability: C8 → EPIC-8 → RFC-003 → #76._

### Added
- **Tokens / DPoP / Admin:** The per-client `require_dpop` flag (#72) is now
  manageable through the admin app API. `POST /api/admin/apps` accepts
  `require_dpop` on creation, `PATCH`/`PUT` toggles it (omitted = unchanged), and
  every app response includes `require_dpop`. Mirrors the existing `require_pkce`
  handling. _Traceability: C8 → EPIC-8 → RFC-003 → #74._

### Added
- **Tokens / DPoP:** Per-client **require-DPoP** policy (RFC 9449). A new
  `apps.require_dpop` flag (migration `0012`, default false) makes the token
  endpoint reject an `authorization_code` or `refresh_token` request from that
  client unless it carries a verified DPoP proof (`400 invalid_dpop_proof`). This
  is the strict end-state of the rollout — unlike global `enforce` (which only
  rejects *present-but-invalid* proofs), a require-DPoP client must also supply a
  proof at all. Default-false, so existing clients are unaffected; the flag
  requires DPoP enabled globally (`DPOP_MODE != off`) to be satisfiable.
  _Traceability: C8 → EPIC-8 → RFC-003 → #72._

### Added
- **Tokens / DPoP:** `DPOP_MODE=enforce` now **rejects a present-but-invalid**
  DPoP proof at the token endpoint with `400 invalid_dpop_proof` (RFC 9449 §5) —
  a malformed, expired, replayed, or mismatched proof can no longer be silently
  downgraded to a bearer token. A valid proof still binds the token and a request
  with **no** proof still proceeds (requiring DPoP per client is a later slice),
  so existing non-DPoP clients are unaffected. The token-endpoint middleware
  (`middleware.DPoP`, renamed from `DPoPObserve`) now handles off/observe/enforce.
  _Traceability: C8 → EPIC-8 → RFC-003 → #70._

### Added
- **Tokens / DPoP:** **Opportunistic sender-constraint** at the token endpoint
  (RFC 9449). When a valid DPoP proof accompanies an `authorization_code` or
  `refresh_token` grant (`DPOP_MODE=observe`/`enforce`), the issued **access
  token is now bound** to the proof's key via `cnf.jkt` — the middleware places
  the verified thumbprint on the request context and the grant uses the new
  `TokenService.GenerateTokenSetWithDPoP`. Clients that send no proof, or an
  invalid one, are unaffected and receive an ordinary bearer token (still never
  rejected — that is the enforce slice). Refresh-token binding is a later slice.
  _Traceability: C8 → EPIC-8 → RFC-003 → #68._

### Added
- **Tokens / DPoP:** Observe-mode DPoP telemetry at the token endpoint
  (RFC 9449 rollout). New `middleware.DPoPObserve` verifies a `DPoP` proof on
  `POST /oauth/token` (binding to the request method/URL, with replay detection)
  and logs structured telemetry — valid vs. rejected, with a short `jkt` prefix
  — **without ever changing the response**. Gated by `DPOP_MODE`
  (`off` default | `observe` | `enforce`-reserved); the replay cache and its
  janitor are created only when enabled and stopped on shutdown. This is the
  "warn-mode telemetry" step before token binding/enforcement.
  _Traceability: C8 → EPIC-8 → RFC-003 → #66._

### Added
- **Tokens / DPoP:** Access tokens can now be **sender-constrained** via the
  `cnf.jkt` confirmation claim (RFC 9449 / RFC 7800). New
  `TokenService.GenerateBoundAccessToken(..., jkt)` issues a token bound to a
  DPoP key thumbprint (an empty `jkt` yields an ordinary unbound token, so it is
  safe to call unconditionally), and token **introspection** now surfaces the
  binding (`cnf.jkt`, RFC 7662 §2.2 / RFC 9449 §7) so resource servers can
  require a matching proof. Ordinary tokens carry no `cnf` (backward
  compatible). The token endpoint does not yet read a `DPoP` request header —
  that wiring (observe→enforce) is the next slice.
  _Traceability: C8 → EPIC-8 → RFC-003 → #64._

### Added
- **Tokens / DPoP:** DPoP proof **replay protection** (RFC 9449 §11.1).
  `dpop.MemoryReplayCache` records proof `jti`s for the brief window a proof is
  acceptable (with a background janitor + graceful `Stop`), and the new
  `dpop.VerifyOnce` verifies a proof *and* enforces single use — a replayed
  `jti` is rejected with `ErrReplayed`, while a proof that fails verification
  never consumes its `jti`. Single-instance in-memory store; a shared
  (e.g. Redis) `ReplayCache` for multi-instance deployments is a later slice.
  Still not wired into the token endpoint — that is the next slice.
  _Traceability: C8 → EPIC-8 → RFC-003 → #62._

### Added
- **Tokens / DPoP:** New `internal/shared/auth/dpop` package — standalone
  verification of DPoP proof JWTs (RFC 9449), the foundation for
  sender-constrained access tokens (EPIC-8 / RFC-003). `dpop.Verify` validates a
  proof's `typ` (`dpop+jwt`), algorithm (ES256), embedded public `jwk`,
  signature, `htm`/`htu` request binding, and `iat` freshness, and returns the
  RFC 7638 JWK thumbprint (`jkt`) used to bind a token to the key. Rejects
  non-ES256 proofs, a `jwk` carrying a private key, and stale/future proofs.
  Verified against generated keys and tamper cases. Not yet wired into the token
  endpoint or resource path — those are later slices.
  _Traceability: C8 → EPIC-8 → RFC-003 → #60._

### Added
- **MFA / Recovery codes:** The MFA status endpoint (`GET /api/profile/mfa`) now
  reports `recovery_codes_remaining` so a user (and the UI) can regenerate backup
  codes before running out — reducing the lockout risk of the admin enforce
  policy. Backed by `MFAService.RemainingRecoveryCodes`; the count is only
  computed for enrolled users (0 otherwise). _Traceability: C9 → EPIC-9 →
  RFC-011 → #58._

### Added
- **Audit / Security:** Audit rows are now **hash-chained** (RFC-007), closing
  the gap left by per-row HMACs (which detect mutation but not deletion or
  reordering). Each row carries the previous chained row's hash (`prev_hash`,
  bound into its own `row_hash`); `repository.VerifyAuditChain` flags any row
  whose backward link is broken, and the integrity scanner records a critical
  `audit_integrity_violation` (with `chain_break_row_id`) for each. Appends are
  serialized with a transaction-scoped advisory lock so the chain cannot fork
  under concurrent writes. Adds the nullable `security_audit_logs.prev_hash`
  column via migration `0011`; existing rows keep an empty `prev_hash` and remain
  verifiable for mutation (the chain hash is backward compatible).
  _Traceability: C5 → EPIC-5 → RFC-007 → #56._

### Security
- **MFA / Login recovery:** Login step-up now accepts a one-time **recovery
  code** in place of a TOTP code, completing the backup story (#52): a user who
  has lost their authenticator can submit a recovery code in the `mfa_code`
  field at login. A valid TOTP code is still the common path and never consumes
  a backup code; only when TOTP fails is the value tried (and consumed) as a
  recovery code, with the redemption audited (`mfa_recovery_code_used`).
  _Traceability: C9 → EPIC-9 → RFC-011 → #54._

### Added
- **MFA / Recovery codes:** One-time backup codes for MFA. `MFAService` can now
  `GenerateRecoveryCodes` (10 per set, replacing any prior set; returned once)
  and `RedeemRecoveryCode` (single-use). Codes are stored only as keyed
  HMAC-SHA256 digests (keyed by `SECRET_KEY_BASE`) in a new `mfa_recovery_codes`
  table (migration `0010`) — a database dump alone cannot reveal or verify them.
  Exposed via `POST /api/profile/mfa/recovery-codes` (requires MFA enabled);
  disabling MFA clears any codes. Redemption is not yet wired into the login
  path — that is the next slice. _Traceability: C9 → EPIC-9 → RFC-011 → #52._

### Security
- **MFA / Admin policy:** Admin-portal login (`/api/admin/login`) can now require
  MFA enrollment, governed by `ADMIN_MFA_POLICY` (observe→enforce rollout):
  `off` (default, unchanged), `observe` (allow superadmins without MFA but audit
  each as a `mfa_policy_violation`), or `enforce` (deny with
  `mfa_enrollment_required` / HTTP 403 until the admin enrolls). An unrecognized
  value fails safe to `off`. Default behaviour is unchanged.
  _Traceability: C9 → EPIC-9 → RFC-011 → #50._
- **MFA / Login step-up:** Login now enforces a second factor for MFA-enrolled
  users (RFC-011). When a user with MFA enabled authenticates, `Login` /
  `AdminLogin` require a valid TOTP code: the first password-only request is
  rejected with `mfa_required` (HTTP 401) and the client retries with
  `mfa_code`; a wrong code returns `invalid mfa code` (401) and is audited as a
  failed login (`reason: mfa_invalid`). Wired via `AuthService.WithMFA` and
  active only for users who have opted in by enrolling — users without MFA see
  no change. _Traceability: C9 → EPIC-9 → RFC-011 → #48._

### Added
- **MFA / API:** Self-service TOTP enrollment endpoints (authenticated, under
  `/api/profile/mfa`): `POST /enroll` (returns the secret + `otpauth://`
  provisioning URI), `POST /confirm` (validates a code and enables MFA),
  `POST /disable`, and `GET /mfa` (status). Wires `service.MFAService` into the
  router/bootstrap; a user can only ever change their own MFA (the id comes from
  the authenticated context). `settings/config` now reports `MFAEnabled: true`.
  Login step-up enforcement is the next slice. _Traceability: C9 → EPIC-9 →
  RFC-011 → #46._
- **MFA:** New `service.MFAService` — the TOTP enrollment/verification lifecycle
  (`BeginEnrollment`, `ConfirmEnrollment`, `Verify`, `Disable`, `IsEnabled`).
  Enrollment generates a TOTP secret, stores it **encrypted at rest**
  (`auth.EncryptSecret`, keyed by `SECRET_KEY_BASE`), and leaves MFA disabled
  until a code is confirmed; a database compromise alone does not reveal the
  seed. Adds `users.mfa_secret` / `users.mfa_enabled` (`User.MFASecret` is never
  serialized) via migration `0009` (additive, nullable/defaulted). The service
  is not yet wired into HTTP enrollment or login step-up — that is the next
  slice. Also adds `totp.GenerateCode` (the symmetric counterpart to
  `ValidateCode`). _Traceability: C9 → EPIC-9 → RFC-011 → #44._
- **Security / crypto:** New `auth.EncryptSecret` / `auth.DecryptSecret` —
  authenticated AES-256-GCM encryption (key derived from `SECRET_KEY_BASE` via
  SHA-256, random nonce) for storing short restricted secrets (e.g. TOTP seeds)
  encrypted at rest. Decryption fails on a wrong key or tampered ciphertext.
  _Traceability: C12 (supporting EPIC-9 MFA) → RFC-010/RFC-011 → #42._
- **MFA:** New `internal/shared/auth/totp` package — standard-library TOTP
  (RFC 6238 / HOTP RFC 4226) primitives: `GenerateSecret`, `ProvisioningURI`
  (otpauth:// for authenticator apps), and `ValidateCode` (6 digits, 30s, ±1
  step skew, constant-time). Verified against the RFC 6238 test vectors. First
  building block of MFA; not yet wired into enrollment/login.
  _Traceability: C9 → EPIC-9 → RFC-011 → #40._

### Security
- **Identity / JWT:** Token verification now enforces the issuer
  (`jwt.WithIssuer`) and requires an expiry (`jwt.WithExpirationRequired`): a
  token whose `iss` is not this server's issuer, or that carries no `exp`, is
  rejected at the parser level. Backward compatible — every issued token sets
  both claims. _Traceability: C3 → EPIC-3 → RFC-002 → #38._

### Added
- **Audit / Security / Ops:** The audit-row integrity scan can now run on a
  timer. `AuditIntegrityScanner.StartSchedule(interval, lookback)` runs the scan
  periodically; `Bootstrap` enables it when `AUDIT_INTEGRITY_SCAN_INTERVAL_SECONDS`
  is set (default `0` = disabled; lookback `AUDIT_INTEGRITY_SCAN_LOOKBACK_SECONDS`
  defaults to 24h) and stops the goroutine on graceful shutdown. Default
  behaviour unchanged. _Traceability: C5 → EPIC-5 → RFC-007 → #36._
- **Audit / Security:** Audit-row tamper-evidence is now **actionable**.
  `repository.VerifyAuditRows` batch-verifies stored rows' HMACs, and the new
  `service.AuditIntegrityScanner.Scan` pages audit rows over a time window,
  flags any that fail verification, and records a critical
  `audit_integrity_violation` event (with the offending row id) per tampered
  row. (An opt-in scheduler to run this automatically is a tracked follow-up.)
  _Traceability: C5 → EPIC-5 → RFC-007 → #34._

### Fixed
- **Tests:** Made `TestLOW02_MaxAge_ExactlyAtBoundary_Accepted` deterministic by
  re-anchoring `LastLogin` immediately before the call, eliminating a timing
  flake that surfaced under the slow `-race` CI runner (elapsed setup time could
  push the measured session age one second past the `max_age` boundary).
  _Traceability: C6 → EPIC-6 → RFC-014 → #28._

### Infrastructure
- **CI / lint:** Enabled `staticcheck` in the `golangci-lint` gate. Fixed its 11
  findings: the 9 `SA9003` empty error-branches in `auth_service.go` (failed-login
  counting, account lockout, last-login update) now **log** the previously-silent
  errors via `logger.Warnf` instead of ignoring them; the RFC-7009 revocation
  ignore is made explicit (`_ =`); and a `QF1003` if-chain became a tagged switch.
  Additive logging only — control flow unchanged. _Traceability: C6 → EPIC-6 → RFC-014 → #32._
- **CI / lint:** Added a `golangci-lint` gate (`.golangci.yml`) enforcing
  `errcheck`, `govet`, `ineffassign`, and `unused`, and resolved all 26
  findings (acknowledged fire-and-forget calls with `_ =`, wrapped deferred
  `Close`, removed dead `web.writeJSON`). Test-file `errcheck` is excluded as
  noise; `staticcheck` (incl. SA9003 empty-branch fixes in the auth path) is a
  tracked follow-up. _Traceability: C6 → EPIC-6 → RFC-014 → #30._
- **CI / formatting:** Normalized the entire repository with `gofmt` and added a
  `gofmt` gate to CI so unformatted code fails the build. Formatting-only change
  (no semantics). `golangci-lint` enforcement remains a follow-up.
  _Traceability: C6 → EPIC-6 → RFC-014 → #26._

- **CI:** Added a GitHub Actions workflow (`.github/workflows/ci.yml`) that runs
  `go build`, `go vet`, `go test -race`, and `govulncheck` on every push to
  `main` and every pull request. _Traceability: C6 → EPIC-6 → RFC-014 → #24._

### Security
- **Toolchain:** Bumped the Go directive to `1.25.11`, clearing 12 standard-
  library vulnerabilities (net/textproto, crypto/x509, crypto/tls,
  html/template, net, net/url, os) flagged by the new `govulncheck` CI gate.
  Patch-level bump; no source changes. _Traceability: C6 → EPIC-6 → RFC-014 → #24._

### Added
- **Audit / Security:** Security audit rows are now **tamper-evident** — each
  row carries a keyed HMAC (`row_hash`) over its immutable content, stamped at
  the repository choke point and keyed by `SECRET_KEY_BASE` (held in config,
  never in the DB). `repository.VerifyAuditRowHash` detects any row mutated
  without the secret. Enabled by configuring the secret (disabled otherwise);
  adds the `security_audit_logs.row_hash` column via migration `0008`.
  Detects row *mutation*; deletion/reordering (hash-chaining) is a later slice.
  _Traceability: C5 → EPIC-5 → RFC-007 → #22._

### Changed
- **Audit / Observability:** Direct (hot-path) security audit writes —
  `authService`/`oauthService.logSecurityEvent` (login, token, OAuth events) —
  now also stamp the `correlation_id` from the request context, via a shared
  `newSecurityAuditLog` builder. Completes request-path audit correlation
  coverage left open by #16. _Traceability: C4 → EPIC-4 → RFC-008 → #20._

### Added
- **Audit / Observability:** Admin-action logs now record a `correlation_id`,
  completing correlation coverage across both audit stores. Adds the
  `admin_logs.correlation_id` column via migration `0007` (additive, nullable,
  indexed). _Traceability: C4 → EPIC-4 → RFC-008 → #18._
- **Audit / Observability:** Security audit events now record a `correlation_id`,
  linking each audit row to the request that produced it (derived from the
  request context, or an explicit `SecurityEvent.CorrelationID`). Adds the
  `security_audit_logs.correlation_id` column via migration `0006` (additive,
  nullable, indexed). _Traceability: C5 → EPIC-5 → RFC-007 → #16._
- **Observability:** Request logs now include a `correlation_id` field when a
  correlation ID is present in the request context, so a request can be traced
  end-to-end across log lines. `middleware.CorrelationID()` now runs before the
  request logger in all router stacks so the ID is available when logging.
  _Traceability: C4 → EPIC-4 → RFC-008 → #14._
- **Identity / KMS / Ops:** Scheduled key rotation + retired-key pruning can now
  be enabled at startup via `KEY_ROTATION_INTERVAL_SECONDS` and
  `KEY_RETENTION_SECONDS` (both default `0` = disabled / derive retention from
  `REFRESH_TOKEN_TTL`). `Bootstrap` starts the schedule when an interval is set,
  warns if the interval exceeds `REFRESH_TOKEN_TTL`, and stops the rotation
  goroutine during graceful shutdown. Default behaviour is unchanged.
  _Traceability: C3 → EPIC-3 → RFC-002 → #12._
- **Identity / KMS:** `KeyManager.PruneRetiredKeys(maxAge)` removes retired
  signing keys older than a retention window (mod-time based) from both the
  in-memory ring and the `retired/` directory, bounding ring and JWKS growth
  across rotations. New `StartRotationScheduleWithRetention(interval, retention)`
  prunes automatically after each rotation when `retention > 0`;
  `StartRotationSchedule(interval)` is unchanged (retention disabled). Pruning
  is conservative — a retired key whose file cannot be stat'd/removed is kept.
  _Traceability: C3 → EPIC-3 → RFC-002 → #10._

### Security
- **Identity / JWT:** Pinned token verification to an explicit algorithm
  allow-list of exactly `RS256` via `jwt.WithValidMethods` in
  `verifyToken`. Tokens presenting any other `alg` (`RS384`/`RS512`, `none`,
  or an HMAC algorithm) are now rejected by the parser before the keyfunc
  runs, regardless of the key. Backward compatible — the server only ever
  issues RS256. _Traceability: C3 → EPIC-3 → RFC-002 → #8._

## [0.2.0]

### Added
- **Identity / KMS:** Introduced a `Signer` interface in `internal/shared/auth`
  that abstracts the JWT signing operation, with a default `localSigner`
  (in-process RSA key via `KeyManager`) and a `NewTokenServiceWithSigner`
  injection constructor. This is the "adapters before replacements" seam that
  lets a future KMS/HSM-backed signer be substituted without changing any
  token-generation code. Behaviour is unchanged (RS256 + `kid` header).
  _Traceability: capability C3 → EPIC-3 → RFC-002 → #6._
