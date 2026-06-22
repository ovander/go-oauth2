# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases follow the platform program defined in `docs/program/RELEASE-ROADMAP.md`
(current line: **v0.x — Foundations & Additive Capabilities**, non-breaking).

## [Unreleased]

### Added
- **Observability / Logging:** Service-layer logs can now be **traced to a single
  request end-to-end** (RFC-008). New `logger.FromContext(ctx)` stamps the
  `correlation_id` (the same id the request logger and audit log already carry)
  onto operational logs; the OAuth/auth flows' error/warn logs now use it, so a
  failed token-family revocation, JTI-blacklist, or login persistence warning can
  be tied to its request. Nil-safe. _Traceability: C4 → EPIC-4 → RFC-008 → #158._

### Added
- **CI / Test gates (Phase 8):** The **Tier A (security-critical) coverage check
  is now blocking** (docs/program/TEST-STRATEGY.md) — a **ratchet**
  (`scripts/coverage-gate.sh`, `make coverage-gate`) that fails the build if
  coverage drops below `TIER_A_MIN` (floor **55%**, raised toward the ≥90% target
  as the suites grow, so coverage can only go up). The adversarial (Phase 2) and
  fuzz seed-corpus (Phase 3) suites are already enforced via the blocking
  `go test ./...` job. This turns the test work of Phases 1–4 into an enforced
  guarantee against regressions. _Traceability: C6 → EPIC-6 → RFC-014 → #156._

### Added
- **Tests / Crypto lifecycle (Phase 4):** Added key-lifecycle tests that connect
  the signing-key ring to **token verification** (docs/program/TEST-STRATEGY.md):
  after a rotation, JWKS exposes both the current and retired `kid` (so a resource
  server can verify either token); and once a retired key is **pruned**, the token
  it signed **no longer verifies** — proving retention must outlive the token TTL
  (RFC-002 / EPIC-3). Complements the existing cross-rotation verification suite
  (which already covers pre/post-rotation, multi-rotation, and after-restart).
  Test-only. _Traceability: C3 → EPIC-3 → RFC-002 / RFC-014 → #154._

### Added
- **Tests / Fuzzing (Phase 3):** Added **Go native fuzz targets** for the
  untrusted-input parsers (docs/program/TEST-STRATEGY.md): PKCE verification
  (`FuzzVerifyPKCE` — never accepts a mismatched S256 challenge or the downgrade
  `plain` method), redirect-URI validation (`FuzzValidateRedirectURI` — the
  **open-redirect invariant**: any accepted URI must use a safe scheme, carry no
  fragment, and resolve to the registered host), and the RFC 8693 token-exchange
  request parser (`FuzzParse` — no panic, no nil/nil). Seed corpora run as the CI
  smoke; active fuzzing (≈0.5M execs) found no bypass or crash. Test-only.
  _Traceability: C6 → EPIC-6 → RFC-014 / RFC 9700 → #152._

### Added
- **Tests / Adversarial (Phase 2):** Added a **JWT/OAuth adversarial suite**
  (docs/program/TEST-STRATEGY.md) mapping the OAuth 2.0 Security BCP (RFC 9700) /
  OWASP ASVS attack classes to failing-by-design tests against access-token
  verification: **`alg=none`**, **RS256→HS256 algorithm confusion** (public key
  as HMAC secret), **foreign-key signature**, **tampered signature**, **expired**,
  **wrong issuer** (mix-up), **token-type confusion** (refresh-as-access), and
  malformed input — each asserted **rejected**. Test-only; guards the
  highest-blast-radius verification path. _Traceability: C6 → EPIC-6 → RFC-014 /
  RFC 9700 → #150._

### Added
- **Tests / Integration (Phase 1):** Added a **router-level integration harness**
  (docs/program/TEST-STRATEGY.md) that drives the OAuth/OIDC endpoints through a
  real `chi` router with the real middleware stack (JSONContentType /
  NoCacheHeaders / DPoP). Covers discovery, JWKS, the token endpoint, and
  introspection end-to-end — asserting routing, status codes, `no-store` headers
  (RFC 7662 §4), content type, method handling (405), and 404s — the HTTP wiring
  that handler unit tests can't see. Test-only; no production change.
  _Traceability: C6 → EPIC-6 → RFC-014 → #148._

### Added
- **CI / Test strategy:** Added `docs/program/TEST-STRATEGY.md` — the
  identity-server test-assurance plan (risk-tiered coverage, adversarial / fuzz /
  mutation / conformance layers, phased roadmap, and the eventual blocking CI
  gates). **Phase 0:** a **report-only** `coverage` CI job now publishes overall
  and **Tier A** (security-critical) coverage and uploads the profile, plus a
  `make coverage-report` helper. Non-blocking — visibility first; Tier-A
  thresholds become required checks in a later phase. Baseline: Tier A ~55%
  (target ≥90%). _Traceability: C6 → EPIC-6 → RFC-014 → #146._

### Added
- **Observability / Audience binding:** Token-issuance audit rows now carry
  **audience-coverage telemetry** (RFC-001 / EPIC-7, Phase 1): `audience_registered`
  (does the client have registered audiences), `audience_count`, and the active
  `audience_mode`. This is the **parity signal** operators watch before enabling
  audience-scoped enforcement — once coverage approaches 100% for clients that
  call protected resources, resource servers can enforce `aud` with ≈0 legitimate
  denials. Added to the `token_issued` (authorization-code, client-credentials)
  and `token_refreshed` events. Additive telemetry only. _Traceability: C7 →
  EPIC-7 → RFC-001 → #144._

### Fixed
- **Identity / Response caching:** The **userinfo, introspection, and revocation**
  responses are now marked **`Cache-Control: no-store` / `Pragma: no-cache`**.
  These carry sensitive material — PII (userinfo), token metadata (introspection,
  RFC 7662 §4), and token state — and must not be cached by browsers or
  intermediaries (RFC 6749 §5.1 / OIDC Core §5.3.2). Previously only the token
  endpoint set no-store. Added a shared `setNoStore` helper (the token endpoint
  now uses it too). _Traceability: C7 → EPIC-7 → RFC 6749 / RFC 7662 → #142._

### Added
- **Observability / Audit completeness:** Confidential-client **authentication
  failures at the token endpoint are now audited** (RFC-007 / RFC 6749 §3.2.1).
  A missing or wrong `client_secret` on the authorization-code, refresh-token, or
  client-credentials grant emits a `client_auth_failed` event (with `client_id`
  and a `missing_secret`/`invalid_secret` reason) — a credential-stuffing /
  brute-force signal that previously went unrecorded. (Token exchange already
  audited this via its own event.) Additive; success and error responses are
  unchanged. _Traceability: C5 → EPIC-5 → RFC-007 → #140._

### Fixed
- **Docs / Config accuracy:** Corrected stale `DPOP_MODE` and `TOKEN_EXCHANGE_MODE`
  documentation in `config.go`. Both `enforce` values were described as
  "reserved / behaves as observe", but they have been **live since v1.0.0**:
  DPoP `enforce` rejects a present-but-invalid proof (`400 invalid_dpop_proof`),
  and token-exchange `enforce` actually issues the exchanged token. The
  misleading comments could have led an operator to avoid `enforce` thinking it
  was a no-op. Comments only — no behaviour change. _Traceability: C8 → EPIC-8 →
  RFC-003 / RFC-019._

### Added
- **Observability / Audit completeness:** Security-relevant **authorization-code
  grant failures are now audited** (RFC-007 / EPIC-5). The token endpoint emits
  `auth_code_failed` for an invalid / expired / already-used code and for a
  `client_id` mismatch, and `pkce_validation_failed` for a missing or wrong PKCE
  `code_verifier` — all strong signals of code-replay or code-interception
  attacks that previously went unrecorded (the event types existed but were never
  emitted). Each row carries the `client_id` and a `reason`. Additive; success
  paths are unchanged. _Traceability: C5 → EPIC-5 → RFC-007 → #136._

### Fixed
- **Identity / PKCE hardening:** PKCE is now enforced for **public clients at the
  point of use**, not just via the create-time default (OAuth 2.1). The
  authorization and token endpoints gate on a new `App.PKCERequired()`
  (`RequirePKCE || IsPublic`), so a public client can never run an unprotected
  authorization-code flow even if its `require_pkce` flag were cleared by a seed,
  a direct DB row, or a future code path. Confidential clients and clients that
  already set `require_pkce` are unaffected. _Traceability: C7 → EPIC-7 → RFC 7636
  / OAuth 2.1 → #134._

### Added
- **Identity / Mix-up defense:** The **authorization response now carries the
  `iss` parameter** (RFC 9207), and discovery advertises
  `authorization_response_iss_parameter_supported: true`. A client that talks to
  more than one authorization server can verify `iss` matches the AS it sent the
  request to, defending against **IdP mix-up attacks**. Additive — clients that
  ignore `iss` are unaffected. _Traceability: C7 → EPIC-7 → RFC-001 / RFC 9207 →
  #132._

### Added
- **Identity / Refresh-token theft detection:** Refresh-token **reuse detection**
  (OAuth 2.0 Security BCP / RFC 9700 §4.14.2). A reused (already-rotated)
  single-use refresh token is still rejected as before, but `REFRESH_REUSE_MODE`
  now adds a theft response: `off` (default — reject only, unchanged), `observe`
  (also audit a `refresh_token_reuse` security event), or `enforce` (also revoke
  the user's **token family** via a token-version bump, so neither the attacker's
  nor the victim's outstanding tokens survive). The reused token's signature and
  audience are verified before acting, so the subject is trustworthy. Default
  `off` is byte-compatible. _Traceability: C14 → EPIC-14 → RFC-012 / RFC 9700 →
  #130._

## [1.0.0] - 2026-06-22

### Added
- **Discovery:** OIDC discovery now advertises the claims added by recent
  capabilities — `claims_supported` includes `auth_time` (RFC 9068), `acr`/`amr`
  (RFC 8176), `act` (RFC 8693), and `cnf` (RFC 9449) — and a new
  `acr_values_supported: ["pwd","mfa"]`. Relying parties can now discover the
  authentication-context and delegation/DPoP claims the OP may assert. Metadata
  only (a listed claim is not present on every token). _Traceability: C9 →
  EPIC-9 → RFC-001 → #127._

### Added
- **Identity / Delegation:** **Delegation step-up** (RFC 8693 / EPIC-17) — the
  human-actor counterpart to impersonation step-up. A delegation token-exchange
  carries an actor token whose `amr` evidences how that human authenticated, so
  `DELEGATION_STEPUP_MODE` can require it to contain **`mfa`**: `off` (default,
  no check), `observe` (audit a would-be denial but still issue), or `enforce`
  (deny with `invalid_grant`). An actor token minted without `amr` (e.g. a
  non-interactive flow) cannot satisfy enforce. Impersonation (actor-absent) is
  unaffected; every decision is audited (`delegation_stepup`). Builds on the
  `amr` claim from the previous slice. _Traceability: C17 → EPIC-17 → RFC-016 →
  #125._

### Added
- **Identity / Authentication context:** Tokens from an **interactive login** now
  carry **`amr` and `acr`** (RFC 8176 / OIDC, part of the RFC-001 canonical claim
  set) on the access and ID tokens, and introspection surfaces them: `["pwd"]` /
  `pwd` for a password login, `["pwd","otp","mfa"]` / `mfa` when a second factor
  was used. Resource servers can now gate on **authentication strength** (e.g.
  require `mfa`) without a separate channel. Purely additive (`omitempty`) — only
  the interactive `Login`/`AdminLogin` paths populate it; refresh, token-exchange,
  and other flows omit it. _Traceability: C9 → EPIC-9 → RFC-011 / RFC-001 → #123._

### Added
- **Docs / Revocation:** Added a **revocation & token-freshness SLA**
  (`docs/REVOCATION-FRESHNESS-SLA.md`, RFC-012 / EPIC-14) stating the guaranteed
  time-to-revoke per validation strategy — **immediate** for introspecting or
  Socrate-authenticated resource servers, **≤ `ACCESS_TOKEN_TTL`** (default 900s)
  for offline local JWT validators — plus how to tighten it and high-assurance
  guidance. Linked from `API.md`. _Traceability: C14 → EPIC-14 → RFC-012 → #121._

### Added
- **Identity / Revocation hygiene:** A scheduled **used-token cleanup** now prunes
  expired rows from the `used_tokens` table (single-use refresh JTIs + the
  per-token revocation blacklist), which previously grew without bound — nothing
  ever pruned it. Runs every `USED_TOKEN_CLEANUP_INTERVAL_SECONDS` (default
  **3600s / 1h**; `0` disables), with deterministic shutdown like the other
  scheduled jobs. Expired rows are safe to drop — the underlying token no longer
  verifies. _Traceability: C14 → EPIC-14 → RFC-012 → #119._

### Fixed
- **Identity / Revocation propagation:** A token **individually revoked** via
  `/oauth/revoke` (its `jti` blacklisted) is now rejected on the **direct-auth
  hot path** too — `AuthMiddleware` rejects it (401 `token has been revoked`) and
  `OptionalAuthMiddleware` treats it as unauthenticated. Previously only
  introspection honored the blacklist, so a per-token revocation didn't
  propagate to APIs that validate the bearer token directly (EPIC-14 / RFC-012).
  The check is nil-safe (disabled when no revocation store is wired) and fails
  open on a store error, so a transient outage never locks out valid tokens.
  _Traceability: C14 → EPIC-14 → RFC-012 → #117._

### Added
- **Identity / Audience binding / Introspection:** Token introspection now
  **surfaces `aud`** (RFC 7662 §2.2), so a resource server that introspects a
  token — rather than verifying the JWT locally — can confirm its own resource
  identifier is in the audience (RFC-001 / EPIC-7). Carries the `client_id` plus
  any registered audiences under `AUDIENCE_MODE=dual`. Additive; `client_id`
  remains the first audience entry. _Traceability: C7 → EPIC-7 → RFC-001 → #115._

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
