# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases follow the platform program defined in `docs/program/RELEASE-ROADMAP.md`
(current line: **v1.x — Foundations & Additive Capabilities**, non-breaking).

## [Unreleased]

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
