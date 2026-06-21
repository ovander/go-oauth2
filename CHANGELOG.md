# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases follow the platform program defined in `docs/program/RELEASE-ROADMAP.md`
(current line: **v1.x — Foundations & Additive Capabilities**, non-breaking).

## [Unreleased]

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
