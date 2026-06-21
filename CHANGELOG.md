# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases follow the platform program defined in `docs/program/RELEASE-ROADMAP.md`
(current line: **v1.x — Foundations & Additive Capabilities**, non-breaking).

## [Unreleased]

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
