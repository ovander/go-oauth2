# Test Strategy — Identity Server Assurance

> **Capability:** C6 (CI/CD Provenance & Gates) · **RFC:** RFC-014 · **Epic:** EPIC-6
>
> How Socrate reaches and sustains identity-server-grade test assurance. For an
> identity provider, line-coverage percentage alone is the wrong target: the bar
> is **risk-tiered coverage + adversarial depth + assertion quality**. This
> document defines the tiers, targets, test layers, the phased roadmap to get
> there, and the CI gates that hold the line.

## 1. Baseline (measured)

| Area | Coverage | Note |
|---|---|---|
| Security logic (`service` + `auth`, cross-package) | ~53% | core funcs 80–100% |
| `tokenexchange` / `dpop` / `totp` / `config` | 100 / 91 / 90 / 90% | strong |
| `internal/http` (router) | ~4% | no end-to-end tests |
| `internal/handler` | ~22% | thin |
| `verifyExchangeToken` refresh/id branches | ~36% | gap |
| `internal/database/migrate` | 0% | no apply test |

Existing strengths: 80+ test files, 23 security-regression tests (CRIT/HIGH/MED/
NEW/LOW-prefixed), `-race` in CI, `govulncheck`, `golangci-lint`.

## 2. Risk tiers (the package map)

Coverage expectations are **differentiated by blast radius**, not uniform.

### Tier A — security-critical (target ≥ 90% branch + mutation floor)
Token issuance/verification, crypto & keys, PKCE, DPoP, token exchange,
revocation, audience binding, authN/authZ middleware, security config.
- `internal/shared/auth`, `internal/shared/auth/dpop`,
  `internal/shared/auth/tokenexchange`, `internal/shared/auth/totp`
- `internal/service`
- `internal/middleware`
- `config`

### Tier B — request layer (target ≥ 75%, mainly via integration tests)
- `internal/handler`, `internal/http`, `internal/web`

### Tier C — glue / infra (smoke + integration only, no unit mandate)
- `internal/repository`, `internal/database/...`, `cmd/server`, `pkg/...`

## 3. Test layers

1. **Unit** — pure logic/branch coverage (Tier A focus).
2. **Integration** — drive the **real `chi` router** end-to-end (Tier B); asserts
   wiring unit tests can't see (middleware order, headers, status/error bodies).
3. **Adversarial / negative** — one failing-by-design test per threat in the
   **OAuth 2.0 Security BCP (RFC 9700)** and **OWASP ASVS L2/L3** auth chapters
   (alg confusion / `none` / `kid` confusion / signature tampering / `exp`/`nbf`,
   PKCE downgrade, audience confusion, IdP mix-up, refresh reuse, code replay,
   redirect-URI bypass / open redirect, consent CSRF, rate-limit).
4. **Property / fuzz** — Go native `FuzzXxx` for every untrusted-input parser
   (JWT/claims, PKCE verify, redirect-URI validation, DPoP proof, token-exchange
   form, introspection input).
5. **Crypto & key lifecycle** — verification across key rotation, retired-key
   ring/JWKS, dual-sign.
6. **Persistence / migration** — apply all migrations against an ephemeral
   Postgres; repository integration tests.
7. **Concurrency** — `-race` (already in CI).
8. **Mutation testing** — assertion quality on Tier A (line coverage proves
   execution, mutation proves the tests *catch* bugs).
9. **Conformance** — OpenID Foundation conformance suite + RFC test vectors.

## 4. Targets — definition of done

- Tier A ≥ **90% branch** and mutation score ≥ **~75%**.
- **100% of OAuth/OIDC endpoints** exercised by router-level integration tests.
- A negative test for **every** RFC 9700 threat + ASVS L2 auth item.
- A **fuzz target for every** untrusted-input parser, run in CI.
- Migrations have an apply test; key-rotation verification tested.
- CI **blocks** PRs that drop Tier-A coverage, break the adversarial suite, or
  fail the fuzz smoke run.

## 5. Phased roadmap

| Phase | Deliverable | Status |
|---|---|---|
| **0** | Strategy doc + **non-blocking** coverage reporting in CI; tier map | ← this PR |
| **1** | Integration harness: real router, all OAuth endpoints end-to-end | planned |
| **2** | Adversarial suite vs RFC 9700 / ASVS; consolidate regression tests | planned |
| **3** | Fuzz targets + seed corpus (parsers); CI smoke + nightly long-run | planned |
| **4** | Crypto & key-rotation/JWKS verification tests | planned |
| **5** | Migration apply test + repository integration (ephemeral Postgres) | planned |
| **6** | Mutation testing (gremlins) on Tier A; mutation-score floor (nightly) | planned |
| **7** | OIDC conformance profile (external/ongoing) | planned |
| **8** | Flip coverage / adversarial / fuzz gates to **blocking** | planned |

Phases 1–2 buy the most confidence per unit of work and are pure test additions.

## 6. CI gating

- **Now (Phase 0):** a `coverage` job reports the total, per-package, and **Tier A**
  coverage, and uploads the profile as an artifact. **Non-blocking** — visibility
  first.
- **Later (Phase 8):** the same measurements become **required checks** with the
  Tier A/B thresholds above, plus a per-PR coverage-diff gate and the adversarial
  + fuzz-smoke suites as required.

Run locally: `make coverage-report`.
