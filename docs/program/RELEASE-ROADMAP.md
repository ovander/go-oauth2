# RELEASE ROADMAP

The program crosses **exactly one** major-version boundary (v2.0), where platform-wide security defaults flip from "verify-if-present" to "verify-or-deny." Everything before v2.0 is backward compatible and additive; v2.x and v3 are enforcement-cleanup and steady state. Each repository versions independently (SemVer) but aligns to these **platform release lines**.

**Release principle:** a capability appears across up to three releases — **introduce (dark/additive)** → **default-on (flag-flip)** → **mandatory (legacy removed)** — never all at once.

---

## v1.x — Foundations & Additive Capabilities (non-breaking)

**Theme:** Build the substrate and ship every new control in observe/dual mode. No consumer breaks.

Contains:
- **EPIC-1** Workload identity + mesh mTLS (additive alongside existing transport).
- **EPIC-2** Dynamic secrets (static secrets retired silently as services adopt).
- **EPIC-3** KMS signing with **dual-sign** rotation; JWKS publishes current+previous (verifiers unaffected).
- **EPIC-4 / EPIC-5** Observability + tamper-evident audit (additive emission).
- **EPIC-6** CI/CD provenance + gates (applies to new builds; no runtime change).
- **EPIC-7 (introduce)** Tokens *carry* `aud`; resource servers verify in **warn-only** mode (log would-be denials).
- **EPIC-9 (introduce)** MFA/passkeys available, opt-in; mandatory only for admins.
- **EPIC-10 (introduce)** Policy engine deployed; backendkit can *consult* it in shadow mode.
- **EPIC-13** Distributed state available behind adapters (single-node still works).

**Exit criteria for v1.x:** every service has identity + telemetry + audit; audience warn-mode shows parity (near-zero would-be denials for legitimate traffic); KMS signing live; admins on MFA.

---

## v2.0 — The Enforcement Boundary (single coordinated major)

**Theme:** Flip defaults to deny. This is the one breaking line; each consumer absorbs it via its compatibility layer and a deprecation window.

Contains (each gated per-app, then platform default):
- **EPIC-7 (default-on)** Audience verification **enforced** — tokens must be audience-bound.
- **EPIC-11 (mandatory)** backendkit **PEP required**; every request yields exactly one authorization decision.
- **EPIC-8 (default-on)** Sender-constrained tokens become the default issuance.
- **EPIC-12 (enforce)** RLS enforced on tenant tables; tenant-context required.
- **EPIC-14** Revocation propagation active with a published freshness SLA.

**Compatibility:** v2.0 ships with legacy paths still *present but deprecated* and flags allowing a per-app phased cutover. The major bump signals "defaults changed," not "legacy deleted."

**Exit criteria for v2.0:** 100% of resource servers enforce audience + PEP; cross-audience and cross-tenant tests pass with zero leakage; no legitimate traffic denied.

---

## v2.x — Hardening & Scale (non-breaking on top of v2.0)

**Theme:** Complete coverage and operate at scale.

Contains:
- **EPIC-8 (mandatory)** All clients sender-constrained; bearer-only issuance removed.
- **EPIC-9 (mandatory)** MFA mandatory for all human identities; step-up everywhere sensitive.
- **EPIC-10 (full)** ABAC + object-level policies fully in PDP.
- **EPIC-13 (full)** Multi-instance/multi-region state; in-process state removed.
- **EPIC-15** AI Gateway live; direct provider calls disallowed.
- **EPIC-16** HA + tested DR + verified backups.
- **EPIC-17** Delegation + impersonation.

**Exit criteria:** platform runs multi-instance/region; DR drills pass; AI mediated; MFA universal.

---

## v3 — Steady-State Zero Trust (cleanup major)

**Theme:** Remove every compatibility shim and legacy path; the target *is* the only path.

Contains:
- Delete deprecated legacy auth/transport/secret paths (deprecation windows elapsed, usage telemetered to zero).
- **EPIC-18** Federation generally available.
- Per-tenant data keys everywhere for regulated data; cryptographic tenant erasure standard.
- Cloud-agnostic abstractions complete; provider-specific code fully behind interfaces.
- Conformance checks block any non-target pattern at admission.

**Exit criteria:** zero legacy paths in production; 100% conformance; the constitution's §13 rules are all CI/admission-enforced.

---

## Release Mechanics (all lines)

- **SemVer per repo**, aligned to platform lines via a compatibility matrix (`REPOSITORY-ROADMAP.md`).
- **Rollout:** canary → progressive → full, gated by SLOs, auto-rollback on regression.
- **Database:** expand–contract only; no release requires a destructive migration to deploy or roll back.
- **One breaking change per consumer per major**; deprecation windows announced in release notes.
- **Reversibility:** every release line is one action from the prior immutable artifact.
