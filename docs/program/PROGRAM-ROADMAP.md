# PROGRAM ROADMAP — Platform Transformation

**Role:** Program Architect
**Mandate:** Transform the existing platform (Socrate, backendkit, ParaShift, GPWA, Ascenda) into the frozen target defined in `PLATFORM-REFERENCE-ARCHITECTURE.md`, with **minimum risk** and **maximum long-term maintainability**, **without ever destabilizing production**.
**Nature:** This is a transformation *program*, not an implementation plan. It sequences capabilities, RFCs, epics, releases, and migrations across five independently-versioned repositories.

**Companion documents (this `docs/program/` set):**
`IMPLEMENTATION-ROADMAP.md` · `RFC-ROADMAP.md` · `EPIC-ROADMAP.md` · `RELEASE-ROADMAP.md` · `REPOSITORY-ROADMAP.md` · `MIGRATION-ROADMAP.md` · `RISK-REGISTER.md`

---

## 1. Executive Summary

The platform reaches the target architecture through a **foundations-first, additive-before-enforcing** strategy. We never "rip and replace." Instead we build each target capability as a **new, parallel control that runs in observe/dual mode first**, prove it in production with telemetry, then **flip enforcement behind a flag**, then **remove the legacy path** only after a deprecation window.

The transformation is organized in four trust tiers, executed largely in this order but with heavy parallelism:

1. **Foundations** (enable everything else): workload/service identity + mesh mTLS, dynamic secrets, KMS/HSM, the observability + tamper-evident audit pipeline, and a gated signed CI/CD. None of these change application behavior; they create the substrate.
2. **Identity hardening** (Socrate): KMS-backed signing with dual-sign rotation, audience-bound token claims, sender-constrained tokens (DPoP/mTLS), MFA/passkeys, and revocation propagation. All additive first, enforced later.
3. **Enforcement substrate** (backendkit + policy): the mandatory Policy Enforcement Point, the policy-as-code Decision Point, tenant-context propagation, and data-layer isolation (RLS + tenant data keys). Adopted app-by-app via a compatibility layer.
4. **Steady-state Zero Trust**: AI Gateway mediation, distributed shared state for multi-instance/multi-region, HA + tested DR, and the removal of every compatibility shim.

The program crosses exactly **one major-version boundary** (v2.0) where platform-wide defaults flip from "verify-if-present" to "verify-or-deny." Everything before v2.0 is backward compatible; everything in v2.x and v3 is the cleanup and the long tail. The result is a platform where **trust is verified at every hop**, delivered without a flag day and reversible at every step.

---

## 2. Transformation Principles

These govern *how* we change the platform. They bind every workstream.

1. **Architecture First.** No work merges that moves away from the frozen target. Every PR cites the capability/RFC it advances.
2. **Backward Compatibility by Default.** Public contracts keep working. New behavior is additive until a major version deliberately flips it.
3. **One Breaking Change per Release Line.** A given consumer absorbs at most one breaking change per major release, with a deprecation window before and after.
4. **Adapters Before Replacements.** A new capability ships behind an adapter/interface so consumers integrate against the contract, not the implementation; the implementation can then be swapped invisibly.
5. **Deprecation Before Removal.** Nothing is deleted until it is deprecated, telemetered to zero usage, and announced through a published window.
6. **Feature Flags Before Default Changes.** Every behavioral change lands dark, is enabled per-tenant/per-app, observed, then defaulted, then made mandatory.
7. **Observe → Enforce.** Security controls run in **report-only** mode first (log what *would* be denied), prove parity, then switch to enforce. We never enable a deny-path blind.
8. **Expand–Contract for Data.** Schema changes add before they remove; rollouts and rollbacks stay safe because old and new code both work against the intermediate schema.
9. **Automation Before Scaling.** A capability is automated (provisioning, rotation, deploy, recovery) before it is scaled out, so scale doesn't multiply manual toil.
10. **Reversibility.** Every release is one action away from rollback; every migration has a defined back-out.
11. **Conformance is Gated, Not Requested.** Target rules become CI/admission checks; conformance is enforced by the pipeline, not by goodwill.

---

## 3. Capability Map

Each capability is a unit of the target architecture. Effort is T-shirt (S/M/L/XL); risk and value are L/M/H. Repos use codes: **SO**=Socrate, **BK**=backendkit, **PS**=ParaShift, **GP**=GPWA, **AS**=Ascenda, **INFRA**=infra/platform (cross-repo).

| # | Capability | Objective | Dependencies | Repos | Effort | Business Value | Tech Risk |
|---|---|---|---|---|---|---|---|
| C1 | **Service / Workload Identity** | Every workload gets SPIFFE identity + automatic mTLS; default-deny east-west | — | INFRA, all | L | H (Zero Trust substrate) | M |
| C2 | **Dynamic Secrets** | Central manager issues short-lived secrets/DB creds; no static secrets | C1 | INFRA, SO, BK, apps | M | H | M |
| C3 | **KMS / HSM Key Custody** | Signing & data-key ops inside KMS; private keys never exported | C2 | SO, INFRA | M | H (root of trust) | M |
| C4 | **Observability Pipeline** | OTel logs/metrics/traces + propagated correlation IDs | C1 | INFRA, BK, all | M | H (operability) | L |
| C5 | **Tamper-Evident Audit** | Append-only, hash-chained audit store independent of producers | C4 | INFRA, SO, BK | M | H (compliance) | M |
| C6 | **CI/CD Provenance & Gates** | Build/test/scan/sign/attest; policy admission; ephemeral deploy identity | C1 | INFRA, all | M | M (supply chain) | L |
| C7 | **Token Audience Binding** | Tokens carry & resource servers enforce a specific `aud` | C3 | SO, BK, apps | M | H (isolation) | M |
| C8 | **Sender-Constrained Tokens** | DPoP (public) / mTLS (confidential) proof-of-possession | C3, C7, C1 | SO, BK, apps | L | H (theft ≠ use) | H |
| C9 | **MFA / Passkeys** | Phishing-resistant human auth + step-up for sensitive ops | C3 | SO | M | H | M |
| C10 | **Policy Engine (PDP)** | Declarative policy-as-code; RBAC+ABAC; single decision contract | C4 | BK, INFRA | L | H (authz) | M |
| C11 | **backendkit PEP** | One mandatory enforcement point per request + tenant-context propagation | C7, C10 | BK, apps | L | H (consistency) | M |
| C12 | **Tenant Data Isolation** | RLS + per-tenant envelope encryption for regulated fields | C3, C11 | BK, apps, INFRA | L | H (isolation) | H |
| C13 | **Distributed State** | Shared store for sessions, rate limits, revocation freshness | C1 | INFRA, SO, BK | M | M (scale/HA) | M |
| C14 | **Revocation Propagation** | Logout/revoke honored everywhere within a freshness window | C7, C13 | SO, BK, apps | M | H | M |
| C15 | **AI Gateway** | Sole mediated AI path; per-tenant isolation + governance + audit | C2, C4, C7 | new repo / INFRA | L | M | M |
| C16 | **Resilience: HA + DR** | Multi-zone HA, tested RPO/RTO, verified backups, tenant erasure | C13, C3 | INFRA, all | L | H | M |
| C17 | **Delegation & Impersonation** | Token-exchange delegation; audited, time-boxed impersonation | C7, C5 | SO, BK | M | M | M |
| C18 | **Federation** | Upstream OIDC/SAML brokering behind provider abstraction | C7, C9 | SO | M | M (enterprise sales) | M |

---

## 4. Dependency Graph

```
                 ┌──────────────── FOUNDATIONS (parallel) ────────────────┐
   C1 Service Identity ──► C2 Secrets ──► C3 KMS/HSM
        │                      │              │
        ├──► C4 Observability ─┴──► C5 Audit  │
        ├──► C6 CI/CD Gates                   │
        └──► C13 Distributed State            │
                                              ▼
                          IDENTITY HARDENING (Socrate)
                          C7 Audience ──► C8 Sender-Constraint
                          C3 ──► C9 MFA/Passkeys
                          C7+C13 ──► C14 Revocation Propagation
                          C7 ──► C17 Delegation     C7+C9 ──► C18 Federation
                                              │
                                              ▼
                          ENFORCEMENT SUBSTRATE
              C10 Policy Engine ──► C11 backendkit PEP ──► C12 Tenant Isolation
                                              │
                                              ▼
                          STEADY-STATE ZERO TRUST
                          C15 AI Gateway        C16 HA + DR        (remove shims → v3)
```

- **Critical Path:** C1 → C2 → C3 → C7 → C11 → C12. This chain gates true tenant-isolated, audience-bound enforcement; it is the spine of the program.
- **Parallel Work:** C4/C5 (observability/audit), C6 (CI/CD), C9 (MFA), C13 (distributed state) proceed alongside the critical path once C1 lands.
- **Blocking Work:** C1 (service identity) and C3 (KMS) block the most. C7 (audience) blocks C8, C11, C14, C17.
- **Optional / Deferrable:** C15 (AI Gateway) and C18 (Federation) are demand-driven; valuable but not on the trust-containment critical path.
- **Breaking Work (must cross v2.0):** C7 enforcement, C8 default-on, C11 mandatory, C12 RLS-enforced, C14 enforce. All other capabilities can land non-breaking.

---

## 5. Workstreams (independently deliverable)

| Workstream | Owns capabilities | Primary repos | Independent deliverable |
|---|---|---|---|
| **WS-Infra (Service Identity & Mesh)** | C1, C13, C16 | INFRA | mTLS mesh + SPIFFE identity + shared state + HA/DR |
| **WS-Security (Keys, Secrets, Audit)** | C2, C3, C5 | INFRA, SO | Dynamic secrets + KMS signing + tamper-evident audit |
| **WS-Identity** | C7, C8, C9, C14, C17, C18 | SO | Hardened, audience-bound, sender-constrained tokens; MFA; revocation; delegation; federation |
| **WS-Framework** | C11, parts of C7/C8/C12/C14 | BK | The mandatory PEP + tenant context + verification client libraries |
| **WS-Authorization** | C10 | BK, INFRA | Policy-as-code PDP + decision contract |
| **WS-Observability** | C4 | INFRA, BK | OTel pipeline + correlation propagation + SLO dashboards |
| **WS-DevEx** | C6, conformance tooling | INFRA, all | Paved-path templates, CI gates, conformance checks |
| **WS-Operations** | C16 ops, runbooks, rotation | INFRA | Automated rotation, DR drills, runbooks, break-glass |
| **WS-AI** | C15 | new AI Gateway repo | Mediated AI with tenant isolation |

Each workstream ships value on its own cadence; cross-workstream coupling is mediated by RFC contracts (see `RFC-ROADMAP.md`), never by shared mutable code.

---

## 12. Success Metrics (program-level; details in companion docs)

| Dimension | Metric | Target |
|---|---|---|
| **Architecture conformance** | % services passing automated conformance checks (PEP present, audience enforced, RLS on, OTel emitting) | 100% by v3 |
| **Security** | % tokens audience-bound + sender-constrained; % human logins MFA; % keys in KMS | 100% by v2.x |
| **Security** | Mean time to revoke (logout-everywhere effective platform-wide) | < token freshness window |
| **Performance** | Added p99 auth/authz overhead per request | within agreed budget (e.g., < 10 ms) |
| **Developer productivity** | Time for a new conformant service to reach production via paved path | days, not weeks |
| **Operational maturity** | % secrets/keys on automated rotation; DR drills passing; backup restores verified | 100% on rotation; DR tested quarterly |
| **Stability** | Production incidents attributable to the transformation | 0 Sev-1/2 |

---

## 13. Governance

- **RFC process:** Any cross-repo or platform-level change starts as an RFC (template: Context → Proposal → Contract → Compatibility → Rollout → Alternatives). Reviewed by all affected repo owners + Platform Architecture. Approved RFCs are immutable; changes are new RFCs that supersede.
- **ADR process:** Per-repo significant decisions (and any exception to the constitution) are recorded as immutable ADRs referencing the relevant RFC.
- **Issue lifecycle:** `triage → accepted → in-progress → in-review → verifying → done`, each issue linked to an Epic and a capability. Security-relevant issues carry a `security` label and route to security review.
- **PR lifecycle:** branch → PR with linked issue + RFC/capability reference → automated gates (tests, scans, conformance) → review (code owner + security owner where flagged) → squash-merge → auto-deploy to staging → promote.
- **Release lifecycle:** SemVer; release notes + changelog; signed artifacts; staged rollout (canary → progressive → full) with SLO gates and auto-rollback. See `RELEASE-ROADMAP.md`.
- **Architecture review:** A standing board approves RFCs and verifies each release line stays aligned to the frozen target. Owns the conformance check definitions.
- **Security review:** Mandatory threat-model review for any change to identity, authorization, tenancy, cryptography, key/secret handling, or data classification. Gate to production for those areas.

---

*This document is the master index. Read it with the seven companion roadmaps in `docs/program/`. All future implementation aligns to this program and the frozen `PLATFORM-REFERENCE-ARCHITECTURE.md`.*
