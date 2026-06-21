# REPOSITORY ROADMAP

Per-repository view: required work, breaking changes, migration strategy, and release sequence. Each repo is independently versioned (SemVer) and aligns to the platform release lines in `RELEASE-ROADMAP.md`. Epics referenced are defined in `EPIC-ROADMAP.md`.

---

## Socrate (Identity Platform) — the most-affected repo

- **Required work:** KMS-backed signing + dual-sign rotation (EPIC-3); canonical audience-bound claim set (EPIC-7); sender-constrained issuance — DPoP/mTLS (EPIC-8); MFA/passkeys + step-up (EPIC-9); revocation propagation + short TTLs (EPIC-14); delegation/impersonation via token exchange (EPIC-17); federation (EPIC-18); emit tamper-evident audit (EPIC-5); dynamic secrets + workload identity (EPIC-2/1); distributed session/revocation state (EPIC-13).
- **Breaking changes:** issuance of audience-bound, sender-constrained tokens as the default (v2.0/v2.x); removal of any legacy long-lived/bearer-only issuance (v3).
- **Migration strategy:** dual-sign during key cutover (verifiers accept current+previous via JWKS); add claims additively; issue both bearer and constrained tokens during transition; MFA opt-in → admin-mandatory → universal. No flag day.
- **Release sequence:** v1.x (KMS dual-sign, claims additive, MFA opt-in, audit) → v2.0 (constrained-by-default, revocation SLA) → v2.x (MFA universal, delegation) → v3 (remove legacy issuance, federation GA).

---

## backendkit (Framework) — the enforcement substrate

- **Required work:** token verification library — signature/iss/aud/exp/nbf + sender-constraint (EPIC-7/8); the mandatory PEP middleware + tenant-context propagation (EPIC-11); PDP client + decision contract (EPIC-10); data-access primitives with RLS + envelope encryption (EPIC-12); OTel instrumentation + correlation propagation (EPIC-4); audit emission (EPIC-5); rate-limit/session adapters over distributed state (EPIC-13); dynamic-secret + workload-identity integration (EPIC-2/1).
- **Breaking changes:** making the PEP mandatory and the verification contract strict (v2.0); removing permissive/legacy middleware (v3). Library API breaks gated by SemVer majors.
- **Migration strategy:** ship the new middleware as **opt-in modules** first; provide an adapter that wraps existing handlers so apps adopt incrementally; run PEP in shadow/warn mode before enforce; deprecate old helpers with compiler-visible notices before removal.
- **Release sequence:** v1.x (verification + PEP available, shadow PDP, OTel/audit) → v2.0 (PEP mandatory, audience enforced, RLS primitives) → v2.x (full ABAC, distributed adapters) → v3 (remove legacy modules).

---

## ParaShift / GPWA / Ascenda (Business Applications) — symmetric work

These three follow the **same conformance path**; effort differs by domain surface, not by approach.

- **Required work (each):** adopt backendkit PEP + tenant context (EPIC-11); register a resource-server audience and verify it (EPIC-7); accept sender-constrained tokens (EPIC-8); move data access to backendkit primitives + enable RLS + tenant data keys for regulated fields (EPIC-12); emit OTel + audit (EPIC-4/5); consume dynamic secrets (EPIC-2); deploy via gated pipeline (EPIC-6); route any AI use through the gateway (EPIC-15).
- **Breaking changes:** internal only — switching to PEP-enforced authorization and RLS-scoped queries. **No change to the app's own public API contract** if done correctly (compatibility layer preserves behavior).
- **Migration strategy:** wrap existing auth/data code with the backendkit adapter; run audience + PEP in warn mode; enable RLS behind a per-tenant flag with expand–contract schema; cut over per app, never platform-wide at once.
- **Release sequence (each app):** v1.x (adopt observability/audit/secrets, PEP shadow) → v2.0 (PEP mandatory, audience + RLS enforced) → v2.x (sender-constraint mandatory, AI via gateway) → v3 (legacy data-access removed).

---

## Cross-repo / Platform (INFRA) and new AI Gateway repo

- **INFRA required work:** service mesh + SPIFFE identity + default-deny networking (EPIC-1); dynamic secrets manager + KMS/HSM (EPIC-2/3); observability + tamper-evident audit stores (EPIC-4/5); distributed state (EPIC-13); CI/CD provenance + admission policy (EPIC-6); HA + backup/DR (EPIC-16); policy engine hosting (EPIC-10).
- **AI Gateway (new repo):** the mediated AI service (EPIC-15) — created in v2.x, conformant from day one via the extension model.
- **Breaking changes:** none to applications (substrate). Networking becomes default-deny (operationally gated, not an API break).
- **Release sequence:** INFRA foundations lead v1.x; AI Gateway lands v2.x; HA/DR completed by v2.x and standardized in v3.

---

## Repository ↔ Release Compatibility Matrix (illustrative)

| Repo | v1.x | v2.0 | v2.x | v3 |
|---|---|---|---|---|
| Socrate | KMS dual-sign, claims additive, MFA opt-in | constrained-default, revocation SLA | MFA universal, delegation | legacy issuance removed, federation GA |
| backendkit | verify+PEP available, shadow PDP | PEP mandatory, audience enforced | full ABAC, distributed adapters | legacy modules removed |
| ParaShift/GPWA/Ascenda | observability/secrets, PEP shadow | PEP+RLS+audience enforced | sender-constraint, AI via gateway | legacy data-access removed |
| INFRA | mesh, secrets, KMS, audit, CI/CD | enforce default-deny | distributed state, HA/DR | cloud-agnostic complete |
| AI Gateway | — | — | live | standard |

Adopting repos MUST declare the minimum backendkit major they require; backendkit MUST hold a deprecation window of at least one major before removing any contract an app depends on.
