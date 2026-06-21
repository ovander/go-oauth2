# RFC ROADMAP

Every cross-cutting contract in the transformation is governed by an RFC. Implementation work references the RFC it satisfies; the RFC — not any single repo's code — is the source of truth for the contract. RFCs are immutable once approved; revisions supersede.

**Legend:** Repos — SO=Socrate, BK=backendkit, PS=ParaShift, GP=GPWA, AS=Ascenda, INFRA=platform/infra, AIG=AI Gateway (new). Priority — P0 (foundational/critical path), P1 (core), P2 (demand-driven). Breaking? = whether the *enforced* end-state breaks an existing consumer contract (the RFC itself defines the non-breaking rollout).

| RFC | Purpose | Repos | Breaking? | Priority | Depends on |
|---|---|---|---|---|---|
| **RFC-001 — Token Claims & Audience Binding** | Canonical JWT claim set (`iss,sub,aud,exp,nbf,iat,jti,tenant,ver,scope,acr,amr`); rule that resource servers enforce `aud`. Defines warn-then-enforce rollout. | SO, BK, PS, GP, AS | Yes (at enforce) | P0 | — |
| **RFC-002 — KMS Signing & Key Rotation** | Signing delegated to KMS/HSM; dual-sign rotation; JWKS publishes current+previous; kid discipline; retired-key pruning. | SO, INFRA | No | P0 | RFC-009 |
| **RFC-003 — Sender-Constrained Tokens** | DPoP for public clients, mTLS-bound for confidential; proof-of-possession verification contract. | SO, BK, apps | Yes (at default-on) | P1 | RFC-001, RFC-006 |
| **RFC-004 — backendkit PEP & Middleware Contract** | The mandatory enforcement chain: authN → authZ → tenant context → validation → audit; stable middleware API + SemVer policy. | BK, apps | Yes (when mandatory) | P0 | RFC-001, RFC-005 |
| **RFC-005 — Policy-as-Code (PDP) & Decision Contract** | Declarative policy format, decision request/response schema, RBAC+ABAC model, object-level checks. | BK, INFRA | No | P0 | RFC-008 |
| **RFC-006 — Workload Identity & Mesh mTLS** | SPIFFE IDs, automatic mTLS, default-deny east-west authorization. | INFRA, all | No (additive) | P0 | — |
| **RFC-007 — Tamper-Evident Audit** | Audit event schema; append-only/hash-chained store; independence from producers; required fields (principal, tenant, action, object, decision, correlation id). | INFRA, SO, BK | No | P0 | RFC-008 |
| **RFC-008 — Observability Standard** | OTel logs/metrics/traces conventions; correlation-ID generation & propagation (incl. async); redaction-at-source rules. | INFRA, BK, all | No | P0 | — |
| **RFC-009 — Dynamic Secrets & Key Ownership** | Short-lived secrets/dynamic DB creds; one-owner-one-secret; no static secrets; rotation intervals. | INFRA, SO, BK, apps | No | P0 | RFC-006 |
| **RFC-010 — Tenant Isolation (RLS + Envelope Encryption)** | Mandatory RLS pattern; per-tenant data keys for regulated fields; cryptographic tenant erasure. | BK, apps, INFRA | Yes (when enforced) | P1 | RFC-002, RFC-004 |
| **RFC-011 — MFA & Passkeys** | WebAuthn/passkey primary, TOTP fallback, step-up for sensitive ops, recovery flows. | SO | No (additive; mandatory later) | P1 | RFC-002 |
| **RFC-012 — Revocation Propagation & Token Freshness** | Short access-token TTL + revocation signal / introspection for high-assurance; token-version mass revocation; freshness SLA. | SO, BK, apps | No | P1 | RFC-001, RFC-013 |
| **RFC-013 — Distributed State** | Shared store contract for sessions, rate-limit counters, revocation freshness; multi-instance semantics. | INFRA, SO, BK | No | P1 | RFC-006 |
| **RFC-014 — CI/CD Provenance & Gates** | Build/test/scan/sign/attest pipeline; SLSA-style provenance; admission policy; ephemeral deploy identity. | INFRA, all | No | P1 | RFC-006 |
| **RFC-015 — Platform Conformance Contract & Versioning** | The checklist a service satisfies to be production-eligible; SemVer rules; automated conformance checks. | all | No | P1 | RFC-004, RFC-008 |
| **RFC-016 — Delegation & Impersonation** | Token-exchange delegation (`act`); audited, time-boxed, step-up impersonation; downstream visibility of both principals. | SO, BK | No | P2 | RFC-001, RFC-007 |
| **RFC-017 — AI Gateway Contract** | Single mediated AI API; caller identity + tenant partitioning; prompt/response governance; provider abstraction; audit. | AIG, BK, apps | No | P2 | RFC-001, RFC-007, RFC-009 |
| **RFC-018 — Resilience: HA, Backup & DR** | RPO/RTO per service; multi-zone HA; verified/tested backups; DR drill cadence; tenant-aware restore. | INFRA, all | No | P1 | RFC-013, RFC-002 |
| **RFC-019 — Federation** | Upstream OIDC/SAML brokering behind a provider abstraction; identity normalization + tenant mapping. | SO | No | P2 | RFC-001, RFC-011 |

**Authoring order (by readiness, not calendar):** RFC-006, RFC-008, RFC-009 first (substrate contracts) → RFC-002, RFC-007, RFC-005, RFC-001 → RFC-004, RFC-013, RFC-014 → RFC-003, RFC-010, RFC-011, RFC-012, RFC-015 → RFC-016, RFC-017, RFC-018, RFC-019.

Every RFC MUST contain a **Compatibility & Rollout** section describing the observe→enforce path, the feature flag(s), the deprecation window, and the back-out — consistent with the transformation principles in `PROGRAM-ROADMAP.md §2`.
