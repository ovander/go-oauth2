# EPIC ROADMAP

Capabilities (`PROGRAM-ROADMAP.md §3`) become GitHub Epics. Each Epic is independently trackable, maps to one or more RFCs, and carries Objectives, Deliverables, Acceptance Criteria, and Success Metrics. Epics are labeled by workstream and target release line.

---

## EPIC-1 — Workload Identity & Service Mesh (C1 / RFC-006)
- **Objective:** Give every workload a cryptographic SPIFFE identity and automatic mTLS; make east-west networking default-deny, identity-based.
- **Deliverables:** Mesh deployed; identity issuance for all services; per-edge authorization policies; migration of internal calls to mTLS.
- **Acceptance Criteria:** 100% of internal traffic is mutually authenticated; an unidentified workload cannot connect; policies are declarative and reviewed.
- **Success Metrics:** % east-west traffic on mTLS = 100%; zero plaintext internal connections; default-deny verified by test.

## EPIC-2 — Dynamic Secrets (C2 / RFC-009)
- **Objective:** Replace static secrets with short-lived, dynamically-issued credentials owned by one identity each.
- **Deliverables:** Secrets manager integrated; dynamic DB credentials; provider keys vaulted; removal of secrets from env/images.
- **Acceptance Criteria:** No static secret in any repo, image, or env file; every secret has an owner and rotation interval; fetch is authenticated and audited.
- **Success Metrics:** static-secret count = 0; % secrets auto-rotated = 100%.

## EPIC-3 — KMS/HSM Key Custody & Rotation (C3 / RFC-002)
- **Objective:** Move all signing/decryption into KMS/HSM; keys are used, never exported; rotation is automated and audited.
- **Deliverables:** KMS-backed signer in Socrate; dual-sign rotation; JWKS current+previous; master key for envelope encryption; rotation scheduler emitting audit events.
- **Acceptance Criteria:** No private key material on disk or in process; rotation is zero-downtime; verification works across a rotation; rotation emits an audit event.
- **Success Metrics:** % keys in KMS = 100%; rotation MTTR automated; verification success across rotation = 100%.

## EPIC-4 — Observability Pipeline (C4 / RFC-008)
- **Objective:** Uniform OTel logs/metrics/traces with a correlation ID propagated end-to-end (including async).
- **Deliverables:** OTel SDK in backendkit + apps; correlation propagation; redaction-at-source; dashboards + SLOs per service.
- **Acceptance Criteria:** Any request reconstructable across hops by correlation ID; no secret/PII in telemetry; every service emits RED/USE metrics.
- **Success Metrics:** % services emitting full telemetry = 100%; trace completeness across hops = 100%.

## EPIC-5 — Tamper-Evident Audit (C5 / RFC-007)
- **Objective:** An append-only, hash-chained audit stream independent of audited systems.
- **Deliverables:** Audit event schema; immutable store; backendkit + Socrate audit emission; legal-hold capability.
- **Acceptance Criteria:** Audit entries are immutable and verifiable; every entry names principal, tenant, action, object, decision, correlation id; tampering is detectable.
- **Success Metrics:** audit coverage of sensitive actions = 100%; chain-integrity verification passes continuously.

## EPIC-6 — CI/CD Provenance & Gates (C6 / RFC-014)
- **Objective:** Every artifact built, tested, scanned, signed, attested, and deployed through policy gates.
- **Deliverables:** Pipeline-as-code in each repo; signing + provenance; dependency/container/secret scanning; ephemeral deploy identity; admission policy.
- **Acceptance Criteria:** Unsigned/unattested artifacts cannot deploy; gates block on failing tests/scans/conformance.
- **Success Metrics:** % deploys via gated pipeline = 100%; unsigned deploys = 0.

## EPIC-7 — Token Audience Binding (C7 / RFC-001)
- **Objective:** Every token carries a specific `aud`; every resource server enforces it.
- **Deliverables:** Canonical claim set in Socrate; verification library in backendkit; per-app audience registration; warn-mode telemetry then enforce.
- **Acceptance Criteria:** A token minted for App A is rejected by App B; claim set matches RFC-001; enforce flips only after warn-mode parity.
- **Success Metrics:** % resource servers enforcing audience = 100%; cross-audience acceptance = 0.

## EPIC-8 — Sender-Constrained Tokens (C8 / RFC-003)
- **Objective:** A stolen token is unusable without its proof-of-possession key.
- **Deliverables:** DPoP for public clients; mTLS-binding for confidential services; verification in backendkit; rollout flags.
- **Acceptance Criteria:** Bearer-only replay of a constrained token fails; binding verified at the resource server.
- **Success Metrics:** % tokens sender-constrained = 100% by v2.x; replay test fails as expected.

## EPIC-9 — MFA & Passkeys (C9 / RFC-011)
- **Objective:** Phishing-resistant human authentication with step-up for sensitive operations.
- **Deliverables:** WebAuthn/passkey enrollment + auth; TOTP fallback; step-up flow; recovery; admin-mandatory policy.
- **Acceptance Criteria:** Sensitive/admin operations require a second factor; passkeys supported; recovery is secure and audited.
- **Success Metrics:** % human logins with MFA = 100% (admins first); step-up enforced on sensitive ops.

## EPIC-10 — Policy Engine / PDP (C10 / RFC-005)
- **Objective:** Centralized, declarative, versioned policy decoupled from application code.
- **Deliverables:** Policy engine; decision request/response contract; RBAC+ABAC model; policy test harness; object-level decision support.
- **Acceptance Criteria:** Authorization decisions come from policy, not ad-hoc code; policies are tested and versioned; one decision per request.
- **Success Metrics:** % authz decisions via PDP = 100%; policy test coverage on critical paths high.

## EPIC-11 — backendkit PEP (C11 / RFC-004)
- **Objective:** One mandatory enforcement point per request in every application, with tenant-context propagation.
- **Deliverables:** PEP middleware; tenant-context contract; verification + PDP client; adoption guide; conformance check.
- **Acceptance Criteria:** Every request passes exactly one PEP decision; tenant context is immutable per request; apps cannot bypass it.
- **Success Metrics:** % apps on PEP = 100%; requests without an authz decision = 0.

## EPIC-12 — Tenant Data Isolation (C12 / RFC-010)
- **Objective:** Tenant isolation enforced independently at the data layer.
- **Deliverables:** RLS on tenant tables; per-tenant envelope encryption for regulated fields; cryptographic erasure; data-access primitives in backendkit.
- **Acceptance Criteria:** A query cannot return another tenant's rows even if application code errs; regulated fields unreadable at storage layer; tenant erasure destroys keys.
- **Success Metrics:** % tenant tables with RLS = 100%; cross-tenant leakage tests = 0 failures.

## EPIC-13 — Distributed State (C13 / RFC-013)
- **Objective:** Shared store for sessions, rate limits, and revocation freshness enabling multi-instance/multi-region.
- **Deliverables:** Distributed store; rate-limit + session + revocation-freshness adapters; multi-instance tests.
- **Acceptance Criteria:** Limits and revocation are consistent across instances; state survives instance restart.
- **Success Metrics:** cross-instance consistency verified; single-node state dependencies = 0.

## EPIC-14 — Revocation Propagation (C14 / RFC-012)
- **Objective:** Logout/revocation honored everywhere within a defined freshness window.
- **Deliverables:** Short access TTLs; revocation signal/introspection path; token-version mass revocation; freshness SLA docs.
- **Acceptance Criteria:** A revoked identity is rejected platform-wide within the freshness window.
- **Success Metrics:** mean time-to-revoke ≤ freshness window; post-revocation acceptance = 0.

## EPIC-15 — AI Gateway (C15 / RFC-017)
- **Objective:** The only path to model providers, with per-tenant isolation and governance.
- **Deliverables:** Gateway service; identity+tenant on every request; provider abstraction; prompt/response governance + audit; no direct provider calls from apps.
- **Acceptance Criteria:** No app calls a provider directly; no cross-tenant context; every AI request audited with tenant + caller.
- **Success Metrics:** % AI traffic via gateway = 100%; cross-tenant context incidents = 0.

## EPIC-16 — Resilience: HA + DR (C16 / RFC-018)
- **Objective:** Multi-zone HA, tested DR, verified backups, tenant-aware restore.
- **Deliverables:** HA topologies; automated encrypted backups; DR runbooks + scheduled drills; RPO/RTO per service.
- **Acceptance Criteria:** No single zone is a SPOF; restores are tested and pass; DR drills meet RPO/RTO.
- **Success Metrics:** DR drill pass rate = 100%; backup restore verification = 100%.

## EPIC-17 — Delegation & Impersonation (C17 / RFC-016)
- **Objective:** Safe delegation and heavily-audited impersonation.
- **Deliverables:** Token-exchange delegation with `act`; impersonation flow with step-up + time box + audit; downstream dual-principal visibility.
- **Acceptance Criteria:** Delegated/impersonated calls show both principals; impersonation requires step-up and auto-expires.
- **Success Metrics:** impersonation events 100% audited with both principals.

## EPIC-18 — Federation (C18 / RFC-019)
- **Objective:** Onboard external IdPs without changing application code.
- **Deliverables:** Provider abstraction; OIDC + SAML brokering; identity normalization + tenant mapping.
- **Acceptance Criteria:** A new external IdP is added via configuration; federated identities map to platform tenants.
- **Success Metrics:** new-IdP onboarding requires no app code change.

---

**Epic → Release mapping** is in `RELEASE-ROADMAP.md`; **Epic → repository work** is in `REPOSITORY-ROADMAP.md`.
