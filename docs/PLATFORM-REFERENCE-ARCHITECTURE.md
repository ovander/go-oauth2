# PLATFORM REFERENCE ARCHITECTURE

**Status:** Constitutional — Normative
**Audience:** Every engineer, reviewer, and operator building on or within the platform.
**Authority:** This document is the canonical target architecture. All future implementation decisions MUST align with it. Deviations require an approved ADR (see §10) referencing the specific rule being excepted.
**Language:** The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are used per RFC 2119. "The platform" means the union of Socrate, backendkit, ParaShift, GPWA, Ascenda, and all future SaaS applications.

> This document describes the architecture that **should exist**. It is a destination, not a description of any current system.

---

## Table of Contents
1. Architectural Principles
2. Reference Architecture
3. Trust Boundaries
4. Identity Architecture
5. Authorization Architecture
6. Data Architecture
7. Security Controls
8. Observability
9. Operations
10. Platform Standards
11. Extension Model
12. Reference Diagrams
13. Engineering Rules (Immutable)
14. Platform Quality Attributes
15. Technology Decisions

---

## Section 1 — Architectural Principles

These principles are ranked. When two principles conflict, the higher-ranked one wins.

1. **Identity First.** Every actor — human, service, or workload — has a strong, verifiable, cryptographic identity *before* it does anything else. There are no anonymous privileged paths. Identity is the primary axis of every security and observability decision.

2. **Zero Trust.** No network location, hostname, header, token, cache, log, or peer service is trusted by default. Every request is authenticated and authorized **at the point of use**, independently, on its own merits — not because of where it came from. Trust is never inherited across a hop.

3. **Secure by Default.** The default configuration of every component is the most secure configuration. Security is opt-out (and opt-out requires an explicit, audited decision), never opt-in. A component that is misconfigured fails **closed**.

4. **Least Privilege.** Every identity holds the minimum capability required for its function, scoped to the narrowest audience, tenant, object, and time window. Privilege is granted explicitly, expires by default, and is reviewed on a schedule.

5. **Defense in Depth.** Every critical asset is protected by **multiple independent controls** such that the failure or compromise of any single control does not yield the asset. No control is a single point of total trust.

6. **Observability First.** A capability is not "done" until it emits structured logs, metrics, traces, and audit events carrying a correlation ID and the acting identity. If it cannot be observed, it cannot be operated or trusted.

7. **Automation First.** Provisioning, deployment, key rotation, secret rotation, scaling, and recovery are automated and reproducible. Manual production access is an exception that is logged, time-bound, and reviewed.

8. **Immutable Infrastructure.** Servers and artifacts are never mutated in place. Changes are delivered by replacing immutable, versioned, signed artifacts. Running state is disposable.

9. **Stateless Services.** Application services hold no durable local state. All state lives in designated stateful backing services (databases, object stores, key managers, message brokers), enabling horizontal scaling, zero-downtime deploys, and clean failure recovery.

10. **API First.** Every capability is exposed through a versioned, documented, contract-tested API. Internal and external consumers use the same contracts. The contract is the source of truth; implementations conform to it.

11. **Backwards Compatibility.** Public contracts evolve without breaking existing consumers. Breaking changes require a new major version and a documented deprecation window.

12. **Cloud Agnostic.** The platform depends on **portable abstractions** (KMS, object storage, message broker, container runtime) rather than proprietary services directly. Provider-specific implementations sit behind interfaces so the platform can run in any compliant environment.

---

## Section 2 — Reference Architecture

The platform is a set of independently deployable, independently identifiable services communicating over mutually-authenticated channels.

### 2.1 Identity Platform — **Socrate**
- **Responsibilities:** Authoritative source of identity, authentication, OAuth 2.1 / OIDC authorization, token issuance, JWKS publication, tenant identity, consent, session lifecycle, service-account issuance, and the identity audit stream.
- **Interfaces:** OIDC discovery, authorization, token, userinfo, introspection, revocation, JWKS, RP-initiated + back-channel logout; an admin API for identity lifecycle; an event stream for identity events.
- **Dependencies:** Key Management Service (signing), Identity Database, Secrets Manager, Messaging (events).
- **Security boundary:** The most privileged boundary on the platform. Socrate issues the credentials every other component consumes; it MUST therefore hold the highest assurance controls. Socrate's signing capability is delegated to a KMS/HSM — Socrate **never holds extractable private key material**.
- **Ownership:** Platform Identity team.

### 2.2 Framework — **backendkit**
- **Responsibilities:** The mandatory security and request-handling substrate that every business application embeds. Provides authentication middleware, authorization enforcement (policy decision + enforcement points), tenant-context propagation, input validation, rate limiting, transport security, structured logging/tracing, audit emission, and safe data-access primitives.
- **Interfaces:** In-process middleware chain + libraries with stable, semantically-versioned APIs; a policy-evaluation client; an audit/event client.
- **Dependencies:** Socrate (JWKS, introspection), Policy service, Observability pipeline, Secrets Manager.
- **Security boundary:** backendkit is the **Policy Enforcement Point** in every application. It is the platform's guarantee that every request is verified consistently, regardless of which application handles it.
- **Ownership:** Platform Framework team.

### 2.3 Business Applications — **ParaShift, GPWA, Ascenda, future SaaS**
- **Responsibilities:** Domain logic only. They consume identity from Socrate and enforce authorization through backendkit. They own their domain data within their tenant boundaries.
- **Interfaces:** Versioned public APIs; standardized health/readiness/observability endpoints.
- **Dependencies:** backendkit (mandatory), Socrate (tokens), their own databases, Messaging, optionally the AI Layer.
- **Security boundary:** Each application is a distinct trust boundary with its own service identity and its own resource-server audience. An application MUST reject any token not explicitly audience-bound to it.
- **Ownership:** Each application's product team; framework conformance owned by the Framework team.

### 2.4 Database
- **Responsibilities:** Durable, tenant-scoped storage of relational data.
- **Interfaces:** Accessed only through backendkit data-access primitives; never raw, ad-hoc connections from application code.
- **Dependencies:** KMS (encryption keys), Secrets Manager (credentials).
- **Security boundary:** Row-Level Security enforces tenant isolation at the engine, independent of application code. Encryption at rest is mandatory. Database credentials are short-lived and issued dynamically.
- **Ownership:** Per-application data owners; platform-wide standards owned by the Data Platform team.

### 2.5 Messaging
- **Responsibilities:** Asynchronous, ordered, durable event transport between services (identity events, audit events, domain events).
- **Interfaces:** Topic/stream contracts with versioned schemas in a schema registry.
- **Dependencies:** KMS (encryption), service identities (mTLS/SASL).
- **Security boundary:** Producers and consumers are mutually authenticated; every message carries tenant + correlation + producer identity. Topics are authorized per-service.
- **Ownership:** Platform Messaging team.

### 2.6 AI Layer — **AI Gateway**
- **Responsibilities:** The sole, mediated path to model providers. Enforces per-tenant isolation, prompt/response governance, PII handling, redaction, audit, and provider abstraction.
- **Interfaces:** A single internal API; no application calls a model provider directly.
- **Dependencies:** Socrate (caller identity), Secrets Manager (provider keys), Observability, Policy.
- **Security boundary:** Every AI request carries an authenticated caller identity and a tenant. Context is strictly tenant-partitioned; no cross-tenant context is ever assembled. Provider credentials live only inside the gateway.
- **Ownership:** Platform AI team.

### 2.7 Secrets
- **Responsibilities:** Central issuance, storage, rotation, and revocation of secrets (DB credentials, provider API keys, service credentials).
- **Interfaces:** Authenticated secret-fetch + dynamic-credential APIs; short-lived leases.
- **Dependencies:** KMS, service identity.
- **Security boundary:** Secrets are never written to disk, environment files, images, or logs. Every secret has exactly one owning service identity and a defined rotation interval.
- **Ownership:** Platform Security team.

### 2.8 Key Management (KMS/HSM)
- **Responsibilities:** Generation, storage, rotation, and *use* of cryptographic keys. Signing and decryption are performed **inside** the boundary; private keys never leave it.
- **Interfaces:** Sign / verify / encrypt / decrypt / rotate operations, authorized per key per identity.
- **Security boundary:** The cryptographic root of trust. Access is identity-bound, rate-limited, and fully audited.
- **Ownership:** Platform Security team.

### 2.9 Logging & Monitoring (Observability Pipeline)
- **Responsibilities:** Collection, processing, storage, and alerting over logs, metrics, traces, and audit events.
- **Interfaces:** OpenTelemetry ingestion; query + dashboard + alerting surfaces; an immutable audit store.
- **Security boundary:** The audit store is append-only and tamper-evident, isolated from the systems it observes. Sensitive fields are redacted at source.
- **Ownership:** Platform Observability team.

### 2.10 CI/CD
- **Responsibilities:** Build, test, scan, sign, and deploy immutable artifacts; enforce policy gates.
- **Interfaces:** Pipeline-as-code in each repository; a central artifact registry with provenance.
- **Security boundary:** The pipeline holds privileged deploy identity; it is itself a high-value trust boundary with least-privilege, ephemeral credentials and signed provenance (SLSA-style).
- **Ownership:** Platform Engineering team.

### 2.11 Infrastructure
- **Responsibilities:** Compute, container orchestration, service mesh, network, and the portable cloud abstractions.
- **Interfaces:** Declarative infrastructure-as-code; a service mesh providing workload identity and mTLS.
- **Security boundary:** Workloads receive cryptographic identity (SPIFFE) from the mesh; all east-west traffic is mutually authenticated and encrypted.
- **Ownership:** Platform Infrastructure team.

### 2.12 Networking
- **Responsibilities:** Segmentation, ingress/egress control, and encrypted transport.
- **Security boundary:** Default-deny. Connectivity is explicitly granted per source-identity → destination-identity. There is no implicit "internal network" trust.
- **Ownership:** Platform Infrastructure team.

---

## Section 3 — Trust Boundaries

For every boundary: **what is trusted**, **what is never trusted**, **verification required**.

| Boundary | Trusted | Never Trusted | Verification Required |
|---|---|---|---|
| **External (Internet → Edge)** | Nothing | Source IP, headers, TLS SNI alone | TLS 1.3; WAF; per-request auth; bot/rate controls |
| **Human → Platform** | A verified human identity *after* MFA | Password alone; session age; device | MFA (phishing-resistant); device posture; re-auth for sensitive ops |
| **Machine → Platform** | A workload with a valid mesh identity | Service name, IP, or shared secret | SPIFFE/mTLS identity + short-lived, audience-bound token |
| **Client → Socrate** | A registered client proving PKCE/possession | redirect_uri input, client-asserted identity | Exact redirect match; PKCE; client authentication |
| **Application ← Socrate token** | A token that is signature-valid **and** audience-bound to this app **and** unexpired **and** sender-constrained | Any token not bound to this audience; any unrevoked-status assumption | Verify signature via JWKS; verify `iss`, `aud`, `exp`, `nbf`; verify DPoP/mTLS binding; check revocation freshness |
| **Application → backendkit** | The framework's enforcement result | Application's own claim that it "already checked" | Single mandatory enforcement point per request |
| **Service → Database** | A connection bearing a tenant context | Application-supplied tenant id without enforcement | RLS at the engine + tenant context set per transaction |
| **Service → AI Gateway** | An authenticated caller + tenant | Prompt content; provider trust | Caller identity + tenant partitioning + output governance |
| **Service → Secrets/KMS** | A specific service identity authorized for a specific secret/key | Broad/standing access | Per-identity, per-resource authorization; short leases; audit |
| **CI/CD → Production** | Signed artifact + passing gates | Unsigned or unattested builds | Provenance verification; policy gates; ephemeral deploy identity |
| **Cloud/Infra** | Declarative, reviewed IaC | Console/manual changes | GitOps; drift detection; default-deny networking |

**Universal rule:** trust is **per-request and per-hop**. A request authenticated at the edge is re-verified at the application; a request authorized at the application is re-isolated at the database.

---

## Section 4 — Identity Architecture

### 4.1 Protocols
- **OAuth 2.1** is the authorization framework. The **authorization code flow with PKCE** is the only interactive flow. Implicit and password grants do not exist. **Client credentials** is the machine-to-machine grant. **Token exchange (RFC 8693)** provides delegation; **resource indicators (RFC 8707)** scope tokens to audiences.
- **OIDC** provides authentication, ID tokens, discovery, and session management including **back-channel logout**.
- For regulated workloads, **PAR (RFC 9126)** and **JAR (RFC 9101)** secure authorization requests.

### 4.2 Tokens (JWT)
- Access and ID tokens are JWTs signed with an asymmetric algorithm whose private key lives only in KMS/HSM. The signing algorithm is pinned (an explicit allow-list); `alg:none` and symmetric-confusion are structurally impossible.
- Every token carries: `iss`, `sub`, `aud` (the specific resource server), `exp`, `nbf`, `iat`, `jti`, a tenant claim, a token-version claim, and the granted scopes. ID tokens additionally carry `nonce`, `auth_time`, `acr`, and `amr`.
- **Audience binding is mandatory and enforced at every resource server.** A token minted for application A is rejected by application B.
- Tokens are **sender-constrained** (DPoP, or mTLS-bound for confidential services). A stolen token is unusable without the proof-of-possession key.
- Access tokens are short-lived (minutes). They are never the unit of long-term trust.

### 4.3 JWKS
- Public keys are published at a stable JWKS endpoint with key IDs. The set includes current and recently-rotated keys to support seamless verification across rotation. Unknown key IDs are rejected, not defaulted.

### 4.4 Token Lifecycle, Refresh, Revocation
- **Refresh tokens** are sender-constrained, single-use, and rotated on every use; reuse is detected and revokes the lineage.
- **Revocation** is authoritative and **propagates**: resource servers verify revocation freshness (short token TTL + a revocation signal, or introspection for high-assurance audiences). A logged-out or revoked identity is honored nowhere after its freshness window.
- A per-identity **token-version** allows instant mass revocation (logout-everywhere, credential change, compromise response).

### 4.5 Service Accounts & Machine Identity
- Services authenticate with **workload identity** (SPIFFE/mTLS) from the mesh and exchange it for short-lived, audience-scoped access tokens. There are no long-lived shared service secrets.
- Each service account is bound to exactly one tenant scope (or is explicitly a platform-scoped identity with elevated review).

### 4.6 Tenant Identity
- Tenancy is a first-class, immutable property of every identity and every token. A request's tenant is derived from the verified token and the routing context and **cannot be changed** mid-request. Cross-tenant operations require a distinct, explicitly-authorized platform identity.

### 4.7 Impersonation & Delegation
- **Delegation** (a service acting *on behalf of* a user) uses token exchange, producing a token that records both the actor (`act`) and the subject. **Impersonation** (an admin acting *as* a user) is a separate, heavily-audited capability requiring step-up auth, explicit scope, a time box, and an immutable audit record naming both principals. The downstream system always sees both identities.

### 4.8 Human Authentication
- **MFA is mandatory** for all human identities; **phishing-resistant factors (passkeys / WebAuthn)** are the primary method, with TOTP as a fallback. Privileged operations require **step-up** re-authentication.
- Passwords (where they exist) use a modern memory-hard or adaptive hash with strong policy and breach checking; they are always a *factor*, never sufficient alone for privileged access.

### 4.9 Future Federation
- The architecture supports **upstream identity brokering** (enterprise OIDC, SAML) and **social login** behind a provider abstraction, so external IdPs can be onboarded without changing application code. Federated identities are normalized into platform identities with explicit tenant mapping.

---

## Section 5 — Authorization Architecture

Authorization is a **policy decision** made at a logically central Policy Decision Point (PDP) and enforced at a Policy Enforcement Point (PEP) in backendkit on **every** request.

- **RBAC** provides coarse, role-based capability at the tenant and platform level (e.g., tenant-admin, platform-admin). Roles are explicit and never implied by data ownership alone.
- **ABAC** refines decisions using attributes of the subject, resource, tenant, action, and environment (time, device posture, risk).
- **Scopes** bound what a *token* may attempt; they are a ceiling, not the decision.
- **Permissions** are fine-grained, named capabilities mapped from roles/attributes by policy.
- **Policies** are declarative, versioned, tested, and stored as code. Policy is decoupled from application logic so it can be reviewed and evolved independently.
- **Object authorization** is mandatory: every access to a specific object verifies the principal's relationship to *that object*, not merely possession of a role. There is no implicit object access.
- **Tenant authorization** is enforced at the data layer (RLS) **in addition to** the application layer — independent controls.
- **Administrative authorization** is explicit, separated from end-user authorization, requires elevated identity + step-up + audit, and is never reachable by a default user role.

**Invariant:** every request yields **exactly one** authorization decision from the PEP — never zero (missing check), never an inconsistent set.

---

## Section 6 — Data Architecture

### 6.1 Classification
| Class | Definition | Examples |
|---|---|---|
| **Public** | Intended for anyone | Marketing content, public keys (JWKS) |
| **Internal** | Non-sensitive operational data | Service metadata, non-PII config |
| **Confidential** | Business-sensitive | Tenant business data, domain records |
| **Restricted** | High-impact if disclosed | Credentials, tokens, secrets, private keys |
| **Regulated** | Governed by law/standard | PII, PHI, cardholder data |

### 6.2 Encryption
- **In transit:** TLS 1.3 externally; mTLS internally for all east-west traffic. No plaintext transport anywhere.
- **At rest:** All Confidential, Restricted, and Regulated data is encrypted at rest. Regulated data fields are additionally **application-layer (envelope) encrypted** with tenant-scoped data keys, so storage-layer access alone does not reveal them.
- **In use:** Restricted material (signing keys, decryption keys) is used only inside KMS/HSM.

### 6.3 Key Ownership
- Every key has exactly one owning identity and a defined purpose. **Signing keys** are owned by Socrate's identity (used via KMS). **Tenant data keys** are envelope-encrypted under a KMS master key and scoped per tenant. No key serves two purposes; no key is shared across trust boundaries.

### 6.4 Retention
- Each data class has a defined, enforced retention period implemented by automated lifecycle policies. Audit and regulated data retention meets the strictest applicable compliance requirement. Retention is enforced by the platform, not left to operators.

### 6.5 Deletion
- Deletion is **complete and verifiable**: erasure propagates to primary stores, derived stores, caches, search indexes, message logs, and backups within a defined window. Tenant offboarding triggers cryptographic erasure (destroying tenant data keys) as the authoritative deletion mechanism. Data-subject erasure (GDPR) is a first-class, audited workflow.

---

## Section 7 — Security Controls (Mandatory per Layer)

| Layer | Mandatory Controls |
|---|---|
| **Identity** | MFA (passkeys), OAuth 2.1 + PKCE, audience-bound tokens, DPoP/mTLS sender-constraining, short TTLs, rotating single-use refresh, token-version revocation, JWKS rotation |
| **Transport** | TLS 1.3 external, mTLS internal (mesh), default-deny networking, no plaintext, HSTS |
| **Application** | Single PEP per request, input validation + output encoding, bounded request bodies, strict CORS, security headers (CSP/HSTS/frame-deny/nosniff), idempotency for mutations |
| **Framework (backendkit)** | Mandatory auth + authz middleware, tenant-context propagation, rate limiting, audit emission, safe data-access primitives, fail-closed defaults |
| **Database** | Row-Level Security, encryption at rest, dynamic short-lived credentials, parameterized access only, per-tenant data keys for regulated fields |
| **Infrastructure** | Workload identity (SPIFFE), immutable signed artifacts, image scanning, admission policy, segmented default-deny network |
| **Operations** | Automated key + secret rotation, tamper-evident audit shipped off-host, SIEM correlation, anomaly alerting, break-glass with approval + full audit |

---

## Section 8 — Observability

- **Logging:** Structured (JSON), event-typed, carrying correlation ID, tenant, and acting identity. **No secrets or unredacted regulated data are ever logged.** Redaction happens at source.
- **Tracing:** Distributed tracing (OpenTelemetry) spans every hop, edge to database to AI gateway, joined by a single trace/correlation ID propagated across services and async messages.
- **Metrics:** RED (Rate/Errors/Duration) and USE (Utilization/Saturation/Errors) for every service, plus security metrics (auth failures, denials, anomaly signals) and SLO indicators.
- **Audit:** A distinct, **append-only, tamper-evident** (hash-chained/WORM) stream, independent of the audited systems. Every audit entry names the principal, tenant, action, object, decision, and correlation ID. Audit is non-repudiable and survives compromise of the producing service.
- **Correlation IDs:** Generated at the edge (or accepted from a trusted upstream), propagated everywhere, and present on every log line, span, audit entry, and outbound call.
- **Incident response:** Telemetry is sufficient to reconstruct any request's full path and authorization decision. Detections trigger runbooks (§9).
- **Evidence preservation:** On incident, relevant logs/audit/traces are placed under legal-hold with immutable retention, isolated from routine lifecycle deletion.

---

## Section 9 — Operations

- **Secret management:** Centralized, dynamic, short-lived secrets with automated rotation; no secret in code, image, env file, or log; one owner per secret.
- **Key management:** KMS/HSM-backed; automated, scheduled rotation; rotation is audited and emits an event; retired keys remain available for verification only until all tokens they signed expire, then are pruned.
- **Deployment:** Immutable, signed artifacts promoted through environments by CI/CD with policy gates; declarative and reproducible.
- **Rollback:** Every deploy is reversible to the previous immutable version with a single, automated action; database changes are backwards-compatible (expand/contract) to make rollback safe.
- **Blue/Green (and canary):** Zero-downtime releases via blue/green or progressive canary with automated health/SLO gates and automatic rollback on regression.
- **Disaster Recovery:** Defined RPO/RTO per service; cross-zone (and where required cross-region) redundancy; DR is **tested on a schedule**, not assumed.
- **Backups:** Automated, encrypted, tenant-aware, integrity-verified, restore-tested backups. An untested backup is not a backup.
- **Incident handling:** Defined severities, on-call, communication paths, and a blameless postmortem process feeding ADRs and roadmap.
- **Runbooks:** Every alert maps to a runbook. Every recurring manual action is a runbook on its way to automation.
- **Break-glass:** Emergency elevated access requires multi-party approval, is time-boxed, is fully audited, and auto-expires.
- **Access reviews:** Human and machine entitlements are reviewed on a defined cadence; unused privilege is revoked automatically.

---

## Section 10 — Platform Standards

- **Repository layout:** A consistent, documented layout across services (clear separation of API contracts, domain/services, data access, configuration, infrastructure). backendkit conformance is structural, not optional.
- **Naming:** Consistent, predictable naming for services, resources, events, topics, metrics, and roles. Names encode ownership and tenancy where relevant.
- **Versioning / SemVer:** All public contracts and shared libraries follow **Semantic Versioning**. Breaking change ⇒ major version. APIs are versioned in the path or media type.
- **Documentation:** Every service ships an API contract (OpenAPI/AsyncAPI), an architecture overview, runbooks, and an ownership record. Documentation lives with the code and is reviewed with it.
- **Testing:** Mandatory unit, integration, contract, and security tests. Authorization and tenant-isolation tests are first-class. A change without tests does not merge.
- **CI/CD:** Every repository has pipeline-as-code performing build, test, dependency + container + secret scanning, artifact signing, and gated deploy.
- **Security reviews:** Threat-model-driven review for new services and for changes to identity, authorization, tenancy, cryptography, or data classification.
- **RFC process:** Cross-cutting or platform-level changes begin as an RFC, reviewed by affected owners before implementation.
- **ADR process:** Every significant or precedent-setting decision (including any exception to this constitution) is recorded as an immutable Architecture Decision Record.
- **Release process:** Releases are versioned, changelogged, signed, progressively rolled out, and reversible.

---

## Section 11 — Extension Model (How a new SaaS application joins)

A new application becomes a first-class platform citizen by satisfying the **Platform Conformance Contract**:

1. **Identity integration:** Register as an OAuth client/resource server in Socrate with an explicit audience, exact redirect URIs, and the minimal scopes it requires. Obtain a workload identity from the mesh.
2. **Framework integration:** Embed backendkit. Authentication, authorization (PEP), tenant-context propagation, validation, rate limiting, and audit emission are inherited — not reimplemented.
3. **Database:** Provision a tenant-scoped store behind backendkit data-access primitives with RLS and encryption-at-rest enabled by default; obtain dynamic DB credentials from Secrets.
4. **Observability:** Emit OpenTelemetry logs/metrics/traces and audit events with correlation IDs and acting identity from day one; register dashboards and SLOs.
5. **Deployment:** Ship pipeline-as-code producing immutable, signed artifacts with the standard policy gates; expose standard health/readiness endpoints.
6. **Secrets:** Consume only dynamic, short-lived secrets from the Secrets Manager; hold no static credentials.
7. **Monitoring & Alerting:** Register service SLOs and alert routes mapped to runbooks.
8. **Security:** Pass the onboarding threat model and authorization/tenant-isolation test suite before receiving production traffic.

Conformance is **verified automatically** where possible (CI checks, policy admission) and is a precondition for production.

---

## Section 12 — Reference Diagrams

### 12.1 Logical Architecture
```
                         ┌──────────────────────────────┐
   Browser / SPA /       │            Edge               │  TLS 1.3, WAF, rate limiting
   Mobile / API client ─▶│  (Ingress + API Gateway)      │
                         └───────────────┬──────────────┘
                                         │  authenticated, correlation-tagged
              ┌──────────────────────────┼───────────────────────────┐
              ▼                          ▼                            ▼
        ┌───────────┐            ┌───────────────┐             ┌──────────────┐
        │  Socrate  │  JWKS /    │ Business Apps │  embeds     │  AI Gateway  │
        │   (IdP)   │  tokens ──▶│ (ParaShift,   │◀──backendkit│ (mediated AI)│
        └─────┬─────┘            │ GPWA, Ascenda)│             └──────┬───────┘
              │                  └───────┬───────┘                    │
   sign via   ▼                          │ RLS, dynamic creds         │ provider keys
        ┌───────────┐            ┌────────▼───────┐             ┌──────▼───────┐
        │  KMS/HSM  │            │   Databases    │             │  Providers   │
        └───────────┘            └────────────────┘             └──────────────┘
              ▲          all services ─▶ Messaging ─▶ Observability (logs/metrics/traces/AUDIT)
              └────────────── Secrets Manager ─── Service Mesh (SPIFFE/mTLS) ───────────────
```

### 12.2 Security Architecture
```
Layer 7  Application/PEP : backendkit verifies token, audience, tenant, policy → one decision
Layer 6  Identity        : Socrate (OAuth2.1/OIDC) + KMS signing + MFA/passkeys
Layer 5  Authorization   : PDP (policy-as-code) RBAC+ABAC, object-level checks
Layer 4  Data            : RLS + encryption-at-rest + tenant data keys
Layer 3  Transport       : TLS1.3 (north-south) / mTLS (east-west via mesh)
Layer 2  Network         : default-deny, identity-based segmentation
Layer 1  Platform        : signed immutable artifacts, workload identity, KMS root of trust
        Cross-cutting    : tamper-evident AUDIT + SIEM + dynamic SECRETS
```

### 12.3 Identity Flow
```
User ─▶ Edge ─▶ Socrate /authorize (PKCE) ─▶ MFA / passkey ─▶ consent
   ─▶ code ─▶ Socrate /token ─▶ {access(aud=App, DPoP-bound, short TTL), id_token, refresh(single-use)}
   ─▶ App: verify sig(JWKS)+iss+aud+exp+nbf+DPoP ─▶ backendkit PEP ─▶ tenant context ─▶ service
```

### 12.4 Authorization Flow
```
Request+token ─▶ backendkit PEP
     ├─ authenticate (sig, aud, exp, sender-constraint)
     ├─ derive principal + tenant (immutable for request)
     ├─ PDP evaluate(policy, subject, action, resource, attrs) ──▶ ALLOW/DENY  (exactly one)
     ├─ object-level check (principal ↔ this object)
     └─ DB access under tenant context (RLS) ─▶ response ─▶ AUDIT(principal, decision, object)
```

### 12.5 Deployment Architecture
```
Git ─▶ CI: build│test│scan(deps,image,secrets)│sign│attest ─▶ Artifact Registry (provenance)
   ─▶ CD: policy gate ─▶ Blue/Green or Canary ─▶ health/SLO gate ─▶ promote │ auto-rollback
   Infra: declarative IaC (GitOps) ─▶ mesh issues SPIFFE identity ─▶ default-deny network
```

### 12.6 Trust Boundaries
```
[Internet]→║edge║→[Apps]→║mesh mTLS║→[Services]→║RLS║→[DB]
   ║human:MFA║         ║token:aud+DPoP║        ║secret:lease║      ║key:KMS-only║
  Each ║ ║ is a verification gate. No gate inherits trust from the one before it.
```

### 12.7 Key Management
```
KMS/HSM (root)
  ├─ Signing keys (Socrate) ── sign-only API ── rotated on schedule ── public half ▶ JWKS
  ├─ Master encryption key ── wraps ▶ tenant data keys (envelope) ── per-tenant erasure
  └─ All operations audited; private material never exported; access identity-bound
```

### 12.8 Incident Response
```
Detect (SIEM/anomaly/alert) ─▶ Triage(severity) ─▶ Contain(token-version bump / revoke / isolate)
   ─▶ Evidence(legal-hold immutable audit) ─▶ Eradicate(rotate keys/secrets, patch)
   ─▶ Recover(restore tested backup / failover) ─▶ Postmortem ─▶ ADR + roadmap update
```

### 12.9 Request Lifecycle
```
Client ─▶ Edge(TLS, correlation-id, rate limit) ─▶ Service(backendkit:
   authN ▶ authZ(PEP/PDP) ▶ tenant-context ▶ validate input ▶ domain logic ▶
   data(RLS, dynamic creds) ▶ emit logs/trace/AUDIT) ─▶ Response(encoded, headers) ─▶ Client
```

---

## Section 13 — Engineering Rules (Immutable)

These rules are non-negotiable. An implementation that violates any of them is non-conformant by definition.

1. **Every request is authenticated** — there are no anonymous privileged paths.
2. **Every request is authorized** at exactly one enforcement point, yielding exactly one decision.
3. **Every token is audience-bound** and verified (`iss`, `aud`, `exp`, `nbf`, signature) at the resource server.
4. **Every token is sender-constrained** (DPoP/mTLS); a stolen token alone is unusable.
5. **Every identity belongs to exactly one tenant context per request**, and that context is immutable for the request's duration.
6. **Every database access is tenant-scoped** and enforced by RLS independently of application code.
7. **Every object access verifies the principal's relationship to that object.**
8. **Every secret is dynamic, short-lived, owned by one identity, and never logged or embedded.**
9. **Every private key lives only in KMS/HSM** and is used, never exported.
10. **Every audit entry is immutable, tamper-evident, and names the principal, tenant, action, object, and decision.**
11. **Every secret and key is rotated** automatically on a defined schedule.
12. **Every service is observable** (logs, metrics, traces, audit) with a propagated correlation ID.
13. **Every artifact is immutable and signed**, deployed by gated CI/CD, and reversible.
14. **Every change is tested**, including authorization and tenant-isolation tests.
15. **Every component fails closed.**
16. **Every cross-tenant or administrative action requires elevated identity, step-up auth, and audit.**

---

## Section 14 — Platform Quality Attributes (Measurable Goals)

| Attribute | Target |
|---|---|
| **Availability** | Core identity and applications meet a defined high-availability SLO (e.g., 99.9%+), with no single zone as a single point of failure. |
| **Performance** | Auth/authz overhead per request stays within a defined low-latency budget; p99 API latency meets per-service SLOs. |
| **Scalability** | Stateless services scale horizontally and linearly; shared state (rate limiting, sessions, revocation) lives in distributed stores enabling multi-instance, multi-region operation. |
| **Recoverability** | Defined and tested RPO/RTO per service; one-action rollback; verified restores; cryptographic tenant erasure. |
| **Security** | Conformance to every rule in §13, validated continuously by automated controls and periodic review. |
| **Operability** | Every alert has a runbook; routine operations are automated; production access is exceptional and audited. |
| **Maintainability** | Consistent structure, SemVer contracts, high test coverage on critical paths, documented ownership. |
| **Developer Experience** | A new conformant service reaches production via the paved path quickly, inheriting security/observability by default rather than rebuilding it. |

---

## Section 15 — Technology Decisions (Target Desired State)

Technologies are specified by **role and required property**; provider-specific choices sit behind the §1 cloud-agnostic abstractions.

| Capability | Target Technology Class | Required Properties |
|---|---|---|
| **Languages/Runtime** | Go for platform services | Strong concurrency, static binaries, small attack surface, fast startup for immutable deploys |
| **Identity** | OAuth 2.1 / OIDC server (Socrate) | Audience-bound + sender-constrained tokens, KMS signing, MFA/passkeys, token exchange |
| **Framework** | backendkit (in-house security substrate) | Mandatory PEP, tenant propagation, audit, safe data primitives |
| **Authorization (PDP)** | Policy-as-code engine (e.g., OPA/Cedar-style) | Declarative, versioned, testable RBAC+ABAC, decoupled from app code |
| **Key Management** | KMS with HSM backing | Non-exportable keys, in-boundary sign/decrypt, audited rotation |
| **Secrets** | Dynamic secrets manager (Vault-class) | Short-lived leases, dynamic DB creds, no static secrets |
| **Workload Identity / Mesh** | SPIFFE/SPIRE + service mesh | Automatic mTLS, identity-based east-west authz |
| **Database** | PostgreSQL-class RDBMS | Row-Level Security, encryption at rest, strong consistency |
| **Cache / Shared State** | Distributed in-memory store (Redis-class) | Multi-instance rate limiting, sessions, revocation freshness |
| **Messaging** | Durable log/broker (Kafka/NATS-class) | Ordered, schema-registered, mutually-authenticated topics |
| **Object Storage** | S3-compatible store | Encrypted, versioned, lifecycle + legal-hold, tenant-scoped access |
| **AI Gateway** | In-house mediation service | Provider abstraction, tenant partitioning, governance, audit |
| **Observability** | OpenTelemetry + metrics/trace/log backends | Unified correlation, dashboards, SLO alerting |
| **Audit Store** | Append-only, tamper-evident store | Hash-chaining/WORM, isolated from audited systems |
| **SIEM** | Central security analytics | Correlation, anomaly detection, retention for compliance |
| **CI/CD** | Pipeline-as-code + signed provenance (SLSA-style) | Build/test/scan/sign/gate, ephemeral deploy identity |
| **Infrastructure** | Containers + orchestration (Kubernetes-class) via declarative IaC | Immutable, GitOps, admission policy, default-deny networking |
| **Edge** | API gateway + WAF + TLS 1.3 termination | Authentication, rate limiting, bot defense |

---

## Closing Statement

This architecture exists to make one property true of the whole platform: **the compromise of any single component does not yield the ecosystem.** It achieves this by giving every actor a verifiable identity, binding every token to an audience and a sender, enforcing one authorization decision per request, isolating every tenant independently at the data layer, keeping every key inside a hardware boundary, and recording every action in an immutable audit trail — so that trust is always verified, never inherited.

All future implementation MUST align with this document. Where reality and this constitution differ, this constitution defines the direction of travel; the gap is the backlog.
