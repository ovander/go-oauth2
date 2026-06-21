# MIGRATION ROADMAP

How existing applications and the platform move to the target **without flag days**, using compatibility layers, dual-running, and observe→enforce gating. The governing rule: **add the new path, prove parity in production telemetry, flip the default, then remove the old path** — each step independently reversible.

---

## Migration Patterns (reused everywhere)

1. **Compatibility Adapter.** Every new capability ships behind an adapter implementing the existing contract. Consumers integrate against the adapter; the implementation swaps underneath without a consumer change.
2. **Dual-Run / Shadow Mode.** New control runs alongside the old, computing its decision and **logging what it *would* do** without acting. We compare shadow vs. live until parity.
3. **Warn → Enforce.** Security checks (audience, PEP, RLS, sender-constraint) start in warn-only (allow + log would-be deny), flip to enforce per-tenant/per-app, then platform-default.
4. **Expand–Contract (data).** Schema and claims add fields first; both old and new code work against the intermediate state; the old field/path is removed only after cutover.
5. **Per-Tenant / Per-App Canary.** Enforcement enables for one tenant or app first, observed, then widened — never a global switch.
6. **Deprecate → Telemeter-to-Zero → Remove.** Legacy paths are deprecated, usage is measured, and removal happens only after telemetry shows zero legitimate use and the window has elapsed.

---

## Capability-by-Capability Migration

### Identity: KMS signing (no consumer impact)
Introduce KMS signer; **dual-sign** so JWKS exposes current+previous keys. Verifiers already accept multiple kids → no change. Retire the old key after all tokens it signed expire, then prune.

### Identity: Audience binding
Add `aud` to tokens (additive). backendkit verifies in **warn mode**, logging would-be denials with the offending audience. Register each resource server's audience. When warn-mode shows zero legitimate denials, flip enforce per app. Old "any-audience" acceptance is removed in v3.

### Identity: Sender-constrained tokens
Issue **both** bearer and constrained tokens during transition; clients adopt DPoP/mTLS at their pace. backendkit accepts both, prefers constrained. Default issuance flips to constrained at v2.x; bearer issuance removed in v3.

### Identity: MFA / passkeys
Opt-in enrollment → mandatory for admins → step-up for sensitive ops → universal. Recovery flows ship before mandates. No user is locked out by a flip; enforcement is staged by cohort.

### Framework: backendkit PEP
Provide an adapter wrapping existing handlers. PEP runs in **shadow** (decides + logs, does not block) until parity with existing checks is shown. Flip to enforce per app. Legacy ad-hoc checks deprecated, then removed once PEP covers them.

### Authorization: Policy engine
Policies authored to **replicate current behavior first** (lift-and-shift), validated in shadow against live decisions, then extended to ABAC/object-level. Decisions move to the PDP only after shadow parity.

### Data: Tenant isolation (RLS + tenant keys)
Enable RLS behind a per-tenant flag; verify with cross-tenant leakage tests in staging and a canary tenant in production. Tenant-context propagation lands in backendkit first so queries carry context before RLS denies. Regulated fields move to envelope encryption via expand–contract (write-both, read-new, drop-old).

### State: Distributed store
Adapters abstract session/rate-limit/revocation state. Switch the backing store from in-process to distributed behind the adapter; run dual-read during cutover; remove in-process path once consistent.

### AI: Gateway
Stand up the gateway; route one app's AI traffic through it first; add governance/audit; disallow direct provider calls only after all apps are routed. Provider keys move into the gateway exclusively.

### Operations: Secrets & keys
Issue dynamic credentials alongside static ones; switch services to dynamic; revoke static once unused. All rotation automated before scale-out.

---

## What we explicitly avoid

- **No flag day:** there is no single moment the whole platform switches. Every flip is per-tenant/per-app with a canary and a back-out.
- **No destructive migration to deploy or roll back:** expand–contract guarantees both directions are safe.
- **No blind deny-path:** every enforcement is preceded by a warn/shadow phase with parity evidence.
- **No orphaned legacy:** removal is gated on telemetry, not assumption.

---

## Per-App Cutover Checklist (ParaShift / GPWA / Ascenda)

1. Adopt observability + audit + dynamic secrets (v1.x) — invisible to users.
2. Wrap handlers with backendkit adapter; run PEP + audience in shadow/warn.
3. Register resource-server audience; reach warn-mode parity.
4. Enable tenant context; turn on RLS for a canary tenant; run leakage tests.
5. Flip PEP + audience + RLS to enforce for the app (v2.0), canary → full.
6. Adopt sender-constrained tokens; route AI via gateway (v2.x).
7. Remove legacy auth/data-access code after deprecation window (v3).

Each step is reversible to the previous step; the app's own public API contract is unchanged throughout.
