# RISK REGISTER

Risks to the transformation program (not to the current system). Each entry: technical / business / operational risk and the **rollback strategy**. Likelihood (L) and Impact (I) are L/M/H. Mitigations follow the transformation principles (observe→enforce, adapters, expand–contract, canary, reversibility).

---

## R1 — KMS signing cutover breaks token verification
- **Capability:** EPIC-3 (C3) · **L:** L · **I:** H
- **Technical:** verifiers reject tokens signed by the new key during rotation.
- **Business:** platform-wide login/verification outage.
- **Operational:** key rollback under incident pressure.
- **Mitigation:** dual-sign; JWKS publishes current+previous; verify-across-rotation tests before enable.
- **Rollback:** revert issuance to the previous key (still in JWKS); no verifier change needed.

## R2 — Audience enforcement denies legitimate traffic
- **Capability:** EPIC-7 (C7) · **L:** M · **I:** H
- **Technical:** an unregistered/legacy audience gets denied at flip.
- **Business:** an app's users blocked.
- **Operational:** emergency flag-off.
- **Mitigation:** warn-only mode until ≈0 legitimate would-be denials; per-app enforce with canary.
- **Rollback:** flip the per-app enforce flag back to warn; instantaneous, no deploy.

## R3 — Mandatory PEP changes an app's effective authorization
- **Capability:** EPIC-11 (C11) · **L:** M · **I:** H
- **Technical:** PEP decision diverges from the app's prior ad-hoc checks.
- **Business:** users wrongly allowed or denied.
- **Operational:** per-app incident.
- **Mitigation:** shadow mode with decision-parity comparison; lift-and-shift policies first; canary per app.
- **Rollback:** disable PEP-enforce flag for the app (adapter falls back to legacy path, still present pre-v3).

## R4 — RLS / tenant isolation regression or query breakage
- **Capability:** EPIC-12 (C12) · **L:** M · **I:** H
- **Technical:** RLS denies legitimate rows, or tenant-context missing on a path.
- **Business:** data access errors; potential isolation gap if mis-scoped.
- **Operational:** schema-level change under load.
- **Mitigation:** tenant-context propagation lands before RLS; per-tenant flag + canary tenant; cross-tenant leakage tests; expand–contract schema.
- **Rollback:** disable RLS flag for the tenant/table (context still set, queries unaffected); envelope-encryption uses write-both/read-old fallback.

## R5 — Sender-constraint (DPoP/mTLS) breaks clients
- **Capability:** EPIC-8 (C8) · **L:** M · **I:** M
- **Technical:** a client can't present proof-of-possession.
- **Business:** integration breakage for slow-to-adopt clients.
- **Operational:** support load.
- **Mitigation:** dual issuance (bearer + constrained); accept both; default-on only after adoption telemetry.
- **Rollback:** continue accepting bearer for the client cohort; defer mandatory step.

## R6 — MFA mandate locks out users
- **Capability:** EPIC-9 (C9) · **L:** L · **I:** M
- **Technical:** enrollment/recovery gaps at the mandate flip.
- **Business:** user lockout, churn.
- **Operational:** support surge.
- **Mitigation:** recovery flows ship first; opt-in → admin → cohort → universal; grace + step-up rather than hard block where safe.
- **Rollback:** revert the cohort's mandate flag to optional.

## R7 — Policy engine becomes a latency/availability dependency
- **Capability:** EPIC-10 (C10) · **L:** M · **I:** M
- **Technical:** PDP latency or downtime affects every request.
- **Business:** platform-wide slowdown.
- **Operational:** new critical dependency to run.
- **Mitigation:** local decision caching with short TTL; fail-closed for sensitive, defined policy for degraded mode; PDP runs HA.
- **Rollback:** pin to last-known-good policy bundle; backendkit uses cached decisions.

## R8 — Service mesh / mTLS rollout disrupts connectivity
- **Capability:** EPIC-1 (C1) · **L:** M · **I:** H
- **Technical:** default-deny blocks an unmodeled connection.
- **Business:** internal outage.
- **Operational:** mesh is a large operational surface.
- **Mitigation:** permissive mTLS first (accept both), model flows from telemetry, then default-deny per namespace; canary.
- **Rollback:** revert mesh policy to permissive; traffic unaffected.

## R9 — Distributed-state migration causes inconsistency
- **Capability:** EPIC-13 (C13) · **L:** M · **I:** M
- **Technical:** divergence between in-process and distributed state during cutover.
- **Business:** inconsistent rate limits / sessions / revocation.
- **Operational:** dual-store window.
- **Mitigation:** adapter abstraction; dual-read; consistency tests before removing in-process path.
- **Rollback:** switch adapter back to in-process store.

## R10 — CI/CD gates block delivery
- **Capability:** EPIC-6 (C6) · **L:** M · **I:** M
- **Technical:** overly strict gates/false positives stall releases.
- **Business:** delivery slowdown.
- **Operational:** pipeline tuning.
- **Mitigation:** gates introduced warn-first; tune thresholds; break-glass deploy with audit for emergencies.
- **Rollback:** downgrade specific gate to warn while fixing.

## R11 — Program scope/coordination across 5 independent repos
- **Capability:** program-wide · **L:** M · **I:** M
- **Technical:** version-skew between backendkit and apps.
- **Business:** stalled v2.0 if apps lag.
- **Operational:** cross-team dependency.
- **Mitigation:** RFC contracts decouple repos; per-app cutover (no global flag day); compatibility matrix + minimum-version declarations; deprecation windows ≥ one major.
- **Rollback:** apps stay on prior backendkit major; legacy path persists until they cut over.

## R12 — AI Gateway centralization risk
- **Capability:** EPIC-15 (C15) · **L:** L · **I:** M
- **Technical:** gateway becomes a bottleneck/SPOF for AI.
- **Business:** AI features degraded.
- **Operational:** new service to run HA.
- **Mitigation:** HA gateway; route one app first; provider abstraction for failover.
- **Rollback:** per-app re-route disabled; AI feature flagged off (no data-plane impact elsewhere).

## R13 — "Verify-only / never-remove-blind" discipline erodes under deadline pressure
- **Capability:** program-wide · **L:** M · **I:** H
- **Technical:** someone enables enforce or deletes legacy without parity evidence.
- **Business:** self-inflicted outage; the exact failure mode the program exists to avoid.
- **Operational:** governance lapse.
- **Mitigation:** enforce flips and legacy removals require parity telemetry + security review sign-off (governance gate); conformance checks prevent skipping warn/shadow.
- **Rollback:** revert the flag/PR; the governance gate is itself the control.

---

## Aggregate Risk Posture

The program's dominant risk is **enabling a deny-path before proving parity** (R2/R3/R4/R13). Every mitigation reduces to the same discipline: **observe → prove → enforce → (much later) remove**, with a per-app/per-tenant flag that is reversible without a deploy. Because each enforcement flip is reversible and each data change is expand–contract, **no single transformation step can produce an unrecoverable production state** — which is the program's core stability guarantee.
