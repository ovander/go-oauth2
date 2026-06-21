# IMPLEMENTATION ROADMAP

The sequenced execution view of the program: how the capabilities (`EPIC-ROADMAP.md`), contracts (`RFC-ROADMAP.md`), and releases (`RELEASE-ROADMAP.md`) are ordered into waves that preserve production stability. This is a **sequencing plan, not a schedule** — waves are ordered by dependency readiness, not fixed dates. Each wave has explicit entry and exit gates.

---

## Sequencing Logic

The critical path is **C1 → C2 → C3 → C7 → C11 → C12** (service identity → secrets → KMS → audience → PEP → tenant isolation). Everything else is scheduled to be ready *before* the critical-path step that consumes it, and to run in parallel where it shares no dependency.

```
Wave 0  Substrate ─┬─ Wave 1 Identity Hardening ─┬─ Wave 2 Enforcement ─── Wave 3 Steady State
(C1,C2,C3,         │  (C7 warn, C8 dual, C9,      │  (C7 enforce, C11,      (C8 mandatory, C13 full,
 C4,C5,C6,C13)     │   C14, C10 shadow)           │   C12, C14 SLA)          C15, C16, C17, C18, cleanup)
   align v1.x      │        align v1.x            │     align v2.0           align v2.x → v3
```

---

## Wave 0 — Substrate (release line: v1.x; non-breaking)

**Goal:** create the foundations every later wave depends on. No application behavior changes.

- **EPIC-1** Workload identity + mesh mTLS (RFC-006)
- **EPIC-2** Dynamic secrets (RFC-009)
- **EPIC-3** KMS/HSM signing + dual-sign rotation (RFC-002)
- **EPIC-4** Observability pipeline (RFC-008)
- **EPIC-5** Tamper-evident audit (RFC-007)
- **EPIC-6** CI/CD provenance + gates (RFC-014)
- **EPIC-13 (intro)** Distributed-state adapters available

**Entry gate:** RFCs 006/008/009/002/007/014 approved.
**Exit gate:** every service has SPIFFE identity + OTel telemetry + audit emission; KMS signing live with dual-sign; no static secrets in adopted services; CI/CD gates active. **No consumer-visible change.**

---

## Wave 1 — Identity Hardening (release line: v1.x; additive)

**Goal:** make tokens strong and human auth phishing-resistant — all additive, enforcement deferred to Wave 2.

- **EPIC-7 (intro/warn)** Audience claim added; resource servers verify in **warn-only** (RFC-001)
- **EPIC-8 (dual)** Sender-constrained tokens issued alongside bearer (RFC-003)
- **EPIC-9** MFA/passkeys opt-in → admin-mandatory (RFC-011)
- **EPIC-10 (shadow)** Policy engine deployed; backendkit consults it in shadow (RFC-005)
- **EPIC-14 (prep)** Short TTLs + revocation signal wired (RFC-012)

**Entry gate:** Wave 0 exit; RFCs 001/003/011/005/012 approved.
**Exit gate:** audience warn-mode shows parity (≈0 legitimate would-be denials); constrained tokens issued and accepted; admins on MFA; PDP shadow matches live decisions.

---

## Wave 2 — Enforcement (release line: v2.0; the one breaking boundary)

**Goal:** flip defaults to deny, per-app via compatibility layers and canaries — never platform-wide at once.

- **EPIC-11** backendkit PEP **mandatory**; one decision per request (RFC-004)
- **EPIC-7 (enforce)** Audience verification enforced (RFC-001)
- **EPIC-12** RLS + tenant-context enforced; envelope encryption for regulated fields (RFC-010)
- **EPIC-14** Revocation propagation active with published freshness SLA (RFC-012)
- **EPIC-8 (default-on)** Constrained tokens become default issuance (RFC-003)

**Entry gate:** Wave 1 parity evidence per app; per-app cutover checklist (`MIGRATION-ROADMAP.md`) passed in staging + canary tenant.
**Exit gate:** 100% resource servers enforce audience + PEP; cross-audience and cross-tenant leakage tests pass with zero failures; no legitimate traffic denied. Legacy paths remain present-but-deprecated.

---

## Wave 3 — Steady State & Cleanup (release lines: v2.x → v3)

**Goal:** complete coverage, operate at scale, then delete every shim.

- **EPIC-8 (mandatory)** / **EPIC-9 (universal)** sender-constraint + MFA everywhere
- **EPIC-10 (full)** ABAC + object-level policies in PDP
- **EPIC-13 (full)** Multi-instance/region state; remove in-process state
- **EPIC-15** AI Gateway live; direct provider calls disallowed
- **EPIC-16** HA + tested DR + verified backups
- **EPIC-17** Delegation + impersonation
- **EPIC-18** Federation (v3)
- **Cleanup (v3):** remove all deprecated legacy auth/transport/secret/data paths; conformance checks block non-target patterns at admission.

**Entry gate:** Wave 2 exit; deprecation windows opened.
**Exit gate (program complete):** zero legacy paths in production; 100% conformance; every §13 constitutional rule enforced by CI/admission; DR drills passing; multi-region operational.

---

## Standing Execution Rules (all waves)

- A capability never enters enforce without a prior shadow/warn phase showing parity.
- Each wave is independently shippable; a later wave slipping never forces an earlier one to roll back.
- Every change carries tests (including authz + tenant-isolation), telemetry, and a back-out.
- Conformance checks added in Wave 0 grow stricter each wave until they encode the full target at v3.
- Production stability is the veto: any wave step that risks a Sev-1/2 is gated behind a larger canary, not forced.
