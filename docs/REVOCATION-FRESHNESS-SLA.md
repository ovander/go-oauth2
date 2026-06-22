# Revocation & Token Freshness SLA

> **Capability:** C14 — Revocation Propagation · **RFC:** RFC-012 · **Epic:** EPIC-14
>
> This document states the **freshness SLA**: the guaranteed upper bound on the
> time between a revocation event and the moment a resource server will reject
> the affected token. Operators use it to choose token TTLs and validation
> strategies that meet their assurance requirements.

## 1. What can be revoked

| Mechanism | Trigger | Scope | Backing |
|-----------|---------|-------|---------|
| **Nuclear (token-version)** | logout, password reset, admin "revoke tokens" | **all** of a user's access + refresh tokens | `users.token_version` (incremented) |
| **Per-token (JTI blacklist)** | `POST /oauth/revoke` (RFC 7009) | the **one** presented token | `used_tokens` row keyed by `jti` |
| **Single-use refresh** | a refresh token is redeemed | that refresh token | `used_tokens` (consumed on rotation) |
| **Natural expiry** | clock | the token | `exp` claim |

## 2. Where revocation is checked

A token's revocation status is only as fresh as the **validation strategy** the
resource server uses. There are three:

| Strategy | Nuclear (token-version) | Per-token (JTI) | Freshness |
|----------|:-----------------------:|:---------------:|-----------|
| **A. Introspection** (`POST /oauth/introspect`, RFC 7662) | ✅ checked | ✅ checked | **immediate** (per call) |
| **B. Socrate's own auth middleware** (direct API calls) | ✅ checked | ✅ checked | **immediate** (per request) |
| **C. Local JWT validation** (verify signature against JWKS, no callback) | ❌ not visible | ❌ not visible | **≤ access-token TTL** (waits for `exp`) |

Strategies A and B consult the live database on every request, so a revocation
takes effect on the **next request**. Strategy C is offline: it trusts the
signed `exp`, so a revoked-but-unexpired token remains accepted until it expires.

## 3. The SLA

Let `T_access` be the access-token TTL (`ACCESS_TOKEN_TTL`, default **900s**).

> **Freshness SLA — time to platform-wide rejection after a revocation:**
>
> - **Introspecting / Socrate-authenticated resource servers (A, B):** `0` —
>   the very next request after the revocation is rejected.
> - **Locally-validating resource servers (C):** `≤ T_access` — bounded by the
>   access token's remaining lifetime; **≤ 900s by default.**
> - **Refresh tokens:** a revoked or rotated refresh token is rejected
>   **immediately** at the next `/oauth/token` call (single-use + token-version
>   + JTI checks all run there).

The platform-wide bound is therefore **`T_access`**, and it is reached only by
offline local validators. **To tighten the SLA, lower `ACCESS_TOKEN_TTL`** (the
cost is more frequent refreshes) or **require introspection** for high-assurance
resources (the cost is a callback per request). Refresh-token TTL does not affect
the access-token freshness bound.

## 4. High-assurance guidance

- For sensitive resources, prefer **introspection** (strategy A): freshness is
  immediate and the response also carries `aud`, `auth_time`, `cnf` (DPoP), and
  `act` (delegation) for the resource server's own checks.
- Keep `ACCESS_TOKEN_TTL` short (the default 900s is a reasonable balance; the
  server warns if it exceeds 30 min). The shorter it is, the tighter the bound
  for offline validators.
- Sender-constrain tokens with **DPoP** (`DPOP_MODE`) so a leaked token is
  unusable without its key — revocation latency then matters far less.

## 5. Operational notes

- The `used_tokens` table (per-token blacklist + single-use refresh JTIs) is
  pruned of expired rows on a timer (`USED_TOKEN_CLEANUP_INTERVAL_SECONDS`,
  default 1h). Pruning never weakens the SLA: a row is only removed **after** the
  token it blocks has already expired (and so already fails validation).
- Nuclear revocation is O(1) (a single `token_version` bump) and needs no
  per-token storage, which is why it is the fallback when a token cannot be
  parsed (e.g. `EndSession` without a token hint).
- All revocation events are recorded in the security audit log
  (`token_revoked`, `token_revoked_all`).
