# Extensibility — hooks, scope policy, custom claims (and what comes next)

Plan A of `docs/program/PLAN-EXTENSIBILITY-OBSERVABILITY.md`. Delivered so far:
**A1** per-client scope policy, **A6** in-process hooks, **A2** custom claims.
A3 (webhooks) builds on the hooks below.

## Per-client scope policy (A1)

`allowed_scopes` on a client (admin API §8.2 of `docs/API.md`), applied by
`SCOPE_POLICY_MODE=off|observe|enforce` at `/oauth/authorize` and at every
grant. Empty = unrestricted. Violations emit a `scope_denied` security event
(and `socrate_security_events_total{event_type="scope_denied"}`); `enforce`
answers `invalid_scope`.

## In-process hooks (A6)

Socrate is a single Go binary; the hook registry in `internal/hooks` lets a
fork (or a build that adds one file) observe or veto identity events without
touching the services. Register before the server starts:

```go
package main

import (
    "context"
    "errors"

    "github.com/ovandermoten/go-oauth2/internal/hooks"
    "github.com/ovandermoten/go-oauth2/internal/model"
)

func init() {
    // Veto: the "legacy" client may only be used by global admins.
    hooks.OnBeforeTokenIssue(func(ctx context.Context, e *hooks.TokenIssue) error {
        if e.App != nil && e.App.ClientID == "legacy" && (e.User == nil || !e.User.IsGlobalAdmin()) {
            return errors.New("legacy client is admin-only")
        }
        return nil
    })
    // Observe: fan out logins to your own pipeline (do the I/O asynchronously).
    hooks.OnAfterLogin(func(ctx context.Context, e hooks.Login) {
        go notify("login", e.User.ID, e.Method, e.MFA)
    })
    hooks.OnUserProvisioned(func(ctx context.Context, e hooks.UserProvisioned) {
        go notify("user_created", e.User.ID, e.Source, false)
    })
}
```

| Hook | Runs | Can fail the request? | Event |
|---|---|---|---|
| `OnBeforeTokenIssue` | before every token grant: `authorization_code`, `refresh_token`, `client_credentials`, JSON `password` login, `magic_link` | **yes** — the first error (or a panic, which fails closed) aborts; the token endpoint answers `403 access_denied` | `TokenIssue{User, App, Grant, Scope}` (`User` is nil for `client_credentials`) |
| `OnAfterLogin` | after a successful interactive login (`password`, `admin_password`, `admin_elevate`) | no — panics are recovered and logged | `Login{User, App, Method, MFA}` |
| `OnUserProvisioned` | after an account is created (`signup`, `invite`, `admin`, `superadmin`) | no | `UserProvisioned{User, App, Source}` |

Rules: hooks run synchronously on the request path — keep them fast and push
I/O to a goroutine; never log the token or secret material available on the
event; a veto is audited by the caller as a failed grant like any other.

## Custom claims (A2)

A client declares, per claim, where its value comes from. Nothing is added to a
token unless a mapping asks for it, so every existing client is unaffected.

```jsonc
// PUT /api/admin/apps/{id}   (admin API §8.2)
{
  "claim_mappings": {
    "tier":       "user.attributes.tier",                          // shorthand → access token
    "department": {"source": "user.attributes.dept", "target": "both"},
    "env":        {"source": "literal:production", "target": "id"}
  }
}
```

```jsonc
// PUT /api/admin/users/{id}/attributes — replaces the whole set, audited
{"attributes": {"tier": "gold", "dept": "engineering"}}
```

The resulting access token carries `"https://socrate/tier": "gold"`.

**Sources** (a closed set — a mapping can only project what the server already
holds): `user.attributes.<key>`, `user.email`, `user.name`, `user.id`,
`app_role`, `app.id`, `app.client_id`, `literal:<constant>`.
**Targets**: `access` (default), `id`, `both`.

Safety properties, each covered by a test:

- **Namespaced.** Every mapped claim is prefixed with `CLAIMS_NAMESPACE`
  (default `https://socrate/`), so a mapping named `sub` or `scope` is issued as
  `https://socrate/sub` and the registered claim is untouched. Beyond that, the
  merge refuses any name already present — a mapping can never overwrite a
  standard claim even if the namespace were cleared.
- **Bounded.** An attribute set is capped at 32 entries / 4 KB
  (`service.MaxUserAttributes`…), and the mapped claim set at 2 KB per token
  (`auth.MaxCustomClaimsBytes`). Over the cap the custom claims are dropped
  whole and logged at error level — the token is still issued and still valid,
  it simply carries the standard claim set. A truncated, non-deterministic claim
  set would be worse than none.
- **Validated at write time.** An unsupported source, an unknown target or an
  unusable claim name is refused by the admin API (`400 invalid claim mapping`),
  not silently dropped at every issuance.
- **Absent, not null.** A mapping whose source resolves to nothing (an attribute
  the user does not have) yields no claim at all.
- **Admin-only.** Attributes are set through the admin API; they are not part of
  `PUT /api/profile`, so a user cannot mint their own claim values.

Attributes are stored in `users.attributes` (jsonb) and mappings in
`apps.claim_mappings` (jsonb) — migrations `0016` and `0017`.

## Outbound webhooks — subscriptions and the outbox (A3)

Socrate delivers identity events to your endpoint. `WEBHOOKS_MODE=off` is the
default: subscriptions can be registered, but nothing is enqueued or sent.

```jsonc
// POST /api/admin/webhooks   (global admin, fresh step-up)
{"name": "SIEM", "url": "https://hooks.example.com/socrate",
 "event_types": ["login.failed", "security.brute_force_detected"]}
// → 201 with "secret": "whsec_…" — shown once, never again
```

`GET /api/admin/webhooks/events` returns the catalogue. `"event_types": ["*"]`
subscribes to everything, including events added by a later release. A
subscription with an `app_id` receives only that client's events.

**The outbox.** An audited event in the catalogue is written to
`webhook_deliveries` **in the same transaction as the security audit row**, so a
delivery can never exist without the audit entry that produced it. The enqueue
runs inside a savepoint: if it fails, the audit row still commits — losing a
security audit entry over a failed webhook enqueue would be the worse trade —
and the failure is logged at error level.

The payload is frozen at enqueue time, so a retry re-sends identical bytes and
the signature stays reproducible:

```json
{"event": "login.failed", "event_id": 8412,
 "occurred_at": "2026-09-04T10:31:22.481Z", "success": false,
 "severity": "warning", "user_id": 7, "app_id": 3,
 "ip_address": "203.0.113.9", "correlation_id": "…", "details": {…}}
```

It deliberately omits the audit row's integrity hashes and the user agent, and
carries no token, secret or credential.

**The catalogue is an allow-list.** Only mapped audit events produce a webhook,
so adding an internal `SecurityEventType` never starts leaking to subscribers by
default. Not currently emitted (no audit event exists for them yet):
`user.deleted`, `user.blocked`, `alert.fired`, `ip.blocked`.

**SSRF is the threat model here.** Socrate's admin API listens on loopback
`:8081` and sits on a VPS beside other services, so a webhook target is an
outbound request with the server's network position. `internal/shared/ssrf`
therefore requires `https`, no credentials in the URL, and a host that resolves
only to public addresses — refusing loopback, RFC 1918, link-local (which covers
`169.254.169.254`), CGNAT, and the IPv4-mapped and NAT64 spellings of each. The
check runs at registration **and again at connect time**, because DNS can change
in between.

Secrets are generated server-side, returned once, stored encrypted with
`SECRET_KEY_BASE` (the same AES-GCM helper as TOTP secrets) and rotatable via
`POST /api/admin/webhooks/{id}/rotate-secret`. Without `SECRET_KEY_BASE` set,
registering a subscription is refused rather than storing a signing key in the
clear. Every subscription change is in the admin audit trail.

### Delivery

The dispatcher drains the outbox on a timer (`WEBHOOK_POLL_INTERVAL`, default
10s). A pass claims up to `WEBHOOK_BATCH_SIZE` due rows with
`SELECT … FOR UPDATE SKIP LOCKED`, so several instances can run it concurrently
and each gets a disjoint batch instead of double-sending. Claimed rows are
leased; if a process dies mid-flight the row becomes due again rather than being
lost. **Delivery is therefore at-least-once** — deduplicate on `event_id`.

Each request carries:

```
POST /your/endpoint
Content-Type: application/json
X-Socrate-Event: login.failed
X-Socrate-Delivery: 8412
X-Socrate-Attempt: 1
X-Socrate-Signature: t=1788529010,v1=6f1c…
```

The signature is `HMAC-SHA256(secret, "<t>.<raw body>")`, hex-encoded. **Verify
over the raw bytes before parsing**, compare in constant time, and reject a `t`
outside your tolerance — the timestamp is inside the signed material precisely
so a captured delivery is not replayable forever. `service.VerifySignature` is
the reference implementation.

Outcomes:

| Response | Result |
|---|---|
| `2xx` | delivered (terminal) |
| `410 Gone` | dead-lettered immediately — taken as "stop sending" |
| any other status, or a transport error | retried |
| subscription deleted or deactivated | dead-lettered |

Retries back off 30s → 1m → 2m → 4m → 8m, capped at 15 minutes, and after
`WEBHOOK_MAX_ATTEMPTS` (default 6) the delivery is **dead-lettered**: kept, never
silently dropped, visible at `GET /api/admin/webhooks/deliveries?status=dead` and
replayable with `POST /api/admin/webhooks/deliveries/{id}/requeue`.

The send path re-applies the SSRF guard **at connect time**, not just at
registration: every connection is checked against the address actually being
dialled, then dialled by IP so nothing can change between the check and the
connect. Redirects are refused outright (a public URL that 302s to
`http://127.0.0.1:8081/` would otherwise undo the whole guard), connection reuse
is disabled, proxy environment variables are ignored, each attempt is bounded by
`WEBHOOK_SEND_TIMEOUT` (default 5s), and the response body is discarded after a
bounded read.

## Shared state — running more than one instance (B4)

Several controls keep state in the process. On one instance that is correct and
fastest, and `STATE_BACKEND=memory` (the default) keeps it that way. On N
instances the controls quietly weaken:

- a rate limit of 5/min becomes **5N/min**, because each instance counts only
  the requests it happened to receive;
- a DPoP proof replayed against a **different** instance is accepted, because
  the instance that saw it first is the only one that remembers the `jti`.

The second is a security hole, not a performance wrinkle. `STATE_BACKEND=postgres`
moves both into the database that is already configured — no new infrastructure:

| State | Memory | Postgres |
|---|---|---|
| Rate-limit counters (login, signup, token) | per instance | shared, `rate_limit_counters` |
| DPoP replay cache (`jti`) | per instance | shared, `dpop_replay` |

Both tables are `UNLOGGED` (migrations `0020`/`0021`): the data is ephemeral and
reconstructible, so skipping the WAL keeps a per-request counter cheap. The cost
— truncation on an unclean shutdown — is the same guarantee memory gives on
restart.

**Two deliberate differences from the in-memory behaviour**, both worth knowing
before you flip the switch:

1. **Fixed windows, not sliding.** A sliding window needs a timestamp per
   request, which is a row per request in a shared store. The known consequence
   is that a caller can send `limit` requests at the end of one window and
   `limit` more at the start of the next, so the true worst case is **2×limit**
   across a boundary.
2. **The rate limiter fails open; the replay store fails closed.** If the store
   is unreachable the limiter allows the request and logs at error level —
   because the endpoints it guards all need the same database, so there is
   nothing left to brute-force, and failing closed would turn a database blip
   into a self-inflicted outage. The replay store fails closed, because there
   its failure mode really would drop a security guarantee.

`STATE_SWEEP_INTERVAL` evicts expired rows; the stores are correct without it
(every read filters on expiry) so it only bounds table growth.
`STATE_OP_TIMEOUT_MS` bounds one round trip.

**Still per-instance:** auto-defense's failed-login counters
(`AutoDefenseService.ipRecords`). Its record is two sliding windows plus a block
escalation count rather than a single counter, so folding it into this interface
needs its own design pass — deferred rather than bodged. The *blocks* it
produces are already shared, since they are rows in `blocked_ips`; only the
pre-block counting is local, which makes brute-force escalation N times slower
to trigger across N instances.

## Next

- **A4 policy decision point** (shadow first), **A5** hosted-page branding.
- **B5 multi-instance readiness** — advisory-lock-guarded key rotation and
  leader-elected sweepers, which is what B4 unblocks.
