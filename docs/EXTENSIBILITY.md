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

> **Delivery is the next slice.** This one lands the subscriptions, the
> transactional outbox and the admin API; rows accumulate as `pending`. The
> dispatcher — `FOR UPDATE SKIP LOCKED` claiming, HMAC-SHA256
> `X-Socrate-Signature`, exponential backoff, dead-lettering — follows.

## Next

- **A3 dispatcher** — claim, sign, send, retry, dead-letter.
