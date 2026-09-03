# Extensibility — hooks, scope policy (and what comes next)

Plan A of `docs/program/PLAN-EXTENSIBILITY-OBSERVABILITY.md`. Delivered so far:
**A1** per-client scope policy, **A6** in-process hooks. A2 (custom claims) and
A3 (webhooks) build on the hooks below.

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

## Next

- **A2 custom claims** — a `ClaimsEnricher` fed by `users.attributes` and a
  per-app mapping; implemented as a `BeforeTokenIssue` hook that adds claims.
- **A3 webhooks** — an outbox written with the audit row and delivered by a
  signed, SSRF-safe dispatcher; `AfterLogin` / `UserProvisioned` are its first
  producers.
