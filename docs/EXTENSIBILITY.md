# Extensibility — hooks, scope policy, custom claims (and what comes next)

Plan A of `docs/program/PLAN-EXTENSIBILITY-OBSERVABILITY.md`. Delivered so far:
**A1** per-client scope policy, **A6** in-process hooks, **A2** custom claims,
**A3** outbound webhooks, and **A4** parts 1–2 — the policy decision point, on
the admin API and for applications.

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

## Policy decision point (A4)

Authorisation on the admin API has so far been code: `RequireGlobalAdmin`,
`RequireRole("superadmin")`, `RequireFreshAuth` on sixteen destructive routes,
`RequirePasswordChangeComplete`. A4 adds a policy decision point (PDP) — rules
held as data, versioned, testable before they are live — and an enforcement
point (PEP) in front of those gates, rolled out the same way as every other
control here: `off → shadow → enforce`.

### The decision

```
Decide({principal, app, action, resource, context}) → {allow, rule, reason, obligations, policy_version}
```

On the admin API the PEP builds the input from the request:

| Field | From |
|---|---|
| `action` | `"<METHOD> <route pattern>"`, e.g. `DELETE /api/admin/apps/{id}` — the matched chi pattern, never the raw path, so it is the same however the router is mounted |
| `principal` | the authenticated user (`id`, `role`, `attributes`, `must_change_password`) and their token (`scopes`, `amr`, `auth_time`, `client_id`) |
| `resource` | `type` = first path segment (`apps`, `users`, `webhooks`…), `id` = the route's `{id}` |
| `context` | `ip` (the resolved client IP), `ip_country` (only when a GeoLite2 database is configured) and the time |

`GET /api/admin/policy/catalogue` lists every admin action, attribute,
operator and obligation, so an editor can offer choices instead of free text.

### Rules

```json
{
  "id": "no-client-deletion-off-network",
  "description": "Deleting an OAuth client needs the office network and MFA.",
  "effect": "deny",
  "actions": ["DELETE /api/admin/apps/{id}"],
  "when": {"any": [
    {"not": {"attr": "context.ip", "op": "cidr", "value": ["10.0.0.0/8"]}},
    {"not": {"attr": "principal.amr", "op": "contains", "value": "mfa"}}
  ]}
}
```

- **`actions`** are globs; `*` matches any run of characters. `* /api/admin/*`
  is every admin route; `* /api/admin/superadmins*` is the superadmin tree.
- **`when`** is a tree of `all` / `any` / `not` over comparisons
  `{"attr", "op", "value"}`, or `{"attr", "op", "ref"}` to compare two
  attributes — which is what an object-level check looks like
  (`resource.attributes.owner_id eq ref principal.id`). Omitted means always.
- **Operators:** `eq`, `ne`, `in`, `not_in`, `contains` (list attributes),
  `lt`/`lte`/`gt`/`gte` (numbers), `starts_with`, `cidr`, `exists`.
- **Attributes:** `action`; `principal.{kind,id,role,client_id,app_role,scopes,amr,auth_time_age,must_change_password}`;
  `app.{id,client_id}`; `resource.{type,id}`; `context.{ip,ip_country,hour_utc}`;
  and the free-form maps `principal.attributes.<key>` (the A2 user attributes),
  `resource.attributes.<key>`, `context.attributes.<key>`.
- **`obligations`** on an allow: `require_fresh_auth` (the step-up window,
  answered with `elevation_required` so the consoles' existing step-up flow
  handles it) and `require_mfa` (`amr` must contain `mfa`).

Every save is validated as a whole and every problem is reported at once — an
unknown attribute, an operator that cannot apply (`eq` on `principal.scopes`,
which is a list), a malformed CIDR. The point is to refuse, at save time, the
rules that would otherwise silently never match.

### How rules combine

**Deny overrides; default deny.** Any applicable deny wins; otherwise any
applicable allow wins, carrying the union of the obligations of every
applicable allow; otherwise the answer is `no_applicable_rule`, a deny. Rule
order never matters.

**Missing data makes the policy stricter, never looser.** A comparison against
an attribute that is absent — a user with no `department`, a token with no
`auth_time` — is neither true nor false but *unknown*. An unknown allow does
not allow; an unknown **deny** denies (`deny_rule_indeterminate`). Otherwise a
deny rule written as `department ne "finance"` would quietly stop applying to
every user who has no department at all. Use `exists` to test for presence
explicitly; it is never unknown.

This matters for `context.ip_country` in particular: without a GeoIP database
it is always absent, so a deny rule that tests it denies every request. That is
the intended fail-closed behaviour — "the country cannot be verified" — and
shadow mode will show it as divergences long before enforce would act on it.

### Versions

The rule set is stored as immutable numbered versions (`policy_versions`,
migration `0023`). A save names the version it was based on and is refused
with `409` if someone else saved in between, so a concurrent change is never
silently overwritten. Restoring an old version writes it forward as a new one,
so the history is never rewritten and every decision in the log is attributable
to the exact rules that made it. Each instance caches the current version and
checks for a newer one every `POLICY_REFRESH_INTERVAL` (10s); its own saves
apply immediately.

**Version 1 is a baseline** that restates the admin API's code gates as rules:

| Code gate | Baseline rule |
|---|---|
| `RequireGlobalAdmin` | `global-admins` — allow `* /api/admin/*` for `admin`/`superadmin` |
| `RequireRole("superadmin")` on `/superadmins` | `superadmin-management` — deny unless `superadmin` |
| `RequirePasswordChangeComplete` | `password-change-pending` — deny while `must_change_password` |
| `RequireFreshAuth` on 16 routes | `destructive-step-up` — allow with `require_fresh_auth` |

A router test walks every admin route for every kind of principal and asserts
the baseline and the code agree everywhere, and that the baseline's step-up
list is exactly the set of routes the router wraps in `RequireFreshAuth` — so
the two cannot drift apart unnoticed.

`ADMIN_SCOPE_MODE`'s scope gates are **not** in the baseline, because a rule
cannot see that environment variable and would be wrong in one of its two
modes. With `ADMIN_SCOPE_MODE=enforce`, add the equivalent rules before reading
shadow divergences, e.g. a deny on `* /api/admin/dashboard*` unless
`principal.scopes contains "monitoring:read"` or `"admin"`.

### Rollout: `POLICY_MODE`

- **`off`** (default) — nothing is consulted. The policy API works, so rules
  can be written and simulated first.
- **`shadow`** — every admin request is evaluated; the response is never
  changed. The PEP compares the policy's decision with what the code gates did
  and records, in `policy_decisions` (migration `0024`), every would-be denial
  and every disagreement: `pdp_deny_code_allow` (the policy is stricter) or
  `pdp_allow_code_deny` (looser). `socrate_policy_divergences_total` counts
  them. With the untouched baseline it should read zero; anything else is a bug
  in one of the two, or a rule someone added on purpose.
- **`enforce`** — a deny is answered `403 policy_denied` (or
  `elevation_required` / `mfa_required` for an unmet obligation) before the code
  gates run. **An allow does not bypass them**: the request must still pass
  every gate, so enforcing can only remove access, never grant it. If no policy
  version can be loaded at all, the admin API fails closed with
  `503 policy_unavailable`; a store outage with a version already loaded keeps
  deciding on that version.

Retiring a code gate in favour of its rule is a later, separate step, taken
once its divergence count has been zero for a release.

**The policy editor is exempt from the policy.** `/api/admin/policy/*`,
`/elevate` and `/change-password` are never gated by the PEP — otherwise one
bad rule in enforce mode would lock out the only place it can be fixed. They
remain behind the code gates, and the policy API is the most tightly gated
surface there is: superadmin only, fresh step-up on every write, every save
and restore in the admin audit trail (`policy_updated`, `policy_restored`).

**The decision log** carries the request's correlation id, so a denial seen by
a user is one query away:
`GET /api/admin/policy/decisions?correlation_id=…` (superadmin), or
`GET /api/admin/security/policy-decisions?correlation_id=…` from the
monitoring console, which reads the log (never the rules) with
`monitoring:read`. Agreeing allows are not
logged — they are counted in `socrate_policy_decisions_total` — so the log
stays a list of things worth reading. Rows older than
`POLICY_DECISION_RETENTION_DAYS` (30) are swept hourly, by one instance.

### Applications: the decide endpoint (part 2)

An application's backend asks the same PDP about its own users:

```
POST /api/apps/{app_id}/service/policy/decide      (admin port)
Authorization: Bearer <the application's client_credentials token>
X-Correlation-ID: <the app's request id>

{"subject":  {"token": "<the user's access token>"},        // or {"user_id": 42}; omit for the app itself
 "action":   "invoice.approve",
 "resource": {"type": "invoice", "id": "inv-9", "attributes": {"amount": 25000, "owner_id": 42}},
 "context":  {"ip": "203.0.113.5", "attributes": {"channel": "web"}}}

→ 200 {"allow": false, "rule": "large-invoices-blocked", "reason": "denied_by_rule",
       "obligations": [], "policy_version": 7, "mode": "shadow"}
```

**What the application can and cannot say.** The caller is the application
proven by its client-credentials token, pinned to `{app_id}` — never a field in
the body. The **subject is resolved by Socrate**: role, A2 attributes, forced
password change, and the user's role *in the calling application*
(`principal.app_role`). An application can only ask about **its own members**
(or global admins): anyone else is `404 unknown subject`, the same answer as for
an id that does not exist, so the endpoint cannot be used to discover users. What
the application does supply — `action`, `resource`, `context` — are facts about
its own domain that only it knows; `context.ip` is the end user's address as it
observed it, and Socrate derives `context.ip_country` from it when GeoIP is
configured.

**Send the user's token, not their id**, whenever you have it. The token is
verified with exactly the checks `AuthMiddleware` applies (signature, expiry,
`token_version`, per-token revocation, lock), and it is the only source of
`principal.scopes`, `principal.amr` and `principal.auth_time_age`. With a bare
`user_id` those are absent, so a rule that depends on them is *unknown* — and a
deny rule that is unknown denies. A revoked or expired subject token is a
`400`, not a decision: that user has no session to decide for. A locked account
is a deny (`subject_locked`) without evaluating anything.

**Actions** are the application's own vocabulary (`invoice.approve`,
`report.export`). The admin namespace (`"<METHOD> /api/admin…"`) is refused
with `400`: those actions are decided only on the admin API's own requests.
Scope rules to an application with `app.client_id`, since a rule whose
`actions` is `*` applies to every application's actions as well as the admin
API's. With the baseline alone, every application action is
`no_applicable_rule` — write the application's allows before shadowing it.

**The mode travels with the answer.** Every response carries `mode`, and the
application's enforcement point acts on it: `off` — ignore; `shadow` — log a
denial, proceed; `enforce` — refuse. An operator therefore moves every
application from shadow to enforce by changing `POLICY_MODE` on Socrate, with
no redeploy anywhere. In `off` the endpoint still answers (so rules can be
tried), but nothing is recorded; in `shadow` and `enforce` denials are written
to the decision log with `source = decide_api` and the calling application's
`client_id`, under the request's correlation id.

**Obligations** are returned, not checked: the application's PEP honours them
against the user's token (backendkit's `pep` does). If no policy version can be
loaded the answer is `503 {"error": "policy_unavailable", "mode": ...}`.

**backendkit.** `socrate.Client.Decide` calls this endpoint with the cached
service token and forwards the request id. The `pep` package is the
enforcement point:

```go
enf, _ := pep.New(pep.Config{Decider: socrateClient})

// route-level
r.Use(enf.Middleware(func(r *http.Request) (string, socrate.PolicyResource, bool) {
    return "invoice.read", socrate.PolicyResource{Type: "invoice"}, true
}))

// object-level, once the resource is loaded
err := enf.Check(r.Context(), "invoice.approve", socrate.PolicyResource{
    Type: "invoice", ID: inv.ID, Attributes: map[string]any{"amount": inv.Amount},
}, pep.ContextFor(r))
if pep.WriteDenial(w, err) { return }
```

It must run after `jwtauth.Middleware` (the user's own token is sent as the
subject; without one it refuses `401` rather than deciding as the
application). It answers `403 policy_denied`, `elevation_required` or
`mfa_required` — the same codes as the admin API. When Socrate cannot be
reached it goes by the last mode it saw: proceed in `off`/`shadow`, refuse
`503` in `enforce`; before any decision has told it the mode it refuses, unless
`FailOpenWhenModeUnknown` is set.

**Part 3:** the console editor (oauth2-admin) and the decision-log view
(oauth2-monitoring).

## Next

- **A4 part 3** — the console editor and decision-log views.
- **A5** hosted-page branding and i18n.
