# Socrate OAuth 2.0 / OpenID Connect — Integration Guide

This document is the canonical reference for **application developers** (backend
and frontend) integrating with the Socrate OAuth 2.0 / OpenID Connect server.
It describes every public endpoint, the supported flows, request/response
shapes, error formats, and copy-paste integration recipes.

> The server implements OAuth 2.0 (RFC 6749), PKCE (RFC 7636), Token
> Introspection (RFC 7662), Token Revocation (RFC 7009), and OpenID Connect
> Core / Discovery. RS256 (RSA) is used for all token signing.

---

## 1. Topology & Base URLs

The server exposes **two separate HTTP routers** that are intended to run on
different ports behind different firewall rules.

| Router | Default port | Audience | Exposure |
|--------|--------------|----------|----------|
| **OAuth / Public API** | `8080` | End users, SPAs, mobile apps, app backends | Public internet |
| **Admin API** | `8081` | Platform operators, app admins, M2M service accounts | Internal / restricted |

Configure the public base URL via `OAUTH_ISSUER` (e.g. `https://auth.example.com`).
All examples below use:

```
OAUTH  base: https://auth.example.com           (port 8080)
ADMIN  base: https://auth-admin.example.com      (port 8081)
```

In single-port (development) mode, `NewRouter` mounts the admin router under the
`/manage` prefix and the OAuth router at `/`.

---

## 2. Concepts

### 2.1 Clients (Apps)

Every integrating application is registered as an **App** and receives a
`client_id`. There are two kinds:

| Type | `is_public` | Has `client_secret`? | Auth at token endpoint | Typical use |
|------|-------------|----------------------|-------------------------|-------------|
| **Confidential** | `false` | Yes (shown once) | `client_secret` (+ optional PKCE) | Server-rendered apps, backend-for-frontend |
| **Public** | `true` | No | **PKCE mandatory** | SPAs, mobile, native apps |

Apps are created through the Admin API (§8.2). The `client_secret` is returned
**only once**, at creation or rotation — store it securely.

### 2.2 Scopes

Supported scopes (`scopes_supported`):

| Scope | Meaning |
|-------|---------|
| `openid` | Request an OpenID Connect ID token |
| `email` | Include `email` / `email_verified` claims |
| `profile` | Include `name` / `preferred_username` claims |
| `offline_access` | Request a refresh token |
| `api` | Default scope for `client_credentials` (M2M) tokens |

Unknown scopes are rejected with `invalid scope`.

### 2.3 Tokens

| Token | Format | Default TTL | Notes |
|-------|--------|-------------|-------|
| Access token | RS256 JWT | `900s` (15 min) | `Authorization: Bearer <token>` |
| Refresh token | RS256 JWT | `604800s` (7 days) | **Single-use** — rotated on every refresh |
| ID token | RS256 JWT | tied to access | OpenID Connect identity, contains `nonce` |

Access-token claims include: `sub`, `iss`, `aud`, `exp`, `iat`, `nbf`, `email`,
`email_verified`, `name`, `preferred_username`, `role`, `app_roles`,
`token_version`, `auth_time`, and — for interactive logins — `amr`/`acr`
(RFC 8176 authentication methods / context class: `["pwd"]`/`pwd` for a password
login, `["pwd","otp","mfa"]`/`mfa` when a second factor was used). Verify
signatures against the JWKS endpoint (§7).

**Nuclear revocation:** every user has a `token_version`. Logout, password
reset, or admin "revoke tokens" increments it, instantly invalidating all
previously issued access/refresh tokens for that user.

For the guaranteed time-to-revoke (the **freshness SLA**) per validation
strategy — introspection vs. local JWT validation — and how to tune it, see
[`REVOCATION-FRESHNESS-SLA.md`](REVOCATION-FRESHNESS-SLA.md).

### 2.4 Roles

**Global roles** (on the user): `user`, `admin`, `superadmin`. `admin` and
`superadmin` are "global admins" with implicit access to every app.

**Per-app roles** (user ↔ app membership): `admin`, `manager`, `editor`,
`viewer`, `user`. A user must have a role for an app to obtain a token for it
through the browser flow.

---

## 3. Choosing an Integration Pattern

| You are building… | Use | Section |
|-------------------|-----|---------|
| A SPA / mobile / native app (no secret) | **Authorization Code + PKCE** | §4 |
| A server-rendered web app with a backend | **Authorization Code (confidential)** | §4 |
| A backend that just needs to call its own protected resources / send magic links | **Client Credentials (service account)** | §6 |
| A custom login UI talking JSON directly (first-party) | **Direct JSON Auth API** | §5 |
| Passwordless email login | **Magic Link** | §5.7 |

---

## 4. Authorization Code Flow (browser-based)

This is the recommended flow for both SPAs (public + PKCE) and server apps
(confidential). The server renders its own login **and consent** pages, so your
app only deals with two endpoints: `/oauth/authorize` and `/oauth/token`.

### Step 1 — Redirect the user to `/oauth/authorize`

```
GET https://auth.example.com/oauth/authorize
  ?response_type=code
  &client_id=YOUR_CLIENT_ID
  &redirect_uri=https://app.example.com/callback
  &scope=openid%20email%20profile%20offline_access
  &state=RANDOM_OPAQUE_VALUE          # REQUIRED (CSRF defence)
  &nonce=RANDOM_NONCE                  # recommended with openid
  &code_challenge=BASE64URL_SHA256     # REQUIRED for public clients
  &code_challenge_method=S256
```

| Parameter | Required | Notes |
|-----------|----------|-------|
| `response_type` | yes | Only `code` is supported |
| `client_id` | yes | |
| `redirect_uri` | yes | Must exactly match a registered URI |
| `state` | **yes** | Server rejects requests without it |
| `scope` | recommended | space-delimited |
| `nonce` | recommended | echoed into the ID token |
| `code_challenge` / `code_challenge_method` | required for public clients | `S256` |
| `max_age` | optional | OIDC: forces re-auth if the session is older |

The server renders a login page (if the user has no session) followed by a
**consent page**. On approval it redirects to:

```
https://app.example.com/callback?code=AUTH_CODE&state=RANDOM_OPAQUE_VALUE&iss=https%3A%2F%2Fauth.example.com
```

The response includes the **`iss`** parameter (RFC 9207): the issuer identifier
of this authorization server. A client that talks to more than one AS should
verify `iss` matches the AS it sent the request to, defending against IdP
mix-up attacks.

On failure it redirects with `?error=...&error_description=...&state=...`
(e.g. `access_denied` if the user clicks "Deny").

> **Always verify** that the returned `state` matches the value you sent.

### Step 2 — Exchange the code at `/oauth/token`

`POST /oauth/token` accepts **either** `application/x-www-form-urlencoded`
(standard) **or** `application/json`.

**Public client (PKCE):**

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTH_CODE
&redirect_uri=https://app.example.com/callback
&client_id=YOUR_CLIENT_ID
&code_verifier=ORIGINAL_PKCE_VERIFIER
```

**Confidential client:** authenticate with the secret, either via HTTP Basic
(`Authorization: Basic base64(client_id:client_secret)`) or body fields
`client_id` / `client_secret`.

**Success `200`:**

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "id_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "openid email profile offline_access",
  "roles": ["editor"],
  "app_roles": {"my-app": "editor"}
}
```

### Step 3 — Refresh

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=eyJ...
&client_id=YOUR_CLIENT_ID            # confidential: + client_secret
```

Refresh tokens are **single-use**: each refresh returns a new refresh token and
invalidates the old one. Reusing a consumed refresh token fails with
`invalid_grant`. Confidential clients must re-authenticate; the token's audience
must match the requesting `client_id`.

### PKCE helper (generating the challenge)

```js
// browser / Web Crypto
const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
const digest   = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
const challenge = base64url(new Uint8Array(digest));
// send challenge in step 1, verifier in step 2
```

---

## 5. Direct JSON Authentication API (first-party)

For first-party clients that render their **own** login UI, the `/api/auth/*`
endpoints accept and return JSON directly (no browser redirect / consent page).
All endpoints are under the **OAuth router** and set `Content-Type:
application/json`.

### 5.1 Signup — `POST /api/auth/signup`

```json
{ "name": "Ada", "email": "ada@example.com", "password": "S3cret!", "client_id": "YOUR_CLIENT_ID" }
```
`201 Created`:
```json
{ "user_id": 42, "message": "Please check your email to verify your account" }
```
(`verify_url` is included only in development.)

### 5.2 Verify email — `GET /api/auth/verify-email?token=...`
`200`: `{ "message": "Email verified successfully" }`

### 5.3 Login — `POST /api/auth/login`

```json
{ "email": "ada@example.com", "password": "S3cret!", "app_client_id": "YOUR_CLIENT_ID" }
```
`200`:
```json
{
  "access_token": "eyJ...", "refresh_token": "eyJ...", "id_token": "eyJ...",
  "token_type": "Bearer", "expires_in": 900, "user_id": 42,
  "roles": ["editor"], "app_roles": {"my-app": "editor"},
  "must_change_password": false
}
```
Errors: `401` invalid credentials, `403` account locked / email not verified.

### 5.4 Refresh — `POST /api/auth/refresh`
`{ "refresh_token": "eyJ..." }` → new `{ access_token, refresh_token, id_token, token_type, expires_in }`. `401` if invalid/expired. (Rate-limited together with `/oauth/token`.)

This endpoint runs the **same single refresh code path** as `/oauth/token`
(`grant_type=refresh_token`): one hardened implementation enforcing
**single-use rotation, replay detection, token-family revocation on reuse**
(`REFRESH_REUSE_MODE`), token-version revocation, and **DPoP** sender-constraint
binding. The client is identified by the refresh token's own `aud` claim — no
`client_id` is sent here. **Confidential clients** (those with a stored secret)
must refresh at `/oauth/token` with client authentication; this bearer endpoint
is for **public first-party clients** (the admin console, SPAs).

### 5.5 Logout — `POST /api/auth/logout`
Requires `Authorization: Bearer <access_token>`. Increments the user's
`token_version` (revokes all their tokens). `200`: `{ "message": "Logged out successfully" }`
When the admin-console refresh cookie channel is enabled (see §5.8), logout also
clears that cookie.

### 5.8 Admin-console refresh cookie (first-party, Tier-0)
When `ADMIN_CONSOLE_CLIENT_ID` is configured, the **first-party admin console**
(a public, PKCE client) does **not** receive its refresh token in the JSON body.
Instead, on `authorization_code` login and on every refresh, `/oauth/token` sets
it as a cookie and omits it from the body:

```
Set-Cookie: refresh_token=<jwt>; Path=/oauth/token; Max-Age=<REFRESH_TOKEN_TTL>;
            HttpOnly; Secure; SameSite=Strict
```

- The **access token** stays a Bearer token in the JSON body (held in memory by
  the SPA); the **refresh token** is never readable by JavaScript (XSS-safe).
- To refresh, the SPA POSTs `grant_type=refresh_token&client_id=<admin client>`
  to `/oauth/token` with the cookie attached — no `refresh_token` form field.
  The server reads it from the cookie and runs the single hardened refresh grant
  (rotation + replay detection + DPoP binding, §5.4 / §2.3), rotating the cookie.
- **Logout** (`/api/auth/logout`) revokes the tokens server-side and clears the
  cookie. The channel is inert (unchanged behaviour) when the env var is unset.

### 5.6 Password reset
- `POST /api/auth/request-password-reset` — `{ "email": "..." }`. Always `200` with a generic message (no email enumeration).
- `POST /api/auth/reset-password` — `{ "token": "...", "password": "..." }`.

### 5.7 Magic link (passwordless)

Two halves, by design:

1. **Request** (backend / service account only) — `POST /api/apps/{app_id}/service/magic-link` on the **Admin router**, authenticated with a `client_credentials` token (§6). Body: `{ "email": "ada@example.com" }`. Always returns `202` with a generic message (no enumeration). The user receives an email containing a single-use token.
2. **Verify** (public) — `POST /api/auth/magic-link/verify` on the OAuth router:
   ```json
   { "token": "RAW_MAGIC_TOKEN", "client_id": "YOUR_CLIENT_ID" }
   ```
   Success returns a full login token set (same shape as §5.3). `422` if the link was already used, `401` if invalid/expired, `403` if locked. **POST-only** so email scanners don't consume the token.

### 5.8 Invitations
- `GET /api/auth/invite?token=...` → `{ "valid": true, "email": "...", "app_name": "...", "expires_at": "..." }`
- `POST /api/auth/invite` → `{ "token": "...", "name": "...", "password": "..." }` to accept and set a password.

### 5.9 Profile (self-service) — requires Bearer token
- `GET /api/profile` → `UserResponse`
- `PUT` / `PATCH /api/profile` → update mutable fields (`name`, `title`, `division`, `company`, `country`, `phone`, `job_title`, `department`, `language`, `timezone`).
- `GET /api/userinfo` → `UserResponse` for the authenticated user.

---

## 6. Client Credentials (Machine-to-Machine)

For an app **backend** to authenticate as itself (no user). Only **confidential**
clients (with a secret) can use this grant.

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET
&scope=api
```
`200`:
```json
{ "access_token": "eyJ...", "token_type": "Bearer", "expires_in": 900, "scope": "api" }
```

The resulting token has `sub = "app:{id}"`. It is used to call **Service Account
routes** on the Admin router, which are scoped to that exact app:

- `POST /api/apps/{app_id}/service/users` — create a user inside the app.
- `POST /api/apps/{app_id}/service/magic-link` — trigger a magic-link email.

`ServiceAccountMiddleware` enforces that the `{app_id}` in the URL matches the
app encoded in the token, so an app can never act on another app's resources.

---

## 7. OpenID Connect Discovery

- `GET /.well-known/openid-configuration` — full metadata document
  (`authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`,
  `introspection_endpoint`, `revocation_endpoint`, supported response types
  `["code"]`, grants `["authorization_code","refresh_token","client_credentials"]`,
  scopes, `code_challenge_methods_supported: ["S256"]`, …). `claims_supported`
  lists the assertable claims including `auth_time`, `acr`, `amr`, `act`, and
  `cnf`; `acr_values_supported` advertises `["pwd","mfa"]` (RFC 8176);
  `authorization_response_iss_parameter_supported: true` (RFC 9207).
- `GET /.well-known/jwks.json` — RSA public keys (JWKS) for verifying RS256
  tokens. Cache and key off the `kid` header; keys rotate automatically.

### UserInfo — `GET`/`POST /oauth/userinfo`
Requires `Authorization: Bearer <access_token>`:
```json
{
  "sub": "42", "email": "ada@example.com", "email_verified": true,
  "name": "Ada", "preferred_username": "ada", "role": "user",
  "app_roles": {"my-app": "editor"}
}
```

### Introspection — `POST /oauth/introspect` (RFC 7662)
Requires client authentication (Basic or body credentials). Returns
`{ "active": true, "scope": "...", "client_id": "...", "username": "...", "exp": ..., "iat": ..., "sub": "...", "auth_time": ... }`
or `{ "active": false }` for invalid/revoked/expired tokens. Additional fields
surface security metadata so a resource server can act on it without locally
parsing the JWT:
- `aud` — the token's audience (RFC 7662 §2.2): the resource identifiers it is
  intended for. A resource server verifies its own identifier appears here
  (RFC-001). Carries the `client_id` plus any registered audiences under
  `AUDIENCE_MODE=dual`.
- `auth_time` — the end-user's last authentication time (RFC 9068 §2.2.1) for
  freshness/step-up decisions. Omitted when the token has no associated user
  authentication (client-credentials / token-exchange results).
- `amr` / `acr` — authentication methods / context class (RFC 8176), for gating
  on authentication strength (e.g. require `mfa`). Present for interactive logins.
- `cnf` `{ "jkt": "..." }` — DPoP sender-constraint (RFC 9449 §7), when present.
- `act` `{ "sub": "...", "act": {...} }` — the actor (delegation/impersonation)
  chain (RFC 8693 §4.1), when the token was minted via token exchange.

### Revocation — `POST /oauth/revoke` (RFC 7009)
Body `{ "token": "...", "token_type_hint": "access_token|refresh_token" }`.
Authenticate either with the user's Bearer token (self-revocation) or with
confidential-client credentials. **Always returns `200`** (even for unknown
tokens) to prevent enumeration.

### End session / logout — `GET`/`POST /oauth/logout`
Revokes the session and optionally redirects to a validated
`post_logout_redirect_uri` (must be registered for the client identified via
`client_id` or a verified `id_token_hint`). Otherwise returns
`{ "message": "logout successful" }`.

---

## 8. Admin API (port 8081)

All `/api/admin/*` routes require a Bearer access token belonging to a global
admin (`admin`/`superadmin`). App-scoped routes require an app role.

**Forced password change (Tier-0).** If the admin's account is flagged
`must_change_password` (returned in the login response), **every** `/api/admin/*`
route returns `403 { "error": "password_change_required" }` — except
`POST /api/admin/change-password` — until the password is changed. Clients must
detect this code and route the admin through the change-password flow.

### 8.1 Admin login — `POST /api/admin/login` (deprecated)
`{ "email": "...", "password": "..." }` (no app context). Returns a token set.
`GET /api/admin/profile` returns the current admin.

**Deprecated** in favour of the admin console's Authorization Code + PKCE flow
(see `docs/ADMIN-SPA-MIGRATION.md`). Always returns a `Deprecation: true` header
(RFC 8594). When `ADMIN_PASSWORD_LOGIN_ENABLED=false` it is refused with
`403 { "error": "password_login_disabled" }`. The first-party admin console is a
public PKCE client auto-registered from `ADMIN_CONSOLE_CLIENT_ID` +
`ADMIN_CONSOLE_REDIRECT_URIS`.

**Step-up for destructive operations (Tier-0).** The most destructive admin
routes — **delete OAuth client** (`DELETE /api/admin/apps/{id}`), **rotate client
secret** (`POST /api/admin/apps/{id}/rotate-secret`), **create/delete superadmin**
(`POST /api/admin/superadmins`, `DELETE /api/admin/superadmins/{id}`), and **block
user** (`POST /api/admin/users/{id}/block`) — require a *recent* authentication.
If the access token's `auth_time` is older than `ADMIN_ELEVATION_MAX_AGE`
(default 5 min), they return `403 { "error": "elevation_required" }`. The client
then calls `POST /api/admin/elevate` (§8.1.2) and retries with the fresh token.
A refreshed session does **not** count as fresh (refresh preserves the original
`auth_time`).

### 8.1.2 Step-up / elevate — `POST /api/admin/elevate`
`{ "password": "...", "mfa_code": "..."? }`. Requires a Bearer token; the
already-authenticated admin re-presents their password (and MFA if enrolled) to
obtain a **fresh-`auth_time` access token** for destructive operations. Returns
the same shape as login but **no refresh token** (elevation proves presence; it
does not start a new session — the existing refresh token / cookie is untouched).
`401` on bad credentials / `mfa_required` / invalid MFA code; `501` if step-up is
not configured.

### 8.1.1 Change password — `POST /api/admin/change-password`
`{ "current_password": "...", "new_password": "..." }`. Requires a Bearer token;
**reachable even while `password_change_required` is in force**. On success the
admin's tokens are revoked (token-version bump) and they must log in again
(`200 { "message": "Password changed successfully; please log in again" }`).
`401` if the current password is wrong; `400` on a weak or unchanged new password.

### 8.2 App (client) management — `/api/admin/apps`
- `GET /` — list apps → `{ "apps": [AppResponse], "total_count": n }`
- `POST /` — create app:
  ```json
  { "name": "My App", "url": "https://app.example.com",
    "redirect_uris": ["https://app.example.com/callback"],
    "is_public": false, "require_pkce": true,
    "audiences": ["https://api.example.com"],
    "allowed_scopes": ["openid", "profile", "email"],
    "claim_mappings": { "tier": "user.attributes.tier",
                        "dept": {"source": "user.attributes.dept", "target": "both"} } }
  ```
  Returns `AppWithSecretResponse` including the one-time `client_secret`
  (empty for public clients). `audiences` (optional) registers the resource
  identifiers tokens for this client are intended for — the canonical `aud`
  claim (RFC-001). `allowed_scopes` (optional) is the client's scope policy:
  the only scopes it may request at `/oauth/authorize` and at every grant,
  refresh included; entries must be supported scopes (§2.2) and an empty list
  means unrestricted. It is applied according to `SCOPE_POLICY_MODE`
  (`off` default · `observe` audits `scope_denied` · `enforce` answers
  `invalid_scope`). `claim_mappings` (optional, A2) declares the custom claims
  this client's tokens carry, keyed by the unqualified claim name; each value is
  either a source string or `{"source": …, "target": "access"|"id"|"both"}`
  (default `access`). Sources are a closed set: `user.attributes.<key>`,
  `user.email`, `user.name`, `user.id`, `app_role`, `app.id`, `app.client_id`,
  `literal:<constant>`. Every mapped claim is issued under `CLAIMS_NAMESPACE`
  (default `https://socrate/`), so it can never shadow a registered claim; an
  unsupported source or target is refused with `400 invalid claim mapping`. See
  `docs/EXTENSIBILITY.md` for the size caps and the full semantics. On update,
  omitting `audiences` / `allowed_scopes` / `claim_mappings` leaves them
  unchanged; a non-null value (including `[]` / `{}`) replaces the set.
- `GET /{id}` · `PUT /{id}` · `DELETE /{id}`
- `POST /{id}/rotate-secret` — issue a new secret (returned once).

`AppResponse`:
```json
{ "id": 1, "name": "My App", "client_id": "...", "active": true,
  "is_public": false, "require_pkce": true, "url": "https://app.example.com",
  "redirect_uris": ["https://app.example.com/callback"], "owner_id": 5,
  "audiences": [], "allowed_scopes": [], "claim_mappings": {},
  "created_at": "2026-01-01T00:00:00Z" }
```

### 8.3 User management — `/api/admin/users`
List/get/delete users, `GET /{id}/apps`, `GET /{id}/sessions`,
`POST /{id}/revoke-tokens`, `POST /{id}/unlock`, `POST /{id}/block`.

- `PUT /{id}/attributes` — replace a user's free-form attributes (A2):
  `{ "attributes": { "tier": "gold", "dept": "engineering" } }` → the updated
  `UserResponse`. Global admin only, audited (`update_user_attributes`; the
  audit row records the attribute *names*, never their values). The body
  replaces the whole set, so `{}` clears it. At most 32 attributes / 4 KB, names
  ≤ 64 characters — `400` otherwise. Attributes are inert on their own: they
  reach a token only when a client declares a matching `claim_mappings` entry.

### 8.3.1 Outbound webhooks — `/api/admin/webhooks`

Global admin only; the mutating routes additionally require fresh step-up.
Delivery is gated by `WEBHOOKS_MODE` (`off` default): with it off, subscriptions
can be managed but nothing is enqueued or sent.

- `GET /events` — the subscribable event catalogue → `{"events": [...], "wildcard": "*"}`
- `GET /` — list subscriptions (`?app_id=` to filter) → `{"webhooks": [...], "total_count": n}`
- `POST /` — register a target:
  ```json
  { "name": "SIEM", "url": "https://hooks.example.com/socrate",
    "app_id": 3, "event_types": ["login.failed", "user.created"] }
  ```
  Returns `201` with the subscription **and its `secret`** — generated
  server-side and shown exactly once. The URL must be `https` and must resolve
  only to public addresses (`400 invalid webhook URL` otherwise); every
  `event_types` entry must be in the catalogue, or `"*"` for everything.
  Omitting `app_id` makes it global (every app's events). Requires
  `SECRET_KEY_BASE` — without it, `501`.
- `GET /{id}` · `PUT /{id}` (name, url, event_types, active) · `DELETE /{id}`
  (also deletes that subscription's undelivered rows)
- `POST /{id}/rotate-secret` — issue a new signing secret, returned once
- `GET /deliveries` — the outbox (`?subscription_id=`, `?status=pending|delivered|dead`,
  `?page=`, `?page_size=`)
- `GET /deliveries/stats` — outbox depth per status
- `POST /deliveries/{id}/requeue` — replay a dead or stuck delivery

Every subscription change is recorded in the admin audit trail
(`webhook_created`, `webhook_updated`, `webhook_deleted`,
`webhook_secret_rotated`, `webhook_delivery_requeued`). See
`docs/EXTENSIBILITY.md` for the payload shape, the transactional-outbox
guarantee and the SSRF rules.

### 8.4 Other admin areas
`/api/admin/stats`, `/activity`, `/dashboard/*`, `/superadmins`,
`/security/*` (events, threats, geo, blocked-ips, ip-reputation),
`/events/stream`, `/sessions`, `/reports/*`, `/alerts/*`, `/tokens/stats`,
`/logs` (audit logs, with `/export`), `/settings/*`.

### 8.5 App-scoped user management — `/api/apps/{app_id}/users`
For **app admins** (per-app `admin` role or global admin). CRUD over an app's
members, `POST /{user_id}/resend-verification`, `POST /{user_id}/reset-password`.
`GET /api/apps/{app_id}/logs` (app admin only) returns activity logs.

---

## 9. Errors

**OAuth endpoints** (`/oauth/*`) use RFC 6749 error objects:
```json
{ "error": "invalid_grant", "error_description": "authorization code expired" }
```
Common codes: `invalid_request`, `invalid_client`, `invalid_grant`,
`unsupported_grant_type`, `invalid_token`, `access_denied`, `server_error`.

**JSON API endpoints** (`/api/*`, admin) use:
```json
{ "error": "invalid credentials" }
```

| HTTP | Meaning |
|------|---------|
| `400` | malformed request / validation error |
| `401` | missing/invalid/expired/revoked token, bad credentials |
| `403` | account locked, email unverified, insufficient role |
| `422` | magic link already used |
| `429` | rate limited (see `Retry-After`) |
| `500` | server error (details never leaked to clients) |

---

## 10. Cross-Cutting Concerns

### Authentication header
Protected resources expect `Authorization: Bearer <access_token>`. Failures
return `401` with `WWW-Authenticate: Bearer realm="oauth2", error="invalid_token"`.

### Rate limiting
Login, signup, token, refresh, password-reset, and magic-link endpoints are
per-IP rate limited. Responses include `X-RateLimit-Limit`,
`X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After` on `429`.
Defaults: login `5/60s`, signup `3/hour`.

### CORS
Set `ALLOWED_ORIGINS` to an explicit comma-separated origin list to enable
credentialed cross-origin requests. A wildcard (`*`) disables credentials (the
spec forbids combining them). Allowed methods: `GET, POST, PUT, PATCH, DELETE,
OPTIONS`. Allowed headers include `Authorization`, `Content-Type`,
`X-Correlation-ID`.

### Correlation IDs
Send `X-Correlation-ID` to trace a request across logs; it is echoed back in the
response.

### Security headers
The server sets `X-Content-Type-Options`, `X-Frame-Options`,
`Content-Security-Policy`, and (under HTTPS) `Strict-Transport-Security`.

### Health & version
`GET /health`, `/health/liveness`, `/health/readiness`, `/version` are available
on both routers as JSON.

---

## 11. Quick Reference — Endpoint Index

**OAuth router (8080)**

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/.well-known/openid-configuration` | — | Discovery |
| GET | `/.well-known/jwks.json` | — | JWKS |
| GET | `/oauth/authorize` | session | Authorization (HTML) |
| POST | `/oauth/authorize` | — | Login/consent submit |
| POST | `/oauth/token` | client | Token issuance/refresh |
| GET/POST | `/oauth/userinfo` | Bearer | UserInfo |
| POST | `/oauth/introspect` | client | Introspection |
| POST | `/oauth/revoke` | Bearer/client | Revocation |
| GET/POST | `/oauth/logout` | optional | End session |
| POST | `/api/auth/signup` | — | Register |
| GET | `/api/auth/verify-email` | — | Verify email |
| POST | `/api/auth/login` | — | JSON login |
| POST | `/api/auth/refresh` | — | JSON refresh |
| POST | `/api/auth/logout` | Bearer | JSON logout |
| POST | `/api/auth/request-password-reset` | — | Request reset |
| POST | `/api/auth/reset-password` | — | Reset |
| GET/POST | `/api/auth/invite` | — | Validate / accept invite |
| POST | `/api/auth/magic-link/verify` | — | Verify magic link |
| GET | `/api/userinfo` | Bearer | Current user |
| GET/PUT/PATCH | `/api/profile` | Bearer | Profile self-service |

**Admin router (8081)**

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/admin/login` | — | Admin login |
| * | `/api/admin/apps/**` | global admin | App management |
| * | `/api/admin/users/**` | global admin | User management |
| * | `/api/admin/{dashboard,security,alerts,reports,logs,…}` | global admin | Ops |
| * | `/api/apps/{app_id}/users/**` | app admin | App-scoped users |
| GET | `/api/apps/{app_id}/logs` | app admin | App activity logs |
| POST | `/api/apps/{app_id}/service/users` | service account | M2M create user |
| POST | `/api/apps/{app_id}/service/magic-link` | service account | M2M magic link |
</content>
</invoke>
