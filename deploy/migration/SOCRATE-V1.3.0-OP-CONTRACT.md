# Socrate OP contract (v1.3.0, updated for v1.12.2)

The values below are the OpenID Provider metadata and token facts for **Socrate**,
derived directly from the server source (module `github.com/ovander/go-oauth2`).
They were first confirmed at v1.3.0 and are kept current; every later change is
additive and marked with the version that introduced it. Use this as the source of
truth for compatibility work when the live discovery document is not reachable (e.g.
an audit environment with blocked egress).

When the OP *is* reachable, still verify against the live document — it reflects the
actual issuer and any per-instance configuration:

```bash
curl -s https://socrate.vandermoten.eu/.well-known/openid-configuration | jq
```

## Discovery document

`{iss}` is the configured issuer (e.g. `https://socrate.vandermoten.eu`), with **no
trailing slash**. Source: `internal/service/oauth_service.go` (`GetOpenIDConfiguration`).

| Field | Value |
|---|---|
| `issuer` | `{iss}` |
| `authorization_endpoint` | `{iss}/oauth/authorize` |
| `token_endpoint` | `{iss}/oauth/token` |
| `userinfo_endpoint` | `{iss}/oauth/userinfo` |
| `introspection_endpoint` | `{iss}/oauth/introspect` |
| `revocation_endpoint` | `{iss}/oauth/revoke` |
| `jwks_uri` | `{iss}/.well-known/jwks.json` |
| `response_types_supported` | `["code"]` (implicit/hybrid removed) |
| `grant_types_supported` | `["authorization_code", "refresh_token", "client_credentials"]` |
| `code_challenge_methods_supported` | `["S256"]` (no `plain`) |
| `token_endpoint_auth_methods_supported` | `["client_secret_basic", "client_secret_post"]` (no `none`) |
| `scopes_supported` | `["openid", "email", "profile", "offline_access", "api"]` |
| `subject_types_supported` | `["public"]` |
| `id_token_signing_alg_values_supported` | `["RS256"]` |
| `acr_values_supported` | `["pwd", "mfa"]` |
| `prompt_values_supported` | `["none", "login"]` |
| `authorization_response_iss_parameter_supported` | `true` (RFC 9207) |
| `claims_supported` | `sub, iss, aud, exp, iat, nbf, email, email_verified, name, preferred_username, picture, role, app_roles, token_version, auth_time, acr, amr, act, cnf` |

**Not advertised / not supported:**

- **No `end_session_endpoint`** is advertised. `GET`/`POST {iss}/oauth/logout`
  exists: it revokes the caller's tokens when a valid bearer is presented, and
  redirects to `post_logout_redirect_uri` (with `state` appended) **only** when that
  URI is one of the client's registered redirect URIs and the client is identified
  by `client_id` or by the audience of a signature-verified `id_token_hint` (an
  expired hint is accepted for this); otherwise it answers
  `{"message":"logout successful"}` as JSON. Socrate keeps no browser SSO session
  beyond the hosted login, so the reliable way for an app to end a session is still
  to revoke its refresh token at `/oauth/revoke`.
- No dynamic client registration endpoint; no device authorization endpoint.
- `response_type=token`/`id_token` (implicit/hybrid) and `grant_type=password` are
  rejected.

## Token and key facts

Source: `internal/shared/auth/token.go`, `internal/shared/auth/keys*.go`,
`internal/service/oauth_service.go`.

- **`sub`** is the user's numeric primary key rendered as a decimal string
  (`strconv(user.ID)`). For `client_credentials` tokens it is `app:<app_id>`.
  → Identity continuity across a data migration requires **preserving the `users`
  primary keys** (and resetting the sequence); then every `sub` is unchanged.
- **`aud`** contains the client's `client_id` as the first entry; an app may also have
  additional registered audiences (resource indicators). The refresh grant verifies
  `aud[0] == client_id`. → A resource server should validate `aud` against its own
  `client_id` (e.g. `jwtauth.WithAudience(client_id)`).
- **`auth_time`** (since v1.10.0) is the time the user actually signed in on
  Socrate's hosted page, carried through the authorization code and **kept on
  every refresh** (a refresh is not a new sign-in). `max_age` is evaluated
  against it, and `prompt=login` (v1.8.0) forces a new sign-in and so a new
  `auth_time`. Before v1.10.0 it was the user's last-login time.
- **`amr` / `acr`** are `["pwd"]` / `"pwd"` for a password sign-in, and
  `["pwd", "otp", "mfa"]` / `"mfa"` when a TOTP or recovery code was also given.
  They are kept on refresh. Use `amr` containing `mfa` to require two factors.
- **`aud` with `AUDIENCE_MODE=dual`** (server-wide, default `off`): the client's
  registered audiences are appended after the `client_id`, so `aud[0]` stays the
  `client_id`. Verifiers that check membership of their own id keep working.
- **Access-token lifetime** is the server default unless the client has its own
  `access_token_ttl_seconds`; read `exp`, never assume a fixed TTL.
- **Custom claims** projected by a client's claim mappings are issued under the
  `CLAIMS_NAMESPACE` prefix (default `https://socrate/`, e.g.
  `https://socrate/tenant_id`), never as bare names, so they cannot shadow a
  registered claim.
- **Refresh tokens** are issued on the authorization-code grant **unconditionally** —
  the `offline_access` scope is *not* required to receive one.
- **Refresh-token rotation with reuse detection**: every refresh returns a new
  refresh token; replaying a consumed one is logged as a reuse event and revokes the
  chain. Clients must persist the newest token and re-authenticate on `invalid_grant`.
- **JWKS keys** always carry `kty:"RSA"`, `use:"sig"`, `alg:"RS256"`, and a UUID
  `kid` (test-enforced). Key rotation keeps retired keys in the JWKS so in-flight
  tokens keep validating.

## `client_credentials` tokens (service accounts)

Source: `handleClientCredentialsGrant` (`internal/service/oauth_service.go`) and
`GenerateClientCredentialsToken` (`internal/shared/auth/token.go`). A service-account token is an
**access token only**: no refresh token, no ID token. The client authenticates with its secret
(`client_secret_basic` or `client_secret_post`) and must be active.

| Claim | Value |
|---|---|
| `iss` | the issuer |
| `sub` | `app:<app_id>`, the numeric id of the calling client |
| `aud` | `[<calling client_id>]`, **only**. `AUDIENCE_MODE=dual` does not apply to these tokens: the client's registered audiences are not added. |
| `scope` | the requested scope, or `api` when none is requested. It must be names from `scopes_supported` (plus the console scopes) and pass the client's `allowed_scopes` under `SCOPE_POLICY_MODE`. |
| `type` | `access` |
| `iat`, `nbf`, `exp`, `jti` | always present. `exp` follows the client's `access_token_ttl_seconds`, else the server default (the same value as `expires_in`). |
| Custom claims | the client's claim mappings with an **app or literal source** only (`literal:…`, `app.id`, `app.client_id`), issued under `CLAIMS_NAMESPACE` (e.g. `https://socrate/tenant_id`). User sources (`user.attributes.*`, `user.email`, `user.name`, `user.id`) and `app_role` yield nothing, and are not reported as `custom_claim_missing`. |
| **Not present** | `role`, `roles`, `app_roles`, `token_version`, `auth_time`, `amr`, `acr`, `email`, `name`, `act`, `cnf` |

The token response has `token_type: "Bearer"`. A client registered with `require_dpop` must
present a DPoP proof to obtain one, but the issued token carries no `cnf`.

**Implications for a resource server**

- The audience a service-account token carries is the **caller's** `client_id`, not the resource
  server's. A service that accepts calls from other services lists each caller's `client_id` in
  its audience check (backendkit: `jwtauth.WithAudiences(callerA, callerB, …)`), then
  distinguishes callers by `aud` or `sub`.
- There is no user, so no `role`: authorise service calls on `sub` (`app:<id>`), the audience and
  the custom claims, never on a role check that a missing `role` would silently fail open.
- `RequireTenant`-style checks see a tenant only through a literal claim mapping (below).

**Per-(consumer, tenant) service accounts.** When a service acts for one tenant at a time,
register one confidential client per (consumer, tenant). Give each a claim mapping
`"tenant_id": "literal:<tenant uuid>"` (target `access`) and the scopes it needs. Every token it
obtains then carries `https://socrate/tenant_id: <tenant uuid>`, which backendkit reads with
`jwtauth.WithTenantClaim("https://socrate/tenant_id")`. The tenant is fixed by registration, so a
compromised consumer secret reaches one tenant only. Rotate or deactivate the client to revoke it.

## Client-registration implications

- **PKCE S256 is mandatory** for interactive clients (public and confidential).
- A requested scope outside the client's allowed-scopes policy is rejected with
  `invalid_scope`, so register each client with exactly the scopes it needs from
  `scopes_supported`.
- Redirect URIs are matched with scheme/host case-normalized and path/query exact;
  register each one explicitly (no wildcards).

> Source commit for these values is recorded in the PR that introduced this file;
> re-derive from `internal/service/oauth_service.go` if the protocol surface changes,
> and keep the [`APP-COMPAT-PROMPT.md`](./APP-COMPAT-PROMPT.md) embedded copy in sync.
