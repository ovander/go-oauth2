# Socrate v1.3.0 — confirmed OP contract

The values below are the OpenID Provider metadata and token facts for **Socrate
v1.3.0**, derived directly from the server source (module
`github.com/ovandermoten/go-oauth2`, at the v1.3.0 level). Use this as the source of
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
| `authorization_response_iss_parameter_supported` | `true` (RFC 9207) |
| `claims_supported` | `sub, iss, aud, exp, iat, nbf, email, email_verified, name, preferred_username, role, app_roles, token_version, auth_time, acr, amr, act, cnf` |

**Not advertised / not supported:**

- **No `end_session_endpoint`** — there is no RP-initiated (front-channel) logout.
  Sessions are ended by revoking the refresh token at `/oauth/revoke`.
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
- **Refresh tokens** are issued on the authorization-code grant **unconditionally** —
  the `offline_access` scope is *not* required to receive one.
- **Refresh-token rotation with reuse detection**: every refresh returns a new
  refresh token; replaying a consumed one is logged as a reuse event and revokes the
  chain. Clients must persist the newest token and re-authenticate on `invalid_grant`.
- **JWKS keys** always carry `kty:"RSA"`, `use:"sig"`, `alg:"RS256"`, and a UUID
  `kid` (test-enforced). Key rotation keeps retired keys in the JWKS so in-flight
  tokens keep validating.

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
