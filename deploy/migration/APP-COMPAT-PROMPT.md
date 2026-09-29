# Socrate v1.3.0 — Application Compatibility Evaluation Prompt

Run this prompt in a **fresh Claude Code session opened in the target application's
repository** (the relying party you intend to migrate), once per application. It is
self-contained, works for any language/stack, and is **read-only** — it evaluates the
app and writes a report; it does not change application code.

Before running, replace the placeholders:

- `{{APP_NAME}}` — the application's name.
- The OP base URL (`https://socrate.vandermoten.eu`) if you are targeting a different
  Socrate host (e.g. a staging instance).

The compatibility contract embedded in the prompt is the canonical client-facing
contract for Socrate v1.3.0; keep it in sync with
[`../../docs/`](../../docs/) if the protocol surface changes.

---

```markdown
# Task: Evaluate this application's compatibility with Socrate v1.3.0

You are auditing whether **{{APP_NAME}}** (this repository) can be migrated from its
current identity provider to the latest **Socrate** OAuth2.1 / OIDC provider at
**https://socrate.vandermoten.eu** (OpenID discovery:
`https://socrate.vandermoten.eu/.well-known/openid-configuration`).

This is a READ-ONLY audit. Do NOT modify application code. Produce a written report.

## What Socrate v1.3.0 requires and supports (the compatibility contract)

Treat the OP's live discovery document as the source of truth for endpoint URLs and
supported values; fetch it if this environment has network access. **If you cannot
reach the OP (blocked egress), use the confirmed v1.3.0 values below instead of
marking those checks UNKNOWN** — they are derived from the server source.

CONFIRMED v1.3.0 DISCOVERY VALUES (`{iss}` = issuer, e.g. `https://socrate.vandermoten.eu`, no trailing slash):
- `authorization_endpoint` = `{iss}/oauth/authorize`, `token_endpoint` = `{iss}/oauth/token`,
  `userinfo_endpoint` = `{iss}/oauth/userinfo`, `revocation_endpoint` = `{iss}/oauth/revoke`,
  `introspection_endpoint` = `{iss}/oauth/introspect`, `jwks_uri` = `{iss}/.well-known/jwks.json`.
- `grant_types_supported` = authorization_code, refresh_token, client_credentials.
- `response_types_supported` = code only. `code_challenge_methods_supported` = S256 only.
- `token_endpoint_auth_methods_supported` = client_secret_basic, client_secret_post.
- `scopes_supported` = openid, email, profile, offline_access, api.
- `id_token_signing_alg_values_supported` = RS256. JWKS keys carry `use:"sig"`, `kty:"RSA"`, `alg:"RS256"`, UUID `kid`.
- **No `end_session_endpoint`** (no RP-initiated logout; revoke the refresh token instead).
- `sub` = the user's numeric id as a decimal string (`app:<id>` for client_credentials).
- `aud[0]` = the client's `client_id`. Refresh tokens are issued without needing `offline_access`.

Full reference: `deploy/migration/SOCRATE-V1.3.0-OP-CONTRACT.md` in the `ovander/go-oauth2` repo.

The contract is:

HARD REQUIREMENTS (a violation is a BLOCKER):
1. **OAuth 2.1 + OIDC.** Only the **Authorization Code** grant (interactive) and
   **client_credentials** (machine-to-machine) are supported.
2. **PKCE with S256 is MANDATORY** for every interactive client — public *and*
   confidential. `plain` PKCE or no PKCE is rejected.
3. **Implicit flow and Resource Owner Password Credentials (password grant) are NOT
   supported.** Any use of `response_type=token`/`id_token` or `grant_type=password`
   is a blocker.
4. **Redirect URIs must be pre-registered and matched** (scheme/host are
   case-normalized; path and query must match exactly). Dynamic or wildcard redirect
   URIs will not work.
5. **Access/ID tokens are RS256 JWTs.** They must be verified against the OP's
   **JWKS** (`jwks_uri` from discovery), honoring the `kid` header and key rotation.
   Verifying tokens with a shared symmetric/HMAC secret (HS256) is a blocker.
6. **Refresh tokens ROTATE and reuse is detected.** Every refresh response returns a
   NEW refresh_token; the app must persist and use the newest one and must never
   replay a consumed refresh_token. Reuse triggers revocation of the entire token
   chain (the user gets logged out). On `invalid_grant`, the app must force
   re-authentication, not retry the old token.
7. **Issuer is `https://socrate.vandermoten.eu`.** The `iss` claim and all endpoint
   URLs change. Any pinned issuer/authority/endpoint must be updated.

SUPPORTED (verify the app uses them correctly if present):
- Token introspection and revocation (confidential clients; check client auth method).
- Token exchange (RFC 8693), DPoP sender-constraining, and a policy `decide`/PEP
  endpoint — flag if the app relies on any of these and confirm against discovery.
- `client_credentials` secrets are bcrypt-verified server-side, so token minting is
  intentionally rate-limited — flag any code path that mints M2M tokens in a hot loop.

RECOMMENDED ARCHITECTURE:
- Browser apps should use a **BFF** (server-side session, httpOnly cookie, CSRF
  token); tokens should not live in the SPA. A public SPA storing tokens in
  localStorage/sessionStorage is a security WARNING, not a blocker.

## Steps

1. **Inventory the integration.** Search the repo for how it talks to the current IdP.
   Look for: OAuth/OIDC client libraries; `.well-known`/discovery URLs; `client_id`,
   `client_secret`, `redirect_uri`, `grant_type`, `response_type`, `scope`;
   `code_challenge`/`code_verifier`; JWT/JWKS verification (and whether HS256 vs
   RS256); refresh-token handling; introspection/revocation; logout/end-session; and
   any hardcoded IdP hostname (e.g. the current `golfperformance.fr`). Record the
   client type (public vs confidential), the exact flow, and every endpoint/URL used,
   each with a `file:line` citation.

2. **Evaluate against the contract above.** For each requirement, decide OK / WARNING
   / BLOCKER based on what the code actually does. Do not assume — cite the code. If
   something can't be determined from the repo, mark it UNKNOWN and say what's needed
   to confirm.

3. **Write the report** to `SOCRATE-COMPAT-REPORT.md` in the repo root with these
   sections:
   - **Verdict:** one of *Compatible* / *Compatible with changes* / *Incompatible*,
     plus counts of blockers / warnings / unknowns.
   - **Integration inventory:** library, client type, flow, endpoints, token
     validation, refresh handling, token storage — with `file:line` refs.
   - **Findings:** a table of Severity | Area | Location (`file:line`) | Issue |
     Required change.
   - **Migration checklist:** the concrete config/code changes to point at
     `https://socrate.vandermoten.eu` (issuer, discovery/JWKS, redirect URI to
     register, PKCE, refresh-rotation handling, secret handling), ordered.
   - **Test plan:** the flows to verify post-migration (login, token validation via
     JWKS, refresh-rotation survival, forced re-auth on reuse, logout).

Keep findings concrete and evidence-based. Rank the report most-severe first.
```

---

## Notes on interpreting the output

- **`client_credentials` / machine-to-machine services** (no browser): the prompt
  still applies. It will find no interactive flow and focus on secret handling, the
  token endpoint, and the (deliberate) M2M token-minting rate ceiling.
- **Apps that already use `backendkit`** (the shared Go client library): the report
  will surface that. For those, migration is largely a configuration change (issuer +
  client registration) because the library already speaks the v1.3.0 contract.
- A verdict of *Compatible with changes* is the common and expected case — the
  migration checklist section is the actionable output; treat the blockers as gating
  and the warnings as follow-ups.
