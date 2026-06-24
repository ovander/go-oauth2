# Admin Console — Session Hardening Migration Guide (for the SPA team)

This is the contract the admin SPA (`oauth2-admin`) must code against after the
Tier-0 admin session-hardening work (Socrate PRs #167, #170, #172, #174, and
this one). It supersedes the legacy `POST /api/admin/login` password flow.

> **Summary of the move:** the admin console becomes a **public Authorization
> Code + PKCE client**. The access token lives in memory; the refresh token
> lives in an **HttpOnly cookie** (never in JS). Destructive actions require a
> recent **step-up**. The legacy password login is deprecated.

---

## 1. Server configuration (operator sets these)

| Env var | Meaning | Default |
|---|---|---|
| `ADMIN_CONSOLE_CLIENT_ID` | `client_id` of the admin console public client. Enables the refresh-cookie channel. | empty (off) |
| `ADMIN_CONSOLE_REDIRECT_URIS` | Comma-separated, exact-match redirect URIs. Seeds the public PKCE client at startup. | empty |
| `ADMIN_PASSWORD_LOGIN_ENABLED` | Keep the deprecated `/api/admin/login` available. Set `false` once on PKCE. | `true` |
| `ADMIN_ELEVATION_MAX_AGE` | Freshness window (seconds) for step-up on destructive routes. `0` disables. | `300` |

When `ADMIN_CONSOLE_CLIENT_ID` + `ADMIN_CONSOLE_REDIRECT_URIS` are set, Socrate
auto-registers the client as **public, PKCE-mandatory, no secret** with those
exact redirect URIs.

## 2. Login — Authorization Code + PKCE

1. Generate `code_verifier` + `code_challenge` (S256).
2. Redirect to:
   ```
   GET {issuer}/oauth/authorize?response_type=code
     &client_id={ADMIN_CONSOLE_CLIENT_ID}
     &redirect_uri={exact registered URI}
     &scope=openid%20email%20profile
     &state={csrf}
     &code_challenge={challenge}&code_challenge_method=S256
   ```
3. User authenticates (password, MFA, consent) on Socrate.
4. On `redirect_uri?code=…&state=…`, exchange the code:
   ```
   POST {issuer}/oauth/token   (application/x-www-form-urlencoded)
     grant_type=authorization_code
     &code={code}&redirect_uri={same URI}
     &client_id={ADMIN_CONSOLE_CLIENT_ID}
     &code_verifier={verifier}
   ```
5. Response: `{ access_token, id_token, token_type, expires_in, ... }`.
   **There is no `refresh_token` in the body** — it was set as a cookie:
   ```
   Set-Cookie: refresh_token=…; Path=/oauth/token; HttpOnly; Secure;
               SameSite=Strict; Max-Age=<refresh TTL>
   ```
   Hold the **access token in memory only**. Never read the refresh cookie (you
   can't — it's HttpOnly, by design).

## 3. Silent refresh

When the access token nears expiry, refresh with the cookie (no token in body):
```
POST {issuer}/oauth/token   (with credentials: 'include')
  grant_type=refresh_token
  &client_id={ADMIN_CONSOLE_CLIENT_ID}
```
The server reads the refresh token from the cookie, **rotates** it (single-use;
replay → family revocation), and sets a fresh cookie. You get a new
`access_token` in the body. This is the **only** refresh path (it is the same
hardened grant as `/oauth/token`).

## 4. Logout
```
POST {admin-api}/api/auth/logout    (Authorization: Bearer <access>)
```
Revokes the session server-side **and** clears the refresh cookie. Drop the
in-memory access token.

## 5. Step-up (elevation) for destructive actions

These routes require an authentication no older than `ADMIN_ELEVATION_MAX_AGE`:
`DELETE /api/admin/apps/{id}`, `POST /api/admin/apps/{id}/rotate-secret`,
`POST /api/admin/superadmins`, `DELETE /api/admin/superadmins/{id}`,
`POST /api/admin/users/{id}/block`.

If the token isn't fresh they return **`403 { "error": "elevation_required" }`**.
Then:
```
POST {admin-api}/api/admin/elevate   (Authorization: Bearer <access>)
  { "password": "...", "mfa_code": "..."? }
```
→ returns a **fresh access token** (no refresh token; your session/cookie is
unchanged). Use that token to retry the destructive call. A *refreshed* token is
**not** fresh — only re-auth via `/elevate` (or a new login) clears the gate.

## 6. Forced password change

If `must_change_password` is set, **every** `/api/admin/*` route returns
**`403 { "error": "password_change_required" }`** except:
```
POST {admin-api}/api/admin/change-password
  { "current_password": "...", "new_password": "..." }
```
On success all tokens are revoked — start a fresh login.

## 7. Error codes to handle

| Code (HTTP) | Meaning | SPA action |
|---|---|---|
| `mfa_required` (401) | Password OK, MFA code needed | Prompt for TOTP/recovery, resubmit |
| `mfa_enrollment_required` (403) | Policy requires MFA enrollment | Route to MFA enrollment |
| `password_change_required` (403) | Forced password change pending | Route to change-password |
| `elevation_required` (403) | Step-up needed for this action | Call `/api/admin/elevate`, retry |
| `password_login_disabled` (403) | Legacy `/api/admin/login` disabled | Use the PKCE flow |
| `invalid or expired refresh token` (400) | Refresh failed (rotated/revoked) | Full re-login |

## 8. Deprecation

`POST /api/admin/login` still works while `ADMIN_PASSWORD_LOGIN_ENABLED=true`,
but always returns a `Deprecation: true` header. Migrate to the PKCE flow, then
ask the operator to set `ADMIN_PASSWORD_LOGIN_ENABLED=false`.
