# CR: OAuth2/OIDC Security Testing SPA

## Overview

A single-page application (SPA) for comprehensive testing of OAuth2 and OpenID Connect server implementations. This app provides automated and manual testing capabilities for security, compliance, and functionality.

## Target OAuth2 Server

- **OAuth Port**: 8080 (public endpoints)
- **Admin Port**: 8081 (internal admin API)
- **Issuer**: Configurable (default: `http://localhost:8080`)

---

## Test Categories

### 1. Discovery & Configuration Tests

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| DISC-01 | Discovery Endpoint | `GET /.well-known/openid-configuration` | Returns valid OIDC configuration JSON |
| DISC-02 | JWKS Endpoint | `GET /.well-known/jwks.json` | Returns valid JWKS with RSA public keys |
| DISC-03 | Required Fields | Verify all required OIDC fields present | `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri` exist |
| DISC-04 | Endpoint URLs Valid | All endpoints in discovery are accessible | No 404 errors on listed endpoints |

---

### 2. Authorization Code Flow Tests

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| AUTH-01 | Basic Auth Code Flow | Complete authorization code flow | Receives valid tokens |
| AUTH-02 | Auth Code with PKCE (S256) | Authorization code + PKCE S256 | Tokens returned, PKCE verified |
| AUTH-03 | Auth Code with PKCE (plain) | Authorization code + PKCE plain | Tokens returned (if supported) |
| AUTH-04 | State Parameter | Include state, verify returned | State matches in callback |
| AUTH-05 | Nonce Parameter | Include nonce, verify in id_token | Nonce claim matches in id_token |
| AUTH-06 | Scope Handling | Request specific scopes | Granted scopes in token response |
| AUTH-07 | Invalid Redirect URI | Use unregistered redirect_uri | Error: `invalid_request` |
| AUTH-08 | Missing client_id | Omit client_id | Error: `invalid_request` |
| AUTH-09 | Invalid client_id | Use non-existent client_id | Error: `unauthorized_client` |
| AUTH-10 | Code Replay Attack | Reuse authorization code | Error: `invalid_grant` |
| AUTH-11 | Code Expiration | Use expired code (>10 min) | Error: `invalid_grant` |

---

### 3. Token Endpoint Tests

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| TOK-01 | Token Exchange | Exchange valid code for tokens | access_token, refresh_token, id_token |
| TOK-02 | Refresh Token | Use refresh_token to get new access_token | New tokens returned |
| TOK-03 | Refresh Token Rotation | Verify refresh token rotates | New refresh_token different from old |
| TOK-04 | Client Credentials Grant | Machine-to-machine auth | access_token returned (no refresh) |
| TOK-05 | Invalid Grant Type | Use unsupported grant_type | Error: `unsupported_grant_type` |
| TOK-06 | Missing Grant Type | Omit grant_type | Error: `invalid_request` |
| TOK-07 | Invalid Code | Use invalid authorization code | Error: `invalid_grant` |
| TOK-08 | Invalid Refresh Token | Use invalid refresh token | Error: `invalid_grant` |
| TOK-09 | Expired Refresh Token | Use expired refresh token | Error: `invalid_grant` |
| TOK-10 | PKCE Mismatch | Wrong code_verifier | Error: `invalid_grant` |
| TOK-11 | JSON Body Support | Send request as JSON | Tokens returned |
| TOK-12 | Form Body Support | Send as x-www-form-urlencoded | Tokens returned |

---

### 4. Token Validation Tests

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| VAL-01 | Access Token Structure | Decode and verify JWT structure | Valid JWT with required claims |
| VAL-02 | ID Token Structure | Decode and verify id_token | Contains sub, iss, aud, exp, iat |
| VAL-03 | Signature Verification | Verify JWT signature with JWKS | Signature valid |
| VAL-04 | Issuer Claim | Verify `iss` matches server | Issuer matches discovery |
| VAL-05 | Audience Claim | Verify `aud` contains client_id | client_id in audience |
| VAL-06 | Expiration Claim | Verify `exp` is future | Token not expired |
| VAL-07 | Not Before Claim | Verify `nbf` is past | Token is active |
| VAL-08 | Token Type Claim | Verify custom `type` claim | "access", "refresh", or "id_token" |

---

### 5. Token Introspection Tests

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| INT-01 | Valid Token Introspection | Introspect valid access_token | `active: true` with claims |
| INT-02 | Expired Token Introspection | Introspect expired token | `active: false` |
| INT-03 | Invalid Token Introspection | Introspect garbage token | `active: false` |
| INT-04 | Revoked Token Introspection | Introspect revoked token | `active: false` |
| INT-05 | Missing Client Auth | Introspect without credentials | Error: `invalid_client` |
| INT-06 | Invalid Client Auth | Introspect with wrong secret | Error: `invalid_client` |
| INT-07 | JSON Body Support | Send introspect as JSON | Valid response |

---

### 6. Token Revocation Tests

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| REV-01 | Revoke Access Token | Revoke valid access_token | 200 OK, token invalidated |
| REV-02 | Revoke Refresh Token | Revoke refresh_token | 200 OK, token invalidated |
| REV-03 | Revoke Invalid Token | Revoke non-existent token | 200 OK (per RFC 7009) |
| REV-04 | Verify Revocation | Use revoked token | 401 Unauthorized |

---

### 7. UserInfo Endpoint Tests

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| USR-01 | Basic UserInfo | `GET /oauth/userinfo` with token | User profile JSON |
| USR-02 | POST UserInfo | `POST /oauth/userinfo` with token | User profile JSON |
| USR-03 | Profile Scope Claims | Request with `profile` scope | name, preferred_username |
| USR-04 | Email Scope Claims | Request with `email` scope | email, email_verified |
| USR-05 | No Token | Request without Authorization | 401 Unauthorized |
| USR-06 | Invalid Token | Request with invalid token | 401 Unauthorized |
| USR-07 | Expired Token | Request with expired token | 401 Unauthorized |

---

### 8. Silent Renewal Tests

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| SIL-01 | Silent Token Renewal | Refresh before expiration | New tokens without user interaction |
| SIL-02 | Iframe Renewal | Hidden iframe renewal | Tokens refreshed silently |
| SIL-03 | Session Check | Verify session still active | Session status returned |

---

### 9. Logout Tests

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| LOG-01 | End Session Endpoint | `GET /oauth/logout` | Session terminated |
| LOG-02 | Post Logout Redirect | Include post_logout_redirect_uri | Redirects to specified URI |
| LOG-03 | ID Token Hint | Include id_token_hint | Logout for specific session |
| LOG-04 | State Parameter | Include state in logout | State returned in redirect |

---

### 10. Security Tests

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| SEC-01 | CSRF Protection | Verify state parameter required | Requests without state rejected |
| SEC-02 | PKCE Required (Public Client) | Public client must use PKCE | Error without PKCE |
| SEC-03 | Redirect URI Validation | Strict redirect URI matching | Partial matches rejected |
| SEC-04 | Token Leakage Prevention | Tokens not in URL fragments | Tokens only in response body |
| SEC-05 | Timing Attack Resistance | Constant-time comparisons | No timing information leaked |
| SEC-06 | Rate Limiting | Excessive requests blocked | 429 Too Many Requests |
| SEC-07 | Account Lockout | Multiple failed logins | Account temporarily locked |
| SEC-08 | Secure Headers | Security headers present | CORS, X-Frame-Options, etc. |

---

### 11. Error Response Tests

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| ERR-01 | Malformed JSON | Send invalid JSON body | 400 Bad Request |
| ERR-02 | Missing Required Fields | Omit required parameters | Specific error message |
| ERR-03 | Invalid Content-Type | Wrong Content-Type header | 400 or 415 |
| ERR-04 | Error Response Format | All errors follow OAuth2 format | `error`, `error_description` |

---

### 12. Role & Permission Tests

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| ROL-01 | App Role in Token | Verify app_roles claim | User's role for app included |
| ROL-02 | Global Role in Token | Verify role claim | User's global role included |
| ROL-03 | Admin Access | Admin user accesses admin endpoint | 200 OK |
| ROL-04 | Non-Admin Denied | Regular user accesses admin endpoint | 403 Forbidden |

---

## Test Implementation

### Request Formats

All endpoints should support both formats:

```javascript
// Form-urlencoded (OAuth2 standard)
fetch('/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: '...',
    client_id: '...'
  })
})

// JSON (convenience)
fetch('/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    grant_type: 'refresh_token',
    refresh_token: '...',
    client_id: '...'
  })
})
```

### Test Data Structure

```typescript
interface TestResult {
  testId: string;
  testName: string;
  category: string;
  status: 'passing' | 'failing' | 'skipped';
  duration: number;
  timestamp: number;
  request?: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: any;
  };
  response?: {
    status: number;
    headers?: Record<string, string>;
    body?: any;
  };
  error?: {
    message: string;
    expected?: any;
    actual?: any;
  };
}

interface TestSuite {
  timestamp: string;
  user: string;
  serverInfo: {
    issuer: string;
    oauthPort: number;
    adminPort: number;
  };
  summary: {
    total: number;
    passing: number;
    failing: number;
    skipped: number;
  };
  results: Record<string, TestResult>;
}
```

---

## UI Components

### 1. Configuration Panel
- Server URL input
- Client ID / Client Secret inputs
- Test user credentials
- Scope selection

### 2. Test Runner
- Run all tests button
- Run by category
- Run individual tests
- Progress indicator

### 3. Results Dashboard
- Summary cards (pass/fail counts)
- Expandable test details
- Request/Response viewer
- Error details

### 4. Token Inspector
- JWT decoder
- Claims viewer
- Signature verification status
- Expiration countdown

### 5. Manual Testing Tools
- Authorization flow initiator
- Token exchange form
- Introspection tester
- Custom request builder

---

## Endpoints Reference

| Endpoint | Method | Port | Description |
|----------|--------|------|-------------|
| `/.well-known/openid-configuration` | GET | 8080 | OIDC Discovery |
| `/.well-known/jwks.json` | GET | 8080 | JSON Web Key Set |
| `/oauth/authorize` | GET | 8080 | Authorization |
| `/oauth/token` | POST | 8080 | Token exchange |
| `/oauth/introspect` | POST | 8080 | Token introspection |
| `/oauth/revoke` | POST | 8080 | Token revocation |
| `/oauth/userinfo` | GET/POST | 8080 | User info |
| `/oauth/logout` | GET/POST | 8080 | End session |
| `/api/userinfo` | GET | 8080 | User profile |
| `/api/profile` | PUT/PATCH | 8080 | Update profile |

---

## Implementation Priority

### Phase 1 - Core Tests
1. Discovery & Configuration (DISC-*)
2. Authorization Code Flow (AUTH-01 to AUTH-06)
3. Token Endpoint (TOK-01 to TOK-04)
4. UserInfo Endpoint (USR-01 to USR-04)

### Phase 2 - Security Tests
5. Error Handling (AUTH-07 to AUTH-11)
6. Token Validation (VAL-*)
7. Introspection (INT-*)
8. Revocation (REV-*)

### Phase 3 - Advanced Tests
9. Security Tests (SEC-*)
10. Role & Permission Tests (ROL-*)
11. Silent Renewal (SIL-*)
12. Logout (LOG-*)

---

## Success Criteria

- All Phase 1 tests passing: MVP complete
- All Phase 2 tests passing: Security validated
- All Phase 3 tests passing: Full compliance

## Notes

- Tests should be idempotent and can run in any order
- Each test should clean up after itself
- Support for both manual and automated execution
- Export results as JSON for CI/CD integration
