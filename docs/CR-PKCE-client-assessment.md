# Change Request (CR)

## Title

PKCE Implementation Assessment & Compliance Timeline Request

## Document ID

CR-AUTH-PKCE-ASSESS-001

## Version

1.0

## Status

Issued for Client Response

## Date

January 2026

## Response Deadline

**Please respond by: [DATE + 2 weeks]**

---

## 1. Purpose

This Change Request is issued to all client applications (frontend and backend) integrating with the Socrate OAuth2 / OpenID Connect authentication platform.

We are planning to **enforce PKCE (Proof Key for Code Exchange)** as a mandatory security requirement for all OAuth2 Authorization Code flows.

**Your response is required** to assess the impact and plan the rollout timeline.

---

## 2. Background

### What is PKCE?

PKCE (RFC 7636) is a security extension to OAuth2 that protects against authorization code interception attacks. It is now **required by OAuth 2.1** for all clients using the Authorization Code flow.

### Why This Change?

| Threat | Without PKCE | With PKCE |
|--------|--------------|-----------|
| Authorization code interception | Vulnerable | Protected |
| Man-in-the-middle attacks | Vulnerable | Protected |
| Malicious app code theft | Vulnerable | Protected |

PKCE adds no user-facing friction — it only requires client-side implementation changes.

---

## 3. Technical Requirements

### Current State (Optional PKCE)

```
GET /oauth/authorize?
  client_id=xxx&
  redirect_uri=xxx&
  response_type=code&
  scope=openid profile&
  state=xxx
```

### Future State (Mandatory PKCE)

```
GET /oauth/authorize?
  client_id=xxx&
  redirect_uri=xxx&
  response_type=code&
  scope=openid profile&
  state=xxx&
  code_challenge=BASE64URL(SHA256(code_verifier))&
  code_challenge_method=S256
```

And on token exchange:

```
POST /oauth/token
  grant_type=authorization_code&
  code=xxx&
  redirect_uri=xxx&
  client_id=xxx&
  client_secret=xxx&
  code_verifier=ORIGINAL_RANDOM_STRING
```

---

## 4. Implementation Guide

### 4.1 Generate Code Verifier

```javascript
// JavaScript example
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}
```

### 4.2 Generate Code Challenge

```javascript
// JavaScript example (S256 method)
async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hash));
}
```

### 4.3 Library Support

Most OAuth2 libraries support PKCE natively:

| Platform | Library | PKCE Support |
|----------|---------|--------------|
| JavaScript | oidc-client-ts | ✅ Built-in |
| React | react-oidc-context | ✅ Built-in |
| Angular | angular-oauth2-oidc | ✅ Built-in |
| Go | golang.org/x/oauth2 | ✅ Built-in |
| Python | authlib | ✅ Built-in |
| .NET | IdentityModel | ✅ Built-in |

---

## 5. Rollout Plan

| Phase | Timeline | Action |
|-------|----------|--------|
| **Phase 1** | Now | Assessment (this CR) |
| **Phase 2** | +2 weeks | Warning mode enabled (logs missing PKCE) |
| **Phase 3** | +6 weeks | Enforcement mode (rejects missing PKCE) |

**Note:** Timeline is tentative and will be adjusted based on your responses.

---

## 6. Required Response

**Please complete and return this assessment:**

### Client Application Information

| Field | Your Response |
|-------|---------------|
| Application Name | |
| Client ID | |
| Application Type | [ ] SPA / [ ] Mobile / [ ] Backend / [ ] Desktop |
| Environment | [ ] Production / [ ] Staging / [ ] Development |

### Current PKCE Status

| Question | Response |
|----------|----------|
| Is PKCE currently implemented? | [ ] Yes / [ ] No / [ ] Partial |
| If yes, which method? | [ ] S256 / [ ] plain |
| OAuth library used | |
| Library version | |

### Compliance Timeline

| Question | Response |
|----------|----------|
| If not implemented, estimated time to implement | |
| Blocking issues or concerns | |
| Preferred enforcement date | |
| Need implementation support? | [ ] Yes / [ ] No |

### Technical Contact

| Field | Your Response |
|-------|---------------|
| Contact Name | |
| Email | |
| Team/Department | |

---

## 7. Response Instructions

Please send your completed assessment to:

- **Email:** [auth-team@yourcompany.com]
- **Subject:** `PKCE Assessment Response - [Application Name]`
- **Deadline:** [DATE + 2 weeks]

---

## 8. Questions & Support

If you need assistance with PKCE implementation:

1. **Documentation:** [Link to OAuth2 integration docs]
2. **Support Channel:** [Slack channel / Email]
3. **Office Hours:** [Schedule if applicable]

---

## 9. Non-Response Policy

Applications that do not respond by the deadline will be:

1. Assumed to require the full timeline (Phase 3 enforcement)
2. Contacted directly for status update
3. Subject to enforcement without extension

---

## 10. References

- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [OAuth 2.1 Draft](https://oauth.net/2.1/)
- [PKCE Best Practices](https://oauth.net/2/pkce/)

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | January 2026 | Auth Team | Initial release |

---

**Thank you for your cooperation in maintaining the security of our platform.**
