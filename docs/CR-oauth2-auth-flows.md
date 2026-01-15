# CR: OAuth2 Authentication Flows for App Integration

## Overview

This document describes the authentication flows that Socrate provides for client applications. Socrate is an OAuth2/OIDC identity provider that handles user authentication, password management, email verification, and user invitations.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Client App    │────▶│     Socrate     │────▶│   Email Service │
│   (e.g. GPWA)   │◀────│  OAuth2 Server  │◀────│   (SMTP)        │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                       │
         │    OAuth2 Flow        │
         │◀─────────────────────▶│
         │                       │
         │    Tokens (JWT)       │
         │◀──────────────────────│
```

## Key Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/oauth/authorize` | GET | Start OAuth2 authorization |
| `/oauth/token` | POST | Exchange code for tokens |
| `/oauth/userinfo` | GET | Get user profile |
| `/.well-known/openid-configuration` | GET | OIDC discovery |
| `/auth/forgot-password` | GET/POST | Request password reset |
| `/auth/reset-password` | GET/POST | Set new password |
| `/auth/verify-email` | GET | Verify email address |
| `/auth/invite` | GET/POST | Accept invitation |

---

## 1. Login Flow (OAuth2 Authorization Code + PKCE)

This is the standard OAuth2 login flow used when a user clicks "Login" in the client app.

### Sequence Diagram

```
┌──────┐          ┌──────────┐          ┌─────────┐
│ User │          │ App (FE) │          │ Socrate │
└──┬───┘          └────┬─────┘          └────┬────┘
   │ Click Login       │                     │
   │──────────────────▶│                     │
   │                   │                     │
   │                   │ Generate PKCE       │
   │                   │ code_verifier       │
   │                   │ code_challenge      │
   │                   │                     │
   │ Redirect to Socrate                     │
   │◀──────────────────│                     │
   │                   │                     │
   │ /oauth/authorize?client_id=...&redirect_uri=...
   │─────────────────────────────────────────▶│
   │                   │                     │
   │                   │        Login Page   │
   │◀────────────────────────────────────────│
   │                   │                     │
   │ Enter credentials │                     │
   │─────────────────────────────────────────▶│
   │                   │                     │
   │ Redirect with code                      │
   │◀────────────────────────────────────────│
   │                   │                     │
   │ /callback?code=xxx&state=yyy            │
   │──────────────────▶│                     │
   │                   │                     │
   │                   │ POST /oauth/token   │
   │                   │ (code + verifier)   │
   │                   │────────────────────▶│
   │                   │                     │
   │                   │ {access_token,      │
   │                   │  id_token,          │
   │                   │  refresh_token}     │
   │                   │◀────────────────────│
   │                   │                     │
   │ Logged in!        │                     │
   │◀──────────────────│                     │
```

### Step-by-Step

#### 1.1 App Initiates Login

```javascript
// Frontend generates PKCE challenge
const codeVerifier = generateRandomString(128);
const codeChallenge = base64UrlEncode(sha256(codeVerifier));

// Store verifier for later
sessionStorage.setItem('code_verifier', codeVerifier);

// Redirect to Socrate
const authUrl = new URL('https://socrate.example.com/oauth/authorize');
authUrl.searchParams.set('client_id', 'your_client_id');
authUrl.searchParams.set('redirect_uri', 'https://app.example.com/callback');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('scope', 'openid email profile');
authUrl.searchParams.set('state', generateRandomState());
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');

window.location.href = authUrl.toString();
```

#### 1.2 User Authenticates on Socrate

Socrate displays its login page. User enters email and password.

#### 1.3 Socrate Redirects Back with Code

```
https://app.example.com/callback?code=AUTH_CODE&state=STATE
```

#### 1.4 App Exchanges Code for Tokens

```javascript
// Backend or frontend exchanges code for tokens
const response = await fetch('https://socrate.example.com/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authCode,
    redirect_uri: 'https://app.example.com/callback',
    client_id: 'your_client_id',
    code_verifier: sessionStorage.getItem('code_verifier')
  })
});

const tokens = await response.json();
// {
//   access_token: "eyJhbG...",
//   id_token: "eyJhbG...",
//   refresh_token: "eyJhbG...",
//   token_type: "Bearer",
//   expires_in: 900,
//   roles: ["admin"],        // User's role in THIS app
//   app_roles: {"client_id": "admin"}
// }
```

#### 1.5 ID Token Contains User Info + App Role

```json
{
  "sub": "123",
  "email": "user@example.com",
  "email_verified": true,
  "name": "John Doe",
  "role": "admin",           // <-- App-scoped role (not Socrate role)
  "app_roles": {
    "your_client_id": "admin"
  },
  "iat": 1699999999,
  "exp": 1700000899
}
```

**Important:** The `role` claim in the ID token is the user's role **within your app**, not their Socrate platform role.

---

## 2. Forgot Password Flow

When a user forgets their password, they request a reset link.

### Sequence Diagram

```
┌──────┐          ┌──────────┐          ┌─────────┐          ┌───────┐
│ User │          │ App (FE) │          │ Socrate │          │ Email │
└──┬───┘          └────┬─────┘          └────┬────┘          └───┬───┘
   │ Forgot Password   │                     │                   │
   │──────────────────▶│                     │                   │
   │                   │                     │                   │
   │ Redirect to Socrate                     │                   │
   │◀──────────────────│                     │                   │
   │                   │                     │                   │
   │ /auth/forgot-password                   │                   │
   │─────────────────────────────────────────▶│                   │
   │                   │                     │                   │
   │                   │       Form Page     │                   │
   │◀────────────────────────────────────────│                   │
   │                   │                     │                   │
   │ Enter email       │                     │                   │
   │─────────────────────────────────────────▶│                   │
   │                   │                     │                   │
   │                   │                     │ Send reset email  │
   │                   │                     │──────────────────▶│
   │                   │                     │                   │
   │                   │    Success message  │                   │
   │◀────────────────────────────────────────│                   │
   │                   │                     │                   │
   │ Email with link   │                     │                   │
   │◀────────────────────────────────────────────────────────────│
```

### User Experience

1. **User clicks "Forgot Password"** in app
2. **App redirects to Socrate**: `https://socrate.example.com/auth/forgot-password`
3. **User enters email** on Socrate's forgot password page
4. **Socrate sends email** with reset link (valid for 1 hour)
5. **User sees confirmation** message (same message whether email exists or not, for security)

### Email Contains

```
Subject: Reset your password

Hi John,

Click here to reset your password:
https://socrate.example.com/auth/reset-password?token=eyJhbG...

This link expires in 1 hour.
```

---

## 3. Reset Password Flow

User clicks the reset link from their email.

### Sequence Diagram

```
┌──────┐          ┌─────────┐
│ User │          │ Socrate │
└──┬───┘          └────┬────┘
   │ Click email link  │
   │ /auth/reset-password?token=xxx
   │──────────────────▶│
   │                   │
   │   Password form   │
   │◀──────────────────│
   │                   │
   │ Enter new password│
   │──────────────────▶│
   │                   │
   │  Validate token   │
   │  Update password  │
   │                   │
   │   Success page    │
   │◀──────────────────│
   │                   │
   │ "Go to login"     │
   │──────────────────▶│ (redirect to app login)
```

### Validation

- Token must be valid and not expired (1 hour TTL)
- Password must be at least 8 characters
- Password confirmation must match
- Token is single-use (marked as used after reset)

### After Reset

User is shown a success page with a "Sign in" button that redirects to the app's login flow.

---

## 4. Email Verification Flow

After signup, users must verify their email before logging in.

### Sequence Diagram

```
┌──────┐          ┌──────────┐          ┌─────────┐          ┌───────┐
│ User │          │ App (FE) │          │ Socrate │          │ Email │
└──┬───┘          └────┬─────┘          └────┬────┘          └───┬───┘
   │ Sign up           │                     │                   │
   │──────────────────▶│                     │                   │
   │                   │ POST /api/auth/signup                   │
   │                   │────────────────────▶│                   │
   │                   │                     │                   │
   │                   │                     │ Send verify email │
   │                   │                     │──────────────────▶│
   │                   │                     │                   │
   │                   │ {user_id, message}  │                   │
   │                   │◀────────────────────│                   │
   │                   │                     │                   │
   │ "Check your email"│                     │                   │
   │◀──────────────────│                     │                   │
   │                   │                     │                   │
   │ Email with link   │                     │                   │
   │◀────────────────────────────────────────────────────────────│
   │                   │                     │                   │
   │ Click verify link │                     │                   │
   │ /auth/verify-email?token=xxx            │                   │
   │─────────────────────────────────────────▶│                   │
   │                   │                     │                   │
   │                   │    Mark verified    │                   │
   │                   │                     │                   │
   │   Success page    │                     │                   │
   │◀────────────────────────────────────────│                   │
```

### Email Contains

```
Subject: Verify your email address

Hi John,

Click here to verify your email:
https://socrate.example.com/auth/verify-email?token=eyJhbG...

This link expires in 24 hours.
```

### After Verification

- User's `is_verified` flag is set to `true`
- User can now log in
- Success page shows "Email verified!" with link to login

---

## 5. Accept Invitation Flow

When an app admin invites a user, they receive an invitation email.

### Sequence Diagram

```
┌───────────┐     ┌──────────┐     ┌─────────┐     ┌───────┐     ┌──────┐
│ App Admin │     │ App (BE) │     │ Socrate │     │ Email │     │ User │
└─────┬─────┘     └────┬─────┘     └────┬────┘     └───┬───┘     └──┬───┘
      │ Invite user    │                │              │            │
      │───────────────▶│                │              │            │
      │                │                │              │            │
      │                │ POST /api/apps/{id}/users     │            │
      │                │ {email, role}  │              │            │
      │                │───────────────▶│              │            │
      │                │                │              │            │
      │                │                │ Create user  │            │
      │                │                │ Assign role  │            │
      │                │                │              │            │
      │                │                │ Send invite  │            │
      │                │                │─────────────▶│            │
      │                │                │              │            │
      │                │ {user_id,      │              │            │
      │                │  invite_token} │              │            │
      │                │◀───────────────│              │            │
      │                │                │              │            │
      │ "Invited!"     │                │              │            │
      │◀───────────────│                │              │            │
      │                │                │              │            │
      │                │                │              │ Email      │
      │                │                │              │───────────▶│
      │                │                │              │            │
      │                │                │              │            │
      │                │                │ Click link   │            │
      │                │                │ /auth/invite?token=xxx    │
      │                │                │◀─────────────────────────│
      │                │                │              │            │
      │                │                │   Set password form      │
      │                │                │─────────────────────────▶│
      │                │                │              │            │
      │                │                │ Submit password          │
      │                │                │◀─────────────────────────│
      │                │                │              │            │
      │                │                │ Set password │            │
      │                │                │ Mark verified│            │
      │                │                │              │            │
      │                │                │   Success    │            │
      │                │                │─────────────────────────▶│
```

### Invitation API

App admin calls Socrate API to invite a user:

```bash
POST /api/apps/{app_id}/users
Authorization: Bearer {admin_token}
Content-Type: application/json

{
  "email": "newuser@example.com",
  "name": "New User",
  "role": "admin"    // Role in this app: admin, user, manager, editor, viewer
}
```

Response:
```json
{
  "user_id": 456,
  "invite_token": "eyJhbG...",
  "role": "admin"
}
```

### Email Contains

```
Subject: You've been invited to join GPWA

Hi New User,

John Smith has invited you to join GPWA.

Click here to accept the invitation:
https://socrate.example.com/auth/invite?token=eyJhbG...

This invitation expires in 24 hours.
```

### Accept Invitation Page

1. User clicks link in email
2. Socrate shows "Accept Invitation" page with:
   - Email (read-only)
   - App name they're joining
   - Password field
   - Confirm password field
3. User sets their password
4. Account is activated and verified
5. User can now log in

---

## 6. Token Refresh Flow

Access tokens expire after 15 minutes. Apps should refresh them.

```javascript
const response = await fetch('https://socrate.example.com/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: storedRefreshToken,
    client_id: 'your_client_id'
  })
});

const tokens = await response.json();
// New access_token, id_token, and refresh_token
```

---

## 7. Logout Flow

### Option A: Revoke Tokens (Recommended)

```javascript
await fetch('https://socrate.example.com/oauth/revoke', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': `Bearer ${accessToken}`
  },
  body: new URLSearchParams({
    token: refreshToken
  })
});

// Clear local storage
localStorage.removeItem('access_token');
localStorage.removeItem('refresh_token');
```

### Option B: OIDC End Session

```javascript
const logoutUrl = new URL('https://socrate.example.com/oauth/logout');
logoutUrl.searchParams.set('id_token_hint', idToken);
logoutUrl.searchParams.set('post_logout_redirect_uri', 'https://app.example.com');

window.location.href = logoutUrl.toString();
```

---

## 8. Role-Based Access Control

### Understanding Roles

Socrate uses a **two-tier role system**:

| Level | Roles | Purpose |
|-------|-------|---------|
| **Socrate Platform** | `superadmin` | Manage Socrate itself (never exposed to apps) |
| **App-Scoped** | `admin`, `manager`, `editor`, `viewer`, `user` | User's role within each app |

### Getting User's Role

The user's **app-scoped role** is included in:

1. **ID Token** - `role` claim
2. **Access Token** - `role` claim
3. **Token Response** - `roles` array
4. **UserInfo Endpoint** - `role` field

```javascript
// Decode ID token to get role
const idToken = jwt_decode(tokens.id_token);
const userRole = idToken.role;  // "admin", "user", etc.

// Or call UserInfo endpoint
const userInfo = await fetch('https://socrate.example.com/oauth/userinfo', {
  headers: { 'Authorization': `Bearer ${accessToken}` }
}).then(r => r.json());

const userRole = userInfo.role;
```

### Role Hierarchy

| Role | Permissions |
|------|-------------|
| `admin` | Full app control, manage users |
| `manager` | Manage content and some users |
| `editor` | Edit content |
| `viewer` | Read-only access |
| `user` | Standard user (default) |

---

## 9. App Integration Checklist

### Frontend

- [ ] Implement OAuth2 authorization code flow with PKCE
- [ ] Store tokens securely (httpOnly cookies or secure storage)
- [ ] Implement token refresh before expiry
- [ ] Add "Forgot Password" link pointing to Socrate
- [ ] Handle role-based UI (check `id_token.role`)
- [ ] Implement logout (revoke + clear storage)

### Backend

- [ ] Validate access tokens on protected endpoints
- [ ] Check token signature against Socrate's JWKS
- [ ] Verify token audience matches your `client_id`
- [ ] Implement role-based authorization
- [ ] Handle token expiry (401 response)

### Configuration

```env
# App's OAuth2 credentials (from Socrate admin)
OAUTH_CLIENT_ID=your_client_id
OAUTH_CLIENT_SECRET=your_client_secret  # For confidential clients

# Socrate endpoints
OAUTH_ISSUER=https://socrate.example.com
OAUTH_AUTHORIZE_URL=https://socrate.example.com/oauth/authorize
OAUTH_TOKEN_URL=https://socrate.example.com/oauth/token
OAUTH_USERINFO_URL=https://socrate.example.com/oauth/userinfo
OAUTH_JWKS_URL=https://socrate.example.com/.well-known/jwks.json

# Your app's callback
OAUTH_REDIRECT_URI=https://app.example.com/callback
```

---

## 10. Error Handling

### Common OAuth2 Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `invalid_client` | Wrong client_id or secret | Check credentials |
| `invalid_grant` | Expired or invalid code/token | Restart auth flow |
| `access_denied` | User denied access | Show appropriate message |
| `invalid_request` | Missing required parameter | Check request format |

### Token Validation Errors

| HTTP Status | Meaning | Action |
|-------------|---------|--------|
| 401 | Token expired or invalid | Refresh token or re-login |
| 403 | Insufficient permissions | Check user's role |

---

## Summary

| Flow | User Action | Socrate URL | Result |
|------|-------------|-------------|--------|
| Login | Click "Login" | `/oauth/authorize` | OAuth2 code flow |
| Forgot Password | Click "Forgot Password" | `/auth/forgot-password` | Reset email sent |
| Reset Password | Click email link | `/auth/reset-password?token=` | Set new password |
| Verify Email | Click email link | `/auth/verify-email?token=` | Email confirmed |
| Accept Invite | Click email link | `/auth/invite?token=` | Set password, join app |
| Logout | Click "Logout" | `/oauth/logout` | Session ended |

All authentication UI is provided by Socrate. Apps only need to:
1. Redirect users to Socrate for login
2. Handle the callback with authorization code
3. Link to Socrate for forgot password
4. Validate tokens on API requests
