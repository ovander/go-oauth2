# Change Request: OAuth2 Server Login Page for SPA Clients

**CR ID:** CR-2024-OAUTH-LOGIN-001
**Date:** 2025-12-27
**Author:** Backend Team
**Status:** Ready for Implementation

---

## Summary

This document describes how the OAuth2 server (port 8080) should serve a login page for SPA (Single Page Application) clients. The login page is hosted and served by the OAuth2 server itself, not by the client applications.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SPA CLIENT (Vue.js)                              │
│                        http://localhost:5175                             │
├─────────────────────────────────────────────────────────────────────────┤
│  1. User clicks "Login"                                                  │
│  2. SPA redirects to OAuth2 server:                                      │
│     GET /oauth/authorize?client_id=...&redirect_uri=...&...              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      OAUTH2 SERVER (Port 8080)                           │
├─────────────────────────────────────────────────────────────────────────┤
│  3. Server checks if user is authenticated                               │
│     - If NOT authenticated → Serve login page                            │
│     - If authenticated → Generate auth code, redirect back               │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                    LOGIN PAGE (Served by OAuth2)                   │ │
│  │  ┌──────────────────────────────────────────────────────────────┐  │ │
│  │  │  ┌─────────────────────────────────────────────────────────┐ │  │ │
│  │  │  │              Logo / Branding                            │ │  │ │
│  │  │  ├─────────────────────────────────────────────────────────┤ │  │ │
│  │  │  │  Email:    [_________________________]                  │ │  │ │
│  │  │  │  Password: [_________________________]                  │ │  │ │
│  │  │  │                                                         │ │  │ │
│  │  │  │            [       Sign In       ]                      │ │  │ │
│  │  │  │                                                         │ │  │ │
│  │  │  │  [Forgot Password?]                                     │ │  │ │
│  │  │  └─────────────────────────────────────────────────────────┘ │  │ │
│  │  │                                                              │  │ │
│  │  │  App "My Vue App" is requesting access to your account      │  │ │
│  │  └──────────────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  4. User submits credentials                                             │
│  5. POST /oauth/authorize (with credentials)                             │
│  6. On success → Redirect to SPA with authorization code                 │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         SPA CLIENT (Vue.js)                              │
├─────────────────────────────────────────────────────────────────────────┤
│  7. SPA receives callback: /callback?code=AUTH_CODE                      │
│  8. SPA exchanges code for tokens: POST /oauth/token                     │
│  9. User is now authenticated in the SPA                                 │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## OAuth2 Authorization Code Flow with PKCE

### Step 1: SPA Initiates Login

```typescript
// In your Vue.js app
function initiateLogin() {
  // Generate PKCE code verifier and challenge
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  // Store verifier for later (needed to exchange code)
  sessionStorage.setItem('code_verifier', codeVerifier);

  // Generate state for CSRF protection
  const state = generateRandomState();
  sessionStorage.setItem('oauth_state', state);

  // Build authorization URL
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: 'your-client-id',
    redirect_uri: 'http://localhost:5175/callback',
    scope: 'openid email profile',
    state: state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });

  // Redirect to OAuth2 server
  window.location.href = `http://localhost:8080/oauth/authorize?${params}`;
}
```

### Step 2: OAuth2 Server Shows Login Page

The OAuth2 server's `/oauth/authorize` endpoint:
1. Validates the request parameters (client_id, redirect_uri, etc.)
2. Checks if user has an active session
3. If no session → **Serves the login page**
4. If session exists → Generates auth code and redirects

---

## Login Page Implementation Options

### Option A: Server-Rendered HTML (Recommended for OAuth2)

The OAuth2 server serves a complete HTML page for the login form.

**Endpoint:** `GET /oauth/authorize` (when not authenticated)

**Response:** HTML page with login form

```
┌─────────────────────────────────────────────────────────────────────┐
│  Content-Type: text/html                                            │
├─────────────────────────────────────────────────────────────────────┤
│  <!DOCTYPE html>                                                    │
│  <html>                                                             │
│  <head>                                                             │
│    <title>Sign In - OAuth2 Server</title>                           │
│    <link rel="stylesheet" href="/static/login.css">                 │
│  </head>                                                            │
│  <body>                                                             │
│    <form action="/oauth/authorize" method="POST">                   │
│      <!-- Hidden fields preserve OAuth params -->                   │
│      <input type="hidden" name="client_id" value="...">             │
│      <input type="hidden" name="redirect_uri" value="...">          │
│      <input type="hidden" name="response_type" value="code">        │
│      <input type="hidden" name="scope" value="...">                 │
│      <input type="hidden" name="state" value="...">                 │
│      <input type="hidden" name="code_challenge" value="...">        │
│      <input type="hidden" name="code_challenge_method" value="..."> │
│                                                                     │
│      <input type="email" name="email" required>                     │
│      <input type="password" name="password" required>               │
│      <button type="submit">Sign In</button>                         │
│    </form>                                                          │
│  </body>                                                            │
│  </html>                                                            │
└─────────────────────────────────────────────────────────────────────┘
```

### Option B: SPA-Based Login Page (Embedded in OAuth2 Server)

The OAuth2 server serves a Vue/React SPA as the login page.

**Structure:**
```
oauth2-server/
├── cmd/server/
├── internal/
├── web/                      # Login page frontend
│   ├── src/
│   │   ├── App.vue
│   │   ├── components/
│   │   │   ├── LoginForm.vue
│   │   │   ├── ConsentScreen.vue
│   │   │   └── ErrorPage.vue
│   │   └── main.ts
│   ├── public/
│   └── dist/                 # Built assets served by Go
└── static/                   # Go serves these files
    └── login/
        ├── index.html
        ├── assets/
        └── ...
```

---

## Recommended Implementation: Server-Rendered with Embedded Templates

### File Structure

```
oauth2-server/
├── internal/
│   ├── handler/
│   │   └── oauth_handler.go      # Handles /oauth/authorize
│   └── templates/
│       ├── login.html            # Login form
│       ├── consent.html          # Consent screen (optional)
│       ├── error.html            # Error page
│       └── base.html             # Base template
└── static/
    ├── css/
    │   └── oauth.css
    └── js/
        └── login.js              # Optional: client-side validation
```

### Template: login.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In</title>
    <link rel="stylesheet" href="/static/css/oauth.css">
</head>
<body>
    <div class="login-container">
        <div class="login-card">
            <!-- Branding -->
            <div class="logo">
                <img src="/static/images/logo.svg" alt="Logo">
            </div>

            <h1>Sign In</h1>

            <!-- App info -->
            <p class="app-info">
                <strong>{{.AppName}}</strong> is requesting access to your account
            </p>

            <!-- Error message -->
            {{if .Error}}
            <div class="error-message">
                {{.Error}}
            </div>
            {{end}}

            <!-- Login form -->
            <form action="/oauth/authorize" method="POST" class="login-form">
                <!-- Preserve OAuth parameters -->
                <input type="hidden" name="client_id" value="{{.ClientID}}">
                <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
                <input type="hidden" name="response_type" value="{{.ResponseType}}">
                <input type="hidden" name="scope" value="{{.Scope}}">
                <input type="hidden" name="state" value="{{.State}}">
                {{if .CodeChallenge}}
                <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
                <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
                {{end}}

                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" id="email" name="email"
                           value="{{.Email}}" required autofocus>
                </div>

                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>

                <button type="submit" class="btn-primary">Sign In</button>

                <div class="form-links">
                    <a href="/forgot-password?return={{.ReturnURL}}">Forgot password?</a>
                </div>
            </form>

            <!-- Requested scopes -->
            <div class="scopes-info">
                <p>This app will be able to:</p>
                <ul>
                    {{range .ScopeDescriptions}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
            </div>
        </div>
    </div>
</body>
</html>
```

---

## OAuth2 Handler Flow

### GET /oauth/authorize

```go
func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
    // 1. Parse and validate OAuth parameters
    params := parseAuthorizationRequest(r)
    if err := validateAuthorizationRequest(params); err != nil {
        renderError(w, err)
        return
    }

    // 2. Validate client and redirect URI
    app, err := h.appService.GetByClientID(params.ClientID)
    if err != nil || !app.HasRedirectURI(params.RedirectURI) {
        renderError(w, "Invalid client or redirect URI")
        return
    }

    // 3. Check if user is authenticated (session cookie)
    user, authenticated := h.getAuthenticatedUser(r)

    if !authenticated {
        // 4a. Not authenticated → Show login page
        h.renderLoginPage(w, r, params, app)
        return
    }

    // 4b. Authenticated → Generate authorization code
    code, err := h.generateAuthorizationCode(user, params)
    if err != nil {
        redirectWithError(w, r, params.RedirectURI, "server_error")
        return
    }

    // 5. Redirect back to client with code
    redirectURL := fmt.Sprintf("%s?code=%s&state=%s",
        params.RedirectURI, code, params.State)
    http.Redirect(w, r, redirectURL, http.StatusFound)
}
```

### POST /oauth/authorize (Login Submission)

```go
func (h *OAuthHandler) AuthorizePost(w http.ResponseWriter, r *http.Request) {
    // 1. Parse form data
    r.ParseForm()
    email := r.FormValue("email")
    password := r.FormValue("password")

    // 2. Reconstruct OAuth params from hidden fields
    params := AuthorizationRequest{
        ClientID:            r.FormValue("client_id"),
        RedirectURI:         r.FormValue("redirect_uri"),
        ResponseType:        r.FormValue("response_type"),
        Scope:               r.FormValue("scope"),
        State:               r.FormValue("state"),
        CodeChallenge:       r.FormValue("code_challenge"),
        CodeChallengeMethod: r.FormValue("code_challenge_method"),
    }

    // 3. Validate credentials
    user, err := h.authService.ValidateCredentials(email, password)
    if err != nil {
        // Re-render login page with error
        h.renderLoginPage(w, r, params, app, "Invalid email or password")
        return
    }

    // 4. Create session
    h.createSession(w, user)

    // 5. Generate authorization code
    code, err := h.generateAuthorizationCode(user, params)
    if err != nil {
        redirectWithError(w, r, params.RedirectURI, "server_error")
        return
    }

    // 6. Redirect back to client with code
    redirectURL := fmt.Sprintf("%s?code=%s&state=%s",
        params.RedirectURI, code, params.State)
    http.Redirect(w, r, redirectURL, http.StatusFound)
}
```

---

## SPA Client Implementation (Vue.js)

### Auth Service

```typescript
// src/services/auth.ts
import { generateCodeVerifier, generateCodeChallenge } from './pkce';

const OAUTH_CONFIG = {
  authorizationEndpoint: 'http://localhost:8080/oauth/authorize',
  tokenEndpoint: 'http://localhost:8080/oauth/token',
  clientId: 'your-vue-app-client-id',
  redirectUri: 'http://localhost:5175/callback',
  scope: 'openid email profile offline_access'
};

export async function initiateLogin(): Promise<void> {
  // Generate PKCE parameters
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  // Store for later use
  sessionStorage.setItem('pkce_code_verifier', codeVerifier);

  // Generate state for CSRF protection
  const state = crypto.randomUUID();
  sessionStorage.setItem('oauth_state', state);

  // Build authorization URL
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: OAUTH_CONFIG.clientId,
    redirect_uri: OAUTH_CONFIG.redirectUri,
    scope: OAUTH_CONFIG.scope,
    state: state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });

  // Redirect to OAuth2 server (shows login page)
  window.location.href = `${OAUTH_CONFIG.authorizationEndpoint}?${params}`;
}

export async function handleCallback(code: string, state: string): Promise<TokenResponse> {
  // Verify state
  const savedState = sessionStorage.getItem('oauth_state');
  if (state !== savedState) {
    throw new Error('Invalid state parameter');
  }

  // Get code verifier
  const codeVerifier = sessionStorage.getItem('pkce_code_verifier');
  if (!codeVerifier) {
    throw new Error('Missing code verifier');
  }

  // Exchange code for tokens
  const response = await fetch(OAUTH_CONFIG.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: OAUTH_CONFIG.redirectUri,
      client_id: OAUTH_CONFIG.clientId,
      code_verifier: codeVerifier
    })
  });

  if (!response.ok) {
    throw new Error('Token exchange failed');
  }

  // Clean up
  sessionStorage.removeItem('pkce_code_verifier');
  sessionStorage.removeItem('oauth_state');

  return response.json();
}

export function logout(): void {
  // Clear local tokens
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');

  // Optional: Redirect to OAuth2 server logout
  window.location.href = 'http://localhost:8080/oauth/logout?' +
    new URLSearchParams({
      post_logout_redirect_uri: 'http://localhost:5175',
      client_id: OAUTH_CONFIG.clientId
    });
}
```

### PKCE Utilities

```typescript
// src/services/pkce.ts
export function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hash));
}

function base64UrlEncode(buffer: Uint8Array): string {
  return btoa(String.fromCharCode(...buffer))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
```

### Callback Page Component

```vue
<!-- src/views/CallbackView.vue -->
<template>
  <div class="callback-page">
    <div v-if="loading" class="loading">
      <p>Completing login...</p>
    </div>
    <div v-else-if="error" class="error">
      <h2>Login Failed</h2>
      <p>{{ error }}</p>
      <button @click="retryLogin">Try Again</button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { handleCallback } from '@/services/auth';
import { useAuthStore } from '@/stores/auth';

const router = useRouter();
const route = useRoute();
const authStore = useAuthStore();

const loading = ref(true);
const error = ref<string | null>(null);

onMounted(async () => {
  try {
    const code = route.query.code as string;
    const state = route.query.state as string;
    const errorParam = route.query.error as string;

    if (errorParam) {
      throw new Error(route.query.error_description as string || errorParam);
    }

    if (!code) {
      throw new Error('No authorization code received');
    }

    // Exchange code for tokens
    const tokens = await handleCallback(code, state);

    // Store tokens
    authStore.setTokens(tokens);

    // Redirect to intended destination
    const returnTo = sessionStorage.getItem('auth_return_to') || '/dashboard';
    sessionStorage.removeItem('auth_return_to');
    router.replace(returnTo);

  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Login failed';
    loading.value = false;
  }
});

function retryLogin() {
  router.push('/login');
}
</script>
```

### Router Configuration

```typescript
// src/router/index.ts
import { createRouter, createWebHistory } from 'vue-router';
import { useAuthStore } from '@/stores/auth';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      component: () => import('@/views/HomeView.vue')
    },
    {
      path: '/callback',
      component: () => import('@/views/CallbackView.vue'),
      meta: { public: true }  // Don't require auth for callback
    },
    {
      path: '/dashboard',
      component: () => import('@/views/DashboardView.vue'),
      meta: { requiresAuth: true }
    }
  ]
});

router.beforeEach((to, from, next) => {
  const authStore = useAuthStore();

  if (to.meta.requiresAuth && !authStore.isAuthenticated) {
    // Save intended destination
    sessionStorage.setItem('auth_return_to', to.fullPath);
    // Redirect to login
    next('/login');
  } else {
    next();
  }
});

export default router;
```

---

## Complete Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              COMPLETE OAUTH2 FLOW                             │
└──────────────────────────────────────────────────────────────────────────────┘

     Vue.js SPA                          OAuth2 Server
     (localhost:5175)                    (localhost:8080)
          │                                    │
          │  1. User clicks "Login"            │
          │  ─────────────────────────────────>│
          │  GET /oauth/authorize              │
          │  ?client_id=xxx                    │
          │  &redirect_uri=.../callback        │
          │  &response_type=code               │
          │  &scope=openid email profile       │
          │  &state=random123                  │
          │  &code_challenge=xxx               │
          │  &code_challenge_method=S256       │
          │                                    │
          │                                    │  2. Server validates
          │                                    │     client & redirect_uri
          │                                    │
          │  3. Server returns login page      │
          │  <─────────────────────────────────│
          │  Content-Type: text/html           │
          │                                    │
    ┌─────┴─────┐                              │
    │   LOGIN   │                              │
    │   PAGE    │                              │
    │  (OAuth2  │                              │
    │  Server)  │                              │
    └─────┬─────┘                              │
          │                                    │
          │  4. User enters credentials        │
          │  ─────────────────────────────────>│
          │  POST /oauth/authorize             │
          │  email=user@example.com            │
          │  password=***                      │
          │  client_id=xxx                     │
          │  ... (all OAuth params)            │
          │                                    │
          │                                    │  5. Server validates
          │                                    │     credentials
          │                                    │
          │  6. Redirect with auth code        │
          │  <─────────────────────────────────│
          │  302 Location:                     │
          │  localhost:5175/callback           │
          │  ?code=AUTH_CODE                   │
          │  &state=random123                  │
          │                                    │
          │  7. SPA handles callback           │
          │  ─────────────────────────────────>│
          │  POST /oauth/token                 │
          │  grant_type=authorization_code     │
          │  code=AUTH_CODE                    │
          │  code_verifier=xxx                 │
          │  client_id=xxx                     │
          │  redirect_uri=.../callback         │
          │                                    │
          │  8. Server returns tokens          │
          │  <─────────────────────────────────│
          │  {                                 │
          │    "access_token": "...",          │
          │    "refresh_token": "...",         │
          │    "id_token": "...",              │
          │    "expires_in": 3600              │
          │  }                                 │
          │                                    │
          │  9. User is authenticated!         │
          ▼                                    │
```

---

## Backend Implementation Checklist

### Required Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/authorize` | GET | Show login page (if not authenticated) or redirect with code |
| `/oauth/authorize` | POST | Handle login form submission |
| `/oauth/token` | POST | Exchange auth code for tokens |
| `/oauth/logout` | GET/POST | End session and redirect |
| `/static/*` | GET | Serve static assets (CSS, JS, images) |

### Required Features

- [ ] HTML template rendering for login page
- [ ] Session management (cookies)
- [ ] PKCE support (code_challenge, code_verifier)
- [ ] State parameter validation
- [ ] Redirect URI validation
- [ ] Error page rendering
- [ ] Static file serving

### Security Considerations

1. **HTTPS Required** in production
2. **Secure cookies** for sessions
3. **CSRF protection** via state parameter
4. **PKCE required** for public clients (SPAs)
5. **Rate limiting** on login attempts
6. **Brute force protection** (account lockout)

---

## Testing Checklist

- [ ] SPA can initiate login flow
- [ ] OAuth2 server shows login page
- [ ] Invalid credentials show error on login page
- [ ] Valid credentials redirect back to SPA
- [ ] SPA can exchange code for tokens
- [ ] Refresh token flow works
- [ ] Logout clears session
- [ ] Invalid client_id shows error
- [ ] Invalid redirect_uri shows error
- [ ] State mismatch is detected

---

## Related Documents

- [CR-superadmin-user-management-frontend.md](./CR-superadmin-user-management-frontend.md) - Admin portal user management
- [CR-admin-app-management-frontend.md](./CR-admin-app-management-frontend.md) - App/client management
