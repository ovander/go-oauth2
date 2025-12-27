# Change Request: Superadmin User Management Frontend Integration

**CR ID:** CR-2024-SUPERADMIN-USERS-001
**Date:** 2025-12-27
**Author:** Backend Team
**Status:** Ready for Implementation

---

## Summary

This document describes the superadmin portal functionalities for managing all types of users in the OAuth2 system. Only superadmins can access the admin portal (port 8081).

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                 ADMIN PORTAL (Port 8081)                    │
│                   Superadmin Only Access                    │
├─────────────────────────────────────────────────────────────┤
│  Superadmin can manage:                                     │
│  ├── Other Superadmins (system administrators)              │
│  ├── All OAuth Apps (CRUD)                                  │
│  ├── App Admins (users with admin role in apps)             │
│  └── App Users (users with user role in apps)               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 OAUTH SERVER (Port 8080)                    │
│              App Users & App Admins login here              │
├─────────────────────────────────────────────────────────────┤
│  - Users authenticate via /api/auth/login                   │
│  - Requires app_client_id                                   │
│  - App admins manage users within their app scope           │
└─────────────────────────────────────────────────────────────┘
```

**User Types:**
| Type | Description | Login Port | Managed By |
|------|-------------|------------|------------|
| Superadmin | System administrator | 8081 | Other superadmins |
| App Admin | Administrator within an app | 8080 | Superadmin |
| App User | Regular user within an app | 8080 | Superadmin, App Admin |

---

## Prerequisites

- Must be authenticated as **superadmin** via `/api/admin/login`
- All requests require JWT: `Authorization: Bearer <token>`
- Base URL: `http://localhost:8081` (Admin port)

---

## Part 1: Superadmin Management

Superadmins manage the OAuth2 system itself.

### 1.1 List Superadmins

**Endpoint:** `GET /api/admin/superadmins`

**Response:**
```json
{
  "superadmins": [
    {
      "id": 1,
      "email": "admin@example.com",
      "name": "Primary Admin",
      "is_verified": true,
      "last_login": "2025-12-27T14:00:00Z",
      "failed_logins": 0,
      "locked_until": null,
      "created_at": "2025-01-01T00:00:00Z",
      "updated_at": "2025-12-27T14:00:00Z"
    }
  ],
  "total_count": 1
}
```

---

### 1.2 Get Superadmin Details

**Endpoint:** `GET /api/admin/superadmins/{id}`

**Response:** Single superadmin object.

---

### 1.3 Create Superadmin

**Endpoint:** `POST /api/admin/superadmins`

**Request:**
```json
{
  "email": "newadmin@example.com",
  "name": "New Admin",
  "password": "SecurePassword123!"
}
```

**Response (201):** Created superadmin object.

**Notes:**
- Superadmins are auto-verified upon creation
- Password must meet security policy

---

### 1.4 Update Superadmin

**Endpoint:** `PUT /api/admin/superadmins/{id}`

**Request (all fields optional):**
```json
{
  "name": "Updated Name",
  "email": "updated@example.com",
  "password": "NewPassword123!"
}
```

**Response:** Updated superadmin object.

---

### 1.5 Delete Superadmin

**Endpoint:** `DELETE /api/admin/superadmins/{id}`

**Response:** `204 No Content`

**Constraints:**
| Constraint | Error |
|------------|-------|
| Cannot delete yourself | 403 - "cannot delete your own account" |
| Cannot delete last superadmin | 403 - "cannot delete the last superadmin" |

---

## Part 2: Global User Management

Superadmin can view and manage ALL users across all apps.

### 2.1 List All Users

**Endpoint:** `GET /api/admin/users`

**Query Parameters:**
| Parameter | Type | Default | Max |
|-----------|------|---------|-----|
| `page` | int | 1 | - |
| `page_size` | int | 20 | 100 |

**Response:**
```json
{
  "users": [
    {
      "id": 1,
      "email": "admin@example.com",
      "name": "Admin User",
      "role": "superadmin",
      "is_verified": true,
      "created_at": "2025-01-01T00:00:00Z"
    },
    {
      "id": 2,
      "email": "appuser@example.com",
      "name": "App User",
      "role": "user",
      "is_verified": true,
      "created_at": "2025-01-15T10:00:00Z"
    }
  ],
  "total_count": 150,
  "page": 1,
  "page_size": 20
}
```

**Global Roles (user.role):**
| Role | Description |
|------|-------------|
| `superadmin` | System administrator (manages OAuth2 server) |
| `user` | Regular user (can be app admin/user within specific apps) |

**Note:** The `role` field here is the **global** role. Users with global role `user` can still be `admin` within specific apps.

---

### 2.2 Get User Details

**Endpoint:** `GET /api/admin/users/{id}`

**Response:** Single user object.

---

### 2.3 Revoke User Tokens

**Endpoint:** `POST /api/admin/users/{id}/revoke-tokens`

**Description:** Invalidates all access and refresh tokens, forcing re-authentication.

**Response:**
```json
{
  "message": "tokens revoked successfully"
}
```

**Use Cases:**
- Security breach suspected
- User left organization
- Force session reset

---

### 2.4 Unlock User Account

**Endpoint:** `POST /api/admin/users/{id}/unlock`

**Description:** Unlocks an account locked due to failed login attempts.

**Response:**
```json
{
  "message": "user unlocked successfully"
}
```

---

## Part 3: App-Scoped User Management

Superadmin can manage users within any app.

### 3.1 List Users in App

**Endpoint:** `GET /api/apps/{app_id}/users`

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | 1 | Page number |
| `page_size` | int | 20 | Results per page |
| `search` | string | - | Search by email/name |

**Response:**
```json
{
  "users": [
    {
      "id": 5,
      "email": "john@example.com",
      "name": "John Doe",
      "role": "admin",
      "is_verified": true,
      "invite_sent": true,
      "last_login": "2025-12-27T14:00:00Z",
      "created_at": "2025-12-01T10:00:00Z"
    },
    {
      "id": 8,
      "email": "jane@example.com",
      "name": "Jane Smith",
      "role": "user",
      "is_verified": true,
      "invite_sent": true,
      "last_login": "2025-12-27T12:30:00Z",
      "created_at": "2025-11-15T09:00:00Z"
    }
  ],
  "total_count": 45,
  "page": 1,
  "page_size": 20
}
```

**App-Scoped Roles (role within app):**
| Role | Description |
|------|-------------|
| `admin` | App administrator - can manage users within this app |
| `user` | Regular app user |

---

### 3.2 Add User to App

**Endpoint:** `POST /api/apps/{app_id}/users`

**Request:**
```json
{
  "email": "newuser@example.com",
  "name": "New User",
  "role": "user"
}
```

**Response (201):**
```json
{
  "user_id": 10,
  "invite_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "role": "user"
}
```

**Behavior:**
| User Exists? | Action |
|--------------|--------|
| No | Create account with temp password, assign role, generate invite |
| Yes | Assign role to existing user, generate invite |

**Error:** `409` if user already has a role in this app.

---

### 3.3 Get User in App

**Endpoint:** `GET /api/apps/{app_id}/users/{user_id}`

**Response:** Single app user object.

---

### 3.4 Update User Role in App

**Endpoint:** `PUT /api/apps/{app_id}/users/{user_id}`

**Request:**
```json
{
  "role": "admin"
}
```

**Response:**
```json
{
  "role": "admin"
}
```

**Actions:**
- Promote `user` → `admin`: User gains ability to manage other users in this app
- Demote `admin` → `user`: User loses management capabilities

---

### 3.5 Remove User from App

**Endpoint:** `DELETE /api/apps/{app_id}/users/{user_id}`

**Response:** `204 No Content`

**Note:** Removes user's access to this specific app. User account remains and may have access to other apps.

---

### 3.6 Resend Verification Email

**Endpoint:** `POST /api/apps/{app_id}/users/{user_id}/resend-verification`

**Response:**
```json
{
  "message": "Verification email sent"
}
```

---

### 3.7 Force Password Reset

**Endpoint:** `POST /api/apps/{app_id}/users/{user_id}/reset-password`

**Response:**
```json
{
  "message": "Password reset email sent"
}
```

---

## Frontend Implementation Guide

### Admin Portal Navigation

```
Admin Portal (Superadmin Only)
├── Dashboard
│   └── System overview, health, stats
├── Apps
│   ├── List all apps
│   ├── Create app
│   └── App Details
│       ├── Settings (name, URLs, status)
│       ├── Credentials (client_id, rotate secret)
│       └── App Users (manage users in this app)
│           ├── List users (admins + users)
│           ├── Add user to app
│           ├── Change role (user ↔ admin)
│           ├── Remove from app
│           └── Account actions (verify, reset password)
├── Users (Global)
│   ├── List all users (across all apps)
│   ├── View user details
│   ├── Revoke tokens
│   └── Unlock account
├── Superadmins
│   ├── List superadmins
│   ├── Create superadmin
│   ├── Update superadmin
│   └── Delete superadmin (with constraints)
└── Activity Log
```

### User Type Distinction in UI

```
┌─────────────────────────────────────────────────────────────┐
│  Users Overview                                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │  SUPERADMINS    │  │  APP ADMINS     │  │  APP USERS   │ │
│  │      3          │  │      12         │  │     135      │ │
│  │  [Manage →]     │  │  [View in Apps] │  │ [View in Apps]│ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### App Users Management UI

```
┌─────────────────────────────────────────────────────────────┐
│  App: My Web Application                    [+ Add User]    │
│  Users in this app: 45                                      │
├─────────────────────────────────────────────────────────────┤
│  Filter: [All ▼]  Search: [_______________] [🔍]            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─ ADMINS (3) ─────────────────────────────────────────┐   │
│  │ 👤 john@example.com                                  │   │
│  │    John Doe | ✓ Verified | Last: 2h ago              │   │
│  │    [Demote to User] [Reset Password] [Remove]        │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌─ USERS (42) ─────────────────────────────────────────┐   │
│  │ 👤 jane@example.com                                  │   │
│  │    Jane Smith | ✓ Verified | Last: 30m ago           │   │
│  │    [Promote to Admin] [Reset Password] [Remove]      │   │
│  │                                                       │   │
│  │ 👤 pending@example.com                               │   │
│  │    Pending User | ⏳ Pending | Never logged in       │   │
│  │    [Resend Invite] [Promote to Admin] [Remove]       │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│  Page 1 of 3  [< Prev] [Next >]                             │
└─────────────────────────────────────────────────────────────┘
```

### TypeScript Interfaces

```typescript
// ==========================================
// Superadmin Types
// ==========================================
interface Superadmin {
  id: number;
  email: string;
  name: string;
  is_verified: boolean;
  last_login?: string;
  failed_logins: number;
  locked_until?: string;
  created_at: string;
  updated_at: string;
}

interface CreateSuperadminRequest {
  email: string;
  name: string;
  password: string;
}

interface UpdateSuperadminRequest {
  name?: string;
  email?: string;
  password?: string;
}

// ==========================================
// Global User Types
// ==========================================
interface GlobalUser {
  id: number;
  email: string;
  name: string;
  role: 'superadmin' | 'user';  // Global role
  is_verified: boolean;
  created_at: string;
}

interface GlobalUserListResponse {
  users: GlobalUser[];
  total_count: number;
  page: number;
  page_size: number;
}

// ==========================================
// App User Types
// ==========================================
interface AppUser {
  id: number;
  email: string;
  name: string;
  role: 'admin' | 'user';  // Role within this app
  is_verified: boolean;
  invite_sent: boolean;
  last_login?: string;
  created_at: string;
}

interface AppUserListResponse {
  users: AppUser[];
  total_count: number;
  page: number;
  page_size: number;
}

interface AddUserToAppRequest {
  email: string;
  name?: string;
  role: 'admin' | 'user';
}

interface AddUserToAppResponse {
  user_id: number;
  invite_token: string;
  role: string;
}

interface UpdateAppUserRoleRequest {
  role: 'admin' | 'user';
}
```

### API Service

```typescript
class SuperadminUserService {
  constructor(private baseUrl: string, private token: string) {}

  private headers(): HeadersInit {
    return {
      'Authorization': `Bearer ${this.token}`,
      'Content-Type': 'application/json'
    };
  }

  // ==========================================
  // Superadmin Management
  // ==========================================

  async listSuperadmins(): Promise<{ superadmins: Superadmin[], total_count: number }> {
    const res = await fetch(`${this.baseUrl}/api/admin/superadmins`, { headers: this.headers() });
    return res.json();
  }

  async createSuperadmin(req: CreateSuperadminRequest): Promise<Superadmin> {
    const res = await fetch(`${this.baseUrl}/api/admin/superadmins`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify(req)
    });
    if (!res.ok) throw new Error((await res.json()).error);
    return res.json();
  }

  async updateSuperadmin(id: number, req: UpdateSuperadminRequest): Promise<Superadmin> {
    const res = await fetch(`${this.baseUrl}/api/admin/superadmins/${id}`, {
      method: 'PUT',
      headers: this.headers(),
      body: JSON.stringify(req)
    });
    return res.json();
  }

  async deleteSuperadmin(id: number): Promise<void> {
    const res = await fetch(`${this.baseUrl}/api/admin/superadmins/${id}`, {
      method: 'DELETE',
      headers: this.headers()
    });
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error);  // "cannot delete your own account" or "cannot delete the last superadmin"
    }
  }

  // ==========================================
  // Global User Management
  // ==========================================

  async listAllUsers(page = 1, pageSize = 20): Promise<GlobalUserListResponse> {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
    const res = await fetch(`${this.baseUrl}/api/admin/users?${params}`, { headers: this.headers() });
    return res.json();
  }

  async revokeUserTokens(userId: number): Promise<void> {
    await fetch(`${this.baseUrl}/api/admin/users/${userId}/revoke-tokens`, {
      method: 'POST',
      headers: this.headers()
    });
  }

  async unlockUser(userId: number): Promise<void> {
    await fetch(`${this.baseUrl}/api/admin/users/${userId}/unlock`, {
      method: 'POST',
      headers: this.headers()
    });
  }

  // ==========================================
  // App User Management
  // ==========================================

  async listAppUsers(appId: number, page = 1, pageSize = 20, search?: string): Promise<AppUserListResponse> {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
    if (search) params.append('search', search);
    const res = await fetch(`${this.baseUrl}/api/apps/${appId}/users?${params}`, { headers: this.headers() });
    return res.json();
  }

  async addUserToApp(appId: number, req: AddUserToAppRequest): Promise<AddUserToAppResponse> {
    const res = await fetch(`${this.baseUrl}/api/apps/${appId}/users`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify(req)
    });
    if (!res.ok) throw new Error((await res.json()).error);
    return res.json();
  }

  async updateAppUserRole(appId: number, userId: number, role: 'admin' | 'user'): Promise<void> {
    await fetch(`${this.baseUrl}/api/apps/${appId}/users/${userId}`, {
      method: 'PUT',
      headers: this.headers(),
      body: JSON.stringify({ role })
    });
  }

  async removeUserFromApp(appId: number, userId: number): Promise<void> {
    await fetch(`${this.baseUrl}/api/apps/${appId}/users/${userId}`, {
      method: 'DELETE',
      headers: this.headers()
    });
  }

  async resendVerification(appId: number, userId: number): Promise<void> {
    await fetch(`${this.baseUrl}/api/apps/${appId}/users/${userId}/resend-verification`, {
      method: 'POST',
      headers: this.headers()
    });
  }

  async forcePasswordReset(appId: number, userId: number): Promise<void> {
    await fetch(`${this.baseUrl}/api/apps/${appId}/users/${userId}/reset-password`, {
      method: 'POST',
      headers: this.headers()
    });
  }
}
```

---

## Error Handling

| Status | Meaning | Action |
|--------|---------|--------|
| 200 | Success | Display data |
| 201 | Created | Show success message |
| 204 | Deleted | Remove from UI |
| 400 | Bad request | Show validation error |
| 401 | Unauthorized | Redirect to admin login |
| 403 | Forbidden | Show constraint error (e.g., "cannot delete self") |
| 404 | Not found | Show "not found" message |
| 409 | Conflict | Show "already exists" message |
| 500 | Server error | Show generic error |

---

## Security Considerations

1. **Superadmin Protection:**
   - Cannot delete your own account
   - Cannot delete the last superadmin
   - These are enforced by backend

2. **Confirmation Dialogs:**
   - Confirm before deleting superadmins
   - Confirm before revoking tokens
   - Confirm before removing users from apps
   - Confirm before demoting app admins

3. **Audit Trail:**
   - All actions are logged in activity log
   - Log includes who performed action and when

---

## Testing Checklist

### Superadmin Management
- [ ] List all superadmins
- [ ] Create new superadmin
- [ ] Update superadmin (name, email, password)
- [ ] Delete superadmin
- [ ] Error: Cannot delete self
- [ ] Error: Cannot delete last superadmin

### Global User Management
- [ ] List all users with pagination
- [ ] View user details
- [ ] Revoke user tokens
- [ ] Unlock locked user

### App User Management
- [ ] List users in app with search
- [ ] Add new user to app (creates account)
- [ ] Add existing user to app
- [ ] Promote user to admin
- [ ] Demote admin to user
- [ ] Remove user from app
- [ ] Resend verification email
- [ ] Force password reset
- [ ] Error: User already in app (409)

---

## Related Documents

- [CR-admin-dashboard-frontend.md](./CR-admin-dashboard-frontend.md) - Dashboard endpoints
- [CR-admin-app-management-frontend.md](./CR-admin-app-management-frontend.md) - App CRUD operations
