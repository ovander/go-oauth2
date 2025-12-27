# Change Request: Admin App Management Frontend Integration

**CR ID:** CR-2024-APP-MGMT-001
**Date:** 2025-12-27
**Author:** Backend Team
**Status:** Ready for Implementation

---

## Summary

This document describes the admin portal API endpoints for managing OAuth applications (clients), users, and related administrative functions. The frontend should integrate with these endpoints to provide full app and user management capabilities.

---

## Prerequisites

- User must be authenticated as a **superadmin** via `/api/admin/login`
- All requests must include the JWT token in the `Authorization: Bearer <token>` header
- Base URL: `http://localhost:8081` (or configured admin port)

---

## Part 1: OAuth App Management

### 1.1 List Apps

**Endpoint:** `GET /api/admin/apps`

**Description:** Returns ALL OAuth apps in the system. The superadmin manages all apps regardless of ownership.

**Response:**
```json
{
  "apps": [
    {
      "id": 1,
      "name": "My Web Application",
      "client_id": "abc123def456",
      "active": true,
      "url": "https://myapp.example.com",
      "redirect_uris": [
        "https://myapp.example.com/callback",
        "https://myapp.example.com/auth/callback"
      ],
      "owner_id": 1,
      "created_at": "2025-01-15T10:30:00Z"
    }
  ],
  "total_count": 1
}
```

---

### 1.2 Get App Details

**Endpoint:** `GET /api/admin/apps/{id}`

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | uint | App ID |

**Response:** Same as single app object above.

**Error Responses:**
| Status | Condition |
|--------|-----------|
| 400 | Invalid app ID |
| 403 | Not owner and not global admin |
| 404 | App not found |

---

### 1.3 Create App

**Endpoint:** `POST /api/admin/apps`

**Request Body:**
```json
{
  "name": "My New Application",
  "url": "https://newapp.example.com",
  "redirect_uris": [
    "https://newapp.example.com/callback"
  ]
}
```

**Field Validation:**
| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Display name for the app |
| `url` | No | App's public URL |
| `redirect_uris` | No | Array of allowed OAuth redirect URIs |

**Response (201 Created):**
```json
{
  "id": 2,
  "name": "My New Application",
  "client_id": "generated-client-id-xyz",
  "active": true,
  "url": "https://newapp.example.com",
  "redirect_uris": ["https://newapp.example.com/callback"],
  "owner_id": 1,
  "created_at": "2025-12-27T15:00:00Z",
  "client_secret": "generated-secret-only-shown-once"
}
```

**IMPORTANT:** The `client_secret` is only returned once during creation. Store it securely - it cannot be retrieved again.

---

### 1.4 Update App

**Endpoint:** `PUT /api/admin/apps/{id}`

**Request Body (all fields optional):**
```json
{
  "name": "Updated App Name",
  "url": "https://updated-url.example.com",
  "redirect_uris": [
    "https://updated-url.example.com/callback"
  ],
  "active": false
}
```

**Response:** Updated app object (without secret).

---

### 1.5 Delete App

**Endpoint:** `DELETE /api/admin/apps/{id}`

**Response:** `204 No Content`

**Warning:** This permanently deletes the OAuth app and invalidates all associated tokens.

---

### 1.6 Rotate Client Secret

**Endpoint:** `POST /api/admin/apps/{id}/rotate-secret`

**Description:** Generates a new client secret, invalidating the old one.

**Response:**
```json
{
  "id": 1,
  "name": "My Application",
  "client_id": "abc123def456",
  "active": true,
  "url": "https://myapp.example.com",
  "redirect_uris": ["https://myapp.example.com/callback"],
  "owner_id": 1,
  "created_at": "2025-01-15T10:30:00Z",
  "client_secret": "new-secret-only-shown-once"
}
```

**IMPORTANT:** Store the new secret immediately. The old secret is invalidated and the new one cannot be retrieved again.

---

## Part 2: App-Scoped User Management

These endpoints manage users within a specific OAuth app. They are accessible to app admins (not just superadmins).

**Base Path:** `/api/apps/{app_id}/users`

**Required Middleware:**
- `AuthMiddleware` - Valid JWT required
- `RequireAppAccess` - User must have a role in the app

---

### 2.1 List App Users

**Endpoint:** `GET /api/apps/{app_id}/users`

**Query Parameters:**
| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `page` | int | 1 | - | Page number |
| `page_size` | int | 20 | 100 | Results per page |
| `search` | string | - | - | Search by email or name |

**Example:** `GET /api/apps/1/users?page=1&page_size=20&search=john`

**Response:**
```json
{
  "users": [
    {
      "id": 5,
      "email": "john@example.com",
      "name": "John Doe",
      "role": "user",
      "is_verified": true,
      "invite_sent": true,
      "last_login": "2025-12-27T14:00:00Z",
      "created_at": "2025-12-01T10:00:00Z"
    }
  ],
  "total_count": 1,
  "page": 1,
  "page_size": 20
}
```

**User Roles:**
| Role | Description |
|------|-------------|
| `user` | Regular app user |
| `admin` | App administrator (can manage users within this app) |

---

### 2.2 Get App User

**Endpoint:** `GET /api/apps/{app_id}/users/{user_id}`

**Response:** Single user object as above.

---

### 2.3 Add User to App

**Endpoint:** `POST /api/apps/{app_id}/users`

**Description:** Adds an existing user or creates a new user and assigns them to the app.

**Request Body:**
```json
{
  "email": "newuser@example.com",
  "name": "New User",
  "role": "user"
}
```

**Field Validation:**
| Field | Required | Description |
|-------|----------|-------------|
| `email` | Yes | User's email address |
| `name` | No | Display name (defaults to email if not provided) |
| `role` | Yes | Role to assign: `user` or `admin` |

**Response (201 Created):**
```json
{
  "user_id": 10,
  "invite_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "role": "user"
}
```

**Behavior:**
- If user with email exists: Assigns role to existing user
- If user doesn't exist: Creates new user with temporary password, then assigns role
- Returns an invite token for the user to set up their account

**Error Responses:**
| Status | Condition |
|--------|-----------|
| 400 | Missing email or role |
| 409 | User already has a role in this app |

---

### 2.4 Update User Role

**Endpoint:** `PUT /api/apps/{app_id}/users/{user_id}`

**Request Body:**
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

---

### 2.5 Remove User from App

**Endpoint:** `DELETE /api/apps/{app_id}/users/{user_id}`

**Response:** `204 No Content`

**Note:** Cannot remove yourself from the app.

---

### 2.6 Resend Verification Email

**Endpoint:** `POST /api/apps/{app_id}/users/{user_id}/resend-verification`

**Description:** Generates a new email verification token and sends verification email.

**Response:**
```json
{
  "message": "Verification email sent"
}
```

---

### 2.7 Force Password Reset

**Endpoint:** `POST /api/apps/{app_id}/users/{user_id}/reset-password`

**Description:** Generates a password reset token and sends reset email to user.

**Response:**
```json
{
  "message": "Password reset email sent"
}
```

---

## Part 3: Global User Management (Superadmin Only)

These endpoints are for global user management across all apps.

---

### 3.1 List All Users

**Endpoint:** `GET /api/admin/users`

**Required:** Global admin (superadmin) role

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
      "email": "user@example.com",
      "name": "Regular User",
      "role": "user",
      "is_verified": true,
      "created_at": "2025-01-15T10:00:00Z"
    }
  ],
  "total_count": 2,
  "page": 1,
  "page_size": 20
}
```

**Global Roles:**
| Role | Description |
|------|-------------|
| `superadmin` | Full system access |
| `admin` | Administrative access (deprecated - use superadmin) |
| `user` | Regular user |

---

### 3.2 Get User Details

**Endpoint:** `GET /api/admin/users/{id}`

**Required:** Global admin role

**Response:** Single user object.

---

### 3.3 Revoke User Tokens

**Endpoint:** `POST /api/admin/users/{id}/revoke-tokens`

**Description:** Invalidates all access and refresh tokens for the user, forcing re-authentication.

**Required:** Global admin role

**Response:**
```json
{
  "message": "tokens revoked successfully"
}
```

---

### 3.4 Unlock User Account

**Endpoint:** `POST /api/admin/users/{id}/unlock`

**Description:** Unlocks a user account that was locked due to failed login attempts.

**Required:** Global admin role

**Response:**
```json
{
  "message": "user unlocked successfully"
}
```

---

## Part 4: Activity Logs

### 4.1 Admin Activity Log

**Endpoint:** `GET /api/admin/activity`

**Description:** Returns activity log for the current admin's actions.

**Query Parameters:**
| Parameter | Type | Default | Max |
|-----------|------|---------|-----|
| `page` | int | 1 | - |
| `page_size` | int | 20 | 100 |

**Response:**
```json
{
  "logs": [
    {
      "id": 42,
      "admin_id": 1,
      "app_id": 2,
      "target_user_id": 5,
      "action": "add_user",
      "details": {
        "email": "newuser@example.com",
        "role": "user",
        "is_new_user": true
      },
      "created_at": "2025-12-27T15:30:00Z"
    }
  ],
  "total_count": 42,
  "page": 1,
  "page_size": 20
}
```

**Action Types:**
| Action | Description |
|--------|-------------|
| `add_user` | User added to an app |
| `remove_user` | User removed from an app |
| `update_role` | User role changed |
| `resend_verification` | Verification email resent |
| `reset_password` | Password reset triggered |
| `revoke_tokens` | User tokens revoked |
| `unlock_user` | User account unlocked |
| `create_superadmin` | Superadmin account created |
| `update_superadmin` | Superadmin account updated |
| `delete_superadmin` | Superadmin account deleted |

---

### 4.2 App Activity Logs

**Endpoint:** `GET /api/apps/{app_id}/logs`

**Required Middleware:** `RequireAppAdmin` - Must be admin of the app

**Query Parameters:**
| Parameter | Type | Default | Max |
|-----------|------|---------|-----|
| `page` | int | 1 | - |
| `page_size` | int | 20 | 100 |

**Response:**
```json
{
  "logs": [
    {
      "id": 100,
      "app_id": 2,
      "user_id": 5,
      "event_type": "login_success",
      "event_category": "auth",
      "metadata": {},
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "success": true,
      "created_at": "2025-12-27T14:00:00Z"
    }
  ],
  "total_count": 150,
  "page": 1,
  "page_size": 20
}
```

---

## Part 5: Quick Stats

### 5.1 Admin Stats

**Endpoint:** `GET /api/admin/stats`

**Description:** Quick statistics for the current admin.

**Response:**
```json
{
  "total_users": 150,
  "total_apps": 3
}
```

---

## Part 6: Superadmin Management

These endpoints allow superadmins to manage other superadmin accounts.

---

### 6.1 List Superadmins

**Endpoint:** `GET /api/admin/superadmins`

**Description:** Returns all superadmin users in the system.

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

### 6.2 Get Superadmin Details

**Endpoint:** `GET /api/admin/superadmins/{id}`

**Response:** Single superadmin object as above.

**Error Responses:**
| Status | Condition |
|--------|-----------|
| 400 | Invalid ID |
| 404 | Superadmin not found or user is not a superadmin |

---

### 6.3 Create Superadmin

**Endpoint:** `POST /api/admin/superadmins`

**Request Body:**
```json
{
  "email": "newadmin@example.com",
  "name": "New Admin",
  "password": "SecurePassword123!"
}
```

**Field Validation:**
| Field | Required | Description |
|-------|----------|-------------|
| `email` | Yes | Unique email address |
| `name` | Yes | Display name |
| `password` | Yes | Must meet password policy |

**Response (201 Created):** Superadmin object.

**Note:** Superadmins are automatically verified upon creation.

**Error Responses:**
| Status | Condition |
|--------|-----------|
| 400 | Missing required fields or invalid password |
| 409 | Email already exists |

---

### 6.4 Update Superadmin

**Endpoint:** `PUT /api/admin/superadmins/{id}`

**Request Body (all fields optional):**
```json
{
  "name": "Updated Name",
  "email": "updated@example.com",
  "password": "NewSecurePassword123!"
}
```

**Response:** Updated superadmin object.

**Error Responses:**
| Status | Condition |
|--------|-----------|
| 400 | Invalid password or target is not a superadmin |
| 404 | Superadmin not found |
| 409 | Email already exists |

---

### 6.5 Delete Superadmin

**Endpoint:** `DELETE /api/admin/superadmins/{id}`

**Response:** `204 No Content`

**Constraints:**
1. **Cannot delete yourself** - Returns 403
2. **Cannot delete the last superadmin** - Returns 403

**Error Responses:**
| Status | Condition |
|--------|-----------|
| 400 | Target user is not a superadmin |
| 403 | Cannot delete your own account |
| 403 | Cannot delete the last superadmin |
| 404 | Superadmin not found |

---

## Frontend Implementation Guide

### Recommended Page Structure

```
Admin Portal
├── Dashboard (uses dashboard endpoints - see other CR)
├── Apps
│   ├── List Apps (/api/admin/apps) - ALL apps in system
│   ├── Create App (/api/admin/apps POST)
│   └── App Details
│       ├── Settings (update/delete app)
│       ├── Credentials (view client_id, rotate secret)
│       └── Users (/api/apps/{id}/users)
│           ├── List Users
│           ├── Add User
│           └── User Actions (role, verify, reset, remove)
├── Users (Global)
│   ├── List All Users
│   └── User Actions (revoke tokens, unlock)
├── Superadmins
│   ├── List Superadmins (/api/admin/superadmins)
│   ├── Create Superadmin (/api/admin/superadmins POST)
│   └── Superadmin Actions (update, delete with constraints)
└── Activity Log (/api/admin/activity)
```

### TypeScript Interfaces

```typescript
// App Management
interface App {
  id: number;
  name: string;
  client_id: string;
  active: boolean;
  url?: string;
  redirect_uris: string[];
  owner_id?: number;
  created_at: string;
}

interface AppWithSecret extends App {
  client_secret: string; // Only on create/rotate
}

interface CreateAppRequest {
  name: string;
  url?: string;
  redirect_uris?: string[];
}

interface UpdateAppRequest {
  name?: string;
  url?: string;
  redirect_uris?: string[];
  active?: boolean;
}

// User Management
interface AppUser {
  id: number;
  email: string;
  name: string;
  role: 'user' | 'admin';
  is_verified: boolean;
  invite_sent: boolean;
  last_login?: string;
  created_at: string;
}

interface GlobalUser {
  id: number;
  email: string;
  name: string;
  role: 'superadmin' | 'admin' | 'user';
  is_verified: boolean;
  created_at: string;
}

interface AddUserRequest {
  email: string;
  name?: string;
  role: 'user' | 'admin';
}

interface AddUserResponse {
  user_id: number;
  invite_token: string;
  role: string;
}

// Superadmin Management
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
```

### Security Considerations

1. **Client Secret Handling:**
   - Display client secret only once after creation/rotation
   - Use a copy-to-clipboard button
   - Show warning that secret cannot be retrieved again
   - Consider masked display with reveal button

2. **Destructive Actions:**
   - Confirm before deleting apps
   - Confirm before removing users
   - Confirm before revoking tokens
   - Confirm before rotating secrets

3. **Role-Based UI:**
   - All admin portal features are for superadmins only
   - Show app-scoped user management only for app admins
   - Disable self-removal from apps

4. **Superadmin Deletion:**
   - Show warning when attempting to delete a superadmin
   - Disable delete button for current user (cannot delete self)
   - Show error message if trying to delete the last superadmin

---

## Error Handling

| HTTP Status | Meaning | Frontend Action |
|-------------|---------|-----------------|
| 200 | Success | Display data |
| 201 | Created | Show success, display new resource |
| 204 | Deleted | Show success, remove from list |
| 400 | Bad Request | Show validation error |
| 401 | Unauthorized | Redirect to login |
| 403 | Forbidden | Show "Access denied" message |
| 404 | Not Found | Show "Not found" message |
| 409 | Conflict | Show specific conflict message |
| 500 | Server Error | Show generic error, allow retry |

---

## Testing Checklist

### App Management
- [ ] List apps - verify ALL apps displayed (not just owned)
- [ ] Create app - verify client_id and client_secret returned
- [ ] Update app - verify changes saved
- [ ] Delete app - verify removal
- [ ] Rotate secret - verify new secret returned

### App User Management
- [ ] List app users with pagination
- [ ] Search users by email/name
- [ ] Add existing user to app
- [ ] Add new user (creates account + assigns role)
- [ ] Update user role
- [ ] Remove user from app
- [ ] Resend verification email
- [ ] Force password reset

### Global User Management (Superadmin)
- [ ] List all users with pagination
- [ ] View user details
- [ ] Revoke user tokens
- [ ] Unlock locked user

### Activity Logs
- [ ] View admin activity log
- [ ] View app-specific logs

### Superadmin Management
- [ ] List superadmins - verify all superadmins displayed
- [ ] Create superadmin - verify account created and auto-verified
- [ ] Update superadmin - verify name/email/password update
- [ ] Delete superadmin - verify removal
- [ ] Delete self - verify 403 error "cannot delete your own account"
- [ ] Delete last superadmin - verify 403 error "cannot delete the last superadmin"

---

## Related Documents

- [CR-admin-dashboard-frontend.md](./CR-admin-dashboard-frontend.md) - Dashboard endpoints
- API implementation files:
  - `internal/handler/admin_handler.go`
  - `internal/handler/app_users_handler.go`
  - `internal/dto/app_dto.go`
  - `internal/dto/superadmin_dto.go`
