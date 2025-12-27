# Change Request: App User Management Frontend Integration

**CR ID:** CR-2024-APP-USERS-001
**Date:** 2025-12-27
**Author:** Backend Team
**Status:** Ready for Implementation

---

## Summary

This document describes the API endpoints for managing users within OAuth applications. App admins can invite users, manage roles, and perform user administration tasks within their specific apps.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    OAuth2 Server                            │
├─────────────────────────────────────────────────────────────┤
│  Superadmin (Port 8081)                                     │
│  └── Manages: ALL apps, ALL users, other superadmins        │
├─────────────────────────────────────────────────────────────┤
│  App Admin (Port 8080)                                      │
│  └── Manages: Users within their specific app(s)            │
├─────────────────────────────────────────────────────────────┤
│  App User (Port 8080)                                       │
│  └── Can: Login, use app, manage own profile                │
└─────────────────────────────────────────────────────────────┘
```

**Key Concepts:**
- **App Admin**: A user with `admin` role within a specific app
- **App User**: A user with `user` role within a specific app
- A user can have different roles in different apps
- App admins can only manage users within their own app(s)

---

## Prerequisites

- User must be authenticated via `/api/auth/login` with `app_client_id`
- Must have `admin` role in the target app for management endpoints
- All requests must include JWT token: `Authorization: Bearer <token>`
- Base URL: `http://localhost:8080` (OAuth port)

---

## Part 1: User Listing and Search

### 1.1 List App Users

**Endpoint:** `GET /api/apps/{app_id}/users`

**Required Role:** App Admin or Superadmin

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
      "email": "john.doe@example.com",
      "name": "John Doe",
      "role": "user",
      "is_verified": true,
      "invite_sent": true,
      "last_login": "2025-12-27T14:00:00Z",
      "created_at": "2025-12-01T10:00:00Z"
    },
    {
      "id": 8,
      "email": "jane.smith@example.com",
      "name": "Jane Smith",
      "role": "admin",
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

**Field Descriptions:**
| Field | Type | Description |
|-------|------|-------------|
| `id` | uint | User ID |
| `email` | string | User's email address |
| `name` | string | Display name |
| `role` | string | Role in this app: `user` or `admin` |
| `is_verified` | bool | Email verified status |
| `invite_sent` | bool | Whether invitation was sent |
| `last_login` | string? | Last login timestamp (null if never logged in) |
| `created_at` | string | When user was added to this app |

---

### 1.2 Get User Details

**Endpoint:** `GET /api/apps/{app_id}/users/{user_id}`

**Required Role:** App Admin or Superadmin

**Response:**
```json
{
  "id": 5,
  "email": "john.doe@example.com",
  "name": "John Doe",
  "role": "user",
  "is_verified": true,
  "invite_sent": true,
  "last_login": "2025-12-27T14:00:00Z",
  "created_at": "2025-12-01T10:00:00Z"
}
```

**Error Responses:**
| Status | Condition |
|--------|-----------|
| 400 | Invalid app_id or user_id |
| 404 | User not found or not in this app |

---

## Part 2: User Invitation and Creation

### 2.1 Add User to App

**Endpoint:** `POST /api/apps/{app_id}/users`

**Required Role:** App Admin or Superadmin

**Description:** Adds a user to the app. If the user doesn't exist, creates a new account with a temporary password and sends an invitation.

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

**Response Fields:**
| Field | Description |
|-------|-------------|
| `user_id` | ID of the created/existing user |
| `invite_token` | JWT token for account setup (send via email) |
| `role` | Assigned role |

**Behavior Matrix:**
| User Exists? | Email Verified? | Action |
|--------------|-----------------|--------|
| No | N/A | Create user with temp password, assign role, generate invite |
| Yes | No | Assign role, generate new invite token |
| Yes | Yes | Assign role, generate invite (for password setup) |

**Error Responses:**
| Status | Condition |
|--------|-----------|
| 400 | Missing email or role |
| 400 | Invalid role (must be `user` or `admin`) |
| 409 | User already has a role in this app |

---

### 2.2 Invite Token Usage

The `invite_token` returned should be used to:
1. Send an invitation email to the user
2. Include a link to the app's setup page: `https://yourapp.com/setup?token={invite_token}`

**Token Claims:**
```json
{
  "sub": "user@example.com",
  "type": "invite",
  "app_id": 1,
  "role": "user",
  "invited_by": 3,
  "exp": 1735344000
}
```

**Frontend Flow:**
```
1. Admin clicks "Add User"
2. Frontend calls POST /api/apps/{app_id}/users
3. Backend returns invite_token
4. Frontend/Backend sends email with setup link
5. New user clicks link, sets password
6. User can now login to the app
```

---

## Part 3: Role Management

### 3.1 Update User Role

**Endpoint:** `PUT /api/apps/{app_id}/users/{user_id}`

**Required Role:** App Admin or Superadmin

**Description:** Changes a user's role within the app.

**Request Body:**
```json
{
  "role": "admin"
}
```

**Valid Roles:**
| Role | Description |
|------|-------------|
| `user` | Regular app user |
| `admin` | App administrator (can manage other users) |

**Response:**
```json
{
  "role": "admin"
}
```

**Error Responses:**
| Status | Condition |
|--------|-----------|
| 400 | Missing or invalid role |
| 400 | User not found in this app |

**Notes:**
- Promoting a user to `admin` gives them user management capabilities
- Demoting an `admin` to `user` removes their management capabilities
- Cannot change your own role (use a different admin account)

---

### 3.2 Remove User from App

**Endpoint:** `DELETE /api/apps/{app_id}/users/{user_id}`

**Required Role:** App Admin or Superadmin

**Response:** `204 No Content`

**Constraints:**
- Cannot remove yourself from the app

**Error Responses:**
| Status | Condition |
|--------|-----------|
| 400 | Cannot remove yourself |
| 400 | User not found in this app |

**Notes:**
- This removes the user's role in this specific app
- The user account still exists and may have roles in other apps
- User loses all access to this app immediately

---

## Part 4: Account Recovery Actions

### 4.1 Resend Verification Email

**Endpoint:** `POST /api/apps/{app_id}/users/{user_id}/resend-verification`

**Required Role:** App Admin or Superadmin

**Description:** Generates a new email verification token and triggers verification email.

**Response:**
```json
{
  "message": "Verification email sent"
}
```

**Use Cases:**
- User didn't receive original verification email
- Verification link expired
- User changed email address

---

### 4.2 Force Password Reset

**Endpoint:** `POST /api/apps/{app_id}/users/{user_id}/reset-password`

**Required Role:** App Admin or Superadmin

**Description:** Generates a password reset token and triggers reset email.

**Response:**
```json
{
  "message": "Password reset email sent"
}
```

**Use Cases:**
- User forgot password and can't access email reset
- Admin-initiated security reset
- Onboarding assistance

---

## Part 5: App Activity Logs

### 5.1 View App Logs

**Endpoint:** `GET /api/apps/{app_id}/logs`

**Required Role:** App Admin or Superadmin

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
      "app_id": 1,
      "user_id": 5,
      "event_type": "login_success",
      "event_category": "auth",
      "metadata": {
        "ip": "192.168.1.100",
        "method": "password"
      },
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
      "success": true,
      "created_at": "2025-12-27T14:00:00Z"
    }
  ],
  "total_count": 1250,
  "page": 1,
  "page_size": 20
}
```

**Event Types:**
| Event Type | Category | Description |
|------------|----------|-------------|
| `login_success` | auth | Successful login |
| `login_failed` | auth | Failed login attempt |
| `logout` | auth | User logged out |
| `signup` | auth | New user signup |
| `password_changed` | security | Password was changed |
| `email_verified` | security | Email was verified |
| `token_refresh` | auth | Token was refreshed |
| `secret_rotated` | admin | Client secret rotated |

---

## Frontend Implementation Guide

### Recommended User Management UI

```
┌─────────────────────────────────────────────────────────────┐
│  App Users                                    [+ Add User]  │
├─────────────────────────────────────────────────────────────┤
│  Search: [_____________________] [Search]                   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │ ☑ john.doe@example.com                              │   │
│  │   John Doe | Role: user | Verified ✓ | Last: 2h ago │   │
│  │   [Change Role ▼] [Reset Password] [Remove]         │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ ☑ jane.smith@example.com                            │   │
│  │   Jane Smith | Role: admin | Verified ✓ | Last: 30m │   │
│  │   [Change Role ▼] [Reset Password] [Remove]         │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ ○ pending@example.com                               │   │
│  │   Pending User | Role: user | Pending ⏳ | Never    │   │
│  │   [Resend Invite] [Change Role ▼] [Remove]          │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  Page 1 of 5  [< Prev] [Next >]                             │
└─────────────────────────────────────────────────────────────┘
```

### Add User Modal

```
┌─────────────────────────────────────────────────────────────┐
│  Add User to App                                      [X]   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Email *                                                    │
│  [_________________________________]                        │
│                                                             │
│  Name                                                       │
│  [_________________________________]                        │
│                                                             │
│  Role *                                                     │
│  ( ) User - Can use the application                         │
│  ( ) Admin - Can manage users in this app                   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ ℹ️ If the user doesn't exist, they will receive an  │   │
│  │    invitation email to set up their account.        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│                              [Cancel]  [Add User]           │
└─────────────────────────────────────────────────────────────┘
```

### TypeScript Interfaces

```typescript
// App User Types
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

interface AppUserListResponse {
  users: AppUser[];
  total_count: number;
  page: number;
  page_size: number;
}

// Request Types
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

interface UpdateRoleRequest {
  role: 'user' | 'admin';
}

interface UpdateRoleResponse {
  role: string;
}

// Activity Log Types
interface AppActivityLog {
  id: number;
  app_id: number;
  user_id?: number;
  event_type: string;
  event_category: string;
  metadata: Record<string, any>;
  ip_address?: string;
  user_agent?: string;
  success: boolean;
  created_at: string;
}

interface AppActivityLogListResponse {
  logs: AppActivityLog[];
  total_count: number;
  page: number;
  page_size: number;
}
```

### API Service Example

```typescript
class AppUserService {
  private baseUrl: string;
  private token: string;

  constructor(baseUrl: string, token: string) {
    this.baseUrl = baseUrl;
    this.token = token;
  }

  private headers(): HeadersInit {
    return {
      'Authorization': `Bearer ${this.token}`,
      'Content-Type': 'application/json'
    };
  }

  // List users with search and pagination
  async listUsers(
    appId: number,
    page = 1,
    pageSize = 20,
    search?: string
  ): Promise<AppUserListResponse> {
    const params = new URLSearchParams({
      page: page.toString(),
      page_size: pageSize.toString()
    });
    if (search) params.append('search', search);

    const response = await fetch(
      `${this.baseUrl}/api/apps/${appId}/users?${params}`,
      { headers: this.headers() }
    );
    return response.json();
  }

  // Add user to app
  async addUser(appId: number, request: AddUserRequest): Promise<AddUserResponse> {
    const response = await fetch(
      `${this.baseUrl}/api/apps/${appId}/users`,
      {
        method: 'POST',
        headers: this.headers(),
        body: JSON.stringify(request)
      }
    );
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to add user');
    }
    return response.json();
  }

  // Update user role
  async updateRole(
    appId: number,
    userId: number,
    role: 'user' | 'admin'
  ): Promise<UpdateRoleResponse> {
    const response = await fetch(
      `${this.baseUrl}/api/apps/${appId}/users/${userId}`,
      {
        method: 'PUT',
        headers: this.headers(),
        body: JSON.stringify({ role })
      }
    );
    return response.json();
  }

  // Remove user from app
  async removeUser(appId: number, userId: number): Promise<void> {
    await fetch(
      `${this.baseUrl}/api/apps/${appId}/users/${userId}`,
      {
        method: 'DELETE',
        headers: this.headers()
      }
    );
  }

  // Resend verification email
  async resendVerification(appId: number, userId: number): Promise<void> {
    await fetch(
      `${this.baseUrl}/api/apps/${appId}/users/${userId}/resend-verification`,
      {
        method: 'POST',
        headers: this.headers()
      }
    );
  }

  // Force password reset
  async forcePasswordReset(appId: number, userId: number): Promise<void> {
    await fetch(
      `${this.baseUrl}/api/apps/${appId}/users/${userId}/reset-password`,
      {
        method: 'POST',
        headers: this.headers()
      }
    );
  }
}
```

---

## User Status Indicators

Display appropriate status indicators based on user state:

| Condition | Status | Icon | Color |
|-----------|--------|------|-------|
| `is_verified = true` | Verified | ✓ | Green |
| `is_verified = false` | Pending | ⏳ | Yellow |
| `last_login = null` | Never logged in | - | Gray |
| `last_login < 30 days` | Active | ● | Green |
| `last_login > 30 days` | Inactive | ○ | Gray |

---

## Error Handling

| HTTP Status | Meaning | Frontend Action |
|-------------|---------|-----------------|
| 200 | Success | Display data |
| 201 | User added | Show success, refresh list |
| 204 | User removed | Show success, remove from list |
| 400 | Bad request | Show validation error |
| 401 | Unauthorized | Redirect to login |
| 403 | Forbidden | Show "No permission" message |
| 404 | Not found | Show "User not found" message |
| 409 | Conflict | Show "User already in app" message |
| 500 | Server error | Show generic error, allow retry |

---

## Security Considerations

1. **Role Verification:**
   - Always verify user has `admin` role before showing management UI
   - Hide "Add User" and action buttons for non-admins
   - Backend enforces role checks even if frontend doesn't

2. **Self-Protection:**
   - Disable "Remove" button for current user
   - Consider disabling "Change Role" for self (prevent accidental demotion)

3. **Confirmation Dialogs:**
   - Require confirmation before removing users
   - Require confirmation before demoting admins
   - Show user email in confirmation to prevent mistakes

4. **Invitation Security:**
   - Invite tokens expire (default: 7 days)
   - Each invite token is single-use
   - Show "Resend Invite" for pending users

---

## Testing Checklist

### User Listing
- [ ] List users with pagination
- [ ] Search by email
- [ ] Search by name
- [ ] Empty state when no users

### User Addition
- [ ] Add new user (creates account)
- [ ] Add existing user (assigns role)
- [ ] Add with `user` role
- [ ] Add with `admin` role
- [ ] Error: user already in app (409)
- [ ] Error: invalid email format

### Role Management
- [ ] Promote user to admin
- [ ] Demote admin to user
- [ ] Error: cannot change own role

### User Removal
- [ ] Remove user successfully
- [ ] Error: cannot remove self

### Account Recovery
- [ ] Resend verification email
- [ ] Force password reset
- [ ] Confirm email sent message

### Activity Logs
- [ ] View activity log with pagination
- [ ] Filter by event type (if implemented)
- [ ] Verify log entries are recorded

---

## Related Documents

- [CR-admin-dashboard-frontend.md](./CR-admin-dashboard-frontend.md) - Dashboard endpoints
- [CR-admin-app-management-frontend.md](./CR-admin-app-management-frontend.md) - App and superadmin management
- API implementation files:
  - `internal/handler/app_users_handler.go`
  - `internal/handler/app_logs_handler.go`
  - `internal/dto/app_dto.go`
