# Change Request: Admin Dashboard Frontend Integration

**CR ID:** CR-2024-DASHBOARD-001
**Date:** 2025-12-27
**Author:** Backend Team
**Status:** Ready for Implementation

---

## Summary

New admin dashboard API endpoints have been added to the OAuth2 server (port 8081). The frontend admin portal should integrate with these endpoints to display dashboard statistics, activity logs, system health, login trends, and per-app usage metrics.

---

## Prerequisites

- User must be authenticated as a **superadmin** via `/api/admin/login`
- All requests must include the JWT token in the `Authorization: Bearer <token>` header
- Base URL: `http://localhost:8081` (or configured admin port)

---

## API Endpoints

### 1. Dashboard Statistics

**Endpoint:** `GET /api/admin/dashboard/stats`

**Description:** Returns overview statistics for the admin dashboard.

**Response:**
```json
{
  "total_users": 150,
  "active_users": 45,
  "total_apps": 5,
  "active_apps": 4,
  "today_logins": 23,
  "today_signups": 2,
  "failed_logins_24h": 7,
  "locked_accounts": 1
}
```

**Field Descriptions:**
| Field | Type | Description |
|-------|------|-------------|
| `total_users` | int64 | Total registered users (excluding soft-deleted) |
| `active_users` | int64 | Users who logged in within the last 30 days |
| `total_apps` | int64 | Total OAuth apps/clients registered |
| `active_apps` | int64 | Apps with `active=true` |
| `today_logins` | int64 | Successful logins since midnight (server time) |
| `today_signups` | int64 | New user registrations since midnight |
| `failed_logins_24h` | int64 | Failed login attempts in the last 24 hours |
| `locked_accounts` | int64 | Currently locked user accounts |

---

### 2. Recent Activity

**Endpoint:** `GET /api/admin/dashboard/activity`

**Query Parameters:**
| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `limit` | int | 10 | 100 | Number of activity items to return |

**Example:** `GET /api/admin/dashboard/activity?limit=20`

**Response:**
```json
{
  "activities": [
    {
      "id": 42,
      "type": "login_success",
      "description": "User logged in successfully",
      "user_id": 15,
      "user_email": "john@example.com",
      "app_id": 3,
      "app_name": "My Web App",
      "ip_address": "192.168.1.100",
      "success": true,
      "metadata": {},
      "created_at": "2025-12-27T14:30:00Z"
    }
  ],
  "total": 1542
}
```

**Activity Types:**
| Type | Description |
|------|-------------|
| `login_success` | User logged in successfully |
| `login_failed` | Login attempt failed |
| `logout` | User logged out |
| `account_locked` | Account was locked due to failed attempts |
| `password_reset` | Password was reset |
| `email_verified` | Email was verified |
| `token_revoked` | Tokens were revoked |
| `signup` | New user signed up |

---

### 3. System Health

**Endpoint:** `GET /api/admin/dashboard/health`

**Description:** Returns system health information including database status and uptime.

**Response:**
```json
{
  "status": "healthy",
  "database": {
    "status": "healthy",
    "latency": "2.5ms"
  },
  "uptime": "5d 12h 30m",
  "version": "1.0.0",
  "details": {
    "go_version": "1.21+",
    "started_at": "2025-12-22T02:00:00Z"
  }
}
```

**Status Values:**
- `healthy` - All systems operational
- `unhealthy` - One or more components have issues

**Database Status:**
```json
{
  "status": "unhealthy",
  "error": "connection refused"
}
```

---

### 4. Login Trends

**Endpoint:** `GET /api/admin/dashboard/login-trends`

**Query Parameters:**
| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `days` | int | 7 | 90 | Number of days to include in trends |

**Example:** `GET /api/admin/dashboard/login-trends?days=30`

**Response:**
```json
{
  "trends": [
    {
      "date": "2025-12-20",
      "success_count": 145,
      "failure_count": 12,
      "unique_users": 89
    },
    {
      "date": "2025-12-21",
      "success_count": 132,
      "failure_count": 8,
      "unique_users": 76
    }
  ],
  "period": "7 days"
}
```

**Suggested Visualization:** Line chart with:
- X-axis: Date
- Y-axis: Count
- Lines: Success (green), Failures (red), Unique Users (blue)

---

### 5. App Usage Statistics

**Endpoint:** `GET /api/admin/dashboard/app-usage`

**Description:** Returns usage statistics for each registered OAuth app.

**Response:**
```json
{
  "apps": [
    {
      "app_id": 1,
      "app_name": "Main Web Application",
      "client_id": "webapp-client-123",
      "total_users": 120,
      "active_users": 45,
      "total_logins": 3420,
      "last_activity": "2025-12-27T14:25:00Z"
    },
    {
      "app_id": 2,
      "app_name": "Mobile App",
      "client_id": "mobile-app-456",
      "total_users": 80,
      "active_users": 32,
      "total_logins": 1890,
      "last_activity": "2025-12-27T13:45:00Z"
    }
  ],
  "total": 2
}
```

**Field Descriptions:**
| Field | Type | Description |
|-------|------|-------------|
| `app_id` | uint | Internal app ID |
| `app_name` | string | Display name of the app |
| `client_id` | string | OAuth client ID |
| `total_users` | int64 | Users with roles in this app |
| `active_users` | int64 | Users who logged in within 30 days |
| `total_logins` | int64 | All-time successful logins |
| `last_activity` | string (nullable) | ISO 8601 timestamp of last activity |

---

## Frontend Implementation Guide

### Recommended Dashboard Layout

```
+--------------------------------------------------+
|  DASHBOARD HEADER                                |
+--------------------------------------------------+
|                                                  |
|  +----------+  +----------+  +----------+        |
|  | Total    |  | Active   |  | Today's  |        |
|  | Users    |  | Users    |  | Logins   |        |
|  |   150    |  |    45    |  |    23    |        |
|  +----------+  +----------+  +----------+        |
|                                                  |
|  +----------+  +----------+  +----------+        |
|  | Total    |  | Failed   |  | Locked   |        |
|  | Apps     |  | (24h)    |  | Accounts |        |
|  |    5     |  |     7    |  |     1    |        |
|  +----------+  +----------+  +----------+        |
|                                                  |
|  +---------------------------+  +-------------+  |
|  | LOGIN TRENDS CHART        |  | SYSTEM      |  |
|  | (Line chart - 7 days)     |  | HEALTH      |  |
|  |                           |  | Status: OK  |  |
|  +---------------------------+  +-------------+  |
|                                                  |
|  +---------------------------+  +-------------+  |
|  | RECENT ACTIVITY           |  | APP USAGE   |  |
|  | - login_success (john@..) |  | - Web App   |  |
|  | - login_failed (jane@..)  |  | - Mobile    |  |
|  +---------------------------+  +-------------+  |
|                                                  |
+--------------------------------------------------+
```

### API Call Pattern

```typescript
// Example: Fetch all dashboard data on load
async function loadDashboard() {
  const token = getAuthToken();
  const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  };

  const [stats, activity, health, trends, appUsage] = await Promise.all([
    fetch('/api/admin/dashboard/stats', { headers }).then(r => r.json()),
    fetch('/api/admin/dashboard/activity?limit=10', { headers }).then(r => r.json()),
    fetch('/api/admin/dashboard/health', { headers }).then(r => r.json()),
    fetch('/api/admin/dashboard/login-trends?days=7', { headers }).then(r => r.json()),
    fetch('/api/admin/dashboard/app-usage', { headers }).then(r => r.json())
  ]);

  return { stats, activity, health, trends, appUsage };
}
```

### Refresh Strategy

| Component | Recommended Refresh Interval |
|-----------|------------------------------|
| Stats | 30 seconds |
| Activity | 10 seconds |
| Health | 60 seconds |
| Trends | 5 minutes |
| App Usage | 2 minutes |

### Error Handling

| HTTP Status | Meaning | Action |
|-------------|---------|--------|
| 200 | Success | Display data |
| 401 | Unauthorized | Redirect to login |
| 403 | Forbidden | Show "Admin access required" |
| 500 | Server Error | Show error message, retry |

---

## Testing

### Test Credentials

Use the superadmin account:
- **Email:** `admin@example.com`
- **Password:** (as configured)
- **Login endpoint:** `POST /api/admin/login`

### Manual Testing Checklist

- [ ] Login as superadmin and verify token received
- [ ] Fetch `/api/admin/dashboard/stats` - verify all counters
- [ ] Fetch `/api/admin/dashboard/activity` - verify activity list
- [ ] Fetch `/api/admin/dashboard/health` - verify status is "healthy"
- [ ] Fetch `/api/admin/dashboard/login-trends` - verify date range
- [ ] Fetch `/api/admin/dashboard/app-usage` - verify app list
- [ ] Test with expired token - should return 401
- [ ] Test with non-admin user - should return 403

---

## Related Endpoints

These endpoints were previously implemented and should be used alongside the dashboard:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/login` | POST | Superadmin login |
| `/api/admin/profile` | GET | Current admin profile |
| `/api/admin/apps` | GET | List OAuth apps |
| `/api/admin/users` | GET | List all users |

---

## Questions / Contact

For any questions about these endpoints, please contact the backend team or refer to the API implementation in:
- `internal/handler/dashboard_handler.go`
- `internal/dto/dashboard_dto.go`
