# CR: OAuth2 Security Monitoring Application

## Overview

A real-time security monitoring dashboard for the OAuth2/OIDC server. This application provides comprehensive visibility into authentication events, security threats, token usage, and system health. It complements the Security Testing SPA by providing ongoing operational monitoring rather than one-time testing.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Monitoring SPA                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │Dashboard │ │ Alerts   │ │ Sessions │ │ Reports  │           │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘           │
│       │            │            │            │                  │
│       └────────────┴────────────┴────────────┘                  │
│                          │                                       │
│                    ┌─────┴─────┐                                │
│                    │  API Layer │                                │
│                    └─────┬─────┘                                │
└──────────────────────────┼──────────────────────────────────────┘
                           │
            ┌──────────────┼──────────────┐
            │              │              │
     ┌──────┴──────┐ ┌─────┴─────┐ ┌─────┴─────┐
     │ REST APIs   │ │ WebSocket │ │   SSE     │
     │ (Port 8081) │ │ (Events)  │ │ (Events)  │
     └─────────────┘ └───────────┘ └───────────┘
```

## Target Ports

- **Admin API**: Port 8081 (internal, authenticated)
- **OAuth API**: Port 8080 (referenced for context)

---

## Existing APIs (Already Implemented)

### Dashboard Statistics
**`GET /api/admin/dashboard/stats`**

Returns aggregate security statistics.

```json
{
  "total_users": 150,
  "active_users": 85,
  "total_apps": 12,
  "active_apps": 10,
  "today_logins": 234,
  "today_signups": 5,
  "failed_logins_24h": 18,
  "locked_accounts": 2
}
```

### Activity Feed
**`GET /api/admin/dashboard/activity?limit=20`**

Returns recent security events.

```json
{
  "activities": [
    {
      "id": 1234,
      "type": "login_failed",
      "description": "Login attempt failed",
      "user_id": 45,
      "user_email": "user@example.com",
      "app_id": 3,
      "app_name": "Portal",
      "ip_address": "192.168.1.100",
      "success": false,
      "metadata": {"reason": "invalid_password"},
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 5000
}
```

### Login Trends
**`GET /api/admin/dashboard/login-trends?days=30`**

Returns login success/failure trends over time.

```json
{
  "trends": [
    {
      "date": "2024-01-15",
      "success_count": 234,
      "failure_count": 18,
      "unique_users": 89
    }
  ],
  "period": "30 days"
}
```

### App Usage
**`GET /api/admin/dashboard/app-usage`**

Returns usage statistics per application.

```json
{
  "apps": [
    {
      "app_id": 1,
      "app_name": "Portal",
      "client_id": "portal-client",
      "total_users": 100,
      "active_users": 45,
      "total_logins": 5000,
      "last_activity": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 12
}
```

### System Health
**`GET /api/admin/dashboard/health`**

Returns system health status.

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
    "started_at": "2024-01-10T00:00:00Z"
  }
}
```

### App Activity Logs
**`GET /api/apps/:app_id/logs?page=1&page_size=20`**

Returns activity logs for a specific application.

---

## New APIs Required

### 1. Security Events Stream (Real-time)

#### WebSocket Endpoint
**`WS /api/admin/events/ws`**

Real-time security event stream via WebSocket.

```json
// Connection message
{"type": "subscribe", "filters": {"severity": ["warning", "error", "critical"]}}

// Event message
{
  "type": "event",
  "data": {
    "id": 5678,
    "event_type": "brute_force_detected",
    "severity": "critical",
    "user_id": 45,
    "ip_address": "203.0.113.50",
    "details": {"failed_attempts": 15},
    "created_at": "2024-01-15T10:30:00Z"
  }
}
```

#### Server-Sent Events (SSE) Endpoint
**`GET /api/admin/events/stream`**

Alternative real-time stream for clients that prefer SSE.

```
event: security_event
data: {"id": 5678, "event_type": "brute_force_detected", ...}

event: heartbeat
data: {"timestamp": "2024-01-15T10:30:00Z"}
```

---

### 2. Advanced Security Queries

#### Security Events Query
**`GET /api/admin/security/events`**

Query parameters:
- `event_type` - Filter by event type (comma-separated)
- `severity` - Filter by severity (info, warning, error, critical)
- `user_id` - Filter by user
- `app_id` - Filter by application
- `ip_address` - Filter by IP address
- `success` - Filter by success/failure
- `from` - Start date (ISO 8601)
- `to` - End date (ISO 8601)
- `page` - Page number
- `page_size` - Items per page (max 100)

```json
{
  "events": [
    {
      "id": 1234,
      "user_id": 45,
      "app_id": 3,
      "event_type": "login_failed",
      "severity": "warning",
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "details": {"reason": "invalid_password"},
      "success": false,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 500,
  "page": 1,
  "page_size": 20
}
```

#### Aggregated Threat Metrics
**`GET /api/admin/security/threats`**

Returns aggregated threat intelligence.

```json
{
  "time_range": "24h",
  "summary": {
    "total_events": 5000,
    "critical_events": 3,
    "error_events": 25,
    "warning_events": 150,
    "unique_attackers": 12
  },
  "top_threats": [
    {
      "type": "brute_force",
      "count": 45,
      "unique_ips": 3,
      "affected_users": 8
    },
    {
      "type": "invalid_token_usage",
      "count": 120,
      "unique_ips": 15,
      "affected_apps": 4
    }
  ],
  "suspicious_ips": [
    {
      "ip_address": "203.0.113.50",
      "event_count": 150,
      "event_types": ["login_failed", "brute_force_detected"],
      "first_seen": "2024-01-15T08:00:00Z",
      "last_seen": "2024-01-15T10:30:00Z"
    }
  ],
  "locked_accounts": [
    {
      "user_id": 45,
      "email": "user@example.com",
      "locked_at": "2024-01-15T10:00:00Z",
      "locked_until": "2024-01-15T10:30:00Z",
      "failed_attempts": 10
    }
  ]
}
```

---

### 3. Active Sessions Management

#### List Active Sessions
**`GET /api/admin/sessions`**

Query parameters:
- `user_id` - Filter by user
- `app_id` - Filter by application
- `page` - Page number
- `page_size` - Items per page

```json
{
  "sessions": [
    {
      "id": "sess_abc123",
      "user_id": 45,
      "user_email": "user@example.com",
      "app_id": 3,
      "app_name": "Portal",
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "created_at": "2024-01-15T08:00:00Z",
      "last_activity": "2024-01-15T10:30:00Z",
      "expires_at": "2024-01-15T20:00:00Z"
    }
  ],
  "total": 85,
  "page": 1,
  "page_size": 20
}
```

#### Get User Sessions
**`GET /api/admin/users/:id/sessions`**

Returns all active sessions for a specific user.

#### Revoke Session
**`DELETE /api/admin/sessions/:id`**

Revokes a specific session immediately.

```json
{
  "message": "session revoked",
  "session_id": "sess_abc123"
}
```

#### Revoke All User Sessions
**`POST /api/admin/users/:id/revoke-sessions`**

Revokes all sessions for a user (already partially implemented via revoke-tokens).

---

### 4. Token Analytics

#### Token Statistics
**`GET /api/admin/tokens/stats`**

Query parameters:
- `period` - Time period (1h, 24h, 7d, 30d)

```json
{
  "period": "24h",
  "issued": {
    "access_tokens": 1250,
    "refresh_tokens": 1250,
    "id_tokens": 1250
  },
  "refreshed": 450,
  "revoked": 25,
  "expired_usage_attempts": 12,
  "invalid_usage_attempts": 8,
  "by_app": [
    {
      "app_id": 1,
      "app_name": "Portal",
      "issued": 500,
      "refreshed": 200,
      "revoked": 10
    }
  ],
  "by_hour": [
    {
      "hour": "2024-01-15T10:00:00Z",
      "issued": 52,
      "refreshed": 18,
      "revoked": 1
    }
  ]
}
```

#### Active Tokens Count
**`GET /api/admin/tokens/active`**

```json
{
  "total_active_tokens": 850,
  "by_type": {
    "access": 850,
    "refresh": 820
  },
  "by_app": [
    {
      "app_id": 1,
      "app_name": "Portal",
      "active_tokens": 350
    }
  ]
}
```

---

### 5. Geographic Analytics

#### Login Geography
**`GET /api/admin/security/geo`**

Query parameters:
- `period` - Time period (24h, 7d, 30d)

```json
{
  "period": "24h",
  "by_country": [
    {
      "country_code": "US",
      "country_name": "United States",
      "login_count": 500,
      "unique_users": 120,
      "failed_count": 15
    }
  ],
  "by_city": [
    {
      "city": "New York",
      "country_code": "US",
      "latitude": 40.7128,
      "longitude": -74.0060,
      "login_count": 150,
      "failed_count": 5
    }
  ],
  "anomalies": [
    {
      "user_id": 45,
      "user_email": "user@example.com",
      "description": "Login from unusual location",
      "usual_country": "US",
      "login_country": "RU",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

---

### 6. Alert Configuration

#### List Alert Rules
**`GET /api/admin/alerts/rules`**

```json
{
  "rules": [
    {
      "id": 1,
      "name": "Brute Force Detection",
      "description": "Alert when 5+ failed logins from same IP in 5 minutes",
      "event_type": "login_failed",
      "condition": {
        "threshold": 5,
        "window_minutes": 5,
        "group_by": "ip_address"
      },
      "severity": "critical",
      "enabled": true,
      "actions": ["email", "webhook"],
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

#### Create Alert Rule
**`POST /api/admin/alerts/rules`**

```json
{
  "name": "Account Lockout Alert",
  "description": "Alert when any account gets locked",
  "event_type": "account_locked",
  "condition": {
    "threshold": 1,
    "window_minutes": 1
  },
  "severity": "error",
  "actions": ["email"],
  "recipients": ["security@example.com"]
}
```

#### Update Alert Rule
**`PUT /api/admin/alerts/rules/:id`**

#### Delete Alert Rule
**`DELETE /api/admin/alerts/rules/:id`**

#### List Triggered Alerts
**`GET /api/admin/alerts/history`**

Query parameters:
- `rule_id` - Filter by rule
- `severity` - Filter by severity
- `acknowledged` - Filter by acknowledgment status
- `from` / `to` - Date range
- `page` / `page_size` - Pagination

```json
{
  "alerts": [
    {
      "id": 5678,
      "rule_id": 1,
      "rule_name": "Brute Force Detection",
      "severity": "critical",
      "message": "15 failed login attempts from IP 203.0.113.50",
      "details": {
        "ip_address": "203.0.113.50",
        "affected_users": [45, 67, 89],
        "event_count": 15
      },
      "acknowledged": false,
      "acknowledged_by": null,
      "acknowledged_at": null,
      "triggered_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 25,
  "unacknowledged": 3
}
```

#### Acknowledge Alert
**`POST /api/admin/alerts/:id/acknowledge`**

```json
{
  "note": "Investigated - false positive from VPN exit node"
}
```

---

### 7. IP Reputation & Blocking

#### List Blocked IPs
**`GET /api/admin/security/blocked-ips`**

```json
{
  "blocked_ips": [
    {
      "id": 1,
      "ip_address": "203.0.113.50",
      "reason": "brute_force",
      "blocked_by": 1,
      "blocked_by_email": "admin@example.com",
      "blocked_at": "2024-01-15T10:00:00Z",
      "expires_at": "2024-01-16T10:00:00Z",
      "permanent": false
    }
  ],
  "total": 5
}
```

#### Block IP
**`POST /api/admin/security/blocked-ips`**

```json
{
  "ip_address": "203.0.113.50",
  "reason": "Repeated brute force attempts",
  "duration_hours": 24,
  "permanent": false
}
```

#### Unblock IP
**`DELETE /api/admin/security/blocked-ips/:id`**

#### Get IP Reputation
**`GET /api/admin/security/ip-reputation/:ip`**

```json
{
  "ip_address": "203.0.113.50",
  "is_blocked": false,
  "risk_score": 75,
  "events_24h": 150,
  "events_7d": 320,
  "failed_logins_24h": 45,
  "unique_users_targeted": 8,
  "first_seen": "2024-01-10T00:00:00Z",
  "last_seen": "2024-01-15T10:30:00Z",
  "recent_events": [
    {
      "event_type": "login_failed",
      "user_email": "user@example.com",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

---

### 8. Audit Reports

#### Generate Security Report
**`POST /api/admin/reports/security`**

```json
{
  "type": "security_summary",
  "period": {
    "from": "2024-01-01T00:00:00Z",
    "to": "2024-01-31T23:59:59Z"
  },
  "format": "pdf",
  "sections": ["overview", "threats", "users", "apps", "recommendations"]
}
```

Response:
```json
{
  "report_id": "rpt_abc123",
  "status": "generating",
  "estimated_completion": "2024-01-15T10:35:00Z"
}
```

#### Get Report Status
**`GET /api/admin/reports/:id`**

```json
{
  "report_id": "rpt_abc123",
  "status": "completed",
  "download_url": "/api/admin/reports/rpt_abc123/download",
  "expires_at": "2024-01-16T10:30:00Z",
  "created_at": "2024-01-15T10:30:00Z"
}
```

#### Download Report
**`GET /api/admin/reports/:id/download`**

Returns the generated report file (PDF, CSV, or JSON).

---

## Dashboard Views

### 1. Overview Dashboard

**Components:**
- Real-time event ticker (last 10 events)
- Key metrics cards (users, logins, failures, locks)
- Login success/failure chart (24h)
- Active sessions count
- System health status

**Refresh Rate:** 30 seconds (metrics), real-time (events via WebSocket)

### 2. Security Events View

**Components:**
- Filterable event table with pagination
- Severity breakdown pie chart
- Event type distribution bar chart
- Timeline visualization
- Export functionality (CSV, JSON)

**Filters:**
- Date range picker
- Event type multi-select
- Severity checkboxes
- User search
- Application filter
- IP address search
- Success/failure toggle

### 3. Threat Intelligence View

**Components:**
- Threat summary cards
- Top attacking IPs table
- Geographic threat map
- Locked accounts list
- Brute force attempts timeline
- Anomaly detection alerts

### 4. Sessions View

**Components:**
- Active sessions table
- Session distribution by app
- User session search
- Bulk revocation controls
- Session duration analytics

### 5. Token Analytics View

**Components:**
- Token issuance chart
- Refresh rate metrics
- Revocation trends
- Token lifetime distribution
- Per-app token statistics

### 6. Alerts View

**Components:**
- Unacknowledged alerts list
- Alert history with filters
- Alert rule configuration
- Alert statistics
- Notification settings

### 7. Reports View

**Components:**
- Report generator wizard
- Report history
- Scheduled reports configuration
- Report templates

### 8. Settings View

**Components:**
- Alert rule management
- IP blocklist management
- Notification preferences
- API key management
- Export settings

---

## UI Components Specification

### Event Severity Badges
```css
.severity-info     { background: #3498db; }
.severity-warning  { background: #f39c12; }
.severity-error    { background: #e74c3c; }
.severity-critical { background: #9b59b6; animation: pulse 1s infinite; }
```

### Real-time Event Card
```typescript
interface EventCardProps {
  event: SecurityEvent;
  onUserClick: (userId: number) => void;
  onIpClick: (ip: string) => void;
  onAppClick: (appId: number) => void;
}
```

### Geographic Map Component
- Interactive world map
- Heat map overlay for login density
- Clickable markers for anomalies
- Country/city drill-down

### Metric Trend Card
```typescript
interface MetricCardProps {
  title: string;
  value: number;
  previousValue: number;
  trend: 'up' | 'down' | 'stable';
  trendIsGood: boolean;
  sparklineData: number[];
}
```

---

## Data Structures

### SecurityEvent
```typescript
interface SecurityEvent {
  id: number;
  userId?: number;
  userEmail?: string;
  appId?: number;
  appName?: string;
  eventType: SecurityEventType;
  severity: 'info' | 'warning' | 'error' | 'critical';
  ipAddress: string;
  userAgent: string;
  details: Record<string, any>;
  success: boolean;
  createdAt: string;
}

type SecurityEventType =
  | 'login_success' | 'login_failed' | 'logout'
  | 'account_locked' | 'account_unlocked'
  | 'password_changed' | 'password_reset_requested' | 'password_reset_used'
  | 'email_verified' | 'email_changed'
  | 'token_issued' | 'token_refreshed' | 'token_revoked'
  | 'invalid_token_used' | 'expired_token_used' | 'revoked_token_used'
  | 'auth_code_issued' | 'auth_code_exchanged' | 'auth_code_failed'
  | 'pkce_validation_failed'
  | 'suspicious_activity' | 'rate_limit_exceeded' | 'brute_force_detected';
```

### AlertRule
```typescript
interface AlertRule {
  id: number;
  name: string;
  description: string;
  eventType: string;
  condition: {
    threshold: number;
    windowMinutes: number;
    groupBy?: 'ip_address' | 'user_id' | 'app_id';
  };
  severity: 'warning' | 'error' | 'critical';
  enabled: boolean;
  actions: ('email' | 'webhook' | 'slack')[];
  recipients?: string[];
  webhookUrl?: string;
  createdAt: string;
  updatedAt: string;
}
```

### Session
```typescript
interface Session {
  id: string;
  userId: number;
  userEmail: string;
  appId: number;
  appName: string;
  ipAddress: string;
  userAgent: string;
  createdAt: string;
  lastActivity: string;
  expiresAt: string;
}
```

---

## Implementation Priority

### Phase 1: Core Monitoring (MVP)
1. Real-time event stream (WebSocket/SSE)
2. Enhanced security events query API
3. Active sessions management
4. IP reputation API

### Phase 2: Analytics & Alerts
5. Token analytics endpoints
6. Alert rule configuration
7. Alert history and acknowledgment
8. Geographic analytics

### Phase 3: Advanced Features
9. Report generation
10. IP blocking management
11. Scheduled reports
12. Webhook integrations

---

## Database Changes Required

### New Tables

#### alert_rules
```sql
CREATE TABLE alert_rules (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  event_type VARCHAR(50) NOT NULL,
  condition JSONB NOT NULL,
  severity VARCHAR(20) NOT NULL,
  enabled BOOLEAN DEFAULT true,
  actions JSONB NOT NULL,
  recipients JSONB,
  webhook_url VARCHAR(500),
  created_by INTEGER REFERENCES users(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### triggered_alerts
```sql
CREATE TABLE triggered_alerts (
  id SERIAL PRIMARY KEY,
  rule_id INTEGER REFERENCES alert_rules(id),
  severity VARCHAR(20) NOT NULL,
  message TEXT NOT NULL,
  details JSONB,
  acknowledged BOOLEAN DEFAULT false,
  acknowledged_by INTEGER REFERENCES users(id),
  acknowledged_at TIMESTAMP,
  acknowledge_note TEXT,
  triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### blocked_ips
```sql
CREATE TABLE blocked_ips (
  id SERIAL PRIMARY KEY,
  ip_address VARCHAR(45) NOT NULL UNIQUE,
  reason TEXT,
  blocked_by INTEGER REFERENCES users(id),
  blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP,
  permanent BOOLEAN DEFAULT false
);
CREATE INDEX idx_blocked_ips_address ON blocked_ips(ip_address);
CREATE INDEX idx_blocked_ips_expires ON blocked_ips(expires_at);
```

#### generated_reports
```sql
CREATE TABLE generated_reports (
  id VARCHAR(50) PRIMARY KEY,
  type VARCHAR(50) NOT NULL,
  status VARCHAR(20) NOT NULL,
  parameters JSONB,
  file_path VARCHAR(500),
  created_by INTEGER REFERENCES users(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  completed_at TIMESTAMP,
  expires_at TIMESTAMP
);
```

### Indexes for Performance

```sql
-- Optimize security_audit_logs queries
CREATE INDEX idx_security_logs_composite
  ON security_audit_logs(event_type, severity, created_at DESC);

CREATE INDEX idx_security_logs_ip_time
  ON security_audit_logs(ip_address, created_at DESC);

CREATE INDEX idx_security_logs_user_time
  ON security_audit_logs(user_id, created_at DESC)
  WHERE user_id IS NOT NULL;
```

---

## Security Considerations

1. **Authentication**: All endpoints require valid admin JWT
2. **Authorization**: Role-based access (superadmin for all, app-admin for their apps)
3. **Rate Limiting**: Apply rate limits to prevent abuse
4. **Audit Logging**: Log all admin actions for compliance
5. **Data Retention**: Implement configurable retention policies
6. **Encryption**: Ensure all data in transit is encrypted (TLS)
7. **IP Filtering**: Optionally restrict admin access by IP

---

## Integration Points

### Email Notifications
- Alert notifications via configured SMTP
- Daily/weekly digest options
- Template-based alert emails

### Webhooks
- Configurable webhook endpoints for alerts
- Retry logic for failed deliveries
- Signature verification for security

### External SIEM Integration
- Syslog forwarding option
- Structured JSON log export
- CEF format support

---

## Success Metrics

1. **Real-time Visibility**: Events displayed within 2 seconds of occurrence
2. **Query Performance**: 95th percentile response time < 500ms
3. **Alert Latency**: Alerts triggered within 30 seconds of threshold breach
4. **Dashboard Load Time**: Initial load < 3 seconds
5. **Data Retention**: 90-day default retention for security events

---

## Attack Detection & Countermeasures

This section details the security attacks the monitoring app can detect and the recommended countermeasures.

### Attack Categories Overview

| Category | Attacks Covered | Detection APIs | Countermeasures |
|----------|-----------------|----------------|-----------------|
| Authentication | 5 attacks | `/security/events`, `/security/threats` | IP blocking, account lockout, alerts |
| OAuth2 Protocol | 7 attacks | `/security/events`, `/tokens/stats` | Token revocation, client blocking |
| Session | 3 attacks | `/sessions`, `/security/events` | Session revocation, force re-auth |
| Token | 4 attacks | `/tokens/stats`, `/security/events` | Token blacklisting, key rotation |
| Infrastructure | 4 attacks | `/security/threats`, `/ip-reputation` | Rate limiting, IP blocking |
| Account | 3 attacks | `/security/events`, `/alerts` | Account lockout, 2FA enforcement |

---

### 1. Authentication Attacks

#### ATK-AUTH-01: Brute Force Attack

**Description:** Attacker attempts multiple password combinations against a single account.

**Detection Signals:**
- Event: `login_failed` - Multiple failures for same `user_id`
- Pattern: 5+ failures within 5 minutes from any IP
- API: `GET /api/admin/security/events?event_type=login_failed&user_id=X`

**Detection Query:**
```sql
SELECT user_id, COUNT(*) as attempts, array_agg(DISTINCT ip_address) as ips
FROM security_audit_logs
WHERE event_type = 'login_failed'
  AND created_at > NOW() - INTERVAL '5 minutes'
GROUP BY user_id
HAVING COUNT(*) >= 5;
```

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Account Lockout | 5 failures | Automatic (server-side) |
| Alert Security Team | 10 failures | `POST /api/admin/alerts/rules` |
| Block Source IP | 15 failures | `POST /api/admin/security/blocked-ips` |
| Force Password Reset | After unlock | `POST /api/admin/users/:id/reset-password` |

**Recommended Alert Rule:**
```json
{
  "name": "Brute Force - Single Account",
  "event_type": "login_failed",
  "condition": {"threshold": 5, "window_minutes": 5, "group_by": "user_id"},
  "severity": "critical",
  "actions": ["email", "webhook"]
}
```

---

#### ATK-AUTH-02: Credential Stuffing

**Description:** Attacker uses stolen credential lists from data breaches to attempt logins across multiple accounts.

**Detection Signals:**
- Event: `login_failed` - Failures across multiple accounts from same IP
- Pattern: 10+ different users targeted from single IP
- Characteristic: Often uses automation (consistent user-agent, timing)

**Detection Query:**
```sql
SELECT ip_address, COUNT(DISTINCT user_id) as users_targeted, COUNT(*) as attempts
FROM security_audit_logs
WHERE event_type = 'login_failed'
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY ip_address
HAVING COUNT(DISTINCT user_id) >= 10;
```

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Block IP (24h) | 10+ users targeted | `POST /api/admin/security/blocked-ips` |
| Block IP (permanent) | 50+ users targeted | `POST /api/admin/security/blocked-ips` |
| Enable CAPTCHA | Attack detected | Application-level |
| Notify affected users | Post-incident | Email service |

**Recommended Alert Rule:**
```json
{
  "name": "Credential Stuffing Attack",
  "event_type": "login_failed",
  "condition": {"threshold": 10, "window_minutes": 60, "group_by": "ip_address", "count_distinct": "user_id"},
  "severity": "critical",
  "actions": ["email", "webhook", "slack"]
}
```

---

#### ATK-AUTH-03: Password Spraying

**Description:** Attacker tries common passwords against many accounts to avoid lockouts.

**Detection Signals:**
- Event: `login_failed` - Low failure rate per account, high total failures
- Pattern: 1-2 attempts per account across 100+ accounts
- Timing: Attempts spread over time to evade rate limits

**Detection Query:**
```sql
SELECT ip_address,
       COUNT(DISTINCT user_id) as accounts_tried,
       COUNT(*) as total_attempts,
       COUNT(*)::float / COUNT(DISTINCT user_id) as attempts_per_account
FROM security_audit_logs
WHERE event_type = 'login_failed'
  AND created_at > NOW() - INTERVAL '24 hours'
GROUP BY ip_address
HAVING COUNT(DISTINCT user_id) >= 50
   AND COUNT(*)::float / COUNT(DISTINCT user_id) <= 3;
```

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Block IP | 50+ accounts attempted | `POST /api/admin/security/blocked-ips` |
| Global rate limit | Attack pattern detected | Server configuration |
| Force password change | High-value accounts | `POST /api/admin/users/:id/reset-password` |

---

#### ATK-AUTH-04: Account Enumeration

**Description:** Attacker determines valid usernames/emails by analyzing login response differences.

**Detection Signals:**
- Event: `login_failed` - High volume of unique usernames from same IP
- Pattern: Sequential or alphabetical username patterns
- Characteristic: Different response times for valid vs invalid users

**Detection Query:**
```sql
SELECT ip_address, COUNT(*) as attempts,
       COUNT(DISTINCT details->>'email') as unique_emails
FROM security_audit_logs
WHERE event_type = 'login_failed'
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY ip_address
HAVING COUNT(DISTINCT details->>'email') >= 20;
```

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Block IP | 20+ unique usernames | `POST /api/admin/security/blocked-ips` |
| Implement timing normalization | Always | Server configuration |
| Generic error messages | Always | Application code |

---

#### ATK-AUTH-05: Account Lockout DoS

**Description:** Attacker intentionally locks out legitimate users by triggering failed login thresholds.

**Detection Signals:**
- Event: `account_locked` - Multiple lockouts from same IP
- Pattern: Targeted lockouts of specific high-value accounts
- Timing: Lockouts during business hours

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Block attacking IP | Multiple lockouts triggered | `POST /api/admin/security/blocked-ips` |
| Admin unlock account | Confirmed attack | `POST /api/admin/users/:id/unlock` |
| Reduce lockout duration | During attack | Server configuration |

---

### 2. OAuth2 Protocol Attacks

#### ATK-OAUTH-01: Authorization Code Interception

**Description:** Attacker intercepts authorization code during redirect.

**Detection Signals:**
- Event: `auth_code_failed` - Code exchange from different IP than authorization
- Event: `auth_code_failed` - Code already used (replay attempt)
- Pattern: Multiple exchange attempts for same code

**Detection Query:**
```sql
SELECT details->>'code' as auth_code,
       array_agg(DISTINCT ip_address) as ips,
       COUNT(*) as exchange_attempts
FROM security_audit_logs
WHERE event_type IN ('auth_code_exchanged', 'auth_code_failed')
  AND created_at > NOW() - INTERVAL '10 minutes'
GROUP BY details->>'code'
HAVING COUNT(DISTINCT ip_address) > 1 OR COUNT(*) > 1;
```

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Invalidate all user tokens | Code compromise suspected | `POST /api/admin/users/:id/revoke-tokens` |
| Block suspicious IP | Multiple intercept attempts | `POST /api/admin/security/blocked-ips` |
| Enforce PKCE | Always | Server configuration |
| Alert user | Suspicious code exchange | Email notification |

---

#### ATK-OAUTH-02: Token Theft/Replay

**Description:** Attacker obtains and uses stolen access or refresh tokens.

**Detection Signals:**
- Event: Token used from new IP/device after legitimate session
- Event: `token_refreshed` - Refresh from different location than issuance
- Pattern: Simultaneous token usage from geographically distant IPs

**Detection Query:**
```sql
WITH token_usage AS (
  SELECT user_id, ip_address, created_at,
         LAG(ip_address) OVER (PARTITION BY user_id ORDER BY created_at) as prev_ip,
         LAG(created_at) OVER (PARTITION BY user_id ORDER BY created_at) as prev_time
  FROM security_audit_logs
  WHERE event_type IN ('token_issued', 'token_refreshed')
    AND created_at > NOW() - INTERVAL '1 hour'
)
SELECT * FROM token_usage
WHERE ip_address != prev_ip
  AND created_at - prev_time < INTERVAL '5 minutes';
```

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Revoke all user tokens | Token theft confirmed | `POST /api/admin/users/:id/revoke-tokens` |
| Force re-authentication | Suspicious activity | Invalidate sessions |
| Block suspicious IP | Stolen token usage | `POST /api/admin/security/blocked-ips` |
| Notify user | Token used from new location | Email notification |

---

#### ATK-OAUTH-03: Refresh Token Abuse

**Description:** Attacker uses compromised refresh token to maintain persistent access.

**Detection Signals:**
- Event: `token_refreshed` - Abnormal refresh patterns
- Pattern: Refreshes from multiple IPs concurrently
- Pattern: Refresh attempts after user logout

**Detection Query:**
```sql
SELECT user_id, COUNT(*) as refreshes, COUNT(DISTINCT ip_address) as unique_ips
FROM security_audit_logs
WHERE event_type = 'token_refreshed'
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY user_id
HAVING COUNT(DISTINCT ip_address) > 2 OR COUNT(*) > 20;
```

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Revoke refresh tokens | Abuse detected | `POST /oauth/revoke` |
| Implement refresh token rotation | Always | Server configuration |
| Reduce refresh token lifetime | High-risk periods | Server configuration |
| Bind tokens to IP/device | Security policy | Server configuration |

---

#### ATK-OAUTH-04: Client Impersonation

**Description:** Attacker uses stolen client credentials to impersonate a legitimate application.

**Detection Signals:**
- Event: Token requests from unexpected IPs for client
- Event: Client credentials used outside normal patterns
- Pattern: Sudden spike in client_credentials grants

**Detection Query:**
```sql
SELECT app_id, ip_address, COUNT(*) as requests
FROM security_audit_logs
WHERE event_type = 'token_issued'
  AND details->>'grant_type' = 'client_credentials'
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY app_id, ip_address
HAVING COUNT(*) > 100;
```

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Rotate client secret | Compromise suspected | `POST /api/admin/apps/:id/rotate-secret` |
| Revoke issued tokens | Client compromise confirmed | Revoke by app_id |
| IP allowlist for client | Security policy | Application configuration |
| Disable client | Active attack | `PUT /api/admin/apps/:id` (active=false) |

---

#### ATK-OAUTH-05: PKCE Downgrade Attack

**Description:** Attacker attempts to bypass PKCE protection.

**Detection Signals:**
- Event: `pkce_validation_failed` - PKCE bypass attempts
- Event: Authorization requests without PKCE for public clients
- Pattern: Code exchange without code_verifier after PKCE-enabled authorize

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Reject non-PKCE requests | Public clients | Server configuration (enforced) |
| Alert on bypass attempts | Any `pkce_validation_failed` | Alert rule |
| Block source IP | Repeated bypass attempts | `POST /api/admin/security/blocked-ips` |

---

#### ATK-OAUTH-06: Redirect URI Manipulation

**Description:** Attacker manipulates redirect_uri to steal authorization codes.

**Detection Signals:**
- Event: Authorization request with invalid redirect_uri
- Pattern: Multiple redirect_uri variations for same client
- Characteristic: Open redirect attempts

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Strict redirect_uri matching | Always | Server configuration (enforced) |
| Log redirect attempts | All authorization requests | Security audit log |
| Alert on pattern | Multiple invalid redirects | Alert rule |

---

#### ATK-OAUTH-07: Scope Escalation

**Description:** Attacker requests elevated scopes beyond authorized permissions.

**Detection Signals:**
- Event: Token request with unauthorized scopes
- Pattern: Repeated attempts to access admin-level scopes
- Characteristic: Scope changes between authorization and token exchange

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Deny unauthorized scopes | Always | Server enforcement |
| Alert on escalation attempts | Repeated scope abuse | Alert rule |
| Review client permissions | Post-incident | `GET /api/admin/apps/:id` |

---

### 3. Session Attacks

#### ATK-SESS-01: Session Hijacking

**Description:** Attacker steals session and impersonates legitimate user.

**Detection Signals:**
- Event: Session used from drastically different IP/location
- Event: User-agent change mid-session
- Pattern: Impossible travel (logins from distant locations in short time)

**Detection Query:**
```sql
WITH user_logins AS (
  SELECT user_id, ip_address, created_at,
         LAG(ip_address) OVER (PARTITION BY user_id ORDER BY created_at) as prev_ip,
         LAG(created_at) OVER (PARTITION BY user_id ORDER BY created_at) as prev_time
  FROM security_audit_logs
  WHERE event_type = 'login_success'
    AND created_at > NOW() - INTERVAL '24 hours'
)
SELECT * FROM user_logins
WHERE ip_address != prev_ip
  AND created_at - prev_time < INTERVAL '30 minutes';
-- Note: Add IP geolocation to detect impossible travel
```

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Terminate all sessions | Hijacking detected | `POST /api/admin/users/:id/revoke-tokens` |
| Force password reset | Confirmed attack | `POST /api/admin/users/:id/reset-password` |
| Block attacker IP | Identified | `POST /api/admin/security/blocked-ips` |
| Notify user | Suspicious session | Email notification |

---

#### ATK-SESS-02: Session Fixation

**Description:** Attacker sets session ID before victim authenticates.

**Detection Signals:**
- Event: Session ID present before authentication
- Pattern: Same session used by multiple IPs
- Characteristic: Session created then authenticated from different IP

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Regenerate session on login | Always | Server enforcement |
| Invalidate pre-auth sessions | Always | Server enforcement |

---

#### ATK-SESS-03: Concurrent Session Abuse

**Description:** Attacker maintains unauthorized parallel sessions.

**Detection Signals:**
- Event: Multiple active sessions for same user
- Pattern: Sessions from unexpected locations
- API: `GET /api/admin/sessions?user_id=X`

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Limit concurrent sessions | Security policy | Server configuration |
| Alert on new sessions | Exceeds threshold | Alert rule |
| Provide session management | User self-service | User portal |

---

### 4. Token Attacks

#### ATK-TOK-01: JWT Signature Bypass

**Description:** Attacker attempts to forge or manipulate JWT tokens.

**Detection Signals:**
- Event: `invalid_token_used` - Signature verification failures
- Pattern: Tokens with "none" algorithm
- Pattern: Tokens with manipulated claims

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Reject invalid signatures | Always | Server enforcement |
| Alert on tampering | Any `invalid_token_used` | Alert rule |
| Block source IP | Repeated attempts | `POST /api/admin/security/blocked-ips` |

---

#### ATK-TOK-02: Expired Token Replay

**Description:** Attacker attempts to use expired tokens.

**Detection Signals:**
- Event: `expired_token_used` - Attempts to use expired tokens
- Pattern: High volume from single IP
- Characteristic: Often automated

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Reject expired tokens | Always | Server enforcement |
| Track patterns | Monitoring | `GET /api/admin/tokens/stats` |
| Block persistent offenders | 10+ attempts | `POST /api/admin/security/blocked-ips` |

---

#### ATK-TOK-03: Revoked Token Usage

**Description:** Attacker attempts to use previously revoked tokens.

**Detection Signals:**
- Event: `revoked_token_used` - Attempts to use revoked tokens
- Pattern: Usage after explicit revocation
- Severity: Critical (indicates token theft)

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Track all revoked tokens | Always | `used_tokens` table |
| Alert immediately | Any `revoked_token_used` | Alert rule (critical) |
| Investigate user account | Post-alert | Security review |

**Recommended Alert Rule:**
```json
{
  "name": "Revoked Token Usage",
  "event_type": "revoked_token_used",
  "condition": {"threshold": 1, "window_minutes": 1},
  "severity": "critical",
  "actions": ["email", "webhook", "slack"]
}
```

---

#### ATK-TOK-04: Token Leakage Detection

**Description:** Tokens exposed through logs, URLs, or referrer headers.

**Detection Signals:**
- Event: Token used from unexpected source
- Pattern: Token correlation with leaked credentials databases
- Monitoring: Search for tokens in logs

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Revoke leaked tokens | Identified | `POST /oauth/revoke` |
| Rotate signing keys | Mass leak | Key rotation process |
| Audit logging practices | Preventive | Code review |

---

### 5. Infrastructure Attacks

#### ATK-INFRA-01: Rate Limit Bypass

**Description:** Attacker attempts to bypass rate limiting protections.

**Detection Signals:**
- Event: `rate_limit_exceeded` - Rate limit triggers
- Pattern: Requests from distributed IPs (botnet)
- Pattern: Header manipulation to bypass limits

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Block offending IPs | Rate limit exceeded | `POST /api/admin/security/blocked-ips` |
| Implement CAPTCHA | Threshold reached | Application level |
| Use distributed rate limiting | Architecture | Redis/central store |

---

#### ATK-INFRA-02: Denial of Service (DoS)

**Description:** Attacker overwhelms service with requests.

**Detection Signals:**
- Event: Massive request volume from single/few IPs
- Pattern: All endpoints targeted
- Impact: Service degradation

**Detection via Dashboard:**
- `GET /api/admin/dashboard/health` - Check service health
- `GET /api/admin/security/threats` - Check for suspicious IPs

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Block attacking IPs | Pattern detected | `POST /api/admin/security/blocked-ips` |
| Enable WAF rules | Attack ongoing | Infrastructure |
| Scale resources | If legitimate traffic | Infrastructure |

---

#### ATK-INFRA-03: Distributed Denial of Service (DDoS)

**Description:** Attacker uses botnet for distributed attack.

**Detection Signals:**
- Pattern: High request volume from many diverse IPs
- Characteristic: Geographic distribution of sources
- Impact: Cannot block by IP alone

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Enable DDoS protection | Attack detected | CDN/WAF |
| Geographic blocking | If applicable | Infrastructure |
| Rate limit per user/session | Defense in depth | Server configuration |

---

#### ATK-INFRA-04: Slowloris Attack

**Description:** Attacker holds connections open to exhaust resources.

**Detection Signals:**
- Pattern: Many incomplete/slow requests
- Impact: Connection pool exhaustion
- Characteristic: Low bandwidth usage

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Connection timeouts | Always | Server configuration |
| Limit connections per IP | Defense | Server configuration |
| Reverse proxy protection | Architecture | nginx/HAProxy |

---

### 6. Account Attacks

#### ATK-ACCT-01: Account Takeover (ATO)

**Description:** Attacker gains full control of user account.

**Detection Signals:**
- Event: Password change from new IP/device
- Event: Email change request
- Event: Unusual activity after login
- Pattern: Activity immediately after credential reset

**Detection Query:**
```sql
SELECT user_id, event_type, ip_address, created_at
FROM security_audit_logs
WHERE event_type IN ('password_changed', 'email_change_requested', 'login_success')
  AND created_at > NOW() - INTERVAL '1 hour'
ORDER BY user_id, created_at;
-- Look for password_changed followed by unusual activity
```

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Lock account | Suspected ATO | `POST /api/admin/users/:id/lock` |
| Revoke all tokens | Confirmed ATO | `POST /api/admin/users/:id/revoke-tokens` |
| Force password reset | Recovery | `POST /api/admin/users/:id/reset-password` |
| Review account activity | Investigation | `GET /api/admin/security/events?user_id=X` |

---

#### ATK-ACCT-02: Privilege Escalation

**Description:** Attacker attempts to gain higher privileges.

**Detection Signals:**
- Event: Role change requests
- Event: Attempts to access admin endpoints
- Pattern: Manipulation of JWT claims

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Deny unauthorized access | Always | Server enforcement |
| Alert on attempts | Any escalation attempt | Alert rule |
| Review role assignments | Regular audit | `GET /api/admin/users/:id/apps` |

---

#### ATK-ACCT-03: Mass Account Creation (Spam)

**Description:** Attacker creates many fake accounts.

**Detection Signals:**
- Event: High signup rate from single IP
- Event: `user_registered` - Pattern analysis
- Pattern: Similar email patterns, timing

**Detection Query:**
```sql
SELECT ip_address, COUNT(*) as signups
FROM security_audit_logs
WHERE event_type = 'user_registered'
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY ip_address
HAVING COUNT(*) >= 10;
```

**Countermeasures:**
| Action | Trigger | API |
|--------|---------|-----|
| Block IP | 10+ signups/hour | `POST /api/admin/security/blocked-ips` |
| Enable CAPTCHA | Attack detected | Application level |
| Email verification | Always | Server enforcement |
| Phone verification | High-risk | Application level |

---

### Pre-configured Alert Rules

The monitoring app should come with these pre-configured alert rules:

```json
[
  {
    "name": "Brute Force - Single Account",
    "event_type": "login_failed",
    "condition": {"threshold": 5, "window_minutes": 5, "group_by": "user_id"},
    "severity": "critical"
  },
  {
    "name": "Credential Stuffing",
    "event_type": "login_failed",
    "condition": {"threshold": 10, "window_minutes": 30, "group_by": "ip_address"},
    "severity": "critical"
  },
  {
    "name": "Account Lockout",
    "event_type": "account_locked",
    "condition": {"threshold": 1, "window_minutes": 1},
    "severity": "error"
  },
  {
    "name": "Revoked Token Usage",
    "event_type": "revoked_token_used",
    "condition": {"threshold": 1, "window_minutes": 1},
    "severity": "critical"
  },
  {
    "name": "Invalid Token Flood",
    "event_type": "invalid_token_used",
    "condition": {"threshold": 20, "window_minutes": 5, "group_by": "ip_address"},
    "severity": "error"
  },
  {
    "name": "Mass Account Creation",
    "event_type": "user_registered",
    "condition": {"threshold": 10, "window_minutes": 60, "group_by": "ip_address"},
    "severity": "warning"
  },
  {
    "name": "PKCE Bypass Attempt",
    "event_type": "pkce_validation_failed",
    "condition": {"threshold": 3, "window_minutes": 10},
    "severity": "critical"
  },
  {
    "name": "Suspicious Token Refresh",
    "event_type": "token_refreshed",
    "condition": {"threshold": 10, "window_minutes": 5, "group_by": "user_id"},
    "severity": "warning"
  }
]
```

---

### Response Playbooks

#### Playbook: Brute Force Attack

1. **Immediate (Automated):**
   - Account locked after 5 failures
   - Alert triggered

2. **Investigation (Manual):**
   - Query: `GET /api/admin/security/events?event_type=login_failed&user_id=X`
   - Check IP reputation: `GET /api/admin/security/ip-reputation/:ip`

3. **Response:**
   - If single IP: Block IP for 24h
   - If distributed: Enable CAPTCHA
   - Notify user if legitimate

4. **Recovery:**
   - Unlock account: `POST /api/admin/users/:id/unlock`
   - Force password reset if compromised

---

#### Playbook: Token Theft

1. **Detection:**
   - Alert on `revoked_token_used` or suspicious refresh patterns

2. **Immediate Response:**
   - Revoke all user tokens: `POST /api/admin/users/:id/revoke-tokens`
   - Block suspicious IP: `POST /api/admin/security/blocked-ips`

3. **Investigation:**
   - Review user activity: `GET /api/admin/security/events?user_id=X`
   - Check for data access

4. **Recovery:**
   - Force password reset
   - Notify user
   - Monitor for continued abuse

---

#### Playbook: Client Compromise

1. **Detection:**
   - Unusual client_credentials usage patterns
   - Client used from unexpected IPs

2. **Immediate Response:**
   - Rotate client secret: `POST /api/admin/apps/:id/rotate-secret`
   - Optionally disable client: `PUT /api/admin/apps/:id` (active=false)

3. **Investigation:**
   - Review tokens issued
   - Check for data access

4. **Recovery:**
   - Update client configuration with new secret
   - Re-enable client
   - Implement IP allowlisting

---

### Attack Detection Dashboard

The monitoring app should include a dedicated "Attacks" dashboard view showing:

1. **Real-time Attack Feed**
   - Critical/error events in last 24h
   - Attack type classification
   - Affected accounts/IPs

2. **Attack Timeline**
   - Visualize attack patterns over time
   - Correlate related events

3. **Top Attackers**
   - IPs with highest threat scores
   - One-click blocking

4. **Affected Accounts**
   - Users targeted in attacks
   - Quick access to lock/unlock

5. **Attack Statistics**
   - Attacks blocked vs successful
   - Trending attack types
   - Geographic distribution

---

## Notes

- This monitoring app complements the Security Testing SPA
- Testing SPA validates OAuth2 compliance; Monitoring App provides ongoing visibility
- Both apps share the same authentication mechanism (admin JWT tokens)
- Consider deploying on internal network only for production

