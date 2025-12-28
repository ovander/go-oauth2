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

## Notes

- This monitoring app complements the Security Testing SPA
- Testing SPA validates OAuth2 compliance; Monitoring App provides ongoing visibility
- Both apps share the same authentication mechanism (admin JWT tokens)
- Consider deploying on internal network only for production

