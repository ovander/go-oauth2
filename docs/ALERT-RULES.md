# Alert Rules Configuration Guide

This document explains how to create and manage security alert rules in the OAuth2 server monitoring system.

## Overview

The alert system monitors security events in real-time and can trigger notifications based on configurable rules. Each alert rule defines:

- **Event Type**: Which security events to monitor
- **Condition**: Thresholds and criteria for triggering
- **Severity**: Critical, high, medium, low, or info
- **Actions**: What to do when triggered (log, email, webhook, block_ip)
- **Recipients**: Who should be notified

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/alerts/rules` | List all alert rules |
| POST | `/api/admin/alerts/rules` | Create a new alert rule |
| PUT | `/api/admin/alerts/rules/:id` | Update an existing rule |
| DELETE | `/api/admin/alerts/rules/:id` | Delete a rule |
| GET | `/api/admin/alerts` | List triggered alerts |
| POST | `/api/admin/alerts/:id/acknowledge` | Acknowledge an alert |

## Creating an Alert Rule

### Request Format

```bash
curl -X POST http://localhost:8081/api/admin/alerts/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_token>" \
  -d '{
    "name": "Brute Force Detection",
    "description": "Detect multiple failed login attempts",
    "event_type": "login_failed",
    "condition": {
      "threshold": 5,
      "window_minutes": 15,
      "group_by": "ip_address"
    },
    "severity": "high",
    "enabled": true,
    "actions": ["log", "email", "block_ip"],
    "recipients": ["security@example.com"],
    "webhook_url": "https://slack.com/webhook/..."
  }'
```

### Available Event Types

| Event Type | Description |
|------------|-------------|
| `login_success` | Successful user login |
| `login_failed` | Failed login attempt |
| `logout` | User logout |
| `account_locked` | Account locked due to failed attempts |
| `account_unlocked` | Account unlocked |
| `password_changed` | Password was changed |
| `password_reset_requested` | Password reset was requested |
| `password_reset_used` | Password reset token was used |
| `token_issued` | OAuth token issued |
| `token_refreshed` | Token was refreshed |
| `token_revoked` | Token was revoked |
| `all_tokens_revoked` | All user tokens revoked |
| `invalid_token_used` | Invalid token usage attempt |
| `expired_token_used` | Expired token usage attempt |
| `auth_code_issued` | Authorization code issued |
| `auth_code_exchanged` | Code exchanged for token |
| `auth_code_failed` | Authorization code exchange failed |
| `pkce_validation_failed` | PKCE verification failed |
| `suspicious_activity` | General suspicious activity |
| `rate_limit_exceeded` | Rate limit was exceeded |
| `brute_force_detected` | Brute force attack detected |
| `user_registered` | New user registration |
| `user_invited` | User invitation sent |
| `invite_accepted` | Invitation accepted |

### Condition Options

| Field | Type | Description |
|-------|------|-------------|
| `threshold` | int | Number of events to trigger alert |
| `window_minutes` | int | Time window for counting events |
| `group_by` | string | Group events by: `ip_address`, `user_id`, `app_id` |
| `match_value` | string | Specific value to match (optional) |

### Available Actions

| Action | Description |
|--------|-------------|
| `log` | Log to security audit |
| `email` | Send email notification |
| `webhook` | Call webhook URL |
| `block_ip` | Automatically block the IP address |

### Severity Levels

| Severity | Description |
|----------|-------------|
| `critical` | Immediate action required |
| `high` | Security incident |
| `medium` | Potential threat |
| `low` | Minor concern |
| `info` | Informational |

---

## 10 Essential Alert Rules

Below are 10 recommended alert rules for production OAuth2 deployments:

### 1. Brute Force Attack Detection

Detects multiple failed login attempts from the same IP address.

```bash
curl -X POST http://localhost:8081/api/admin/alerts/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "Brute Force Attack",
    "description": "More than 10 failed logins from same IP in 5 minutes",
    "event_type": "login_failed",
    "condition": {
      "threshold": 10,
      "window_minutes": 5,
      "group_by": "ip_address"
    },
    "severity": "critical",
    "enabled": true,
    "actions": ["log", "email", "block_ip"],
    "recipients": ["security@example.com"]
  }'
```

### 2. Account Takeover Attempt

Detects failed login attempts for a specific user account.

```bash
curl -X POST http://localhost:8081/api/admin/alerts/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "Account Takeover Attempt",
    "description": "Multiple failed logins for same user account",
    "event_type": "login_failed",
    "condition": {
      "threshold": 5,
      "window_minutes": 10,
      "group_by": "user_id"
    },
    "severity": "high",
    "enabled": true,
    "actions": ["log", "email"],
    "recipients": ["security@example.com"]
  }'
```

### 3. Account Lockout Notification

Alerts when user accounts are locked.

```bash
curl -X POST http://localhost:8081/api/admin/alerts/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "Account Locked",
    "description": "User account has been locked",
    "event_type": "account_locked",
    "condition": {
      "threshold": 1,
      "window_minutes": 1
    },
    "severity": "high",
    "enabled": true,
    "actions": ["log", "email"],
    "recipients": ["security@example.com", "helpdesk@example.com"]
  }'
```

### 4. Suspicious Token Activity

Detects attempts to use invalid or expired tokens.

```bash
curl -X POST http://localhost:8081/api/admin/alerts/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "Invalid Token Usage",
    "description": "Multiple invalid token usage attempts",
    "event_type": "invalid_token_used",
    "condition": {
      "threshold": 5,
      "window_minutes": 5,
      "group_by": "ip_address"
    },
    "severity": "high",
    "enabled": true,
    "actions": ["log", "email", "block_ip"],
    "recipients": ["security@example.com"]
  }'
```

### 5. Mass Token Refresh

Detects unusual volume of token refreshes (potential token theft).

```bash
curl -X POST http://localhost:8081/api/admin/alerts/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "Unusual Token Refresh Activity",
    "description": "High volume of token refreshes from same IP",
    "event_type": "token_refreshed",
    "condition": {
      "threshold": 50,
      "window_minutes": 5,
      "group_by": "ip_address"
    },
    "severity": "medium",
    "enabled": true,
    "actions": ["log", "email"],
    "recipients": ["security@example.com"]
  }'
```

### 6. PKCE Bypass Attempts

Detects potential PKCE bypass attempts.

```bash
curl -X POST http://localhost:8081/api/admin/alerts/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "PKCE Bypass Attempt",
    "description": "PKCE validation failures detected",
    "event_type": "pkce_validation_failed",
    "condition": {
      "threshold": 3,
      "window_minutes": 10,
      "group_by": "ip_address"
    },
    "severity": "critical",
    "enabled": true,
    "actions": ["log", "email", "block_ip"],
    "recipients": ["security@example.com"]
  }'
```

### 7. Rate Limit Abuse

Alerts on repeated rate limit violations.

```bash
curl -X POST http://localhost:8081/api/admin/alerts/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "Rate Limit Abuse",
    "description": "Repeated rate limit violations from same source",
    "event_type": "rate_limit_exceeded",
    "condition": {
      "threshold": 10,
      "window_minutes": 5,
      "group_by": "ip_address"
    },
    "severity": "medium",
    "enabled": true,
    "actions": ["log", "block_ip"],
    "recipients": ["security@example.com"]
  }'
```

### 8. Password Reset Abuse

Detects potential password reset abuse.

```bash
curl -X POST http://localhost:8081/api/admin/alerts/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "Password Reset Abuse",
    "description": "Multiple password reset requests",
    "event_type": "password_reset_requested",
    "condition": {
      "threshold": 5,
      "window_minutes": 15,
      "group_by": "ip_address"
    },
    "severity": "medium",
    "enabled": true,
    "actions": ["log", "email"],
    "recipients": ["security@example.com"]
  }'
```

### 9. OAuth Application Abuse

Monitors for unusual activity on specific OAuth applications.

```bash
curl -X POST http://localhost:8081/api/admin/alerts/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "High Volume Token Issuance",
    "description": "Unusual number of tokens issued for application",
    "event_type": "token_issued",
    "condition": {
      "threshold": 1000,
      "window_minutes": 60,
      "group_by": "app_id"
    },
    "severity": "medium",
    "enabled": true,
    "actions": ["log", "email"],
    "recipients": ["security@example.com"]
  }'
```

### 10. New User Registration Spike

Detects potential spam account creation.

```bash
curl -X POST http://localhost:8081/api/admin/alerts/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "Registration Spike",
    "description": "High volume of new registrations",
    "event_type": "user_registered",
    "condition": {
      "threshold": 50,
      "window_minutes": 10,
      "group_by": "ip_address"
    },
    "severity": "high",
    "enabled": true,
    "actions": ["log", "email", "block_ip"],
    "recipients": ["security@example.com"]
  }'
```

---

## Managing Triggered Alerts

### List Triggered Alerts

```bash
curl -X GET "http://localhost:8081/api/admin/alerts?page=1&page_size=20" \
  -H "Authorization: Bearer <token>"
```

### Filter by Severity

```bash
curl -X GET "http://localhost:8081/api/admin/alerts?severity=critical" \
  -H "Authorization: Bearer <token>"
```

### Acknowledge an Alert

```bash
curl -X POST "http://localhost:8081/api/admin/alerts/123/acknowledge" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "note": "Investigated - false positive from load testing"
  }'
```

---

## Webhook Integration

When an alert is triggered with the `webhook` action, a POST request is sent to the configured URL:

```json
{
  "alert_id": 123,
  "rule_name": "Brute Force Attack",
  "severity": "critical",
  "message": "10 failed login attempts from IP 192.168.1.100",
  "triggered_at": "2024-01-15T10:30:00Z",
  "details": {
    "ip_address": "192.168.1.100",
    "count": 10,
    "window_minutes": 5
  }
}
```

### Slack Webhook Example

Configure a Slack incoming webhook and use it as the `webhook_url`:

```bash
curl -X POST http://localhost:8081/api/admin/alerts/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "Critical Security Alert",
    "event_type": "brute_force_detected",
    "condition": {"threshold": 1, "window_minutes": 1},
    "severity": "critical",
    "actions": ["webhook"],
    "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
  }'
```

---

## Best Practices

1. **Start with monitoring mode**: Enable rules with just the `log` action initially to tune thresholds
2. **Set appropriate thresholds**: Too low causes alert fatigue, too high misses incidents
3. **Use IP blocking carefully**: Only for clear attack patterns to avoid blocking legitimate users
4. **Review alerts regularly**: Acknowledge alerts and refine rules based on patterns
5. **Layer your alerts**: Combine low-threshold warnings with high-threshold critical alerts
6. **Test your webhooks**: Verify integration before relying on them for critical alerts
7. **Document your rules**: Use clear names and descriptions for team understanding
8. **Monitor rule effectiveness**: Disable rules that produce too many false positives

---

## Troubleshooting

### Alert Not Triggering

1. Verify the rule is enabled: `GET /api/admin/alerts/rules/:id`
2. Check event types are being logged: `GET /api/admin/security/events`
3. Verify threshold and time window are appropriate

### Too Many False Positives

1. Increase the threshold value
2. Narrow the time window
3. Add more specific conditions

### Webhook Not Receiving Alerts

1. Verify the webhook URL is accessible from the server
2. Check server logs for HTTP errors
3. Ensure the webhook endpoint returns 2xx status

---

## Quick Reference

### Create All 10 Essential Rules (Script)

```bash
#!/bin/bash
TOKEN="your_admin_token"
BASE_URL="http://localhost:8081"

# 1. Brute Force Attack
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Brute Force Attack","event_type":"login_failed","condition":{"threshold":10,"window_minutes":5,"group_by":"ip_address"},"severity":"critical","actions":["log","email","block_ip"]}'

# 2. Account Takeover Attempt
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Account Takeover Attempt","event_type":"login_failed","condition":{"threshold":5,"window_minutes":10,"group_by":"user_id"},"severity":"high","actions":["log","email"]}'

# 3. Account Locked
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Account Locked","event_type":"account_locked","condition":{"threshold":1,"window_minutes":1},"severity":"high","actions":["log","email"]}'

# 4. Invalid Token Usage
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Invalid Token Usage","event_type":"invalid_token_used","condition":{"threshold":5,"window_minutes":5,"group_by":"ip_address"},"severity":"high","actions":["log","email","block_ip"]}'

# 5. Unusual Token Refresh
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Unusual Token Refresh Activity","event_type":"token_refreshed","condition":{"threshold":50,"window_minutes":5,"group_by":"ip_address"},"severity":"medium","actions":["log","email"]}'

# 6. PKCE Bypass Attempt
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"PKCE Bypass Attempt","event_type":"pkce_validation_failed","condition":{"threshold":3,"window_minutes":10,"group_by":"ip_address"},"severity":"critical","actions":["log","email","block_ip"]}'

# 7. Rate Limit Abuse
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Rate Limit Abuse","event_type":"rate_limit_exceeded","condition":{"threshold":10,"window_minutes":5,"group_by":"ip_address"},"severity":"medium","actions":["log","block_ip"]}'

# 8. Password Reset Abuse
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Password Reset Abuse","event_type":"password_reset_requested","condition":{"threshold":5,"window_minutes":15,"group_by":"ip_address"},"severity":"medium","actions":["log","email"]}'

# 9. High Volume Token Issuance
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"High Volume Token Issuance","event_type":"token_issued","condition":{"threshold":1000,"window_minutes":60,"group_by":"app_id"},"severity":"medium","actions":["log","email"]}'

# 10. Registration Spike
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Registration Spike","event_type":"user_registered","condition":{"threshold":50,"window_minutes":10,"group_by":"ip_address"},"severity":"high","actions":["log","email","block_ip"]}'

echo "All alert rules created!"
```

Save as `setup-alerts.sh` and run:
```bash
chmod +x setup-alerts.sh
./setup-alerts.sh
```
