# Alert Rules Configuration Guide

This document explains how to create and manage security alert rules in the OAuth2 server monitoring system.

## Overview

Alert rules watch the security audit log and raise an alert, and notifications, when a kind of
event happens too often. Each alert rule defines:

- **Event Type**: which security events to count
- **Condition**: how many events (`threshold`) in how long (`window_minutes`), optionally per IP
  address, user or application (`group_by`)
- **Severity**: `warning`, `error` or `critical`
- **Actions**: who is told when it triggers: `email`, `webhook` or `slack`
- **Recipients** (for `email`) and **Webhook URL** (for `webhook` and `slack`)

## Evaluation (`ALERT_RULES_MODE`)

Rules are evaluated only when the server runs with `ALERT_RULES_MODE` set (#258):

| Mode | Effect |
|------|--------|
| `off` (default) | Rules are stored and edited, but nothing evaluates them: no alert, no notification. |
| `observe` | Rules are evaluated and triggered alerts are recorded (alert history, an `alert_triggered` security event), but no notification is sent. |
| `enforce` | As `observe`, and each triggered alert's notifications are sent. |

Run `observe` first: the alert history then shows what each rule would have sent, so thresholds
can be tuned before anyone is paged.

Every `ALERT_RULES_INTERVAL_SECONDS` (default 60, at least 10), each enabled rule counts its
`event_type`'s events of the last `window_minutes`, per group of `group_by` (all together without
it; an event with no value for `group_by`, such as no user, is not counted). A group whose count
reaches `threshold` triggers one alert; the rule does not alert again for that group until its
window has passed. With several Socrate instances, one evaluates at a time.

A rule whose condition is invalid (a `threshold` under 1, a `window_minutes` outside 1–1440, an
unknown `group_by`) is skipped and logged; the other rules still run.

`GET /api/admin/alerts/rules` reports the mode in `evaluation_mode`. A triggered alert's
`details` hold the `event_type`, `group_by`, `group`, `count`, `threshold` and `window_minutes`,
and under `notifications` the outcome of each action: `sent`, `failed`, or why it was not sent
(the mode is `observe`, no recipient or webhook URL, email not configured, unknown action).

## Default rules

A fresh install, and a server upgraded with no rule of its own, starts with seven rules (migration
0037). They are enabled and notify by email, but have no recipient: under `ALERT_RULES_MODE=enforce`
nobody is emailed until recipients are added, and the alert records why. Edit, disable or delete
them like any other rule; a server that already had rules gets none of them.

| Rule | Event | Condition | Severity |
|------|-------|-----------|----------|
| Brute force from one IP | `login_failed` | 10 in 5 min, per `ip_address` | `error` |
| Account under attack | `login_failed` | 5 in 10 min, per `user_id` | `warning` |
| Account locked | `account_locked` | 1 in 5 min, per `user_id` | `warning` |
| Refresh token reused | `refresh_token_reuse` | 1 in 5 min | `critical` |
| Revoked token still in use | `revoked_token_used` | 3 in 10 min, per `ip_address` | `error` |
| Client secret guessing | `client_auth_failed` | 10 in 5 min, per `ip_address` | `warning` |
| Audit log tampering | `audit_integrity_violation` | 1 in 60 min | `critical` |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/alerts/rules` | List all alert rules |
| POST | `/api/admin/alerts/rules` | Create a new alert rule |
| PUT | `/api/admin/alerts/rules/:id` | Update an existing rule |
| DELETE | `/api/admin/alerts/rules/:id` | Delete a rule |
| GET | `/api/admin/alerts/history` | List triggered alerts |
| POST | `/api/admin/alerts/:id/acknowledge` | Acknowledge an alert |

Creating, updating and deleting a rule require a fresh step-up (`403 elevation_required`
otherwise, see [`API.md` §8.1](API.md#81-admin-login--post-apiadminlogin-deprecated)) and, with
`ADMIN_SCOPE_MODE=enforce`, the `monitoring:write` scope; reads need `monitoring:read`.

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
    "severity": "error",
    "enabled": true,
    "actions": ["email"],
    "recipients": ["security@example.com"],
    "webhook_url": "https://slack.com/webhook/..."
  }'
```

### Available Event Types

A rule only triggers on events the server records. Among them:

| Event Type | Description |
|------------|-------------|
| `login_success` | Successful sign-in |
| `login_failed` | Failed sign-in |
| `account_locked` | Account locked after failed sign-ins |
| `password_changed` | Password changed |
| `password_reset_requested` | Password reset requested |
| `user_registered` | New user registration |
| `invite_accepted` | Invitation accepted |
| `token_issued` | Token issued |
| `token_refreshed` | Token refreshed |
| `token_revoked` | Token revoked |
| `all_tokens_revoked` | All of a user's tokens revoked |
| `invalid_token_used` | A forged, malformed or unknown-user bearer token was presented |
| `revoked_token_used` | A revoked bearer token was presented |
| `refresh_token_reuse` | A rotated refresh token was used again |
| `client_auth_failed` | Client authentication failed |
| `auth_code_failed` | Authorization code exchange failed (`reason: code_replayed` for a replayed code under `CODE_REPLAY_MODE`) |
| `pkce_validation_failed` | PKCE verification failed |
| `scope_denied` | A requested scope was refused |
| `redirect_uri_inexact_match` | A redirect URI matched its registration only after normalization |
| `mfa_policy_violation` | A sign-in broke the admin MFA policy |
| `dpop_validation_failed` | A DPoP proof was refused |
| `audit_integrity_violation` | The audit-log integrity scan found a row that does not verify |
| `ip_blocked`, `ip_unblocked` | An IP address was blocked or unblocked |
| `alert_triggered` | An alert rule triggered |

Some event types exist in the code but are never recorded, so a rule on them never triggers:
`logout`, `account_unlocked`, `password_reset_used`, `email_change_requested`, `email_changed`,
`user_invited`, `expired_token_used` (deliberately: an expired token followed by a refresh is
normal), `auth_code_issued`, `auth_code_exchanged`, `suspicious_activity`, `rate_limit_exceeded`
and `brute_force_detected`.

### Condition Options

| Field | Type | Description |
|-------|------|-------------|
| `threshold` | int | Number of events to trigger alert |
| `window_minutes` | int | Time window for counting events |
| `group_by` | string | Group events by: `ip_address`, `user_id`, `app_id` |

### Available Actions

| Action | Description |
|--------|-------------|
| `email` | Email each address in `recipients` (needs SMTP configured) |
| `webhook` | POST the alert as JSON to `webhook_url` (see [Webhook Integration](#webhook-integration)) |
| `slack` | POST `{"text": "[severity] message"}` to `webhook_url`, a Slack incoming webhook |

Every triggered alert is also recorded as an `alert_triggered` security event; there is no
separate `log` action. Blocking an IP is not an alert action: block it with
`POST /api/admin/security/blocked-ips` (the monitoring console's Blocked IPs page).

### Severity Levels

| Severity | Description |
|----------|-------------|
| `critical` | Immediate action required |
| `error` | Security incident |
| `warning` | Potential threat (also used for any other value) |

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
    "actions": ["email"],
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
    "severity": "error",
    "enabled": true,
    "actions": ["email"],
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
    "severity": "error",
    "enabled": true,
    "actions": ["email"],
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
    "severity": "error",
    "enabled": true,
    "actions": ["email"],
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
    "severity": "warning",
    "enabled": true,
    "actions": ["email"],
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
    "actions": ["email"],
    "recipients": ["security@example.com"]
  }'
```

### 7. Admin MFA Policy Violations

Alerts when sign-ins keep breaking the admin MFA policy (`ADMIN_MFA_POLICY`).

```bash
curl -X POST http://localhost:8081/api/admin/alerts/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "Admin MFA Policy Violations",
    "description": "Sign-ins refused by the admin MFA policy",
    "event_type": "mfa_policy_violation",
    "condition": {
      "threshold": 3,
      "window_minutes": 15,
      "group_by": "user_id"
    },
    "severity": "warning",
    "enabled": true,
    "actions": ["email"],
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
    "severity": "warning",
    "enabled": true,
    "actions": ["email"],
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
    "severity": "warning",
    "enabled": true,
    "actions": ["email"],
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
    "severity": "error",
    "enabled": true,
    "actions": ["email"],
    "recipients": ["security@example.com"]
  }'
```

---

## Managing Triggered Alerts

### List Triggered Alerts

```bash
curl -X GET "http://localhost:8081/api/admin/alerts/history?page=1&page_size=20" \
  -H "Authorization: Bearer <token>"
```

The answer carries `alerts`, `total`, `unacknowledged`, `page` and `page_size` (at most 100).

### Unacknowledged Only

```bash
curl -X GET "http://localhost:8081/api/admin/alerts/history?acknowledged=false" \
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

Under `ALERT_RULES_MODE=enforce`, a triggered alert with the `webhook` action is POSTed as JSON
(`Content-Type: application/json`) to the rule's `webhook_url`:

```json
{
  "type": "socrate.alert_triggered",
  "alert_id": 123,
  "rule_id": 4,
  "rule_name": "Brute Force Attack",
  "severity": "critical",
  "message": "Brute Force Attack: 10 login_failed events in 5 min (ip_address 203.0.113.7)",
  "triggered_at": "2026-11-25T10:30:00Z",
  "details": {
    "event_type": "login_failed",
    "group_by": "ip_address",
    "group": "203.0.113.7",
    "count": 10,
    "threshold": 10,
    "window_minutes": 5
  }
}
```

The URL must be `https` and reach a public address: it is called through the same SSRF guard as
the outbound webhooks, checked when the connection is made. A 2xx answer counts as sent; anything
else, or no answer within 10 seconds, as failed. There is no retry: the next alert is sent anew.

### Slack Webhook Example

Configure a Slack incoming webhook, use it as the `webhook_url` and the `slack` action, which
sends the alert's message as Slack expects it (`{"text": ...}`):

```bash
curl -X POST http://localhost:8081/api/admin/alerts/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "Critical Security Alert",
    "event_type": "refresh_token_reuse",
    "condition": {"threshold": 1, "window_minutes": 5},
    "severity": "critical",
    "actions": ["slack"],
    "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
  }'
```

---

## Best Practices

1. **Start with `ALERT_RULES_MODE=observe`**: alerts are recorded without notifying anyone, so thresholds can be tuned
2. **Set appropriate thresholds**: Too low causes alert fatigue, too high misses incidents
3. **Group by the attacker**: `group_by: ip_address` alerts once per source, not once for all of them
4. **Review alerts regularly**: Acknowledge alerts and refine rules based on patterns
5. **Layer your alerts**: Combine low-threshold warnings with high-threshold critical alerts
6. **Test your webhooks**: Verify integration before relying on them for critical alerts
7. **Document your rules**: Use clear names and descriptions for team understanding
8. **Monitor rule effectiveness**: Disable rules that produce too many false positives

---

## Troubleshooting

### Alert Not Triggering

1. Check that the server evaluates rules: `evaluation_mode` in `GET /api/admin/alerts/rules`
   must be `observe` or `enforce` (`ALERT_RULES_MODE`)
2. Verify the rule is enabled: `GET /api/admin/alerts/rules/:id`
3. Check event types are being logged: `GET /api/admin/security/events`
4. Verify threshold and time window are appropriate, and look in the server log for
   `alert rule <id>`: a rule with an invalid condition is skipped
5. A group that already alerted is not alerted again until its window has passed

### Too Many False Positives

1. Increase the threshold value
2. Narrow the time window
3. Add more specific conditions

### Webhook Not Receiving Alerts

1. Check that `ALERT_RULES_MODE=enforce`: under `observe` nothing is sent
2. Look at the alert's `details.notifications`: `failed`, or why it was not sent
3. Verify the webhook URL is `https`, public and reachable from the server, and returns 2xx
4. Check the server log for `alert rules: notification failed`

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
  -d '{"name":"Brute Force Attack","event_type":"login_failed","condition":{"threshold":10,"window_minutes":5,"group_by":"ip_address"},"severity":"critical","actions":["email"]}'

# 2. Account Takeover Attempt
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Account Takeover Attempt","event_type":"login_failed","condition":{"threshold":5,"window_minutes":10,"group_by":"user_id"},"severity":"error","actions":["email"]}'

# 3. Account Locked
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Account Locked","event_type":"account_locked","condition":{"threshold":1,"window_minutes":1},"severity":"error","actions":["email"]}'

# 4. Invalid Token Usage
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Invalid Token Usage","event_type":"invalid_token_used","condition":{"threshold":5,"window_minutes":5,"group_by":"ip_address"},"severity":"error","actions":["email"]}'

# 5. Unusual Token Refresh
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Unusual Token Refresh Activity","event_type":"token_refreshed","condition":{"threshold":50,"window_minutes":5,"group_by":"ip_address"},"severity":"warning","actions":["email"]}'

# 6. PKCE Bypass Attempt
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"PKCE Bypass Attempt","event_type":"pkce_validation_failed","condition":{"threshold":3,"window_minutes":10,"group_by":"ip_address"},"severity":"critical","actions":["email"]}'

# 7. Admin MFA Policy Violations
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Admin MFA Policy Violations","event_type":"mfa_policy_violation","condition":{"threshold":3,"window_minutes":15,"group_by":"user_id"},"severity":"warning","actions":["email"]}'

# 8. Password Reset Abuse
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Password Reset Abuse","event_type":"password_reset_requested","condition":{"threshold":5,"window_minutes":15,"group_by":"ip_address"},"severity":"warning","actions":["email"]}'

# 9. High Volume Token Issuance
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"High Volume Token Issuance","event_type":"token_issued","condition":{"threshold":1000,"window_minutes":60,"group_by":"app_id"},"severity":"warning","actions":["email"]}'

# 10. Registration Spike
curl -s -X POST "$BASE_URL/api/admin/alerts/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Registration Spike","event_type":"user_registered","condition":{"threshold":50,"window_minutes":10,"group_by":"ip_address"},"severity":"error","actions":["email"]}'

echo "All alert rules created!"
```

Save as `setup-alerts.sh` and run:
```bash
chmod +x setup-alerts.sh
./setup-alerts.sh
```
