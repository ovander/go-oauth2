# OAuth2 Server Test Configuration Guide

This document provides complete configuration for testing the OAuth2 server on a Raspberry Pi cluster or any development/staging environment.

---

## Table of Contents

1. [Environment Setup](#environment-setup)
2. [Network Configuration](#network-configuration)
3. [Server Configuration](#server-configuration)
4. [Database Setup](#database-setup)
5. [Test Data Fixtures](#test-data-fixtures)
6. [Load Testing](#load-testing)
7. [Security Testing](#security-testing)
8. [Monitoring Configuration](#monitoring-configuration)
9. [Troubleshooting](#troubleshooting)

---

## Environment Setup

### Hardware Requirements

| Component | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| **OAuth Server** | Pi 4 (2GB) | Pi 4 (4GB) | ARM64 build required |
| **Database** | Pi 4 (4GB) | Pi 4 (8GB) + SSD | SSD via USB 3.0 |
| **Load Balancer** | Pi 3B+ | Pi 4 (2GB) | HAProxy or Nginx |
| **Test Client** | Any | Laptop/Desktop | Runs load tests |

### IP Address Allocation

```
┌─────────────────────────────────────────────────────┐
│              TEST NETWORK: 192.168.1.0/24           │
├─────────────────────────────────────────────────────┤
│                                                     │
│  192.168.1.10  - Load Balancer (HAProxy)           │
│  192.168.1.11  - OAuth Server Instance 1           │
│  192.168.1.12  - OAuth Server Instance 2           │
│  192.168.1.14  - PostgreSQL Database               │
│  192.168.1.20  - Test Client Machine               │
│                                                     │
│  192.168.1.1   - Router/Gateway                    │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## Network Configuration

### /etc/hosts (on all nodes)

```bash
# OAuth2 Test Cluster
192.168.1.10  oauth.local lb.local
192.168.1.11  oauth1.local
192.168.1.12  oauth2.local
192.168.1.14  db.local postgres.local
```

### Firewall Rules (UFW)

```bash
# On Load Balancer (192.168.1.10)
sudo ufw allow 80/tcp      # HTTP
sudo ufw allow 443/tcp     # HTTPS
sudo ufw allow 8404/tcp    # HAProxy Stats
sudo ufw allow 22/tcp      # SSH

# On OAuth Servers (192.168.1.11, 192.168.1.12)
sudo ufw allow from 192.168.1.10 to any port 8080  # OAuth API
sudo ufw allow from 192.168.1.10 to any port 8081  # Admin API
sudo ufw allow 22/tcp                               # SSH

# On Database (192.168.1.14)
sudo ufw allow from 192.168.1.11 to any port 5432  # PostgreSQL
sudo ufw allow from 192.168.1.12 to any port 5432  # PostgreSQL
sudo ufw allow 22/tcp                               # SSH
```

---

## Server Configuration

### Environment Variables (.env)

#### Production-Like Testing

```bash
# ===========================================
# PRODUCTION-LIKE TEST CONFIGURATION
# ===========================================

# Server
PORT=8080
ADMIN_PORT=8081
LOG_LEVEL=info
LOG_FORMAT=json

# Database
DB_HOST=192.168.1.14
DB_PORT=5432
DB_NAME=oauth_test
DB_USER=oauth
DB_PASSWORD=test_secure_password_123
DB_SSLMODE=disable
DB_POOL_SIZE=30
DB_MAX_IDLE_CONNS=15
DB_CONN_MAX_LIFETIME=30m
DB_CONN_MAX_IDLE_TIME=10m

# JWT Configuration
JWT_PRIVATE_KEY_PATH=/home/pi/oauth/keys/private.pem
JWT_PUBLIC_KEY_PATH=/home/pi/oauth/keys/public.pem
JWT_ACCESS_TOKEN_TTL=15m
JWT_REFRESH_TOKEN_TTL=168h
JWT_ISSUER=https://oauth.local

# Security Settings
AUTO_DEFENSE_ENABLED=true
AUTO_DEFENSE_FAILED_LOGIN_THRESHOLD=10
AUTO_DEFENSE_FAILED_LOGIN_WINDOW=5m
AUTO_DEFENSE_BLOCK_DURATION=1h
AUTO_DEFENSE_CHECK_INTERVAL=30s
AUTO_DEFENSE_CLEANUP_INTERVAL=10m

# Rate Limiting
RATE_LIMIT_LOGIN=10
RATE_LIMIT_LOGIN_WINDOW=60
RATE_LIMIT_SIGNUP=5
RATE_LIMIT_SIGNUP_WINDOW=3600

# CORS
ALLOWED_ORIGINS=http://192.168.1.20:3000,http://localhost:3000,http://oauth.local

# Session
SESSION_DURATION=24h
COOKIE_SECURE=false
COOKIE_DOMAIN=.local
```

#### Development/Debug Testing

```bash
# ===========================================
# DEBUG TEST CONFIGURATION
# ===========================================

# Server
PORT=8080
ADMIN_PORT=8081
LOG_LEVEL=debug
LOG_FORMAT=text

# Database (local)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=oauth_dev
DB_USER=oauth
DB_PASSWORD=dev_password
DB_SSLMODE=disable
DB_POOL_SIZE=10
DB_MAX_IDLE_CONNS=5
DB_CONN_MAX_LIFETIME=1h

# JWT Configuration
JWT_PRIVATE_KEY_PATH=./keys/private.pem
JWT_PUBLIC_KEY_PATH=./keys/public.pem
JWT_ACCESS_TOKEN_TTL=1h
JWT_REFRESH_TOKEN_TTL=24h
JWT_ISSUER=http://localhost:8080

# Security Settings (relaxed for testing)
AUTO_DEFENSE_ENABLED=true
AUTO_DEFENSE_FAILED_LOGIN_THRESHOLD=50
AUTO_DEFENSE_FAILED_LOGIN_WINDOW=10m
AUTO_DEFENSE_BLOCK_DURATION=5m

# Rate Limiting (relaxed)
RATE_LIMIT_LOGIN=100
RATE_LIMIT_LOGIN_WINDOW=60
RATE_LIMIT_SIGNUP=50
RATE_LIMIT_SIGNUP_WINDOW=60

# CORS
ALLOWED_ORIGINS=*

# Debug
DEBUG_MODE=true
ENABLE_PPROF=true
```

#### Stress Test Configuration

```bash
# ===========================================
# STRESS TEST CONFIGURATION
# ===========================================

# Server
PORT=8080
ADMIN_PORT=8081
LOG_LEVEL=warn
LOG_FORMAT=json

# Database (maxed connections)
DB_HOST=192.168.1.14
DB_PORT=5432
DB_NAME=oauth_stress
DB_USER=oauth
DB_PASSWORD=stress_test_password
DB_SSLMODE=disable
DB_POOL_SIZE=50
DB_MAX_IDLE_CONNS=25
DB_CONN_MAX_LIFETIME=15m

# JWT
JWT_PRIVATE_KEY_PATH=/home/pi/oauth/keys/private.pem
JWT_PUBLIC_KEY_PATH=/home/pi/oauth/keys/public.pem
JWT_ACCESS_TOKEN_TTL=5m
JWT_REFRESH_TOKEN_TTL=1h

# Security (disabled for stress test)
AUTO_DEFENSE_ENABLED=false

# Rate Limiting (disabled)
RATE_LIMIT_LOGIN=0
RATE_LIMIT_SIGNUP=0

# CORS
ALLOWED_ORIGINS=*
```

---

## Database Setup

### Create Test Database

```sql
-- Connect as postgres superuser
sudo -u postgres psql

-- Create test databases
CREATE DATABASE oauth_test;
CREATE DATABASE oauth_dev;
CREATE DATABASE oauth_stress;

-- Create user
CREATE USER oauth WITH PASSWORD 'test_secure_password_123';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE oauth_test TO oauth;
GRANT ALL PRIVILEGES ON DATABASE oauth_dev TO oauth;
GRANT ALL PRIVILEGES ON DATABASE oauth_stress TO oauth;

-- Connect to each database and grant schema permissions
\c oauth_test
GRANT ALL ON SCHEMA public TO oauth;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO oauth;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO oauth;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO oauth;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO oauth;

\c oauth_dev
GRANT ALL ON SCHEMA public TO oauth;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO oauth;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO oauth;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO oauth;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO oauth;

\c oauth_stress
GRANT ALL ON SCHEMA public TO oauth;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO oauth;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO oauth;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO oauth;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO oauth;
```

### PostgreSQL Test Configuration

```ini
# /etc/postgresql/15/main/postgresql.conf

# Memory (for 4GB Raspberry Pi)
shared_buffers = 512MB
effective_cache_size = 1536MB
work_mem = 8MB
maintenance_work_mem = 128MB

# Connections
max_connections = 150
superuser_reserved_connections = 5

# Write Ahead Log
wal_buffers = 16MB
checkpoint_completion_target = 0.9
synchronous_commit = off  # Faster for testing

# Query Planning
random_page_cost = 1.1
effective_io_concurrency = 200

# Logging
log_min_duration_statement = 500
log_checkpoints = on
log_connections = off
log_disconnections = off
log_lock_waits = on
log_temp_files = 0

# Statistics
track_activities = on
track_counts = on
track_io_timing = on
track_functions = all
```

---

## Test Data Fixtures

### Generate RSA Keys

```bash
#!/bin/bash
# generate-keys.sh

mkdir -p keys

# Generate RSA private key
openssl genrsa -out keys/private.pem 2048

# Extract public key
openssl rsa -in keys/private.pem -pubout -out keys/public.pem

# Set permissions
chmod 600 keys/private.pem
chmod 644 keys/public.pem

echo "Keys generated in ./keys/"
```

### Seed Test Data

```sql
-- seed-test-data.sql
-- Run with: psql -U oauth -d oauth_test -f seed-test-data.sql

-- Create test superadmin
INSERT INTO users (email, password_hash, first_name, last_name, is_superadmin, email_verified, created_at, updated_at)
VALUES (
    'admin@test.local',
    '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZRGdjGj/n3.wNkJpXgGVmeLqj5q2O', -- password: admin123
    'Test',
    'Admin',
    true,
    true,
    NOW(),
    NOW()
) ON CONFLICT (email) DO NOTHING;

-- Create test users
INSERT INTO users (email, password_hash, first_name, last_name, is_superadmin, email_verified, created_at, updated_at)
VALUES
    ('user1@test.local', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZRGdjGj/n3.wNkJpXgGVmeLqj5q2O', 'User', 'One', false, true, NOW(), NOW()),
    ('user2@test.local', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZRGdjGj/n3.wNkJpXgGVmeLqj5q2O', 'User', 'Two', false, true, NOW(), NOW()),
    ('user3@test.local', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZRGdjGj/n3.wNkJpXgGVmeLqj5q2O', 'User', 'Three', false, true, NOW(), NOW())
ON CONFLICT (email) DO NOTHING;

-- Create test applications
INSERT INTO apps (name, client_id, client_secret, redirect_uris, grant_types, scopes, created_at, updated_at)
VALUES
    (
        'Test Web App',
        'test_web_app_client_id',
        '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZRGdjGj/n3.wNkJpXgGVmeLqj5q2O', -- secret: test_secret
        ARRAY['http://localhost:3000/callback', 'http://192.168.1.20:3000/callback'],
        ARRAY['authorization_code', 'refresh_token'],
        ARRAY['openid', 'profile', 'email'],
        NOW(),
        NOW()
    ),
    (
        'Test API Client',
        'test_api_client_id',
        '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZRGdjGj/n3.wNkJpXgGVmeLqj5q2O',
        ARRAY[]::text[],
        ARRAY['client_credentials'],
        ARRAY['api:read', 'api:write'],
        NOW(),
        NOW()
    ),
    (
        'Load Test App',
        'load_test_client_id',
        '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZRGdjGj/n3.wNkJpXgGVmeLqj5q2O',
        ARRAY['http://localhost:8888/callback'],
        ARRAY['client_credentials', 'authorization_code', 'refresh_token'],
        ARRAY['openid', 'profile', 'email', 'api:read'],
        NOW(),
        NOW()
    )
ON CONFLICT DO NOTHING;

-- Create alert rules for testing
INSERT INTO alert_rules (name, description, event_type, condition, severity, enabled, actions, created_at, updated_at)
VALUES
    (
        'Test Brute Force Alert',
        'Alert on brute force detection',
        'brute_force_detected',
        '{"threshold": 1}',
        'critical',
        true,
        ARRAY['log'],
        NOW(),
        NOW()
    ),
    (
        'Test Account Lockout Alert',
        'Alert on account lockout',
        'account_locked',
        '{"threshold": 1}',
        'error',
        true,
        ARRAY['log'],
        NOW(),
        NOW()
    )
ON CONFLICT DO NOTHING;
```

### Test Credentials Reference

| User | Email | Password | Role |
|------|-------|----------|------|
| Admin | admin@test.local | admin123 | Superadmin |
| User 1 | user1@test.local | admin123 | User |
| User 2 | user2@test.local | admin123 | User |
| User 3 | user3@test.local | admin123 | User |

| App | Client ID | Client Secret | Flows |
|-----|-----------|---------------|-------|
| Web App | test_web_app_client_id | test_secret | authorization_code, refresh_token |
| API Client | test_api_client_id | test_secret | client_credentials |
| Load Test | load_test_client_id | test_secret | All |

---

## Load Testing

### Apache Bench (ab)

```bash
#!/bin/bash
# load-test-ab.sh

BASE_URL="http://192.168.1.10"

echo "=== Health Check Load Test ==="
ab -n 1000 -c 50 $BASE_URL/health

echo ""
echo "=== Discovery Endpoint Load Test ==="
ab -n 500 -c 25 $BASE_URL/.well-known/openid-configuration

echo ""
echo "=== JWKS Endpoint Load Test ==="
ab -n 500 -c 25 $BASE_URL/.well-known/jwks.json
```

### k6 Load Test Script

```javascript
// load-test.js
// Run with: k6 run load-test.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const errorRate = new Rate('errors');
const tokenLatency = new Trend('token_latency');

export const options = {
    stages: [
        { duration: '30s', target: 10 },   // Ramp up
        { duration: '1m', target: 50 },    // Stay at 50 users
        { duration: '30s', target: 100 },  // Peak
        { duration: '1m', target: 100 },   // Stay at peak
        { duration: '30s', target: 0 },    // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<500'],  // 95% requests under 500ms
        errors: ['rate<0.1'],               // Error rate under 10%
    },
};

const BASE_URL = __ENV.BASE_URL || 'http://192.168.1.10';
const CLIENT_ID = 'load_test_client_id';
const CLIENT_SECRET = 'test_secret';

export function setup() {
    // Get initial token
    const tokenRes = http.post(`${BASE_URL}/oauth/token`, {
        grant_type: 'client_credentials',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        scope: 'api:read',
    });

    return { token: JSON.parse(tokenRes.body).access_token };
}

export default function(data) {
    // Test 1: Health check
    let res = http.get(`${BASE_URL}/health`);
    check(res, { 'health check OK': (r) => r.status === 200 });
    errorRate.add(res.status !== 200);

    // Test 2: Token issuance
    const start = Date.now();
    res = http.post(`${BASE_URL}/oauth/token`, {
        grant_type: 'client_credentials',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        scope: 'api:read',
    });
    tokenLatency.add(Date.now() - start);
    check(res, { 'token issued': (r) => r.status === 200 });
    errorRate.add(res.status !== 200);

    // Test 3: Token introspection
    if (data.token) {
        res = http.post(`${BASE_URL}/oauth/introspect`, {
            token: data.token,
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
        });
        check(res, { 'introspect OK': (r) => r.status === 200 });
    }

    // Test 4: Discovery endpoint
    res = http.get(`${BASE_URL}/.well-known/openid-configuration`);
    check(res, { 'discovery OK': (r) => r.status === 200 });

    sleep(0.1); // 100ms pause between iterations
}

export function teardown(data) {
    console.log('Load test completed');
}
```

### k6 Execution Commands

```bash
# Basic run
k6 run load-test.js

# With environment variables
k6 run -e BASE_URL=http://192.168.1.10 load-test.js

# With output to file
k6 run --out json=results.json load-test.js

# With specific VUs and duration
k6 run --vus 50 --duration 5m load-test.js
```

### Locust Load Test

```python
# locustfile.py
# Run with: locust -f locustfile.py --host=http://192.168.1.10

from locust import HttpUser, task, between
import json

class OAuthUser(HttpUser):
    wait_time = between(0.1, 0.5)

    def on_start(self):
        """Get token on user start"""
        response = self.client.post("/oauth/token", data={
            "grant_type": "client_credentials",
            "client_id": "load_test_client_id",
            "client_secret": "test_secret",
            "scope": "api:read"
        })
        if response.status_code == 200:
            self.token = response.json().get("access_token")
        else:
            self.token = None

    @task(10)
    def health_check(self):
        self.client.get("/health")

    @task(5)
    def get_token(self):
        self.client.post("/oauth/token", data={
            "grant_type": "client_credentials",
            "client_id": "load_test_client_id",
            "client_secret": "test_secret",
            "scope": "api:read"
        })

    @task(3)
    def discovery(self):
        self.client.get("/.well-known/openid-configuration")

    @task(2)
    def jwks(self):
        self.client.get("/.well-known/jwks.json")

    @task(2)
    def introspect(self):
        if self.token:
            self.client.post("/oauth/introspect", data={
                "token": self.token,
                "client_id": "load_test_client_id",
                "client_secret": "test_secret"
            })
```

---

## Security Testing

### Security Test Configuration

```bash
# security-test.env
# Configuration for security testing SPA

OAUTH_SERVER_URL=http://192.168.1.10
ADMIN_API_URL=http://192.168.1.10:8081
CLIENT_ID=test_web_app_client_id
CLIENT_SECRET=test_secret
TEST_USER_EMAIL=user1@test.local
TEST_USER_PASSWORD=admin123
ADMIN_EMAIL=admin@test.local
ADMIN_PASSWORD=admin123
```

### Brute Force Test Script

```bash
#!/bin/bash
# test-brute-force.sh

BASE_URL="http://192.168.1.10"
CLIENT_ID="test_web_app_client_id"

echo "=== Brute Force Protection Test ==="
echo "Sending 15 failed login attempts..."

for i in {1..15}; do
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$BASE_URL/oauth/token" \
        -d "grant_type=password" \
        -d "client_id=$CLIENT_ID" \
        -d "username=user1@test.local" \
        -d "password=wrong_password_$i")

    echo "Attempt $i: HTTP $response"

    if [ "$response" = "429" ]; then
        echo "Rate limited at attempt $i - Protection working!"
        break
    fi

    sleep 0.5
done

echo ""
echo "=== Checking blocked IPs ==="
curl -s "$BASE_URL:8081/api/admin/security/blocked-ips" \
    -H "Authorization: Bearer $(cat /tmp/admin_token)" | jq .
```

### XSS Test Script

```bash
#!/bin/bash
# test-xss-protection.sh

BASE_URL="http://192.168.1.10"
CLIENT_ID="test_web_app_client_id"

echo "=== XSS Redirect URI Protection Test ==="

dangerous_uris=(
    "javascript:alert(1)"
    "data:text/html,<script>alert(1)</script>"
    "vbscript:msgbox(1)"
    "file:///etc/passwd"
)

for uri in "${dangerous_uris[@]}"; do
    echo -n "Testing: $uri ... "

    response=$(curl -s -o /dev/null -w "%{http_code}" \
        "$BASE_URL/oauth/authorize?client_id=$CLIENT_ID&response_type=code&redirect_uri=$(echo $uri | jq -sRr @uri)")

    if [ "$response" = "400" ]; then
        echo "BLOCKED (400) - OK"
    else
        echo "HTTP $response - POTENTIAL ISSUE!"
    fi
done
```

### Security Headers Test

```bash
#!/bin/bash
# test-security-headers.sh

BASE_URL="http://192.168.1.10"

echo "=== Security Headers Test ==="

headers=$(curl -sI "$BASE_URL/health")

required_headers=(
    "X-Content-Type-Options"
    "X-Frame-Options"
    "Content-Security-Policy"
    "Strict-Transport-Security"
)

for header in "${required_headers[@]}"; do
    if echo "$headers" | grep -qi "$header"; then
        value=$(echo "$headers" | grep -i "$header" | cut -d: -f2- | tr -d '\r')
        echo "✅ $header:$value"
    else
        echo "❌ $header: MISSING"
    fi
done
```

---

## Monitoring Configuration

### HAProxy Stats

Access at: `http://192.168.1.10:8404/stats`

Credentials: `admin:yourpassword`

### Real-time Event Monitoring

```bash
#!/bin/bash
# monitor-events.sh

ADMIN_URL="http://192.168.1.10:8081"
TOKEN=$(cat /tmp/admin_token)

echo "=== Real-time Security Events ==="
echo "Press Ctrl+C to stop"

curl -N -H "Authorization: Bearer $TOKEN" \
    "$ADMIN_URL/api/admin/events/stream?severity=warning,error,critical"
```

### Cluster Health Check Script

```bash
#!/bin/bash
# cluster-health.sh

echo "=========================================="
echo "   OAuth2 Cluster Health Check"
echo "   $(date)"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

check_endpoint() {
    local name=$1
    local url=$2
    local expected=$3

    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url")

    if [ "$status" = "$expected" ]; then
        echo -e "${GREEN}✅${NC} $name: UP (HTTP $status)"
        return 0
    else
        echo -e "${RED}❌${NC} $name: DOWN (HTTP $status, expected $expected)"
        return 1
    fi
}

echo "--- Load Balancer ---"
check_endpoint "HAProxy Health" "http://192.168.1.10/health" "200"
check_endpoint "HAProxy Stats" "http://192.168.1.10:8404/stats" "401"

echo ""
echo "--- OAuth Servers ---"
check_endpoint "OAuth1 Health" "http://192.168.1.11:8080/health" "200"
check_endpoint "OAuth1 Readiness" "http://192.168.1.11:8080/health/readiness" "200"
check_endpoint "OAuth2 Health" "http://192.168.1.12:8080/health" "200"
check_endpoint "OAuth2 Readiness" "http://192.168.1.12:8080/health/readiness" "200"

echo ""
echo "--- Database ---"
if pg_isready -h 192.168.1.14 -p 5432 -U oauth > /dev/null 2>&1; then
    echo -e "${GREEN}✅${NC} PostgreSQL: UP"
else
    echo -e "${RED}❌${NC} PostgreSQL: DOWN"
fi

echo ""
echo "--- OAuth Endpoints ---"
check_endpoint "Discovery" "http://192.168.1.10/.well-known/openid-configuration" "200"
check_endpoint "JWKS" "http://192.168.1.10/.well-known/jwks.json" "200"

echo ""
echo "--- Admin API ---"
check_endpoint "Admin Health" "http://192.168.1.10:8081/health" "200"

echo ""
echo "=========================================="
```

### Prometheus Metrics Collection

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'oauth-servers'
    static_configs:
      - targets:
        - '192.168.1.11:8080'
        - '192.168.1.12:8080'
    metrics_path: '/metrics'

  - job_name: 'haproxy'
    static_configs:
      - targets: ['192.168.1.10:8404']
    metrics_path: '/stats'
    params:
      stats: ['all']

  - job_name: 'postgres'
    static_configs:
      - targets: ['192.168.1.14:9187']
```

---

## Troubleshooting

### Common Issues

#### 1. Connection Refused

```bash
# Check if service is running
systemctl status oauth

# Check if port is listening
ss -tlnp | grep 8080

# Check firewall
sudo ufw status
```

#### 2. Database Connection Failed

```bash
# Test connection
psql -h 192.168.1.14 -U oauth -d oauth_test -c "SELECT 1"

# Check PostgreSQL status
systemctl status postgresql

# Check pg_hba.conf allows connection
cat /etc/postgresql/15/main/pg_hba.conf | grep oauth
```

#### 3. Token Generation Failed

```bash
# Check key files exist
ls -la /home/pi/oauth/keys/

# Test key validity
openssl rsa -in /home/pi/oauth/keys/private.pem -check
```

#### 4. High Latency

```bash
# Check database connection pool
curl http://192.168.1.11:8081/health/readiness | jq .

# Check system resources
htop

# Check network latency
ping -c 10 192.168.1.14
```

### Debug Logging

```bash
# Enable debug mode temporarily
export LOG_LEVEL=debug
systemctl restart oauth

# Watch logs
journalctl -u oauth -f

# Disable debug mode
export LOG_LEVEL=info
systemctl restart oauth
```

### Performance Profiling

```bash
# Enable pprof (add to .env)
ENABLE_PPROF=true

# Collect CPU profile (30 seconds)
curl -o cpu.prof http://192.168.1.11:6060/debug/pprof/profile?seconds=30

# Collect heap profile
curl -o heap.prof http://192.168.1.11:6060/debug/pprof/heap

# Analyze with go tool
go tool pprof cpu.prof
```

---

## Quick Reference

### Useful Commands

```bash
# Get admin token
curl -s -X POST http://192.168.1.10/oauth/token \
    -d "grant_type=password" \
    -d "client_id=test_web_app_client_id" \
    -d "client_secret=test_secret" \
    -d "username=admin@test.local" \
    -d "password=admin123" | jq -r .access_token > /tmp/admin_token

# Test client_credentials flow
curl -X POST http://192.168.1.10/oauth/token \
    -d "grant_type=client_credentials" \
    -d "client_id=test_api_client_id" \
    -d "client_secret=test_secret" \
    -d "scope=api:read" | jq .

# Check security events
curl -H "Authorization: Bearer $(cat /tmp/admin_token)" \
    http://192.168.1.10:8081/api/admin/security/events | jq .

# Check threat metrics
curl -H "Authorization: Bearer $(cat /tmp/admin_token)" \
    http://192.168.1.10:8081/api/admin/security/threats | jq .

# Generate security report
curl -X POST -H "Authorization: Bearer $(cat /tmp/admin_token)" \
    -H "Content-Type: application/json" \
    -d '{"type":"security_summary","format":"json"}' \
    http://192.168.1.10:8081/api/admin/reports/security | jq .
```

### Expected Performance Metrics

| Metric | Single Pi 4 | 2x Pi 4 Cluster | Target |
|--------|-------------|-----------------|--------|
| Token/sec | 80-120 | 150-200 | >100 |
| Login/sec | 50-80 | 100-150 | >50 |
| P95 Latency | 40-60ms | 30-50ms | <100ms |
| Error Rate | <0.1% | <0.1% | <1% |
| Memory | 150-250MB | 150-250MB each | <512MB |

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024-12-28 | Initial test configuration document |

