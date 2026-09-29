# CR: Geographic Analytics API

## Overview

This document describes the Geographic Analytics API for the OAuth2 Security Monitoring system. The API provides real-time geographic intelligence about authentication activity across your applications.

## Feature Summary

| Feature | Description |
|---------|-------------|
| **IP Geolocation** | Real-time country/city lookup for all login IPs |
| **Country Analytics** | Aggregated login statistics by country |
| **City Analytics** | Detailed city-level login data with coordinates |
| **Anomaly Detection** | Automatic detection of suspicious login patterns |
| **Period Filtering** | Flexible time-range filtering (15m to 30d) |

---

## API Endpoint

### GET /api/admin/security/geo

Returns geographic analytics for authentication events.

#### Authentication

Requires admin authentication via Bearer token.

```bash
curl -X GET "http://localhost:8081/api/admin/security/geo?period=24h" \
  -H "Authorization: Bearer <admin_token>"
```

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `period` | string | No | `24h` | Time period for analytics |

**Available Periods:**

| Value | Description |
|-------|-------------|
| `15m` | Last 15 minutes (real-time monitoring) |
| `1h` | Last hour |
| `24h` | Last 24 hours |
| `7d` | Last 7 days |
| `30d` | Last 30 days |

---

## Response Schema

### GeoAnalyticsResponse

```typescript
interface GeoAnalyticsResponse {
  period: string;           // The requested time period
  geo_configured: boolean;  // Whether GeoIP database is configured
  by_country: GeoCountryStats[];
  by_city: GeoCityStats[];
  anomalies: GeoAnomaly[];
}
```

### GeoCountryStats

```typescript
interface GeoCountryStats {
  country_code: string;    // ISO 3166-1 alpha-2 code (e.g., "US", "FR")
  country_name: string;    // Full country name (e.g., "United States")
  login_count: number;     // Total login attempts
  unique_users: number;    // Number of unique users
  failed_count: number;    // Failed login attempts
}
```

### GeoCityStats

```typescript
interface GeoCityStats {
  city: string;            // City name or IP address if unknown
  country_code: string;    // ISO country code
  latitude: number;        // GPS latitude (for map display)
  longitude: number;       // GPS longitude (for map display)
  login_count: number;     // Total login attempts
  failed_count: number;    // Failed login attempts
}
```

### GeoAnomaly

```typescript
interface GeoAnomaly {
  user_id: number;
  user_email: string;
  description: string;     // Human-readable anomaly description
  usual_country: string;   // User's typical login country
  login_country: string;   // Current login country
  created_at: string;      // ISO 8601 timestamp
}
```

---

## Example Response

### With GeoIP Configured

```json
{
  "period": "24h",
  "geo_configured": true,
  "by_country": [
    {
      "country_code": "US",
      "country_name": "United States",
      "login_count": 1250,
      "unique_users": 342,
      "failed_count": 45
    },
    {
      "country_code": "FR",
      "country_name": "France",
      "login_count": 320,
      "unique_users": 89,
      "failed_count": 12
    },
    {
      "country_code": "DE",
      "country_name": "Germany",
      "login_count": 185,
      "unique_users": 56,
      "failed_count": 8
    }
  ],
  "by_city": [
    {
      "city": "New York",
      "country_code": "US",
      "latitude": 40.7128,
      "longitude": -74.0060,
      "login_count": 450,
      "failed_count": 15
    },
    {
      "city": "Paris",
      "country_code": "FR",
      "latitude": 48.8566,
      "longitude": 2.3522,
      "login_count": 280,
      "failed_count": 10
    },
    {
      "city": "San Francisco",
      "country_code": "US",
      "latitude": 37.7749,
      "longitude": -122.4194,
      "login_count": 220,
      "failed_count": 5
    }
  ],
  "anomalies": [
    {
      "user_id": 123,
      "user_email": "john@example.com",
      "description": "Suspicious: Login from Russia (usually from United States)",
      "usual_country": "United States",
      "login_country": "Russia",
      "created_at": "2024-01-15T14:30:00Z"
    }
  ]
}
```

### Without GeoIP Configured (Fallback Mode)

```json
{
  "period": "24h",
  "geo_configured": false,
  "by_country": [
    {
      "country_code": "LO",
      "country_name": "Local Network",
      "login_count": 150,
      "unique_users": 25,
      "failed_count": 5
    },
    {
      "country_code": "XX",
      "country_name": "Unknown",
      "login_count": 1200,
      "unique_users": 300,
      "failed_count": 50
    }
  ],
  "by_city": [
    {
      "city": "192.168.1.100",
      "country_code": "LO",
      "latitude": 0,
      "longitude": 0,
      "login_count": 150,
      "failed_count": 5
    },
    {
      "city": "45.33.32.156",
      "country_code": "XX",
      "latitude": 0,
      "longitude": 0,
      "login_count": 85,
      "failed_count": 3
    }
  ],
  "anomalies": [
    {
      "user_id": 456,
      "user_email": "jane@example.com",
      "description": "Login from multiple IPs (5 different IPs)",
      "usual_country": "192.168.1.50",
      "login_country": "10.0.0.25",
      "created_at": "2024-01-15T10:15:00Z"
    }
  ]
}
```

---

## Special Country Codes

| Code | Meaning |
|------|---------|
| `XX` | Unknown location (GeoIP lookup failed or not configured) |
| `LO` | Local/Private network (127.x.x.x, 192.168.x.x, 10.x.x.x, etc.) |

---

## Frontend Implementation Guide

### 1. World Map Visualization

Use the `by_city` data to display login locations on a map:

```javascript
// Using Leaflet.js or similar
byCity.forEach(city => {
  if (city.latitude !== 0 && city.longitude !== 0) {
    addMarker({
      lat: city.latitude,
      lng: city.longitude,
      label: `${city.city}: ${city.login_count} logins`,
      color: city.failed_count > 10 ? 'red' : 'green'
    });
  }
});
```

### 2. Country Distribution Chart

```javascript
// Pie chart data
const chartData = byCountry.map(country => ({
  label: country.country_name,
  value: country.login_count,
  failRate: (country.failed_count / country.login_count * 100).toFixed(1)
}));
```

### 3. Anomaly Alerts

Display anomalies prominently with severity indicators:

```javascript
anomalies.forEach(anomaly => {
  const isCrossCountry = anomaly.usual_country !== anomaly.login_country;
  showAlert({
    severity: isCrossCountry ? 'high' : 'medium',
    user: anomaly.user_email,
    message: anomaly.description,
    time: anomaly.created_at
  });
});
```

### 4. GeoIP Status Banner

Show configuration status to admins:

```javascript
if (!response.geo_configured) {
  showBanner({
    type: 'warning',
    message: 'GeoIP database not configured. Geographic data is limited.',
    action: {
      label: 'Configure GeoIP',
      link: '/admin/settings/geoip'
    }
  });
}
```

---

## Configuration

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `GEOIP_CITY_DB` | Path to GeoLite2-City.mmdb file | `/data/GeoLite2-City.mmdb` |
| `GEOIP_ASN_DB` | Path to GeoLite2-ASN.mmdb (optional) | `/data/GeoLite2-ASN.mmdb` |

### Setting Up MaxMind GeoLite2

1. **Create a free MaxMind account**: https://www.maxmind.com/en/geolite2/signup

2. **Download the databases**:
   - GeoLite2-City.mmdb (required)
   - GeoLite2-ASN.mmdb (optional, for ISP info)

3. **Configure the server**:
   ```bash
   export GEOIP_CITY_DB=/path/to/GeoLite2-City.mmdb
   export GEOIP_ASN_DB=/path/to/GeoLite2-ASN.mmdb
   ```

4. **Restart the OAuth server**

---

## Use Cases

### 1. Security Monitoring Dashboard

Display a real-time map showing:
- Active login locations (last 15 minutes)
- Failed login hotspots (highlighted in red)
- Anomalous login patterns

### 2. Compliance Reporting

Generate geographic distribution reports for:
- GDPR compliance (EU user locations)
- Data residency requirements
- User base analytics

### 3. Threat Detection

Identify potential threats:
- Login attempts from unusual countries
- Impossible travel (login from two distant locations within minutes)
- Concentrated failed logins from specific regions

### 4. Access Policy Enforcement

Use geographic data to:
- Trigger additional MFA for foreign logins
- Block logins from embargoed countries
- Alert on after-hours logins from unexpected regions

---

## Rate Limiting

| Endpoint | Rate Limit |
|----------|------------|
| GET /api/admin/security/geo | 60 requests/minute |

---

## Error Responses

| Status | Error | Description |
|--------|-------|-------------|
| 401 | Unauthorized | Missing or invalid auth token |
| 403 | Forbidden | User lacks admin privileges |
| 500 | Internal Server Error | Database or service error |

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01-15 | Initial release |
| 1.1.0 | 2024-01-20 | Added 15m period, GeoIP integration |

---

## Related APIs

- [Alert Rules API](./ALERT-RULES.md) - Configure geographic-based alerts
- Security events and token analytics — the other `/api/admin/security/*` and monitoring endpoints,
  used by the monitoring console ([`ovander/oauth2-monitoring`](https://github.com/ovander/oauth2-monitoring))
