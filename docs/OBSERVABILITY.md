# Observability — metrics, logs, SLOs

Plan items **B1** (Prometheus), **B3** (log schema) and **B7** (SLOs & alerts) of the extensibility
and observability programme. Traces (B2) are a later slice.

## 1. Metrics

`GET /metrics` on the **admin port only** (`127.0.0.1:8081`). It is never routed
from a public host — the Caddy site blocks in the deploy kits do not expose it,
and the runbook forbids adding it. Scrape from the same host or over a private
network (`deploy/observability/prometheus.yml`).

Cardinality rule: every label is a bounded enumeration. **No label carries a
user, client id, IP address or token** — those belong in the audit log.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `socrate_http_requests_total` | counter | `router` (`oauth`/`admin`/`unified`), `route` (chi pattern, e.g. `/oauth/token`, `/api/admin/users/{id}`, `unmatched`), `method`, `status` (`2xx`…`5xx`) | RED requests + errors |
| `socrate_http_request_duration_seconds` | histogram | `router`, `route`, `method` | RED latency (buckets 5 ms … 5 s) |
| `socrate_tokens_issued_total` | counter | `grant` (`authorization_code`, `refresh_token`, `client_credentials`, …), `outcome` (`success`, `invalid_grant`, `invalid_client`, `invalid_scope`, `unauthorized_client`, `unsupported_grant_type`, `error`) | token endpoint results |
| `socrate_security_events_total` | counter | `event_type` (every `SecurityEventType`: `login_success`, `login_failed`, `refresh_token_reuse`, `dpop_validation_failed`, `pkce_validation_failed`, `scope_denied`, `ip_blocked`, …), `success` | one counter per persisted audit event — the SOC console's raw signal as a time series |
| `socrate_rate_limit_hits_total` | counter | `route` | 429s per route pattern |
| `socrate_ip_blocks_total` | counter | — | requests refused by the block list |
| `socrate_policy_decisions_total` | counter | `source` (`admin_pep`, `decide_api`), `mode` (`shadow`/`enforce`), `outcome` (`allow`/`deny`/`error`) | A4 policy decisions; `error` means no policy version could be loaded |
| `socrate_policy_divergences_total` | counter | `source`, `kind` (`pdp_deny_code_allow`/`pdp_allow_code_deny`) | requests where the policy and the code gates disagreed — zero with the baseline; must be zero before a code gate is retired |
| `socrate_signing_key_age_seconds` | gauge | — | age of the active RSA key; compare with `KEY_ROTATION_INTERVAL_SECONDS` |
| `socrate_db_pool_{open_connections,in_use,idle,wait_count_total,wait_seconds_total}` | gauge | — | `sql.DB` pool |
| `socrate_build_info` | gauge | `version`, `commit` | always 1 |
| `go_*`, `process_*` | — | — | Go runtime and process collectors |

Useful expressions:

```promql
# token endpoint p99 (SLO: < 150 ms)
histogram_quantile(0.99, sum by (le) (rate(socrate_http_request_duration_seconds_bucket{route="/oauth/token"}[5m])))
# 5xx ratio, public router
sum(rate(socrate_http_requests_total{router="oauth",status="5xx"}[5m])) / sum(rate(socrate_http_requests_total{router="oauth"}[5m]))
# login failure ratio
sum(rate(socrate_security_events_total{event_type="login_failed"}[10m])) / sum(rate(socrate_security_events_total{event_type=~"login_(failed|success)"}[10m]))
# refresh-token reuse (any value > 0 is a token-theft signal)
increase(socrate_security_events_total{event_type="refresh_token_reuse"}[15m])
```

## 2. Logs

One JSON object per line (`LOG_FORMAT=json`, the production default), written
by logrus. Fields:

| Field | Always | Source |
|---|---|---|
| `time`, `level`, `msg` | yes | logrus |
| `correlation_id` | on requests | `X-Correlation-ID` (generated when absent), propagated to responses |
| `request_id` | on requests | chi request id |
| `client_ip` | on requests | the attributed client IP (`TRUSTED_PROXIES`-aware) — if this is always `127.0.0.1` behind Caddy, proxy trust is misconfigured |
| `method`, `path`, `status`, `duration_ms` | on requests | **path, never the query string** — reset / verify / invite tokens travel in query strings |
| `user_id`, `app_id`, `client_id` | when known | identifiers, never emails in request logs |
| `caller` | yes | file:line |

Rules, enforced by `pkg/logger/redaction_guard_test.go` (fails the build when
a log call carries a secret-bearing expression): never log access, refresh or
ID tokens, client secrets, passwords or hashes, TOTP secrets, code verifiers,
`Authorization` headers, or private keys. Error values from repositories are
logged (`logger.Warnf("…: %v", err)`) but never returned to clients (P2-1/P2-2).

Levels: `error` = operator action needed; `warn` = rejected request or
degraded dependency; `info` = lifecycle and one line per request; `debug` =
per-grant dispatch (`LOG_LEVEL=debug`, not in production).

Shipping: the systemd units log to the journal (`journalctl -u socrate -o json`);
`deploy/observability/promtail.yml` is a starting point for Loki.

## 3. SLOs and alerts (B7)

| SLO | Objective | Measured by |
|---|---|---|
| Token endpoint availability | 99.9 % non-5xx over 30 d | `socrate_http_requests_total{route="/oauth/token"}` |
| Token endpoint latency | p99 < 150 ms | `socrate_http_request_duration_seconds{route="/oauth/token"}` |
| Hosted login latency | p99 < 400 ms (bcrypt-bound) | `route="/oauth/authorize"`, `POST` |
| Signing key freshness | age < rotation interval + 1 h | `socrate_signing_key_age_seconds` |
| Revocation freshness | per `REVOCATION-FRESHNESS-SLA.md` | access-token TTL config |

`deploy/observability/alert-rules.yml` turns these — plus the security
signals (refresh reuse, DPoP rejects, auto-defense blocks, rate-limit surges,
scope denials in enforce mode, JWKS/DB pool saturation) — into Alertmanager
rules with runbook links. `grafana-dashboard.json` is the matching dashboard
(identity overview, auth funnel, security signals, resources).
