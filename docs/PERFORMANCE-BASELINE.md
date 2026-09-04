# Performance baseline (B6)

Measured numbers for sizing a deployment, and the method to reproduce them.
Scenarios live in [`deploy/perf/`](../deploy/perf/).

> **The headline, up front.** Every endpoint that authenticates a client by its
> secret is bounded by **bcrypt at cost 12 — 273 ms of CPU per verification**.
> On 4 vCPUs that is a hard ceiling of **~14 requests/second**, no matter how
> fast the database or the network is. Endpoints that do *not* verify a client
> secret run roughly **12× faster** and saturate around 110 rps on the same box.
> Size for the mix you actually serve, and read [Sizing](#sizing) before
> provisioning.

## The measured baseline

Environment: 4 vCPU container, PostgreSQL 16 on loopback, Go server and load
generator on the same host, k6 v1.8.1, 20 s constant-arrival-rate runs.
Co-locating the load generator costs the server some CPU, so treat these as a
**conservative floor** rather than a ceiling.

| Scenario | Offered rate | Achieved | p95 | Failures | Bound by |
|---|---:|---:|---:|---:|---|
| `discovery` (+ JWKS) | 50/s | 50/s | **0.8 ms** | 0% | nothing — framework floor |
| `token_refresh` (public client) | 50/s | 45/s | **24 ms** | 0% | Postgres + RS256 signing |
| `token_refresh` (public client) | 100/s | 89/s | **22 ms** | 0% | as above |
| `token_refresh` (public client) | 200/s | **108/s** | 954 ms | 0% | saturated — see below |
| `login` (password) | 10/s | 10/s | **93 ms** | 0% | bcrypt cost 10 (68 ms) |
| `introspect` (confidential) | 10/s | 9.8/s | **295 ms** | 0% | **bcrypt cost 12 (273 ms)** |
| `client_credentials` (confidential) | 10/s | 10/s | **299 ms** | 0% | **bcrypt cost 12 (273 ms)** |
| `client_credentials` (confidential) | 50/s | 19/s | **20.5 s** | 20% | past the ceiling — collapsed |

Two rows are worth dwelling on.

**`token_refresh` at 200/s** delivered 108/s with **zero errors** and a p95 of
954 ms. That is clean saturation: the server kept every request and answered
correctly, it simply could not go faster, so latency absorbed the excess. The
sustainable figure on this hardware is **~110 rps**.

**`client_credentials` at 50/s** is what exceeding a bcrypt ceiling looks like:
20% outright failures and a p95 of 20 seconds. The queue grows without bound
because arrivals (50/s) exceed service capacity (~14/s) — nothing recovers until
load drops.

## Why the client-secret endpoints are slow

`HashClientSecret` uses **bcrypt cost 12** (`internal/shared/auth/password.go`).
Measured on this hardware:

| bcrypt cost | per verification | per core | 4 cores |
|---|---:|---:|---:|
| 10 (user passwords) | 68 ms | 14.6/s | ~59/s |
| 12 (client secrets) | 273 ms | 3.7/s | **~14.6/s** |

Every confidential-client request pays it once:

- `POST /oauth/token` — `client_credentials`
- `POST /oauth/token` — `authorization_code` and `refresh_token` **for a
  confidential client**
- `POST /oauth/introspect` and `POST /oauth/revoke` (both authenticate the
  client since P4-4)

A **public** client (SPA, mobile, or a BFF using PKCE) has no secret to verify
and skips this entirely — which is the whole reason `token_refresh` above is
measured against a public client. Using a confidential client there would
produce a bcrypt benchmark wearing a refresh benchmark's name.

### Worth reconsidering

bcrypt's work factor exists to slow brute force against **low-entropy human
passwords**. A Socrate client secret is 32 bytes of `crypto/rand` — roughly 256
bits of entropy. No work factor meaningfully changes the cost of brute-forcing
that; the entropy already does. Cost 12 buys close to nothing here and costs a
factor of ~20 in throughput on the busiest machine-to-machine paths.

A keyed hash (HMAC-SHA-256 over the secret, keyed by `SECRET_KEY_BASE`) would be
equally safe for a high-entropy value and about four orders of magnitude faster,
lifting the ceiling from ~14/s to something bounded by the database instead.
That is a **security-relevant change and is not made here** — it is recorded so
the decision is made deliberately rather than inherited. Dropping to cost 10
would be a smaller, cheaper step (~59/s on 4 cores).

Until then, the practical mitigations are: prefer public clients with PKCE where
the architecture allows, validate JWTs locally at resource servers instead of
calling `/oauth/introspect` on every request (see
[`REVOCATION-FRESHNESS-SLA.md`](REVOCATION-FRESHNESS-SLA.md) for the tradeoff),
and size CPU for the confidential-client rate you actually need.

## Sizing

Per vCPU, roughly:

| Traffic | Per vCPU |
|---|---|
| Discovery / JWKS | thousands/s — never the constraint |
| Public-client token refresh | ~25–30/s |
| Password logins | ~14/s |
| Confidential-client token calls | **~3.7/s** |

For a deployment serving 100 concurrent SPA sessions with hourly refresh
(~0.03 rps) and a handful of service accounts, 2 vCPU is ample. What forces a
bigger box is confidential-client volume: 50 rps of `client_credentials` needs
**~14 vCPU** at cost 12, or ~4 at cost 10, or barely one with a keyed hash.

## Reproducing

Start a server with a seeded confidential client (`perf-client`), a public
client (`perf-public`) and a verified user, then:

```bash
cd deploy/perf
./run.sh                          # every scenario at its default rate
./run.sh token_refresh            # one scenario
RATE=200 DURATION=60s ./run.sh token_refresh
```

`run.sh` gives each scenario its own default rate on purpose — driving the
bcrypt-bound scenarios at the rates the public paths sustain measures a queue,
not a server. Summaries are written to `deploy/perf/results/`.

Scenarios read `BASE_URL`, `CLIENT_ID`, `PUBLIC_CLIENT`, `USER_EMAIL`,
`USER_PASSWORD`, `RATE`, `DURATION`, `VUS` and `P95_MS`; see
[`lib/config.js`](../deploy/perf/lib/config.js).

All scenarios use k6's `constant-arrival-rate` executor: it holds the offered
rate no matter how slow the server becomes. A VU-loop would quietly reduce load
as latency rose and report a flattering number — which is exactly how a
collapsed endpoint gets mistaken for a fast one.

## CI

The `perf smoke` job runs `discovery` and `token_refresh` against a real server
and Postgres on every pull request, with thresholds set from the table above
plus headroom for a shared CI runner. It is a **regression tripwire, not a
benchmark** — a GitHub runner is noisy and its absolute numbers mean little.
The bcrypt-bound scenarios are deliberately excluded: at ~14 rps their runtime
is dominated by a cost we already know, and they would add minutes to every PR
to re-measure a constant.

## Note on the plan's original target

`PLAN-EXTENSIBILITY-OBSERVABILITY.md` proposed *p95 token < 100 ms at 200 rps*.
That is achievable for **public-client** token traffic (measured: 22 ms p95 at
89 rps, saturating near 110 rps on 4 vCPU — 200 rps needs ~8 vCPU). It is **not
achievable for confidential clients** at any hardware size while client-secret
verification is bcrypt cost 12: 200 rps would require ~55 vCPU doing nothing but
bcrypt. The target has been restated per client type rather than quietly
dropped.
