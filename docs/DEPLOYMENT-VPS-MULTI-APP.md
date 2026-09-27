# Socrate Suite — Deployment on a Linux VPS (Caddy + Postgres), multi-app

**Scope.** One Linux VPS running the whole suite — the Socrate OAuth 2.1 / OIDC
server (`go-oauth2`), the admin console and the monitoring console (each a
static SPA plus a Go BFF) — **and any number of relying-party applications**
that authenticate against Socrate: their own SPAs, BFFs or back-ends, on their
own subdomains, sharing the same Caddy edge and the same Postgres cluster.

This document is the suite-level runbook. The per-repo deploy kits it builds on:

| Kit | Installs | Path in repo |
|---|---|---|
| `oauth2-monitoring/deploy/` | the `socrate` service user, **Socrate itself** (`socrate.service`, `socrate.env`), the monitoring BFF, the **main `/etc/caddy/Caddyfile`**, backups | `deploy/README.md` |
| `oauth2-admin/deploy/` | the admin BFF, its env file, and the admin **Caddy site file** under `/etc/caddy/sites/` | `deploy/README.md` |

Security posture and the closed audit ledger are in
`docs/CR-socrate-suite-remediation-plan.md` (rev. 6). Nothing in this document
relaxes a control from that plan.

---

## 1. Topology

```
                              Internet (80/443 only)
                                       │
                                ┌──────▼──────┐
                                │    Caddy    │  the ONLY public listener
                                │  TLS, static│  one site block per hostname
                                └┬──┬──┬──┬──┬┘
        auth.example.com         │  │  │  │  │
        ┌────────────────────────┘  │  │  │  └───────────────────────┐
        ▼                           │  │  │                           ▼
 127.0.0.1:8080  Socrate OAuth      │  │  │          app-N.example.com: SPA files (root-owned)
 (public OIDC: authorize, token,    │  │  │          + /bff/* /api/* → 127.0.0.1:9N00  (app-N BFF / API)
  jwks, userinfo, hosted login)     │  │  │                           │
        │                           │  │  │                           │ validates JWTs via JWKS,
        │  admin.example.com        │  │  │                           │ or calls Socrate as a
        │  ┌────────────────────────┘  │  └────────────┐              │ confidential client
        │  ▼                           ▼               ▼              │
        │ /srv/admin/dist (SPA)   monitoring.example.com              │
        │ + /bff/* /api/admin/*   /srv/monitoring/dist (SPA)          │
        │   /api/profile          + /bff/* /api/admin/*               │
        │   /api/version               │                              │
        │   /api/auth/*-password-reset │                              │
        │        │                     │                              │
        │        ▼                     ▼                              │
        │ 127.0.0.1:8091          127.0.0.1:8090                      │
        │ admin BFF               monitoring BFF                      │
        │        │                     │                              │
        │        └─────────┬───────────┘                              │
        │                  ▼                                          │
        │        127.0.0.1:8081  Socrate ADMIN API (loopback only)    │
        │                  │                                          │
        ▼                  ▼                                          ▼
   127.0.0.1:5432  Postgres — one cluster, one database + role per service
                   (socrate · app_1 · app_2 · …)
```

**Invariants** (everything below exists to keep these true):

1. Caddy is the only process bound to a public interface. Every service binds
   `127.0.0.1`.
2. The Socrate admin API (`:8081`) has **no public hostname**. Its only clients
   are the two console BFFs, over loopback.
3. Browsers never hold OAuth tokens for the consoles: each console's BFF is a
   confidential client that keeps tokens in a server-side session and injects
   the bearer. Relying-party apps are encouraged to use the same pattern
   (§6.2) but may be public PKCE clients (§6.3).
4. One Postgres cluster, but **one database and one role per service**; no
   service can read another's tables.
5. Secrets live only in `/etc/socrate/*.env` (`0640 root:<service-user>`) and
   in each app's equivalent — never in a repo, an SPA bundle or a Caddyfile.
6. Every reverse proxy relies on Caddy replacing client-supplied
   `X-Forwarded-For`. **Do not set Caddy `trusted_proxies`** unless another
   proxy sits in front of Caddy (see §4.4).

### Port and host plan

| Component | Bind | Public hostname | Unit |
|---|---|---|---|
| Caddy | `:80`, `:443` | all | distro package |
| Socrate OAuth | `127.0.0.1:8080` | `auth.example.com` | `socrate.service` |
| Socrate admin API | `127.0.0.1:8081` | — | same binary (`ADMIN_PORT`) |
| Monitoring BFF | `127.0.0.1:8090` | `monitoring.example.com` | `socrate-monitoring-bff.service` |
| Admin BFF | `127.0.0.1:8091` | `admin.example.com` | `socrate-admin-bff.service` |
| App *N* BFF / API | `127.0.0.1:9N00` (9100, 9200, …) | `app-n.example.com` | `app-n.service` |
| Postgres | `127.0.0.1:5432` | — | distro package |

Reserve 8080–8099 for the suite, 9100+ for relying-party apps, one hundred per
app.

---

## 2. Prerequisites

1. **DNS.** An `A`/`AAAA` record per hostname (`auth`, `admin`, `monitoring`,
   one per app) pointing at the VPS. Caddy will not obtain certificates until
   they resolve publicly.
2. **Firewall.** Inbound `22`, `80`, `443` only. Port 80 is needed for the ACME
   HTTP challenge and the HTTPS redirect.
   ```bash
   sudo ufw allow 22/tcp && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
   sudo ufw enable
   ```
3. **Packages.** `caddy`, `postgresql` (15+), `rsync`. No Go or Node on the
   VPS — everything is built on a workstation and shipped as artifacts.
4. **Secrets, generated up front** (never reused between services):
   ```bash
   openssl rand -hex 32   # SECRET_KEY_BASE (Socrate)
   openssl rand -hex 32   # Postgres password, one per role
   openssl rand -hex 32   # per-app session/signing secrets as each app requires
   ```
   Client secrets for the BFFs are issued by Socrate when you register the
   clients (§5.3), not generated by hand.
5. **SMTP credentials.** Invitations, verification and password-reset mail are
   how users get into apps (§6.4). Without `SMTP_HOST` Socrate still runs, but
   every invite-based onboarding path is dead.

---

## 3. Postgres: one cluster, one database per service

```bash
# Socrate (authorization state: users, clients, tokens, audit log)
sudo -u postgres createuser socrate
sudo -u postgres createdb -O socrate socrate
sudo -u postgres psql -c "ALTER ROLE socrate WITH PASSWORD '<socrate-db-password>';"

# Monitoring BFF durable sessions (optional; only if BFF_SESSION_DSN is used).
# Give the BFF its OWN role so a compromised BFF cannot read Socrate's tables.
sudo -u postgres createuser socrate_bff
sudo -u postgres createdb -O socrate_bff socrate_bff
sudo -u postgres psql -c "ALTER ROLE socrate_bff WITH PASSWORD '<bff-db-password>';"

# One pair per relying-party app
sudo -u postgres createuser app_1
sudo -u postgres createdb -O app_1 app_1
sudo -u postgres psql -c "ALTER ROLE app_1 WITH PASSWORD '<app1-db-password>';"
```

Rules:

- `pg_hba.conf` stays at the distro default (local + loopback, password auth).
  Postgres is never exposed on a public interface.
- No role is a superuser, and no role owns another service's database. The
  monitoring BFF's session store creates its two tables (`bff_sessions`,
  `bff_login_states`) in *its* database on first start.
- Schema migrations are deliberate: Socrate applies them only when
  `AUTO_MIGRATE=true` (set it, start once, set it back to `false`). Apps
  should follow the same discipline.
- **Backups** (§8.3) dump each database separately. The BFF session database
  is excluded from backups entirely — its rows are live OAuth tokens in
  plaintext.

---

## 4. Socrate (the identity server)

Run the monitoring kit's bootstrap once; it creates the `socrate` user, the
directories, both systemd units, the env stubs and the main Caddyfile:

```bash
git clone https://github.com/ovander/oauth2-monitoring
sudo bash oauth2-monitoring/deploy/scripts/bootstrap.sh
```

### 4.1 `/etc/socrate/socrate.env`

The production-relevant settings, with the multi-app ones called out. Anything
not listed keeps its default (`go-oauth2/.env.example` documents every
variable).

```ini
ENV=production
PORT=8080
ADMIN_PORT=8081
ADMIN_BIND_HOST=127.0.0.1               # admin API loopback only — never change

OAUTH_ISSUER=https://auth.example.com   # must be https and match the hostname
DATABASE_URL=postgres://socrate:<pw>@127.0.0.1:5432/socrate?sslmode=disable
SECRET_KEY_BASE=<64 hex chars>          # >= 32 chars; the server refuses to start otherwise
KEYS_PATH=/var/lib/socrate/keys         # ABSOLUTE; writable (key rotation); matches the unit's ReadWritePaths
AUTO_MIGRATE=false                      # true only for the one migration run

# Reverse-proxy trust: the default (loopback) is correct for same-host Caddy and
# the BFFs. Widen it ONLY if the proxy connects from another address; set to
# "none" only if Socrate is exposed directly (it is not, in this topology).
TRUSTED_PROXIES=127.0.0.1/32,::1/128

# CORS — browser origins allowed to call the OAuth/JSON APIs directly.
# The consoles are same-origin via their BFFs and do NOT need to be here.
# Add an app origin only if its SPA calls Socrate from the browser (public
# PKCE client, §6.3, or the direct JSON auth API). Hosted-login redirects are
# top-level navigations and need no CORS entry.
ALLOWED_ORIGINS=https://app-1.example.com,https://app-2.example.com

# Mail — required for invites, verification and password reset (§6.4)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURITY=starttls
SMTP_USERNAME=<user>
SMTP_PASSWORD=<pw>
FROM_EMAIL=no-reply@example.com
FROM_NAME=Socrate

# Admin plane hardening
ADMIN_ELEVATION_MAX_AGE=300             # step-up freshness for destructive admin actions
ADMIN_MFA_POLICY=enforce                # admins must enrol TOTP before the admin portal admits them
ADMIN_PASSWORD_LOGIN_ENABLED=false      # consoles use Authorization Code + PKCE through their BFFs
RATE_LIMIT_TOKEN=60                     # never 0 in production (Validate() warns)

# Token TTLs (defaults shown; shorter access tokens = faster revocation at resource servers)
ACCESS_TOKEN_TTL=900
REFRESH_TOKEN_TTL=604800
REFRESH_REUSE_MODE=enforce              # a replayed refresh token revokes the whole family
```

Optional, per your integration choices: `AUDIENCE_MODE=dual` once apps verify
`aud` against a registered resource id (§6.2), `DPOP_MODE=observe|enforce` if
any client uses DPoP, `ADMIN_SCOPE_MODE=enforce` only after both console
clients are registered with the right scopes (the env example explains the
order).

`Validate()` refuses to start in production without an https issuer, a
32+ character `SECRET_KEY_BASE`, a production `DATABASE_URL` and an absolute
`KEYS_PATH`.

### 4.2 Signing keys, schema, first superadmin

```bash
# RSA signing keys (generated on the workstation, copied in):
cd go-oauth2 && make gen-keys
sudo cp -r keys/. /var/lib/socrate/keys/ && sudo chown -R socrate:socrate /var/lib/socrate/keys && sudo chmod 0700 /var/lib/socrate/keys

# Schema: AUTO_MIGRATE=true → systemctl start socrate → confirm /health → AUTO_MIGRATE=false → restart

# First superadmin (the admin console admits global admins only):
sudo -u socrate bash -c 'set -a; . /etc/socrate/socrate.env; set +a; \
  /usr/local/bin/socrate-seed -email you@example.com -name "Your Name"'
# → one-time password, flagged MustChangePassword; enrol MFA at first login.
```

### 4.3 What Socrate exposes publicly

Only what Caddy routes to `:8080` on `auth.example.com`: discovery
(`/.well-known/openid-configuration`, `/.well-known/jwks.json`), `/oauth/*`
(authorize, token, userinfo, introspect, revoke, logout), the hosted login,
signup, invite, verify and password-reset pages under `/auth/*`, and the JSON
auth API under `/api/auth/*`. The admin API is on `:8081` and is never routed
by a public site block — and neither is `GET /metrics`, which the admin port
serves for Prometheus (see `docs/OBSERVABILITY.md` and
`deploy/observability/`). Scrape it from the VPS itself.

### 4.4 Client-IP attribution across the chain

Rate limits, lockouts, IP blocking and the audit trail key on the client IP.
The chain is: client → Caddy (replaces any incoming `X-Forwarded-For` with the
real peer, because its default `trusted_proxies` is empty) → BFF (honours the
header only from a loopback peer, strips `X-Real-IP`/`True-Client-IP`/
`Forwarded`, appends itself) → Socrate (walks `X-Forwarded-For` from the right,
skipping `TRUSTED_PROXIES`, and lands on the client). Every link assumes the
one before it; the one configuration that breaks all of them is a Caddy
`trusted_proxies` directive that trusts a public range.

---

## 5. The two consoles

Both consoles are static SPAs plus a Go BFF, and both need a **confidential**
OAuth client registered in Socrate. Their BFFs refuse to start without one
(`BFF_CLIENT_ID` + `BFF_CLIENT_SECRET`); the pass-through migration modes are
opt-in only and log a WARNING.

### 5.1 Install order

1. Monitoring kit bootstrap (§4) — already done; it also installed
   `socrate-monitoring-bff.service` and `/etc/socrate/bff.env`.
2. Admin kit bootstrap:
   ```bash
   git clone https://github.com/ovander/oauth2-admin
   sudo oauth2-admin/deploy/scripts/bootstrap.sh
   # → socrate-admin-bff.service, /etc/socrate/admin-bff.env,
   #   /etc/caddy/sites/admin.example.com.caddy, /srv/admin/dist (root-owned)
   ```
3. Make sure the main Caddyfile ends with `import /etc/caddy/sites/*.caddy`
   (§7) so the admin site file — and later every app's — is picked up.

### 5.2 Env files

`/etc/socrate/bff.env` (monitoring) and `/etc/socrate/admin-bff.env` (admin)
are seeded by the kits with Phase 2 enabled. Fill:

```ini
BFF_OAUTH_PUBLIC_URL=https://auth.example.com     # browser-facing authorize URL
BFF_OAUTH_UPSTREAM=http://127.0.0.1:8080          # back-channel token endpoint
BFF_ADMIN_UPSTREAM=http://127.0.0.1:8081          # loopback admin API
BFF_PUBLIC_ORIGIN=https://monitoring.example.com  # (or https://admin.example.com)
BFF_CLIENT_ID=<from §5.3>
BFF_CLIENT_SECRET=<from §5.3>
BFF_COOKIE_SECURE=true
BFF_SESSION_IDLE=30m
BFF_SESSION_ABSOLUTE=8h
# monitoring only, optional durable sessions (requires backendkit >= v1.12.0, which the shipped BFF has):
# BFF_SESSION_DSN=postgres://socrate_bff:<pw>@127.0.0.1:5432/socrate_bff?sslmode=disable
```

Per-IP budgets (`BFF_LOGIN_RATE`, `BFF_ELEVATE_RATE`, admin's
`BFF_PASSWORD_RESET_RATE`) default to sane values; leave them.

### 5.3 Register the console clients

Bootstrapping order matters: the admin console needs its own client to log
in. Use the seeded superadmin against the admin API **over loopback** for
the first client, then do everything else from the console UI.

```bash
# On the VPS, once, with the superadmin's credentials (password login is still
# enabled at this point; disable it in socrate.env afterwards).
TOKEN=$(curl -s http://127.0.0.1:8081/api/admin/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"<one-time-pw>"}' | jq -r .access_token)

curl -s http://127.0.0.1:8081/api/admin/apps -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "name": "Admin console (BFF)",
    "redirect_uris": ["https://admin.example.com/bff/callback"],
    "is_public": false, "require_pkce": true
  }'
# → client_id + client_secret (shown once) → /etc/socrate/admin-bff.env
```

Then, logged into `https://admin.example.com`, register the monitoring
client the same way (`redirect_uris: ["https://monitoring.example.com/bff/callback"]`,
confidential, PKCE required) and put its credentials in `/etc/socrate/bff.env`.
Finally set `ADMIN_PASSWORD_LOGIN_ENABLED=false` and restart Socrate.

Redirect URIs are matched **exactly** (scheme, host, path); `https` is
mandatory in production.

### 5.4 Who may use the consoles

Since P3-1 the admin API admits only **global admins** (`role=admin` or
`superadmin`); `/api/admin/superadmins/*` needs `superadmin`. A plain `user`
with a monitoring or admin OAuth session gets 403 everywhere. Promote console
operators through the admin console (Users → role), and enrol them in MFA —
with `ADMIN_MFA_POLICY=enforce` the portal refuses admins without it.

---

## 6. Adding a relying-party application

Every application that authenticates users through Socrate is an **App**
(OAuth client) with a `client_id`. Three integration shapes fit this VPS; pick
per app.

| Shape | Client type | Where tokens live | When |
|---|---|---|---|
| **6.2 SPA + BFF** (recommended) | confidential, PKCE | server-side session in the app's BFF; browser has an HttpOnly cookie | Any browser app with a Go back-end. Same model as the consoles, built on `backendkit/bff`. |
| **6.3 SPA as public client** | public (`is_public: true`, PKCE enforced) | in the browser (memory) | Only when there is no back-end at all. Weakest posture; needs a CORS entry. |
| **6.5 Server-to-server** | confidential, `client_credentials` | in the service | Back-ends calling their own protected resources, sending magic links, etc. |

Whatever the shape, an app's **resource server** validates Socrate's RS256
JWTs locally against `https://auth.example.com/.well-known/jwks.json`
(`backendkit/jwtauth` does this with caching), or calls `/oauth/introspect`
with its client credentials when it needs the revocation freshness described
in `docs/REVOCATION-FRESHNESS-SLA.md`.

### 6.1 Register the app (admin console → Applications → New)

| Field | Set to |
|---|---|
| `name` | human name |
| `redirect_uris` | exact `https://app-1.example.com/bff/callback` (BFF) or `https://app-1.example.com/callback` (public SPA) — one per environment, no wildcards |
| `is_public` | `false` for a BFF or server app (secret issued once); `true` only for §6.3 |
| `require_pkce` | `true` (public clients get it regardless) |
| `require_dpop` | `false` unless the client implements DPoP and `DPOP_MODE` is on |
| `audiences` | the app's resource identifier, e.g. `https://app-1.example.com/api`, if `AUDIENCE_MODE=dual` and the API verifies `aud` |
| `allow_token_exchange` / `allow_impersonation` | `false` unless the app is a delegation broker |

Copy the `client_id` (and secret, shown once) into the app's env file.

**Scopes are not a per-client boundary (P3-8, open).** Any registered client
may request any supported scope, including `admin` / `monitoring:*`; what
protects the admin plane is the per-user role gate (P3-1), not the scope.
Do not build an app that treats "the token carries scope X" as authorisation
on its own — check the user's roles (global `role`, per-app `app_roles`).

### 6.2 Shape A — SPA + BFF on `backendkit/bff` (recommended)

The app's Go binary is a BFF exactly like the consoles': it runs the
Authorization Code + PKCE flow server-side as a confidential client, keeps
tokens in a `bff.Session`, sets a `__Host-` HttpOnly cookie, and proxies the
SPA's `/api/*` calls to the app's own API with the bearer injected.
`oauth2-monitoring/bff` is the reference implementation (about 600 lines);
copy it and change the names.

Minimum wiring:

```go
gw := &bff.Gateway{
    Store:     store,                          // bff.NewMemoryStore(idle, absolute) or a Postgres store
    Cookie:    bff.CookieConfig{Name: "app1_session", Secure: true},
    Refresher: socrateClient,                  // *socrate.Client satisfies bff.TokenRefresher
}
mux.HandleFunc("/api/", gw.ProxyWithSession(bff.NewSingleHostProxy(apiUpstream)))
```

Keep the defaults: the gateway is fail-closed (no session ⇒ 401), unsafe
methods need the `X-CSRF-Token` double-submit header, refreshes are coalesced
and written through, and only a refresh the issuer rejects tears a session
down. Bind the binding-nonce cookie on login (`bff.LoginBinding`) so a
captured callback URL cannot swap a victim onto an attacker's session.

App env (naming is yours; backendkit reads no env itself):

```ini
APP_LISTEN_ADDR=127.0.0.1:9100
APP_PUBLIC_ORIGIN=https://app-1.example.com
SOCRATE_ISSUER=https://auth.example.com                     # expected iss
SOCRATE_JWKS_URL=https://auth.example.com/.well-known/jwks.json
SOCRATE_TOKEN_URL=http://127.0.0.1:8080/oauth/token         # back-channel over loopback
SOCRATE_CLIENT_ID=<client_id>
SOCRATE_CLIENT_SECRET=<client_secret>
DATABASE_URL=postgres://app_1:<pw>@127.0.0.1:5432/app_1?sslmode=disable
```

Back-channel calls (token, refresh, revoke, introspect, Socrate API) go to
`http://127.0.0.1:8080` over loopback; only the browser's authorize redirect
uses the public `https://auth.example.com`. No CORS entry is needed.

Caddy site file, `/etc/caddy/sites/app-1.example.com.caddy`:

```caddyfile
app-1.example.com {
	encode zstd gzip
	import security_headers
	header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"

	# Everything the SPA calls goes to the app's BFF; the BFF allowlists paths.
	@bff path /bff/* /api/*
	reverse_proxy @bff 127.0.0.1:9100 {
		header_up X-Forwarded-Proto {scheme}
	}

	handle {
		root * /srv/app-1/dist
		try_files {path} /index.html
		file_server
	}
}
```

### 6.3 Shape B — SPA as a public PKCE client

Register with `is_public: true`. The SPA redirects to
`https://auth.example.com/oauth/authorize?...code_challenge_method=S256`,
exchanges the code at `/oauth/token` from the browser, keeps the access token
in memory and refreshes with the rotated refresh token. Requirements on this
VPS:

- Add the SPA origin to `ALLOWED_ORIGINS` in `socrate.env` (the token,
  userinfo and revoke calls are cross-origin XHR).
- `code_challenge_method=S256` is mandatory since P3-4; omitting it is
  `invalid_request`.
- The app's API validates JWTs via JWKS and is itself a separate service
  (`127.0.0.1:9100`) behind the same site block; it needs no client secret.

Prefer §6.2 whenever the app has any server-side component — a public client
cannot use the refresh-cookie channel, cannot be sender-constrained without
DPoP, and leaks the access token to any XSS.

### 6.4 Users, roles and onboarding into an app

A user obtains a token for an app through the browser flow only if they hold
a **per-app role** (`admin`, `manager`, `editor`, `viewer`, `user`) in
`user_app_roles` — global admins are exempt. Ways in:

- **Invite** (admin console → Application → Users → Add): creates the user if
  needed, assigns the role and emails an invite link
  (`https://auth.example.com/auth/invite?token=…`). Needs SMTP (§4.1). The
  app-admin actions *resend verification* and *force password reset* are
  limited to that app's members (P3-7).
- **Self-signup** (`POST /api/auth/signup` or the hosted `/auth/signup`
  page with `client_id`): creates the user with the `user` role in that app.
  It is open to any registered `client_id` — a product decision still pending
  (`AllowSignup` per app, plan §2.4). If an app must not be self-service,
  do not link to signup from it and review new sign-ups in the console.
- **Magic link** (`/api/auth/magic-link`, passwordless) — see `docs/API.md` §5.7.

An **app admin** (per-app role `admin`) manages that app's users through
`/api/apps/{app_id}/users` from the admin console without being a global
admin. Global admins see every app.

### 6.5 Shape C — server-to-server (`client_credentials`)

Register a confidential client with no redirect URIs. The service posts
`grant_type=client_credentials` with its `client_id`/`client_secret` to
`http://127.0.0.1:8080/oauth/token` (loopback; or the public URL from another
host) and receives a short-lived access token with scope `api`. Since P2-5
the grant validates the requested scope and honours the client's DPoP
requirement; unknown scopes are `invalid_scope`.

### 6.6 App checklist

- [ ] Client registered; exact `https` redirect URI(s); secret stored only in
      the app's env file (`0640 root:app-n`).
- [ ] Own Postgres database + role; migrations applied deliberately.
- [ ] Own system user and hardened systemd unit (copy
      `socrate-monitoring-bff.service`, change user, env file, binary).
- [ ] Binds `127.0.0.1:9N00`; Caddy site file in `/etc/caddy/sites/`;
      `caddy validate` clean.
- [ ] SPA files under `/srv/app-n/dist`, **root-owned 0644/0755** (the app's
      service user must not be able to modify the JavaScript it serves).
- [ ] `ALLOWED_ORIGINS` touched only for a public-client SPA.
- [ ] Users assigned app roles (or invited); an app admin nominated.
- [ ] Smoke test (§8.4) added for the app.

---

## 7. Caddy: one main file plus one site file per host

The monitoring kit installs `/etc/caddy/Caddyfile` with the global options,
the `security_headers` snippet, the `auth.` site (→ `:8080`) and the
`monitoring.` site (→ `:8090`). Every other host — the admin console and each
app — lives in its own file under `/etc/caddy/sites/`, pulled in by a single
line at the end of the main file:

```caddyfile
import /etc/caddy/sites/*.caddy
```

Conventions that keep the invariants of §1:

- **Never route `/api/admin/*` of any public host to `127.0.0.1:8081`.** The
  admin API is reached only through the console BFFs. The admin site file from
  `oauth2-admin/deploy/Caddyfile` routes `/bff/*`, `/api/admin/*`,
  `/api/profile`, `/api/version` and the two password-reset posts to the admin
  BFF on `:8091`.
- Path matchers are allowlists (`@bff path /bff/* /api/*`); the BFF behind
  them is an allowlist again, so a typo in Caddy cannot open a path the BFF
  does not serve.
- `header_up X-Forwarded-Proto {scheme}` on every proxy so BFFs set `Secure`
  cookies; **no `trusted_proxies`** (§4.4).
- `flush_interval -1` on the monitoring proxy (SSE event stream).
- One `Content-Security-Policy` per host, `connect-src 'self'` — with a BFF
  every call is same-origin. A public-client SPA (§6.3) needs `connect-src
  'self' https://auth.example.com` instead.
- Validate before reload, every time: `caddy validate --config /etc/caddy/Caddyfile`
  (the install scripts do this and roll back on failure).

---

## 8. Operations

### 8.1 Deploy

Build on the workstation, ship artifacts, install and restart remotely:

```bash
# Socrate + monitoring (needs the go-oauth2 checkout next to the repo, or GO_OAUTH2_DIR)
VPS_HOST=deploy@vps.example.com oauth2-monitoring/deploy/scripts/push.sh
# Admin console
VPS_HOST=deploy@vps.example.com oauth2-admin/deploy/scripts/push.sh
# Each app: the same pattern — build, rsync to /srv/app-n and /usr/local/bin, restart, health-check
```

`install-remote.sh` backs up the previous binaries to
`/var/backups/socrate/<timestamp>/`, installs, validates Caddy, restarts and
health-checks (`:8081/health`, `:8090/bff/healthz`, `:8080/health`,
`:8091/bff/healthz`), rolling back on failure.

Build toolchains: Go **1.26.8** everywhere — `toolchain go1.26.8` in every
`go.mod` (Socrate, backendkit, both BFFs) and `golang:1.26.8-alpine` in every
Dockerfile, with CI failing if the two drift — and Node 20. Go 1.25 is out of
support since Go 1.27's release; move the pin forward with each Go patch
release, in all four repositories together.

### 8.2 Rollback

```bash
sudo install -m0755 /var/backups/socrate/<ts>/socrate /usr/local/bin/socrate
sudo systemctl restart socrate
```

Same for `socrate-monitoring-bff`, `socrate-admin-bff` and each app binary.
Schema rollbacks are manual: restore the database dump from before the deploy.

### 8.3 Backups

What matters, in order:

1. **Postgres `socrate`** — users, clients, tokens, audit log. Daily:
   ```bash
   sudo -u postgres bash oauth2-monitoring/deploy/scripts/backup-db.sh   # DB=socrate
   ```
   The script excludes the rows of `bff_sessions` / `bff_login_states`
   (live OAuth tokens in plaintext); if the BFF uses its own database, simply
   do not back that database up.
2. **Signing keys** `/var/lib/socrate/keys` — lose them and every issued token
   becomes unverifiable. Offline, encrypted:
   `sudo tar czf socrate-keys.tgz -C /var/lib/socrate keys`.
3. **Env files** `/etc/socrate/*.env` and each app's — encrypted, offline.
4. **Each app's database** — `DB=app_1 bash backup-db.sh`, on the app's
   schedule.

Restore: `gunzip -c <dump> | sudo -u postgres psql <db>`; BFF sessions simply
re-login.

### 8.4 Smoke test (after every deploy)

```bash
# Socrate metadata + keys
curl -fsS https://auth.example.com/.well-known/openid-configuration | jq .issuer
curl -fsS https://auth.example.com/.well-known/jwks.json | jq '.keys | length'

# Admin plane is private (both must FAIL)
curl -fsS --max-time 5 https://admin.example.com/api/admin/apps && echo LEAK || echo ok
curl -fsS --max-time 5 http://<vps-ip>:8081/health          && echo LEAK || echo ok

# BFFs fail closed without a session (401, not a proxied response)
curl -s -o /dev/null -w '%{http_code}\n' https://admin.example.com/api/admin/apps        # 401
curl -s -o /dev/null -w '%{http_code}\n' https://monitoring.example.com/api/admin/dashboard/stats  # 401
curl -s -o /dev/null -w '%{http_code}\n' https://app-1.example.com/api/anything          # 401

# Encoded dot-segments never reach an upstream (404 from the BFF)
curl -s -o /dev/null -w '%{http_code}\n' 'https://admin.example.com/api/admin/%2e%2e/x'  # 404

# Browser: log into admin as the superadmin; open monitoring (dashboard renders);
# log into one app as an invited user; log out and confirm the API returns 401.
```

### 8.5 Routine

- **Key rotation** is automatic (`KEY_ROTATION_INTERVAL_SECONDS`,
  `KEY_RETENTION_SECONDS`); resource servers must re-fetch JWKS on an unknown
  `kid` (backendkit/jwtauth does).
- **Logs** — `journalctl -u socrate -u socrate-admin-bff -u socrate-monitoring-bff`.
  Socrate logs the client IP it attributed (`client_ip`); a stream of
  `127.0.0.1` there means a proxy-trust misconfiguration (§4.4).
- **Vulnerability drift** — go-oauth2 and backendkit run `govulncheck` in CI;
  the consoles run `npm audit` gates. Rebuild and redeploy when CI goes red on
  `main`.
- **Blocked IPs and lockouts** — visible and reversible in the monitoring
  console (auto-defense) and the admin console (user unlock).

### 8.6 Turning on the admin policy (A4)

The policy decision point ships `off`. To adopt it:

1. **Shadow.** Set `POLICY_MODE=shadow` and restart. Version 1 of the policy is
   a baseline that restates the admin API's existing gates, so
   `socrate_policy_divergences_total` should stay at **zero**. If it does not,
   read `GET /api/admin/policy/decisions?divergence=true` (superadmin) before
   anything else — each row names the action, the rule and the status the
   request ended with. With `ADMIN_SCOPE_MODE=enforce`, add the scope rules
   from `docs/EXTENSIBILITY.md` first, or every scope refusal shows up here.
2. **Add rules.** Save, then watch the new rule's `pdp_deny_code_allow` rows in
   shadow for as long as it takes to see normal traffic. `POST /policy/simulate`
   answers "what would this request get, and why" without touching traffic.
3. **Enforce.** Set `POLICY_MODE=enforce` and restart. An allow never bypasses
   the code gates, so this can only take access away.

If a rule locks admins out in enforce mode, the policy API itself is exempt:
a superadmin can still `POST /api/admin/policy/versions/{v}/restore` a known-good
version (after `/elevate`). Setting `POLICY_MODE=shadow` and restarting is the
blunt alternative.

---

## 8bis. Running two Socrate instances (B5)

One instance is the documented default and is what most deployments should run.
Add a second only when you need redundancy or headroom — and read this section
first, because a second instance is **not** a matter of starting the binary
twice.

### The two prerequisites

**1. `STATE_BACKEND=postgres` on every instance.** With the default in-memory
backend, two instances each keep their own copy of the security state:

- a rate limit of 5/min becomes 10/min, because each counts only what it saw;
- **a DPoP proof replayed against the other instance is accepted**, because the
  one that saw it first is the only one that remembers the `jti`.

The second is a security hole, not a capacity nuisance. Never run two instances
on the in-memory backend.

**2. `TRUSTED_PROXIES` set to Caddy's address** on both. Otherwise every request
attributes to the proxy, and rate limits and IP blocks collapse into a single
global bucket that any one user can exhaust for everybody.

Then both instances point at the same `DATABASE_URL`, and Caddy load balances
only the **public** port. The admin API stays on loopback, per instance, and is
never fronted.

### What coordinates itself

With `STATE_BACKEND=postgres`, the background jobs elect a runner per tick
through a PostgreSQL advisory lock, so each runs once across the cluster rather
than once per instance:

| Job | Coordination |
|---|---|
| Schema migration | **Blocking** lock — a second instance starting at the same time waits, then finds the work already done |
| Signing-key rotation | Try-lock per tick — one rotation per interval cluster-wide, not N |
| Used-token pruning | Try-lock per tick |
| Audit-chain integrity scan | Try-lock per tick |
| Shared-state sweep | Try-lock per tick |
| **Webhook delivery** | **Deliberately not locked** — the outbox already claims rows with `FOR UPDATE SKIP LOCKED`, so every instance should dispatch; that is throughput, not duplication |

There is no leader to elect or fail over. Each instance tries on every tick and
one wins; if the winner dies mid-job, its connection drops, the lock vanishes,
and the next tick is contested normally. A crashed instance costs one interval.

### Caddy

Use [`deploy/caddy/socrate-ha.caddy`](../deploy/caddy/socrate-ha.caddy). It
health-checks `/health/readiness`, which now reports the database, the signing
key and the shared-state backend by name — so an instance that booted but cannot
mint a token is taken out of rotation instead of serving errors:

```json
{"status":"ok","checks":{"database":"ok","signing_key":"ok","shared_state":"ok"}}
```

A failing check returns `503` with the same shape, naming what is wrong.

`lb_policy round_robin` spreads load; `first` gives an active/passive pair where
the second instance only takes over on failure.

### Verifying it before you trust it

With `RATE_LIMIT_LOGIN=5`, send six failing logins alternating between the two
instances. Requests 1–5 must return `401` and request 6 must return `429`. If
you get six `401`s, the instances are not sharing state — check
`STATE_BACKEND` on **both**.

For key rotation, set `KEY_ROTATION_INTERVAL_SECONDS` low on a scratch database,
run both at `LOG_LEVEL=debug`, and confirm one instance logs
`another instance holds the job lock for this tick` while the number of retired
keys grows by exactly one per interval — not two.

### Sizing

See [`PERFORMANCE-BASELINE.md`](PERFORMANCE-BASELINE.md). Note especially that
client-secret verification is bcrypt-bound at ~14 requests/second per 4 vCPU, so
for confidential-client traffic a second instance buys close to linear headroom —
it is CPU you are adding, which is exactly what that path is short of.

## 9. Security checklist (suite-wide)

- [ ] `ufw`: 22/80/443 only; every service bound to `127.0.0.1`.
- [ ] Caddy: no `trusted_proxies`; no public host routes to `:8081`;
      `caddy validate` clean; HSTS + CSP per host.
- [ ] Socrate: `ENV=production`, https issuer, 32+ char `SECRET_KEY_BASE`,
      absolute `KEYS_PATH` (`0700 socrate`), `TRUSTED_PROXIES` at default,
      `RATE_LIMIT_TOKEN` > 0, `ADMIN_PASSWORD_LOGIN_ENABLED=false`,
      `ADMIN_MFA_POLICY=enforce`, SMTP configured, `AUTO_MIGRATE=false`.
- [ ] Console BFFs: Phase 2 on with confidential clients; `BFF_COOKIE_SECURE=true`;
      no `*_PASSTHROUGH` flags; backendkit ≥ v1.12.0 (shipped).
- [ ] Console operators are global admins with MFA; nobody else needs the
      consoles.
- [ ] One Postgres role/database per service; none is a superuser; BFF
      session database excluded from backups.
- [ ] Env files `0640 root:<service user>`; SPA directories root-owned and
      read-only for the service users.
- [ ] Each app: confidential client + BFF unless there is no back-end; exact
      https redirect URIs; JWT validation against JWKS; roles, not scopes, as
      the authorisation boundary.
- [ ] Backups scheduled: `socrate` DB daily, keys and env files offline.
- [ ] Smoke test (§8.4) green after each deploy.

## 10. Known open items

From `CR-socrate-suite-remediation-plan.md` §2.4 — none blocks deployment:

- **Per-client scope policy (P3-8)** — any client may request any scope; the
  role gate is the boundary. Decide before opening client registration to
  third parties.
- **Self-signup on first-party clients** — reachable for the console
  `client_id`s; harmless without a role.
- **Tokens at rest** in a Postgres BFF session store — plaintext; excluded from
  backups; envelope encryption is the next step if the database is shared.
- **Shared gateway touch** — the proxy path's throttled session touch is still
  an upsert in backendkit; the consoles' `/bff/session` path uses UPDATE-only.
