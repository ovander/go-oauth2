# Socrate — Backend Deployment

Production deployment kit for the **Socrate OAuth 2.1 / OIDC server** (this repo)
on a single Linux VPS: a **Dockerfile**, the **systemd unit**, a **Caddy site**,
an **env template**, and a **bootstrap** script.

> ## 📌 Authoritative runbook
> This kit deploys **only the backend**. The **full single-VPS runbook** — Caddy
> + Postgres + Socrate + the monitoring BFF + both SPAs, with a build/push script
> that does health-checks and **automatic rollback** — lives in the
> **`oauth2-monitoring` repo at [`deploy/README.md`](https://github.com/ovander/oauth2-monitoring/blob/main/deploy/README.md)**.
> If you are standing up the whole stack, follow **that** guide; it is the source
> of truth. This kit uses the **same canonical paths** so the two never conflict:
>
> | Thing | Canonical path |
> |-------|----------------|
> | Binary | `/usr/local/bin/socrate` |
> | Env file | `/etc/socrate/socrate.env` (`0640`, `root:socrate`) |
> | Signing keys (writable) | `/var/lib/socrate/keys` (`KEYS_PATH`) |
> | Optional GeoIP data | `/var/lib/socrate/data` |

## Where Socrate sits

```
Internet ─► Caddy ─ socrate.vandermoten.eu → 127.0.0.1:8080  Socrate OAuth (public OIDC)
                                                    │
                                              127.0.0.1:8081  Socrate admin API  ← LOOPBACK ONLY
                                              127.0.0.1:5432  Postgres            (no public route)
```

- **Dual-port:** public OAuth on `:8080` (fronted by Caddy), admin API on `:8081`
  bound to **loopback** (`ADMIN_BIND_HOST=127.0.0.1`) — off the public internet.
- **Signing keys** (`make gen-keys`) live in `/var/lib/socrate/keys`. `KEYS_PATH`
  **must be an absolute path in production** — the server refuses to start with a
  relative one — and the directory must be writable for key rotation.

## Files

| Path | Purpose |
|------|---------|
| `../Dockerfile` | Multi-stage → distroless static image |
| `systemd/socrate.service` | Hardened unit (no-login user, `ProtectSystem=strict`, dropped caps, syscall allowlist; only `/var/lib/socrate/keys` writable) |
| `Caddyfile.example` | `socrate.vandermoten.eu` → `127.0.0.1:8080` (admin API stays loopback) |
| `env/socrate.env.example` | Production env template (`/etc/socrate/socrate.env`) |
| `scripts/bootstrap.sh` | One-time VPS prep (user, `/etc/socrate` + `/var/lib/socrate`, unit, Caddy site, env) |

## First-time setup (on the VPS)

```bash
git clone https://github.com/ovander/go-oauth2
sudo bash go-oauth2/deploy/scripts/bootstrap.sh
sudo vi /etc/socrate/socrate.env               # DATABASE_URL, SECRET_KEY_BASE, issuer, KEYS_PATH
sudo -u postgres createuser socrate
sudo -u postgres createdb -O socrate socrate
cd go-oauth2 && make gen-keys                  # RSA signing keys → keys/
sudo cp -r keys/. /var/lib/socrate/keys/ && sudo chown -R socrate:socrate /var/lib/socrate/keys
sudo chmod 0700 /var/lib/socrate/keys
# Migrate once: set AUTO_MIGRATE=true, start, then set back to false.
```

## Deploy

**Production path (recommended):** use the umbrella `push.sh` in the
`oauth2-monitoring` deploy kit — it builds this repo's binary, installs it to
`/usr/local/bin/socrate`, restarts the service, **health-checks** it, and rolls
back automatically on failure.

```bash
# from a workstation with both repos checked out side by side:
VPS_HOST=deploy@vps.vandermoten.eu ./oauth2-monitoring/deploy/scripts/push.sh
```

Then on first deploy:

```bash
sudo systemctl enable --now socrate
sudo systemctl reload caddy
```

> The repo's `make deploy` target uses an older `/opt/socrate` layout and is kept
> for standalone/dev use only. For the production VPS, prefer the umbrella
> `push.sh` so all artifacts land on the canonical paths above.

### Container alternative

```bash
make docker-build
docker run -p 8080:8080 -p 127.0.0.1:8081:8081 \
  --env-file /etc/socrate/socrate.env \
  -v /var/lib/socrate/keys:/var/lib/socrate/keys \
  oauth-server
```

## Operations

- **Logs:** `journalctl -u socrate -f`
- **Migrations:** `make migrate-up` / `migrate-status` (goose), or `AUTO_MIGRATE=true` once.
- **Key rotation:** keys in `/var/lib/socrate/keys` (the unit makes that path writable).
- **Health:** `curl http://127.0.0.1:8080/health` and `http://127.0.0.1:8081/health`.

## Security notes

- Admin API is **loopback-only** — the public surface is just Caddy on 443.
- Client IPs (rate limits, IP blocks, auto-defense, audit) are taken from
  `X-Forwarded-For` **only** when the peer is in `TRUSTED_PROXIES` (default:
  loopback, i.e. Caddy and the consoles' BFFs on this box). Caddy replaces any
  client-supplied `X-Forwarded-For` for peers outside its own `trusted_proxies`
  (none configured here), so the leftmost entry is the real client. If you move
  the proxy off-box, set `TRUSTED_PROXIES` to its address — never to a range
  clients can reach you from.
- The systemd unit runs as a no-login `socrate` user with `ProtectSystem=strict`,
  `NoNewPrivileges`, an empty capability set, and a syscall allowlist; only
  `/var/lib/socrate/keys` is writable.
- Secrets live in `/etc/socrate/socrate.env` (`0640`, `root:socrate`) — never in
  the image or the repo.
