# Socrate — Backend Deployment

Production deployment kit for the **Socrate OAuth 2.1 / OIDC server** (this repo)
on a single Linux VPS. It complements the existing `Makefile` targets
(`build-linux`, `deploy`, `gen-keys`, `migrate-up`) by adding the pieces that
weren't versioned: a **Dockerfile**, the **systemd unit**, a **Caddy site**, an
**env template**, and a **bootstrap** script.

> Companion kits: the monitoring SPA + BFF and the admin SPA are deployed from
> their own repos. Together they form the single-VPS topology below.

## Where Socrate sits

```
Internet ─► Caddy ─ socrate.vandermoten.eu → 127.0.0.1:8080  Socrate OAuth (public OIDC)
                                                    │
                                              127.0.0.1:8081  Socrate admin API  ← LOOPBACK ONLY
                                              127.0.0.1:5432  Postgres            (no public route)
```

- **Dual-port:** public OAuth on `:8080` (fronted by Caddy), admin API on `:8081`
  bound to **loopback** (`ADMIN_BIND_HOST=127.0.0.1`) — off the public internet.
- RSA signing keys live in `/opt/socrate/keys` (`make gen-keys`); GeoIP data
  (optional) in `/opt/socrate/data`.

## Files

| Path | Purpose |
|------|---------|
| `../Dockerfile` | Multi-stage → distroless static image (fixes `make docker-build`) |
| `systemd/socrate.service` | Hardened unit (no-login user, `ProtectSystem=strict`, dropped caps, syscall allowlist) |
| `Caddyfile.example` | `socrate.vandermoten.eu` → `127.0.0.1:8080` (admin API stays loopback) |
| `env/socrate.env.example` | Production env template |
| `scripts/bootstrap.sh` | One-time VPS prep (user, `/opt/socrate`, unit, Caddy site, env) |

## First-time setup (on the VPS)

```bash
git clone https://github.com/ovander/go-oauth2
sudo bash go-oauth2/deploy/scripts/bootstrap.sh
sudo vi /opt/socrate/.env                      # DATABASE_URL, SECRET_KEY_BASE, issuer
sudo -u postgres createuser socrate
sudo -u postgres createdb -O socrate socrate
cd go-oauth2 && make gen-keys                  # RSA signing keys → keys/
sudo cp -r keys/. /opt/socrate/keys/ && sudo chown -R socrate:socrate /opt/socrate/keys
# Migrate once: set AUTO_MIGRATE=true, start, then set back to false.
```

## Deploy (from your workstation)

The repo's Makefile already builds and ships the binary:

```bash
make deploy VPS=deploy@vps.vandermoten.eu     # build-linux → scp → systemctl restart socrate
```

Then on first deploy:

```bash
sudo systemctl enable --now socrate
sudo systemctl reload caddy
```

### Container alternative

```bash
make docker-build                              # now works — root Dockerfile added
docker run -p 8080:8080 -p 127.0.0.1:8081:8081 \
  --env-file /opt/socrate/.env \
  -v /opt/socrate/keys:/opt/socrate/keys:ro \
  oauth-server
```

## Operations

- **Logs:** `journalctl -u socrate -f`
- **Migrations:** `make migrate-up` / `migrate-status` (goose), or `AUTO_MIGRATE=true` once.
- **Key rotation:** keys in `/opt/socrate/keys` (the unit makes that path writable).
- **Health:** `curl http://127.0.0.1:8080/health` and `http://127.0.0.1:8081/health`.

## Security notes

- Admin API is **loopback-only** — the public surface is just Caddy on 443.
- The systemd unit runs as a no-login `socrate` user with `ProtectSystem=strict`,
  `NoNewPrivileges`, an empty capability set, and a syscall allowlist; only
  `/opt/socrate/keys` is writable.
- Secrets live in `/opt/socrate/.env` (`0640`, `root:socrate`) — never in the
  image or the repo.
