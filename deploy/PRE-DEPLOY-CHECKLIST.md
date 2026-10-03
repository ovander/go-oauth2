# Socrate — pre-deployment checklist (VPS)

Run through this on the VPS before and after each deploy of the Socrate suite
(server + admin console + monitoring console). It covers the configuration that
lives only on the box, which the repo cannot verify. Pair it with the harness in
[`deploy/e2e/`](e2e/) to re-verify a deployment end to end.

Commands assume the canonical paths from [`deploy/README.md`](README.md) and the
multi-app runbook [`docs/DEPLOYMENT-VPS-MULTI-APP.md`](../docs/DEPLOYMENT-VPS-MULTI-APP.md).

## 0. Release identity
- [ ] The commit to deploy is **tagged** (e.g. `v1.8.0`); deploy that tag, not a
      moving branch: `SOCRATE_REF=v1.8.0 ./oauth2-monitoring/deploy/scripts/push.sh <mon-tag>`.
- [ ] After deploy, `curl -s localhost:8081/metrics | grep socrate_build_info`
      shows the **real version**, not `dev`.

## 1. Env files (`/etc/socrate/*.env`)
Perms first — secrets must not be world-readable:
```bash
ls -l /etc/socrate/*.env      # expect 0640, root:<service-user> per file
```
`socrate.env`:
- [ ] `ENV=production`
- [ ] `OAUTH_ISSUER=https://auth.<domain>` (https, public hostname)
- [ ] `SECRET_KEY_BASE` ≥ 32 bytes, unique to prod, not in git
- [ ] `DATABASE_URL` points at the prod DB; not `sslmode=disable` unless DB is loopback-only
- [ ] `AUTO_MIGRATE=false` (set true only for the one-time migrate, then back)
- [ ] `TRUSTED_PROXIES=127.0.0.1/32,::1/128` (only loopback — Caddy is same-host)
- [ ] `POLICY_MODE=off` or `shadow` for first rollout (not `enforce`)
- [ ] `RATE_LIMIT_*` at defaults (not loosened)
- [ ] SMTP configured (`SMTP_HOST/PORT/SECURITY`, `FROM_EMAIL`) and reachable
- [ ] Opt-in modes only if intended: `REFRESH_REUSE_MODE`, `SCOPE_POLICY_MODE`,
      `ADMIN_SCOPE_MODE`, `WEBHOOKS_MODE`, `TOKEN_EXCHANGE_MODE`, `DPOP_MODE`,
      `AUDIENCE_MODE`
- [ ] `AUDIT_INTEGRITY_SCAN_INTERVAL_SECONDS` > 0 if you want tamper-evidence
      actually verified (0 = stamped but never scanned)

Both BFF env files (`admin-bff.env`, `bff.env`):
- [ ] `BFF_CLIENT_ID` + `BFF_CLIENT_SECRET` set (BFF refuses to start otherwise)
- [ ] `BFF_COOKIE_SECURE=true`
- [ ] `BFF_OAUTH_PUBLIC_URL` = public issuer; `*_UPSTREAM` = loopback
- [ ] No `BFF_PHASE1_PASSTHROUGH` / `BFF_ALLOW_PASSTHROUGH` in production

## 2. Signing keys & data
- [ ] `/var/lib/socrate/keys` exists, `0700 socrate:socrate`, contains the RSA keys
- [ ] Keys are backed up somewhere the DB backup is not (losing them invalidates all tokens)

## 3. Database
- [ ] **Backup taken and restore-tested** before any migration (0015→0025 are
      forward-only; rollback = restore)
- [ ] Postgres listens on loopback only (`ss -lntp | grep 5432` → 127.0.0.1)
- [ ] The DB user has only the privileges it needs

## 4. Caddy / TLS / network
```bash
caddy validate --config /etc/caddy/Caddyfile
grep -n 'import /etc/caddy/sites' /etc/caddy/Caddyfile   # must be present
```
- [ ] Main Caddyfile ends with `import /etc/caddy/sites/*.caddy`
- [ ] TLS certs issued for auth/admin/monitoring hostnames
- [ ] The admin API (`:8081`) and `GET /metrics` are **not** in any public site block
- [ ] Firewall: only 80/443 inbound; 8080/8081/8090/8091 and 5432 bound to loopback
      (`ss -lntp` to confirm)
- [ ] No `trusted_proxies` directive trusting a public range (breaks IP attribution)

## 5. systemd
```bash
systemctl status socrate socrate-admin-bff socrate-monitoring-bff
systemctl is-enabled socrate socrate-admin-bff socrate-monitoring-bff
```
- [ ] All three enabled and active
- [ ] Units carry the hardening directives (NoNewPrivileges, ProtectSystem=strict,
      dropped caps, syscall allowlist) — installed from `deploy/systemd/`

## 6. Post-deploy smoke (on the box)
```bash
curl -sf localhost:8080/health/readiness           # {"status":"ok", db+signing_key ok}
curl -sf localhost:8080/.well-known/openid-configuration | head -c 80
curl -s  localhost:8081/metrics | grep socrate_build_info   # real version
curl -so /dev/null -w '%{http_code}\n' https://admin.<domain>/       # 200
curl -so /dev/null -w '%{http_code}\n' https://monitoring.<domain>/  # 200
```
Then from a browser: sign in to each console through the hosted login, confirm no
console/CSP errors, and that the monitoring live feed and policy-decisions load.

## 7. Rollback readiness
- [ ] `install-remote.sh` keeps a timestamped backup under `/var/backups/socrate/`
      and auto-rolls-back on a failed health check — confirm the backup dir is writable
- [ ] You know the previous good tag to redeploy if needed

## Known operational limits (accept, don't fix at deploy time)
- Confidential-client calls (client_credentials / introspect / confidential
  refresh) are bcrypt-bound to **~14 req/s per 4 vCPU** — size accordingly.
- Run a **single instance** unless `STATE_BACKEND=postgres`; auto-defense
  counters are per-instance regardless.
- Observability gaps tracked as issues (SSE resume, alert engine, audit IP/UA) —
  see the test report §6.
