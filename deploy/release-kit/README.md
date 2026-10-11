# Release kit — upgrade the running Socrate suite

Three scripts take a running single-VPS suite (Socrate, the admin console, the monitoring
console, behind Caddy) from one set of tags to the next. The bundle is built on the
workstation from the published tags and installed on the VPS; nothing is built on the server.
A fourth prepares a new VPS, once, before its first install.

| Script | Runs on | Does |
|--------|---------|------|
| `socrate-vps-prep.sh` | VPS, as root, once | installs PostgreSQL 16 and Caddy; creates the service users, directories, database, env files (secrets generated on the host), backup script and Caddy sites (dry run, then `--apply`) |
| `socrate-release.sh` | workstation (macOS bash 3.2 or Linux) | builds the bundle from the three tags, writes a runbook with its checksums |
| `socrate-vps-install.sh` | VPS, as root | verifies the bundle, backs up, installs binaries, SPAs and units, migrates, restarts, smoke-tests |
| `socrate-caddy-update.sh` | VPS, as root | brings the console Caddy sites in line with the bundle (dry run, then `--apply`) |

## 0. Prepare a new VPS (once)

On a fresh Ubuntu 22.04 or 24.04 host whose three DNS names already point at it:

```bash
sudo bash socrate-vps-prep.sh --acme-email ops@example.com            # the plan, nothing changed
sudo bash socrate-vps-prep.sh --acme-email ops@example.com --apply    # do it
```

The host names default to the production ones, like the installer and the Caddy updater; set
`--op-host`, `--admin-host` and `--mon-host` (or `OP_HOST`, `ADMIN_HOST`, `MON_HOST`) otherwise,
and give the same variables to those two scripts. `--help` lists the other options: SMTP (the
password from a file, never on the command line) and `--firewall` (ufw: SSH first, then 80 and
443; off by default). What it sets up, for `socrate-vps-install.sh` to find:

| What | Where |
|------|-------|
| Packages | PostgreSQL **16** (the PostgreSQL project's apt repository on 22.04), Caddy (its official repository), curl, python3, openssl, rsync, cron |
| Service users | `socrate`, `socrate-admin-bff`, `socrate-mon-bff` (system, no login, each with its own group) |
| Directories | `/var/lib/socrate` and `/var/lib/socrate/keys` (0700 socrate; the server creates its signing keys there at first start), `/srv/admin/dist`, `/srv/monitoring/dist` (root, 0755), `/var/backups/socrate` (root, 0700) |
| Database | role and database `socrate` on 127.0.0.1:5432, password generated on the host |
| Env files | `/etc/socrate/socrate.env`, `admin-bff.env`, `bff.env`: 0640 root:<service group>; ports 8080 (OP), 8082 (admin API, loopback), 8090 (monitoring BFF), 8092 (admin BFF); `AUTO_MIGRATE=false`, `ADMIN_PASSWORD_LOGIN_ENABLED=false`; the two BFF client ids and secrets are `CHANGE_ME_AFTER_CLIENT_REGISTRATION` |
| Backups | `/usr/local/sbin/socrate-backup.sh` (prints `done: OK <dump> <size> migrations=<n>`, keeps 14 dumps), run daily from `/etc/cron.d/socrate-backup` |
| Caddy | `/etc/caddy/Caddyfile` (ACME e-mail, `import /etc/caddy/sites/*.caddy`), one site per host in `/etc/caddy/sites/<host>.caddy`, in the form `socrate-caddy-update.sh` edits |

It never overwrites what is already there (env file, secret, role, database, Caddy site,
backup script): it reports it as kept, so a re-run is safe. The only file it replaces is the
Caddy package's default welcome-page Caddyfile, after copying it to `/var/backups/socrate/`.

The units, binaries and SPAs come from the bundle. The console OAuth clients are created by
`socrate-vps-install.sh` on its first run: it creates the first superadmin (you choose the e-mail
and password), registers both consoles as confidential clients through the loopback admin API,
and writes their ids and secrets over the placeholders. Then continue with step 1.

## 1. Build (workstation)

From the folder holding the three clones (or symlinks to them), named `go-oauth2`,
`oauth2-admin` and `oauth2-monitoring`:

```bash
bash go-oauth2/deploy/release-kit/socrate-release.sh v1.14.1 v1.7.0 v1.2.0
```

The arguments are the Socrate, admin console and monitoring console tags. Each must be an
annotated tag, pushed to origin (`FETCH=1` fetches the tags first; `ALLOW_UNTAGGED=1` allows
a dry build from any ref). Each repository is built in a temporary worktree, so the clones
are left as they are.

Requirements: git, Go with `GOTOOLCHAIN=auto` (the default; each binary must be built with
the Go its `go.mod` names, and the script checks), Node.js at least each console's `.nvmrc`,
with npm, and tar.

Options, as environment variables: `OUT_DIR` (default `./release`), `VPS_SSH` (the
`user@host` written into the runbook), `PUBLIC_ISSUER` (the URL the runbook checks
`/version` on).

Output, in `./release/`:

- `socrate-suite-<tag>.tar.gz`, the bundle;
- `socrate-vps-install.sh`, `socrate-caddy-update.sh` and `socrate-vps-prep.sh`, copied from this
  folder;
- `RUNBOOK-<tag>.md`, the deploy steps below filled in with this build's checksum;
- `SHA256-<tag>.txt`.

## 2. Deploy (VPS)

Follow the generated `RUNBOOK-<tag>.md`: upload, back up the database, verify and unpack the
bundle, run the installer, run the Caddy updater (dry run, then `--apply`), and check
`/version`.

The installer keeps the previous binaries, SPAs and units in `/var/backups/socrate/install-*`.
The Caddy updater keeps the previous site files in `/var/backups/socrate/caddy-*`, and restores
them by itself if validation or the reload fails.

## Bundle layout

```
socrate-suite-<tag>/
  MANIFEST                    repos, tags, commits, build time, Go and Node versions
  SHA256SUMS                  every other file in the bundle
  bin/socrate                 Socrate server, version-stamped (/version)
  bin/socrate-seed
  bin/socrate-admin-bff
  bin/socrate-monitoring-bff
  www/admin/dist/             admin SPA
  www/monitoring/dist/        monitoring SPA
  systemd/socrate.service               from go-oauth2 (canonical)
  systemd/socrate-admin-bff.service     from oauth2-admin
  systemd/socrate-monitoring-bff.service from oauth2-monitoring
  caddy/admin-csp.txt                   the admin site's Content-Security-Policy
  caddy/admin-csp-report-only.txt       its Trusted Types Report-Only policy
  caddy/admin-reporting-endpoints.txt   its Reporting-Endpoints header
  caddy/admin-bff-paths.txt             the paths its @bff matcher routes to the BFF
```

The `caddy/` files are read from oauth2-admin's `deploy/Caddyfile` at its tag. The binaries
are static linux/amd64 builds (`CGO_ENABLED=0`, `-trimpath`).

## Editing the kit

`socrate-release.sh` stays ASCII-only and bash 3.2-compatible (no associative arrays,
`mapfile` or `${var,,}`), because macOS ships bash 3.2. CI checks that every script here
parses and that `socrate-release.sh` and `socrate-vps-prep.sh` (and its test) are ASCII, and
runs `test-caddy-update.sh`, which drives `socrate-caddy-update.sh` end to end (dry run and
`--apply`) on fixture sites with stub `caddy`, `systemctl` and `curl`. Run it locally as root
or with sudo before changing the updater.

`test-vps-prep.sh` runs `socrate-vps-prep.sh` against a fake root (`PREP_ROOT`, for tests only)
with stub apt, Postgres, Caddy, systemd and user commands: the dry-run plan on a fresh host, the
files, keys and modes of an `--apply`, a second run that changes nothing, the Caddy sites through
`socrate-caddy-update.sh` (and through a real Caddy with `CADDY_BIN=/path/to/caddy`), and the
backup script's result line. Run it after changing the prep script, the installer's expectations
or the updater. What it cannot cover (apt, the real database, certificates, ufw) needs a
throwaway VPS.
