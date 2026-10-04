# Release kit — upgrade the running Socrate suite

Three scripts take a running single-VPS suite (Socrate, the admin console, the monitoring
console, behind Caddy) from one set of tags to the next. The bundle is built on the
workstation from the published tags and installed on the VPS; nothing is built on the server.

| Script | Runs on | Does |
|--------|---------|------|
| `socrate-release.sh` | workstation (macOS bash 3.2 or Linux) | builds the bundle from the three tags, writes a runbook with its checksums |
| `socrate-vps-install.sh` | VPS, as root | verifies the bundle, backs up, installs binaries, SPAs and units, migrates, restarts, smoke-tests |
| `socrate-caddy-update.sh` | VPS, as root | brings the console Caddy sites in line with the bundle (dry run, then `--apply`) |

## 1. Build (workstation)

From the folder holding the three clones (or symlinks to them), named `go-oauth2`,
`oauth2-admin` and `oauth2-monitoring`:

```bash
bash go-oauth2/deploy/release-kit/socrate-release.sh v1.10.0 v1.5.0 v1.0.1
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
- `socrate-vps-install.sh` and `socrate-caddy-update.sh`, copied from this folder;
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
parses and that `socrate-release.sh` is ASCII.
