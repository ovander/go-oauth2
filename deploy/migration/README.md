# Socrate migration — moving applications to the latest OP

This directory documents how to migrate relying-party applications onto the latest
**Socrate v1.3.0** OAuth2.1 / OIDC provider.

## Approach: strangler-fig, not in-place upgrade

The new Socrate is stood up on its **own subdomain, beside** any existing
deployment, rather than upgrading an old instance in place. Applications are then
moved over **one at a time**. This keeps the running identity provider untouched
until each app has been verified against the new one, and makes rollback per app a
configuration change (point the app back at the old issuer).

Benefits over an in-place database upgrade:

- The live IdP keeps serving un-migrated apps throughout.
- The new database starts empty and migrates `0001 → 0024` cleanly (verified), with
  no risky forward-migration of production data.
- New issuer ⇒ new RS256 signing keys; tokens are issuer-scoped, so each app simply
  re-authenticates against the new issuer as it cuts over.

## Target topology (proposed)

> The exact hostnames are confirmed per rollout — this section records the
> recommended default. The data-migration policy is settled (see below).

Recommended hostname scheme — **nested** under a single `socrate` label:

| Host | Service | Port | Exposure |
|---|---|---|---|
| `socrate.vandermoten.eu` | Socrate OP (v1.3.0) | 8080 | public via Caddy |
| — its admin API | (same binary) | 8082 | loopback only |
| `admin.socrate.vandermoten.eu` | Socrate Admin (BFF + SPA) | 8092 | public via Caddy |
| `monitor.socrate.vandermoten.eu` | Socrate Monitor (BFF + SPA) | 8090 | public via Caddy |

Display names: **Socrate** (OP), **Socrate Admin**, **Socrate Monitor**.

DNS records to create (all pointing at the VPS; add `AAAA` too if it has IPv6):

```
socrate.vandermoten.eu.          A   <vps-ip>
admin.socrate.vandermoten.eu.    A   <vps-ip>
monitor.socrate.vandermoten.eu.  A   <vps-ip>
```

Certificates are issued automatically by Caddy over HTTP-01 (no DNS-provider API
token required for explicit hostnames).

## Data migration policy: ID-preserving carry-over (confirmed)

Users, apps and their role assignments are **copied from the old database with their
primary keys preserved**. A Socrate token's `sub` is the user's numeric id, so this
keeps every subject identical: relying parties that match users by `sub` (e.g.
Ascenda's `users.external_id`) keep working with **no remap**, and people and
confidential clients keep their existing passwords and client secrets (bcrypt hashes
are carried as-is).

[`carry-over.sh`](./carry-over.sh) implements it:

- **Column-intersection copy** — the old schema (e.g. migration 0005) and v1.3.0
  (0024) differ, so only shared columns are copied; columns the old schema lacks are
  normalised to the values an in-place upgrade would have produced (`{}` for
  `allowed_scopes`, `audiences`, `claim_mappings`, `attributes`; `false` for flags).
- **Per-app or all** — `APPS=client_id[,…]` copies those apps, their role holders and
  each app's owner; `APPS=ALL` copies everything.
- **Idempotent** — `ON CONFLICT DO NOTHING`, so re-running or migrating a second app
  with overlapping users is safe. Id sequences are reset past the carried ids.
- **Streams through a pipe** — no temp files, so credential hashes never touch disk.
- **Safe by default** — refuses a target not named `*_test` unless `FORCE=1`.

```bash
# 1) rehearse against a throwaway copy of the new database
OLD_DB=db_socrate NEW_DB=db_socrate_v13_test APPS=<client_id> ./carry-over.sh
# 2) then the real target
FORCE=1 OLD_DB=db_socrate NEW_DB=db_socrate_v13 APPS=<client_id> ./carry-over.sh
```

Two settings to know about after a carry-over:

- **PKCE enforcement is per client.** Carried apps would otherwise have
  `require_pkce=false`, so the script sets it to `true` on the migrated apps
  (`SET_REQUIRE_PKCE=1`, the default). Only do this for apps whose compatibility
  report confirms they send PKCE; a client that does not will be rejected.
- **Scope policy.** `allowed_scopes` is empty on carried apps. With the default
  `SCOPE_POLICY_MODE=off` that means "no restriction". Populate each app's allowed
  scopes **before** switching the mode to `observe`/`enforce`.

Take a `pg_dump` of both databases before the real run.

## Per-application migration workflow

1. **Evaluate compatibility.** Run [`APP-COMPAT-PROMPT.md`](./APP-COMPAT-PROMPT.md)
   in a fresh Claude Code session opened in the application's repository. It produces
   a `SOCRATE-COMPAT-REPORT.md` with a verdict, findings, a migration checklist, and a
   test plan. Resolve any blockers before proceeding.
2. **Register the client** on the new OP (redirect URI from the report; PKCE required).
3. **Migrate data** for that app with [`carry-over.sh`](./carry-over.sh) (its app
   record, role holders and owner; ids preserved) — rehearse on a `*_test` copy first.
4. **Cut over** the app's configuration to `https://socrate.vandermoten.eu` (issuer,
   discovery/JWKS, client id/secret).
5. **Verify** with the report's test plan (login, JWKS validation, refresh-rotation
   survival, forced re-auth on reuse, logout).
6. **Roll back** if needed by pointing the app back at the previous issuer.

## Files

- [`APP-COMPAT-PROMPT.md`](./APP-COMPAT-PROMPT.md) — the per-application compatibility
  evaluation prompt, plus the canonical v1.3.0 client contract it checks against.
- [`SOCRATE-V1.3.0-OP-CONTRACT.md`](./SOCRATE-V1.3.0-OP-CONTRACT.md) — the confirmed
  v1.3.0 OpenID Provider metadata and token/key facts, derived from the server source.
  Use it as the source of truth when the live discovery document is unreachable.
- [`carry-over.sh`](./carry-over.sh) — the ID-preserving data migration (users, apps,
  role assignments) from the old database into the new one.
