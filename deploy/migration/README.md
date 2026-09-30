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

### When the new server is not empty

`carry-over.sh` was written for a freshly installed target. Once the new server has its
own rows, the copy's `ON CONFLICT DO NOTHING` **silently skips** any legacy row whose id
or unique key is already taken. Typical sources of such rows are the first superadmin,
the console clients, and apps registered by hand. A skipped row causes one of three
failures:

- **A legacy user whose id is taken:** the user isn't carried, and its `sub` now points
  at someone else.
- **A legacy user whose email is taken under another id:** the user isn't carried, and
  its `sub` changes.
- **A legacy app whose id is taken:** the app isn't carried, and its role rows attach to
  the app that holds the id.

Four scripts, run in this order, make it safe. All of them run as root on the Socrate VPS
and take `OLD_DB` (default `db_socrate`) and `NEW_DB`. They are idempotent, and the
ones that change data dry-run unless given `--apply`.

1. **[`carry-over-preflight.sh`](./carry-over-preflight.sh)** (read-only). Run it with the
   `APPS` and `EXCLUDE_USERS` you will give the copy. It names every collision, checks
   that new ids are reserved clear of the legacy ranges, and reports MFA users (legacy
   TOTP secrets are encrypted with the legacy `SECRET_KEY_BASE`, so those users must
   re-enrol). Emails are printed masked.
2. **[`reserve-legacy-ids.sh`](./reserve-legacy-ids.sh).** Moves the `users`, `apps` and
   `user_app_roles` id sequences of the new database past the legacy maximum plus
   `HEADROOM` (default 1000). The legacy server keeps creating rows until its last app
   has moved, so anything the new server creates meanwhile must not take an id a later
   carry-over needs. Run it before creating anything else on the new server. It never
   lowers a sequence, and `carry-over.sh` no longer does either.
3. **[`move-user-to-legacy-id.sh`](./move-user-to-legacy-id.sh)
   `--email <e> --to <legacy id>`.** Use it when a person was created on the new server
   (typically the first superadmin) under an id other than their legacy one. In one
   transaction it:
   - retires the current row: soft-deleted, `token_version` bumped;
   - inserts the same person under the legacy id, with the same password hash, role,
     MFA secret and profile;
   - moves their MFA recovery codes, app roles and owned apps.

   The audit rows are **not** rewritten: they are HMAC-chained over `user_id`, so they
   keep the old id, and the integrity chain stays valid. It refuses unless the legacy
   row with that id has the same email and the id is free in the new database.
4. **`carry-over.sh`** with `APPS=<client_id>[,…]`, plus `EXCLUDE_USERS=<legacy id>[,…]`
   for obsolete accounts (not carried, nor their roles; an app they own is carried with
   no owner). Rehearse it on a `*_test` copy of the new database
   (`createdb -T socrate socrate_test`, or a `pg_dump` restore), then run it with
   `FORCE=1`.

Re-run the preflight before step 4: it must end with `No collision`. The whole sequence
was rehearsed on databases with this deployment's layout: legacy users 1–11, with the
operator at 9 and an obsolete account at 1; legacy apps 2, 4 and 6–10; a new server
holding the operator at 1, two console clients and one hand-registered app. The result:
- user ids and `sub`s preserved;
- the operator's new-server credentials kept;
- the obsolete account and its roles excluded;
- sequences only moved forward;
- the audit chain byte-identical;
- every script a no-op on re-run.

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
- [`carry-over-preflight.sh`](./carry-over-preflight.sh), [`reserve-legacy-ids.sh`](./reserve-legacy-ids.sh),
  [`move-user-to-legacy-id.sh`](./move-user-to-legacy-id.sh) — making the carry-over safe
  when the new server is not empty (see *When the new server is not empty*).
