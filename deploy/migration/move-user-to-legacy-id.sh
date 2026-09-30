#!/usr/bin/env bash
# move-user-to-legacy-id.sh — give an account created on the new Socrate the id it has on the
# legacy one, so its `sub` stays the same for every carried app. Run as root on the Socrate VPS:
#
#   sudo bash move-user-to-legacy-id.sh --email you@example.com --to 9            # dry run
#   sudo bash move-user-to-legacy-id.sh --email you@example.com --to 9 --apply
#
# The typical case: the first superadmin was created by the install before the carry-over, and got
# id 1, while the same person has another id on the legacy server.
#
# The row is NOT renumbered in place. Audit rows are HMAC-chained over their user_id, and
# rewriting them would break the integrity chain. Instead, in ONE transaction:
#   1. the current row is retired: soft-deleted, token_version bumped. Tokens minted for the old
#      id stop working; the audit history keeps pointing at it, untouched.
#   2. a copy with the legacy id is inserted: the same email, password hash, role, MFA secret and
#      profile. The MFA secret is encrypted with SECRET_KEY_BASE alone, so it stays valid.
#   3. what belongs to the person moves with them: MFA recovery codes, app roles, owned apps.
# Historical rows (security_audit_logs, admin_logs, alert and block records) keep the old id.
# Refuses unless the legacy row with that id has the same email, and the id is free in the new
# database (live or deleted rows).
#
# Env: OLD_DB (default db_socrate), NEW_DB (default socrate), PSQL (default: sudo -u postgres psql).
set -euo pipefail
OLD_DB="${OLD_DB:-db_socrate}"
NEW_DB="${NEW_DB:-socrate}"
PSQL="${PSQL:-sudo -u postgres psql}"
EMAIL=""; TO=""; APPLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --email) EMAIL="${2:-}"; shift 2 ;;
    --to)    TO="${2:-}"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    *) echo "usage: $0 --email <email> --to <legacy id> [--apply]" >&2; exit 2 ;;
  esac
done
cd / # psql run through sudo -u postgres cannot read the caller's home directory
die() { printf '✖ %s\n' "$*" >&2; exit 1; }
q() { $PSQL -X -q -At -v ON_ERROR_STOP=1 "$1" -c "$2"; }
[ -n "$EMAIL" ] && [ -n "$TO" ] || die "usage: $0 --email <email> --to <legacy id> [--apply]"
case "$TO" in *[!0-9]*) die "--to must be a numeric id";; esac
case "$EMAIL" in *\'*|*\\*) die "unexpected character in --email";; esac
em="$(tr '[:upper:]' '[:lower:]' <<<"$EMAIL")"

from="$(q "$NEW_DB" "SELECT string_agg(id::text, ',') FROM users WHERE lower(email)='$em' AND deleted_at IS NULL")"
[ -n "$from" ] || die "no live user with that email in $NEW_DB"
case "$from" in *,*) die "several live users with that email in $NEW_DB ($from)";; esac
[ "$from" != "$TO" ] || { echo "✔ already at id $TO — nothing to do"; exit 0; }
legacy="$(q "$OLD_DB" "SELECT lower(email) FROM users WHERE id=$TO")"
[ "$legacy" = "$em" ] || die "legacy user $TO is not this person (legacy email differs or id not found) — refusing"
[ "$(q "$NEW_DB" "SELECT count(*) FROM users WHERE id=$TO")" = 0 ] || die "id $TO is already used in $NEW_DB (live or deleted row) — refusing"

cols="$(q "$NEW_DB" "SELECT string_agg(quote_ident(column_name), ',' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name NOT IN ('id','deleted_at','updated_at')")"
has() { [ "$(q "$NEW_DB" "SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='$1' AND column_name='$2'")" = 1 ]; }
moves=()
has mfa_recovery_codes user_id && moves+=("UPDATE mfa_recovery_codes SET user_id=$TO WHERE user_id=$from;")
has user_app_roles user_id    && moves+=("UPDATE user_app_roles SET user_id=$TO WHERE user_id=$from;")
has apps owner_id             && moves+=("UPDATE apps SET owner_id=$TO WHERE owner_id=$from;")

printf '\n▶ plan (%s)\n' "$NEW_DB"
echo "  · retire user $from: soft-delete, bump token_version (its tokens stop working; audit rows untouched)"
echo "  · insert the same person as user $TO (legacy id, same email in $OLD_DB): password, role, MFA, profile copied"
for tbl in mfa_recovery_codes user_app_roles; do
  has "$tbl" user_id && echo "  · move $(q "$NEW_DB" "SELECT count(*) FROM $tbl WHERE user_id=$from") $tbl row(s) to $TO"
done
has apps owner_id && echo "  · move ownership of $(q "$NEW_DB" "SELECT count(*) FROM apps WHERE owner_id=$from") app(s) to $TO"
echo "  · keep on $from (history): $(q "$NEW_DB" "SELECT count(*) FROM security_audit_logs WHERE user_id=$from") audit row(s) and the admin/alert records"
[ "$APPLY" = 1 ] || { printf '\nDry run only. Re-run with --apply.\n'; exit 0; }

q "$NEW_DB" "BEGIN;
UPDATE users SET deleted_at = now(), token_version = token_version + 1, updated_at = now() WHERE id = $from AND deleted_at IS NULL;
INSERT INTO users (id, $cols, deleted_at, updated_at) SELECT $TO, $cols, NULL, now() FROM users WHERE id = $from;
${moves[*]}
COMMIT;" >/dev/null
got="$(q "$NEW_DB" "SELECT id FROM users WHERE lower(email)='$em' AND deleted_at IS NULL")"
[ "$got" = "$TO" ] || die "verification failed: the live row for that email is '$got'"
printf '\n✔ %s is now user %s in %s (user %s retired). Sign in again: sessions for the old id are over.\n' "$EMAIL" "$TO" "$NEW_DB" "$from"
