#!/usr/bin/env bash
# reserve-legacy-ids.sh — keep the new Socrate from handing out ids the legacy one already uses.
# Run as root on the Socrate VPS, once, before carrying anything over (and again if the legacy
# server has grown past the reservation):
#
#   sudo bash reserve-legacy-ids.sh            # dry run: show the plan
#   sudo bash reserve-legacy-ids.sh --apply
#
# The carry-over keeps legacy primary keys (a user's id is its `sub`). The carry-over can run app
# by app, at each app's cut-over, and the legacy server keeps creating users meanwhile. So any id
# the new server assigns in the meantime (a new user, app or role) must stay clear of the legacy
# ranges. Otherwise a later carry-over silently skips the legacy row (ON CONFLICT DO NOTHING).
# This moves the users, apps and user_app_roles id sequences of NEW_DB past
# max(legacy id) + HEADROOM. It never lowers a sequence and changes no row.
#
# Env: OLD_DB (default db_socrate), NEW_DB (default socrate), HEADROOM (default 1000),
#      PSQL (default: sudo -u postgres psql).
set -euo pipefail
OLD_DB="${OLD_DB:-db_socrate}"
NEW_DB="${NEW_DB:-socrate}"
HEADROOM="${HEADROOM:-1000}"
PSQL="${PSQL:-sudo -u postgres psql}"
APPLY=0; [ "${1:-}" = --apply ] && APPLY=1
cd / # psql run through sudo -u postgres cannot read the caller's home directory

q() { $PSQL -X -q -At -v ON_ERROR_STOP=1 "$1" -c "$2"; }
case "$HEADROOM" in ''|*[!0-9]*) echo "HEADROOM must be a number" >&2; exit 2;; esac
for db in "$OLD_DB" "$NEW_DB"; do
  [ "$(q postgres "SELECT count(*) FROM pg_database WHERE datname='$db'")" = 1 ] || { echo "database $db not found" >&2; exit 2; }
done

changes=0
printf '\n▶ plan (next id each table will hand out in %s)\n' "$NEW_DB"
for tbl in users apps user_app_roles; do
  seq="$(q "$NEW_DB" "SELECT pg_get_serial_sequence('$tbl','id')")"
  [ -n "$seq" ] || { echo "  $tbl: no id sequence — skipped"; continue; }
  old_max="$(q "$OLD_DB" "SELECT COALESCE(MAX(id),0) FROM $tbl")"   # soft-deleted rows included
  new_max="$(q "$NEW_DB" "SELECT COALESCE(MAX(id),0) FROM $tbl")"
  next="$(q "$NEW_DB" "SELECT CASE WHEN is_called THEN last_value + 1 ELSE last_value END FROM $seq")"
  want=$(( old_max + HEADROOM + 1 ))
  [ "$new_max" -ge "$want" ] && want=$(( new_max + 1 ))
  if [ "$next" -ge "$want" ]; then
    printf '  ✔ %-15s next id %s (legacy max %s, new max %s) — already clear\n' "$tbl" "$next" "$old_max" "$new_max"
  else
    changes=1
    printf '  · %-15s next id %s → %s (legacy max %s + headroom %s; new max %s)\n' "$tbl" "$next" "$want" "$old_max" "$HEADROOM" "$new_max"
    [ "$APPLY" = 1 ] && q "$NEW_DB" "SELECT setval('$seq', $want, false)" >/dev/null
  fi
done
if [ "$changes" = 0 ]; then echo; echo "Nothing to change."
elif [ "$APPLY" = 1 ]; then echo; echo "✔ sequences moved. New users, apps and roles now get ids above the legacy ranges."
else echo; echo "Dry run only. Re-run with --apply."; fi
